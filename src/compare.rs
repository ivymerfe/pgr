use std::{
    collections::VecDeque,
    fs::File,
    io::{self, BufReader, Read},
};

use ahash::AHashMap;
use anyhow::anyhow;
use tracing::{info, warn};

use crate::capture::{
    CaptureReader, ClientEvent, ClientId, MSG_BIND, MSG_CLOSE, MSG_CONNECT, MSG_DISCONNECT,
    MSG_EXECUTE, MSG_PARSE, MSG_SIMPLE_QUERY, MSG_SYNC,
};

pub struct TimingData {
    pub id: ClientId,
    pub event_type: u8,
    pub ts: u64,
}

pub struct TimingReader {
    reader: BufReader<File>,
}

impl TimingReader {
    pub fn new(file: File) -> Self {
        Self {
            reader: BufReader::new(file),
        }
    }

    pub fn next(&mut self) -> io::Result<Option<TimingData>> {
        let mut buf = [0u8; 13];
        match self.reader.read_exact(&mut buf) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }
        Ok(Some(TimingData {
            id: u32::from_le_bytes(buf[0..4].try_into().unwrap()),
            event_type: buf[4],
            ts: u64::from_le_bytes(buf[5..13].try_into().unwrap()),
        }))
    }
}

#[derive(Default, Clone, Copy)]
struct Dev {
    count: u64,
    sum_us: u64,
    max_us: u64,
}

impl Dev {
    fn add(&mut self, v: u64) {
        self.count += 1;
        self.sum_us += v;
        self.max_us = self.max_us.max(v);
    }

    fn avg_ms(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.sum_us as f64 / self.count as f64 / 1e3
        }
    }

    fn max_ms(&self) -> f64 {
        self.max_us as f64 / 1e3
    }
}

#[derive(Default)]
struct TypeStats {
    early: Dev,
    late: Dev,
}

#[derive(Default)]
struct ClientStats {
    cap: VecDeque<(u8, u64, bool)>,
    tim: VecDeque<(u8, u64)>,
    connect_us: Option<i64>,
    disconnect_us: Option<i64>,
    msgs: TypeStats,
    matched: u64,
    skipped: u64,
}

fn event_code(e: &ClientEvent) -> Option<u8> {
    match e {
        ClientEvent::Connect { .. } => Some(MSG_CONNECT),
        ClientEvent::Disconnect => Some(MSG_DISCONNECT),
        ClientEvent::SimpleQuery { .. } => Some(MSG_SIMPLE_QUERY),
        ClientEvent::Parse { .. } => Some(MSG_PARSE),
        ClientEvent::Bind { .. } => Some(MSG_BIND),
        ClientEvent::Execute { .. } => Some(MSG_EXECUTE),
        ClientEvent::Sync => Some(MSG_SYNC),
        ClientEvent::Close { .. } => Some(MSG_CLOSE),
        ClientEvent::Lsn { .. } | ClientEvent::TxEnd { .. } => None,
    }
}

fn drain(c: &mut ClientStats, anchor: &mut Option<(u64, u64)>) {
    while let (Some((ct, cts, restore)), Some((tt, tts))) =
        (c.cap.front().copied(), c.tim.front().copied())
    {
        c.cap.pop_front();
        if ct != tt {
            c.skipped += 1;
            continue;
        }
        c.tim.pop_front();
        let (ac, at) = *anchor.get_or_insert((cts, tts));
        let dev = (tts as i64 - at as i64) - (cts as i64 - ac as i64);
        match ct {
            MSG_CONNECT => c.connect_us = Some(dev),
            MSG_DISCONNECT => c.disconnect_us = Some(dev),
            _ if restore => {}
            _ => {
                if dev >= 0 {
                    c.msgs.late.add(dev as u64);
                } else {
                    c.msgs.early.add(dev.unsigned_abs());
                }
            }
        }
        c.matched += 1;
    }
}

pub fn compare(
    mut capture_reader: CaptureReader,
    mut timing_reader: TimingReader,
) -> anyhow::Result<()> {
    let mut clients = AHashMap::<ClientId, ClientStats>::new();
    let mut anchor: Option<(u64, u64)> = None;
    let mut capture_eof = false;

    loop {
        let t = match timing_reader.next() {
            Ok(Some(t)) => t,
            Ok(None) => break,
            Err(e) => return Err(anyhow!("Failed to read timing: {e}")),
        };
        let c = clients.entry(t.id).or_default();
        c.tim.push_back((t.event_type, t.ts));
        drain(c, &mut anchor);

        while !capture_eof && !clients[&t.id].tim.is_empty() {
            match capture_reader.read_event() {
                Ok(Some(msg)) => {
                    if let Some(code) = event_code(&msg.event) {
                        let restore = matches!(
                            &msg.event,
                            ClientEvent::Connect { session_id } if !session_id.is_empty()
                        );
                        let c = clients.entry(msg.id).or_default();
                        c.cap.push_back((code, msg.ts, false));
                        if restore {
                            c.cap.push_back((MSG_SIMPLE_QUERY, msg.ts, true));
                        }
                        drain(c, &mut anchor);
                    }
                }
                Ok(None) => {
                    info!("Finished reading capture on timing id={}", t.id);
                    capture_eof = true;
                }
                Err(e) => return Err(anyhow!("Failed to read capture: {e}")),
            }
        }
    }

    let mut ids: Vec<ClientId> = clients.keys().copied().collect();
    ids.sort();
    let (mut matched, mut unmatched) = (0u64, 0u64);
    for id in &ids {
        let c = clients.get_mut(&id).unwrap();
        drain(c, &mut anchor);
        matched += c.matched;
        unmatched += c.tim.len() as u64;

        let connect_ms = c.connect_us.unwrap_or(0) as f64 / 1e3;
        let disconnect_ms = c.disconnect_us.unwrap_or(0) as f64 / 1e3;
        info!(
            "[{}] c={:+.3}ms d={:+.3}ms avg={:+.3}ms max={:+.3}ms <{}/{}> avg={:+.3}ms max={:+.3}ms",
            id,
            connect_ms,
            disconnect_ms,
            -c.msgs.early.avg_ms(),
            -c.msgs.early.max_ms(),
            c.msgs.early.count,
            c.msgs.late.count,
            c.msgs.late.avg_ms(),
            c.msgs.late.max_ms()
        );
    }
    if unmatched > 0 {
        warn!("{} timing events without capture pair", unmatched);
    }
    info!("Matched {}", matched);
    Ok(())
}
