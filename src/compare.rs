use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    fmt,
    fs::File,
    io::{BufWriter, Write},
};

use crate::{
    capture::reader::{CaptureEvent, CaptureMessage, CaptureReader, ClientId, ReadError},
    proto::c2s::{PgMsg, PgMsgParser},
    utils::format::DisplayBytes,
};

use anyhow::anyhow;
use tracing::{error, info, warn};

#[derive(Default)]
struct Side {
    connect_ts: u64,
    count: u64,
    frames: VecDeque<(u64, usize, Vec<u8>)>,
}

impl Side {
    fn on_message(&mut self, msg: CaptureMessage) {
        match msg.event {
            CaptureEvent::Connect => self.connect_ts = msg.ts,
            CaptureEvent::PqFrame { offset, frame, tag } => {
                if tag != 0 {
                    self.count += 1;
                    self.frames.push_back((msg.ts, offset, frame));
                }
            }
            _ => {}
        }
    }
}

#[derive(Default)]
struct Replay {
    src_id: Option<ClientId>,
    side: Side,
}

#[derive(Default)]
struct Acc {
    cnt: f64,
    sum: f64,
    ext: f64,
}

impl Acc {
    fn add(&mut self, d: f64) {
        self.cnt += 1.0;
        self.sum += d;
        if d.abs() > self.ext.abs() {
            self.ext = d;
        }
    }

    fn avg(&self) -> f64 {
        if self.cnt != 0.0 {
            self.sum / self.cnt
        } else {
            0.0
        }
    }
}

struct Source {
    id: ClientId,
    side: Side,
    parser: PgMsgParser,
    replay_id: Option<ClientId>,
    replay_connect_ts: u64,
    replay_count: u64,
    behind: Acc,
    ahead: Acc,
}

impl Source {
    fn new(id: ClientId) -> Self {
        Self {
            id,
            side: Side::default(),
            parser: PgMsgParser::default(),
            replay_id: None,
            replay_connect_ts: 0,
            replay_count: 0,
            behind: Acc::default(),
            ahead: Acc::default(),
        }
    }

    fn compare(
        &mut self,
        replay: &mut Side,
        writer: &mut Option<BufWriter<File>>,
    ) -> anyhow::Result<()> {
        self.replay_connect_ts = replay.connect_ts;
        self.replay_count = replay.count;
        let rid = self.replay_id.unwrap();

        while !self.side.frames.is_empty() && !replay.frames.is_empty() {
            let (s_ts, s_offset, s_data) = self.side.frames.pop_front().unwrap();
            let (r_ts, r_offset, r_data) = replay.frames.pop_front().unwrap();
            let s_ts = s_ts.saturating_sub(self.side.connect_ts);
            let r_ts = r_ts.saturating_sub(replay.connect_ts);

            let min_time = s_ts.min(r_ts) as f64 / 1e6;
            let delta = r_ts as f64 - s_ts as f64;
            let same = s_data == r_data;

            if let Some(w) = writer {
                writeln!(
                    w,
                    "{:.6},{:.3},{},{}",
                    min_time,
                    delta / 1e3,
                    self.id,
                    DisplayFrame(self.parser.parse(&s_data), &s_data)
                )?;
                if !same {
                    writeln!(
                        w,
                        "{:.6},{:.3},{},{}",
                        min_time,
                        delta / 1e3,
                        rid,
                        DisplayFrame(self.parser.parse(&r_data), &r_data)
                    )?;
                }
            }
            if !same {
                let e = format!(
                    "Frame contents do not match:\n{} at {} <=> {} at {}\n{}",
                    self.id,
                    s_offset,
                    self.replay_id.unwrap(),
                    r_offset,
                    DisplayFrame(self.parser.parse(&s_data), &s_data),
                );
                let e = format!("{e}\n{}", DisplayFrame(self.parser.parse(&r_data), &r_data));
                return Err(anyhow!(e));
            }
            if delta > 0.0 {
                self.behind.add(delta);
            } else {
                self.ahead.add(delta);
            }
        }
        Ok(())
    }
}

fn startup_client_id(frame: &[u8]) -> Option<ClientId> {
    let mut parser = PgMsgParser::new();
    let msg = parser.parse(frame).ok()?;
    let PgMsg::StartupMessage { params, .. } = &msg else {
        return None;
    };
    (0..params.len())
        .filter_map(|i| msg.startup_param(i))
        .find(|(k, _)| *k == "pgr.client_id")
        .and_then(|(_, v)| v.parse().ok())
}

pub fn compare(
    mut src_reader: Box<dyn CaptureReader>,
    mut replay_reader: Box<dyn CaptureReader>,
    mut writer: Option<BufWriter<File>>,
) -> anyhow::Result<()> {
    let mut sources: BTreeMap<ClientId, Source> = BTreeMap::new();
    let mut replays: HashMap<ClientId, Replay> = HashMap::new();
    let mut ignored = HashSet::new();

    let (mut src_eof, mut replay_eof) = (false, false);
    while !src_eof || !replay_eof {
        if !src_eof {
            match src_reader.next() {
                Ok(msg) => {
                    let id = msg.client;
                    let src = sources.entry(id).or_insert_with(|| Source::new(id));
                    src.side.on_message(msg);
                    if let Some(replay) = src.replay_id.and_then(|r| replays.get_mut(&r)) {
                        src.compare(&mut replay.side, &mut writer)?;
                    }
                }
                Err(ReadError::Eof) => src_eof = true,
                Err(ReadError::Error(e)) => {
                    error!("Failed to read source capture: {e}");
                    return Ok(());
                }
            }
        }
        if !replay_eof {
            match replay_reader.next() {
                Ok(msg) => {
                    let rid = msg.client;
                    if ignored.contains(&rid) {
                        continue;
                    }
                    let replay = replays.entry(rid).or_default();
                    match &msg.event {
                        CaptureEvent::PqFrame { tag: 0, frame, .. } => {
                            if replay.src_id.is_none() {
                                replay.src_id = startup_client_id(frame);
                            }
                            continue;
                        }
                        CaptureEvent::PqFrame { .. } if replay.src_id.is_none() => {
                            info!("[{}:replay] pgr.client_id not found", rid);
                            ignored.insert(rid);
                            replays.remove(&rid);
                            continue;
                        }
                        _ => {}
                    }
                    replay.side.on_message(msg);
                    let Some(id) = replay.src_id else { continue };
                    let src = sources.entry(id).or_insert_with(|| Source::new(id));
                    src.replay_id = Some(rid);
                    src.compare(&mut replay.side, &mut writer)?;
                }
                Err(ReadError::Eof) => replay_eof = true,
                Err(ReadError::Error(e)) => {
                    error!("Failed to read replay capture: {e}");
                    return Ok(());
                }
            }
        }
    }

    for s in sources.values() {
        if s.side.count != s.replay_count {
            warn!(
                "{}: frame count mismatch: {} / {}",
                s.id, s.side.count, s.replay_count
            );
        }
        info!(
            "{}: conn {:.2}ms; avg {:.2}ms; max {:.2}ms <{}/{}> avg {:.2}ms; max {:.2}ms",
            s.id,
            (s.replay_connect_ts as f64 - s.side.connect_ts as f64) / 1e3,
            s.behind.avg() / 1e3,
            s.behind.ext / 1e3,
            s.behind.cnt,
            s.ahead.cnt,
            s.ahead.avg() / 1e3,
            s.ahead.ext / 1e3,
        );
    }
    Ok(())
}

struct DisplayFrame<'a, 'b>(Result<PgMsg<'a>, &'static str>, &'b [u8]);

impl fmt::Display for DisplayFrame<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Ok(msg) => write!(f, "{}", msg),
            Err(e) => write!(f, "({}),{}", e, DisplayBytes(self.1)),
        }
    }
}
