use std::collections::HashSet;
use std::fmt::{self, Display, Formatter};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::{collections::HashMap, error::Error, net::SocketAddr, path::Path};

use tracing::{error, info, warn};

use crate::parser::c2s::parse_pg_message;
use crate::parser::pcap::{CaptureReader, ReadState};
use crate::parser::pq_stream::{PqFrame, PqStream};
use crate::replay_frame_tags::should_replay_frame;

pub struct CompareState {
    s1_to_s2: HashMap<SocketAddr, SocketAddr>,
    s2_to_s1: HashMap<SocketAddr, SocketAddr>,
    s1_ignore: HashSet<SocketAddr>,
    s2_ignore: HashSet<SocketAddr>,
    s1_start_ts: u64,
    s2_start_ts: u64,

    pub total_frames: f64,
    pub delta_max: f64,
    pub delta_sum: f64,
}

impl CompareState {
    pub fn new() -> Self {
        return Self {
            s1_to_s2: HashMap::new(),
            s2_to_s1: HashMap::new(),
            s1_ignore: HashSet::new(),
            s2_ignore: HashSet::new(),
            s1_start_ts: 0,
            s2_start_ts: 0,

            total_frames: 0.0,
            delta_max: 0.0,
            delta_sum: 0.0,
        };
    }

    pub fn load_map<P: AsRef<Path>>(&mut self, path: P) -> Result<(), Box<dyn Error>> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        for line_result in reader.lines() {
            let line = line_result?;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let mut parts = trimmed.split("->");
            let left_str = parts.next().ok_or("Missing left SocketAddr")?.trim();
            let right_str = parts.next().ok_or("Missing right SocketAddr")?.trim();

            let addr_1: SocketAddr = left_str.parse()?;
            let addr_2: SocketAddr = right_str.parse()?;

            self.s1_to_s2.insert(addr_1, addr_2);
            self.s2_to_s1.insert(addr_2, addr_1);
        }

        Ok(())
    }

    pub fn compare_ts(&mut self, ts1: u64, ts2: u64) {
        if self.s1_start_ts == 0 {
            self.s1_start_ts = ts1;
        }
        if self.s2_start_ts == 0 {
            self.s2_start_ts = ts2;
        }
        let rel_1 = (ts1 - self.s1_start_ts) as f64 / 1e6;
        let rel_2 = (ts2 - self.s2_start_ts) as f64 / 1e6;
        let delta = rel_2 - rel_1;
        if delta.abs() > self.delta_max.abs() {
            self.delta_max = delta;
        }
        self.delta_sum += delta.abs();
        self.total_frames += 1.0;
    }

    pub fn compare<P: AsRef<Path>>(
        &mut self,
        c1: P,
        c2: P,
        port1: u16,
        port2: u16,
    ) -> Result<(), Box<dyn Error>> {
        let file1 = File::open(c1)?;
        let file2 = File::open(c2)?;
        let meta1 = file1.metadata()?;
        let meta2 = file2.metadata()?;

        let c1_buf_reader = BufReader::with_capacity(131072, file1);
        let c2_buf_reader = BufReader::with_capacity(131072, file2);
        let mut c1_reader = CaptureReader::new(c1_buf_reader, port1)?;
        let mut c2_reader = CaptureReader::new(c2_buf_reader, port2)?;

        loop {
            match c1_reader.next() {
                ReadState::Ok(stream) => {
                    let addr = stream.addr;
                    if self.s1_ignore.contains(&addr) {
                        continue;
                    }
                    let pair_addr = self.s1_to_s2.get(&addr);
                    if pair_addr.is_none() {
                        warn!("Cannot find pair s1->s2: {addr}");
                        self.s1_ignore.insert(addr);
                    }
                    if let Some(pair_stream) = c2_reader.get_stream(&pair_addr.unwrap()) {
                        self.compare_streams(stream, pair_stream)?;
                    }
                }
                ReadState::Eof => {
                    break;
                }
                ReadState::ReadFail(e) => {
                    error!("Failed to read capture1: {e}");
                    return Ok(());
                }
                ReadState::RefillFail(e) => {
                    error!("Failed to refill capture1: {e}");
                    return Ok(());
                }
            }
            match c2_reader.next() {
                ReadState::Ok(stream) => {
                    let addr = stream.addr;
                    if self.s2_ignore.contains(&addr) {
                        continue;
                    }
                    let pair_addr = self.s2_to_s1.get(&addr);
                    if pair_addr.is_none() {
                        warn!("Cannot find pair s2->s1: {addr}");
                        self.s2_ignore.insert(addr);
                    }
                    if let Some(pair_stream) = c1_reader.get_stream(&pair_addr.unwrap()) {
                        self.compare_streams(pair_stream, stream)?;
                    }
                }
                ReadState::Eof => {
                    break;
                }
                ReadState::ReadFail(e) => {
                    error!("Failed to read capture2: {e}");
                    return Ok(());
                }
                ReadState::RefillFail(e) => {
                    error!("Failed to refill capture2: {e}");
                    return Ok(());
                }
            }
        }
        info!(
            "C1: {} packets, {}/{} bytes",
            c1_reader.packets_read,
            c1_reader.bytes_read,
            meta1.len()
        );
        info!(
            "C2: {} packets, {}/{} bytes",
            c2_reader.packets_read,
            c2_reader.bytes_read,
            meta2.len()
        );
        info!(
            "Frames processed: {:.0}\nMax delta: {:.3}s\nAvg delta: {:.3}s",
            self.total_frames,
            self.delta_max,
            self.delta_sum / self.total_frames,
        );
        Ok(())
    }

    fn compare_streams(
        &mut self,
        s1: &mut PqStream,
        s2: &mut PqStream,
    ) -> Result<(), CompareError> {
        let addr1 = s1.addr.clone();
        let addr2 = s2.addr.clone();

        loop {
            let maybe1 = s1.peek_frame(true);
            let maybe2 = s2.peek_frame(true);
            if maybe1.is_some() && maybe2.is_some() {
                let (consume1, frame1) = maybe1.unwrap();
                if !should_replay_frame(frame1.tag) {
                    s1.consume(consume1);
                    continue;
                }
                let (consume2, frame2) = maybe2.unwrap();
                if !should_replay_frame(frame2.tag) {
                    s2.consume(consume2);
                    continue;
                }
                if frame1.payload != frame2.payload {
                    return Err(CompareError::MismatchedFrames {
                        addr1,
                        addr2,
                        info: format!("{}\n{}", frame1, frame2),
                    });
                }
                self.compare_ts(frame1.ts, frame2.ts);
                s1.consume(consume1);
                s2.consume(consume2);
            } else {
                break;
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum CompareError {
    MismatchedFrames {
        addr1: SocketAddr,
        addr2: SocketAddr,
        info: String,
    },
}

impl Display for CompareError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            CompareError::MismatchedFrames { addr1, addr2, info } => {
                write!(
                    f,
                    "Compare failed: Frame contents do not match:\nC1: {addr1}\nC2: {addr2}\n{info}"
                )
            }
        }
    }
}

impl Error for CompareError {}

impl<'a> Display for PqFrame<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match parse_pg_message(self.tag, &self.payload[self.offset..]) {
            Ok(msg) => {
                write!(
                    f,
                    "tag={} ts={} len={}: {}",
                    self.tag,
                    self.ts,
                    self.payload.len(),
                    msg
                )
            }
            Err(e) => {
                write!(
                    f,
                    "tag={} ts={} len={}: ({e}) {}",
                    self.tag,
                    self.ts,
                    self.payload.len(),
                    self.payload.escape_ascii()
                )
            }
        }
    }
}
