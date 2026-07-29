use std::collections::HashSet;
use std::fmt::{self, Display, Formatter};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::{collections::HashMap, error::Error, net::SocketAddr, path::Path};

use tracing::{error, info, warn};

use crate::parser::c2s::parse_pg_message;
use crate::parser::pcap::{CaptureReader, ReadState};
use crate::parser::pq_stream::{PqFrame, PqStream};
use crate::replay::frame_tags::should_replay_frame;

pub struct CompareState {
    s1_to_s2: HashMap<SocketAddr, SocketAddr>,
    s2_to_s1: HashMap<SocketAddr, SocketAddr>,
    s1_ignore: HashSet<SocketAddr>,
    s2_ignore: HashSet<SocketAddr>,
    packet_timings: HashMap<SocketAddr, TimingInfo>,
}

impl CompareState {
    pub fn new() -> Self {
        return Self {
            s1_to_s2: HashMap::new(),
            s2_to_s1: HashMap::new(),
            s1_ignore: HashSet::new(),
            s2_ignore: HashSet::new(),
            packet_timings: HashMap::new(),
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
        let (mut c1_eof, mut c2_eof) = (false, false);
        while !c1_eof || !c2_eof {
            if !c1_eof {
                match c1_reader.next() {
                    ReadState::Ok(stream) => {
                        let addr = stream.addr;
                        if self.s1_ignore.contains(&addr) {
                            continue;
                        }
                        if let Some(pair_addr) = self.s1_to_s2.get(&addr) {
                            if let Some(ts) = stream.take_ts() {
                                let timings = self.packet_timings.entry(addr).or_default();
                                timings.add_s1(ts);
                            }
                            if let Some(pair_stream) = c2_reader.get_stream(&pair_addr) {
                                self.compare_streams(stream, pair_stream)?;
                            }
                        } else {
                            warn!("Cannot find pair s1->s2: {addr}");
                            self.s1_ignore.insert(addr);
                        }
                    }
                    ReadState::Eof => {
                        c1_eof = true;
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
            }
            if !c2_eof {
                match c2_reader.next() {
                    ReadState::Ok(stream) => {
                        let addr = stream.addr;
                        if self.s2_ignore.contains(&addr) {
                            continue;
                        }
                        if let Some(pair_addr) = self.s2_to_s1.get(&addr) {
                            if let Some(ts) = stream.take_ts() {
                                let timings =
                                    self.packet_timings.entry(pair_addr.clone()).or_default();
                                timings.add_s2(ts);
                            }
                            if let Some(pair_stream) = c1_reader.get_stream(&pair_addr) {
                                self.compare_streams(pair_stream, stream)?;
                            }
                        } else {
                            warn!("Cannot find pair s2->s1: {addr}");
                            self.s1_ignore.insert(addr);
                        }
                    }
                    ReadState::Eof => {
                        c2_eof = true;
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
        self.analyze_timings();
        Ok(())
    }

    fn analyze_timings(&self) {
        for (addr, timings) in &self.packet_timings {
            if let Some(pair) = self.s1_to_s2.get(addr) {
                let (avg, max) = timings.avg_max();
                info!(
                    "{addr}({}) <- {pair}({}): avg = {:.2}ms; max = {:.2}ms",
                    timings.s1.len(),
                    timings.s2.len(),
                    avg / 1e3,
                    max / 1e3
                );
            }
        }
    }

    fn compare_streams(
        &mut self,
        s1: &mut PqStream,
        s2: &mut PqStream,
    ) -> Result<(), CompareError> {
        loop {
            if let Some((consume1, frame1)) = s1.read_frame() {
                if !should_replay_frame(frame1.tag) {
                    s1.consume(consume1);
                    continue;
                }
                if let Some((consume2, frame2)) = s2.read_frame() {
                    if !should_replay_frame(frame2.tag) {
                        s2.consume(consume2);
                        continue;
                    }
                    if frame1.payload != frame2.payload {
                        return Err(CompareError::MismatchedFrames {
                            addr1: s1.addr,
                            addr2: s2.addr,
                            off1: s1.offset(),
                            off2: s2.offset(),
                            info: format!("{}\n{}", frame1, frame2),
                        });
                    }
                    s1.consume(consume1);
                    s2.consume(consume2);
                    continue;
                }
            }
            break;
        }
        Ok(())
    }
}

#[derive(Default)]
struct TimingInfo {
    s1: Vec<u64>,
    s2: Vec<u64>,
}

impl TimingInfo {
    pub fn add_s1(&mut self, ts: u64) {
        self.s1.push(ts);
    }

    pub fn add_s2(&mut self, ts: u64) {
        self.s2.push(ts);
    }

    pub fn avg_max(&self) -> (f64, f64) {
        let len = self.s1.len().min(self.s2.len());
        if len == 0 {
            return (0.0, 0.0);
        }
        let base1 = self.s1[0];
        let base2 = self.s2[0];
        let (mut max, mut sum) = (0.0, 0.0);
        for i in 1..len {
            let rel_1 = (self.s1[i] - base1) as f64;
            let rel_2 = (self.s2[i] - base2) as f64;
            let delta = rel_2 - rel_1;
            if delta.abs() > max {
                max = delta;
            }
            sum += delta;
        }
        return (sum / (len as f64), max);
    }
}

#[derive(Debug)]
pub enum CompareError {
    MismatchedFrames {
        addr1: SocketAddr,
        addr2: SocketAddr,
        off1: usize,
        off2: usize,
        info: String,
    },
}

impl Display for CompareError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            CompareError::MismatchedFrames {
                addr1,
                addr2,
                off1,
                off2,
                info,
            } => {
                write!(
                    f,
                    "Compare failed: Frame contents do not match:\nC1: {addr1} at {off1}\nC2: {addr2} at {off2}\n{info}"
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
                write!(f, "tag={} len={}: {}", self.tag, self.payload.len(), msg)
            }
            Err(e) => {
                write!(
                    f,
                    "tag={} len={}: ({e}) {}",
                    self.tag,
                    self.payload.len(),
                    self.payload.escape_ascii()
                )
            }
        }
    }
}
