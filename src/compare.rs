use std::collections::HashSet;
use std::fmt::{self, Display, Formatter};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::{collections::HashMap, error::Error, net::SocketAddr, path::Path};

use tracing::{error, warn};

use crate::parser::pcap::{CaptureReader, ReadState};
use crate::parser::pq_stream::PqStream;

pub struct CompareState {
    s1_to_s2: HashMap<SocketAddr, SocketAddr>,
    s2_to_s1: HashMap<SocketAddr, SocketAddr>,
    s1_ignore: HashSet<SocketAddr>,
    s2_ignore: HashSet<SocketAddr>,

    pub max_ts_diff: u64,
    pub mean_ts_diff: f64,
}

impl CompareState {
    pub fn new() -> Self {
        return Self {
            s1_to_s2: HashMap::new(),
            s2_to_s1: HashMap::new(),
            s1_ignore: HashSet::new(),
            s2_ignore: HashSet::new(),
            max_ts_diff: 0,
            mean_ts_diff: 0.0,
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
        let c1_buf_reader = BufReader::with_capacity(131072, File::open(c1)?);
        let c2_buf_reader = BufReader::with_capacity(131072, File::open(c2)?);
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
        // todo - total packets processed, bytes read of cap files
        Ok(())
    }

    fn compare_streams(&mut self, s1: PqStream, s2: PqStream) {}
}

impl Display for CompareState {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Max time deviation: {}\nAverage time deviation: {}",
            self.max_ts_diff, self.mean_ts_diff
        )
    }
}
