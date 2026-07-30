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

struct Client {
    c1_addr: SocketAddr,
    c2_addr: SocketAddr,
    c1_stream: PqStream,
    c2_stream: PqStream,
    c1_timings: Vec<u64>,
    c2_timings: Vec<u64>,
}

pub struct CompareState {
    c1_to_c2: HashMap<SocketAddr, SocketAddr>,
    c2_to_c1: HashMap<SocketAddr, SocketAddr>,
    c1_ignore: HashSet<SocketAddr>,
    c2_ignore: HashSet<SocketAddr>,
    clients: HashMap<SocketAddr, Client>,
}

impl CompareState {
    pub fn new() -> Self {
        return Self {
            c1_to_c2: HashMap::new(),
            c2_to_c1: HashMap::new(),
            c1_ignore: HashSet::new(),
            c2_ignore: HashSet::new(),
            clients: HashMap::new(),
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

            self.c1_to_c2.insert(addr_1, addr_2);
            self.c2_to_c1.insert(addr_2, addr_1);
        }

        Ok(())
    }

    fn get_or_create_client(&mut self, c1_addr: SocketAddr, c2_addr: SocketAddr) -> &mut Client {
        self.clients.entry(c1_addr).or_insert_with(|| Client {
            c1_addr,
            c2_addr,
            c1_stream: PqStream::default(),
            c2_stream: PqStream::default(),
            c1_timings: Vec::new(),
            c2_timings: Vec::new(),
        })
    }

    fn find_c1(&mut self, c1_addr: SocketAddr) -> Option<&mut Client> {
        if let Some(c2_addr) = self.c1_to_c2.get(&c1_addr) {
            return Some(self.get_or_create_client(c1_addr, c2_addr.clone()));
        }
        return None;
    }

    fn find_c2(&mut self, c2_addr: SocketAddr) -> Option<&mut Client> {
        if let Some(c1_addr) = self.c2_to_c1.get(&c2_addr) {
            return Some(self.get_or_create_client(c1_addr.clone(), c2_addr));
        }
        return None;
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

        let mut c1_reader = CaptureReader::new(file1)?;
        let mut c2_reader = CaptureReader::new(file2)?;

        let (mut c1_packets, mut c2_packets) = (0, 0);
        let (mut c1_eof, mut c2_eof) = (false, false);
        while !c1_eof || !c2_eof {
            if !c1_eof {
                match c1_reader.next() {
                    ReadState::Ok(packet) => {
                        if packet.tcp.destination_port() != port1 {
                            continue;
                        }
                        c1_packets += 1;
                        let addr = packet.addr;
                        if self.c1_ignore.contains(&addr) {
                            continue;
                        }
                        if let Some(client) = self.find_c1(addr) {
                            let stream = &mut client.c1_stream;
                            if stream.process_packet(packet.tcp) {
                                let skip = stream.find_frame(true);
                                if skip > 0 {
                                    warn!("[{}] Corrupted stream, resync", packet.addr);
                                    stream.consume(skip);
                                }
                                client.c1_timings.push(packet.ts);
                                Self::check_client(client)?;
                            }
                        } else {
                            warn!("Cannot find pair s1->s2: {addr}");
                            self.c1_ignore.insert(addr);
                        }
                    }
                    ReadState::Continue => (),
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
                    ReadState::Ok(packet) => {
                        if packet.tcp.destination_port() != port2 {
                            continue;
                        }
                        c2_packets += 1;
                        let addr = packet.addr;
                        if self.c2_ignore.contains(&addr) {
                            continue;
                        }
                        if let Some(client) = self.find_c2(addr) {
                            let stream = &mut client.c2_stream;
                            if stream.process_packet(packet.tcp) {
                                let skip = stream.find_frame(true);
                                if skip > 0 {
                                    warn!("[{}] Corrupted stream, resync", packet.addr);
                                    stream.consume(skip);
                                }
                                client.c2_timings.push(packet.ts);
                                Self::check_client(client)?;
                            }
                        } else {
                            warn!("Cannot find pair s2->s1: {addr}");
                            self.c2_ignore.insert(addr);
                        }
                    }
                    ReadState::Continue => (),
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
            c1_packets,
            c1_reader.bytes_read,
            meta1.len()
        );
        info!(
            "C2: {} packets, {}/{} bytes",
            c2_packets,
            c2_reader.bytes_read,
            meta2.len()
        );
        self.analyze_timings();
        Ok(())
    }

    fn analyze_timings(&self) {
        for c in self.clients.values() {
            let (avg, max) = c.avg_max();
            info!(
                "{}({}) <- {}({}): avg = {:.2}ms; max = {:.2}ms",
                c.c1_addr,
                c.c1_timings.len(),
                c.c2_addr,
                c.c2_timings.len(),
                avg / 1e3,
                max / 1e3
            );
        }
    }

    fn check_client(client: &mut Client) -> Result<(), CompareError> {
        let s1 = &mut client.c1_stream;
        let s2 = &mut client.c2_stream;
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
                            addr1: client.c1_addr,
                            addr2: client.c2_addr,
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

impl Client {
    pub fn avg_max(&self) -> (f64, f64) {
        let c1 = &self.c1_timings;
        let c2 = &self.c2_timings;

        let len = c1.len().min(c2.len());
        if len == 0 {
            return (0.0, 0.0);
        }
        let base1 = c1[0];
        let base2 = c2[0];
        let (mut max, mut sum) = (0.0f64, 0.0f64);
        for i in 1..len {
            let rel_1 = (c1[i] - base1) as f64;
            let rel_2 = (c2[i] - base2) as f64;
            let delta = rel_2 - rel_1;
            if delta.abs() > max.abs() {
                info!("Delta {delta} at {i}");
                max = delta;
            }
            sum += delta.abs();
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
