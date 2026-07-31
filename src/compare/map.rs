use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader},
    net::SocketAddr,
    path::Path,
};

use crate::compare::client::Client;

pub struct ClientPair {
    pub c1: Client,
    pub c2: Client,
}

#[derive(Default)]
pub struct CompareStats {
    pub cnt_behind: i64,
    pub avg_behind: f64,
    pub max_behind: f64,
    pub cnt_ahead: i64,
    pub avg_ahead: f64,
    pub max_ahead: f64,
}

fn divide_or_zero(a: f64, b: f64) -> f64 {
    if b != 0.0 { a / b } else { 0.0 }
}

impl ClientPair {
    pub fn avg_max(&self) -> CompareStats {
        let t1 = &self.c1.timings;
        let t2 = &self.c2.timings;

        let len = t1.len().min(t2.len());
        let base1 = self.c1.connect_ts;
        let base2 = self.c2.connect_ts;

        let (mut cnt_behind, mut cnt_ahead) = (0, 0);
        let (mut max_behind, mut sum_behind) = (0.0f64, 0.0f64);
        let (mut max_ahead, mut sum_ahead) = (0.0f64, 0.0f64);
        for i in 0..len {
            let rel_1 = (t1[i] - base1) as f64;
            let rel_2 = (t2[i] - base2) as f64;
            let delta = rel_2 - rel_1;
            if delta > 0.0 {
                cnt_behind += 1;
                sum_behind += delta;
                max_behind = max_behind.max(delta);
            } else {
                cnt_ahead += 1;
                sum_ahead += delta;
                max_ahead = max_ahead.min(delta);
            }
        }
        return CompareStats {
            cnt_behind,
            avg_behind: divide_or_zero(sum_behind, cnt_behind as f64),
            max_behind,
            cnt_ahead,
            avg_ahead: divide_or_zero(sum_ahead, cnt_ahead as f64),
            max_ahead,
        };
    }
}

#[derive(Default)]
pub struct CompareMap {
    c1_to_c2: HashMap<SocketAddr, SocketAddr>,
    c2_to_c1: HashMap<SocketAddr, SocketAddr>,
    pub clients: HashMap<SocketAddr, ClientPair>,
}

impl CompareMap {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut c1_to_c2 = HashMap::new();
        let mut c2_to_c1 = HashMap::new();

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

            c1_to_c2.insert(addr_1, addr_2);
            c2_to_c1.insert(addr_2, addr_1);
        }

        Ok(Self {
            c1_to_c2,
            c2_to_c1,
            clients: HashMap::new(),
        })
    }

    fn get_or_create_pair(&mut self, c1_addr: SocketAddr, c2_addr: SocketAddr) -> &mut ClientPair {
        self.clients.entry(c1_addr).or_insert_with(|| ClientPair {
            c1: Client::new(c1_addr),
            c2: Client::new(c2_addr),
        })
    }

    pub fn find_c1(&mut self, c1_addr: SocketAddr) -> Option<&mut ClientPair> {
        if let Some(c2_addr) = self.c1_to_c2.get(&c1_addr) {
            return Some(self.get_or_create_pair(c1_addr, c2_addr.clone()));
        }
        return None;
    }

    pub fn find_c2(&mut self, c2_addr: SocketAddr) -> Option<&mut ClientPair> {
        if let Some(c1_addr) = self.c2_to_c1.get(&c2_addr) {
            return Some(self.get_or_create_pair(c1_addr.clone(), c2_addr));
        }
        return None;
    }
}
