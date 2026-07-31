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

impl ClientPair {
    pub fn avg_max(&self) -> (f64, f64) {
        let t1 = &self.c1.timings;
        let t2 = &self.c2.timings;

        let len = t1.len().min(t2.len());
        if len == 0 {
            return (0.0, 0.0);
        }
        let base1 = t1[0];
        let base2 = t2[0];
        let (mut max, mut sum) = (0.0f64, 0.0f64);
        for i in 1..len {
            let rel_1 = (t1[i] - base1) as f64;
            let rel_2 = (t2[i] - base2) as f64;
            let delta = rel_2 - rel_1;
            if delta.abs() > max.abs() {
                max = delta;
            }
            sum += delta.abs();
        }
        return (sum / (len as f64), max);
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
