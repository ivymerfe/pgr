use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader},
    net::SocketAddr,
    path::Path,
};

use crate::compare::client::Client;

#[derive(Default)]
pub struct CompareStats {
    pub cnt_behind: f64,
    pub sum_behind: f64,
    pub max_behind: f64,
    pub cnt_ahead: f64,
    pub sum_ahead: f64,
    pub max_ahead: f64,
    pub total_updates: u64
}

impl CompareStats {
    pub fn update_ts(&mut self, rel_ts1: u64, rel_ts2: u64) {
        self.total_updates += 1;
        
        let rel_1 = rel_ts1 as f64;
        let rel_2 = rel_ts2 as f64;
        let delta = rel_2 - rel_1;
        if delta > 0.0 {
            self.cnt_behind += 1.0;
            self.sum_behind += delta;
            self.max_behind = self.max_behind.max(delta);
        } else {
            self.cnt_ahead += 1.0;
            self.sum_ahead += delta;
            self.max_ahead = self.max_ahead.min(delta);
        }
    }
}

pub struct ComparePair {
    pub c1: Client,
    pub c2: Client,
    pub stats: CompareStats,
}


#[derive(Default)]
pub struct PairMap {
    c1_to_c2: HashMap<SocketAddr, SocketAddr>,
    c2_to_c1: HashMap<SocketAddr, SocketAddr>,
    pub clients: HashMap<SocketAddr, ComparePair>,
}

impl PairMap {
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

    fn get_or_create_pair(&mut self, c1_addr: SocketAddr, c2_addr: SocketAddr) -> &mut ComparePair {
        self.clients.entry(c1_addr).or_insert_with(|| ComparePair {
            c1: Client::new(c1_addr),
            c2: Client::new(c2_addr),
            stats: CompareStats::default()
        })
    }

    pub fn find_c1(&mut self, c1_addr: SocketAddr) -> Option<&mut ComparePair> {
        if let Some(c2_addr) = self.c1_to_c2.get(&c1_addr) {
            return Some(self.get_or_create_pair(c1_addr, c2_addr.clone()));
        }
        return None;
    }

    pub fn find_c2(&mut self, c2_addr: SocketAddr) -> Option<&mut ComparePair> {
        if let Some(c1_addr) = self.c2_to_c1.get(&c2_addr) {
            return Some(self.get_or_create_pair(c1_addr.clone(), c2_addr));
        }
        return None;
    }
}
