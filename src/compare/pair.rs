use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader},
    net::SocketAddr,
};

use anyhow::anyhow;

use crate::compare::client::Client;

#[derive(Default)]
pub struct CompareStats {
    pub cnt_behind: f64,
    pub sum_behind: f64,
    pub max_behind: f64,
    pub cnt_ahead: f64,
    pub sum_ahead: f64,
    pub max_ahead: f64,
    pub total_updates: u64,
}

impl CompareStats {
    pub fn update_ts(&mut self, src_time: f64, replay_time: f64) {
        self.total_updates += 1;

        let delta = replay_time - src_time;
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
    pub src: Client,
    pub replay: Client,
    pub stats: CompareStats,
}

#[derive(Default)]
pub struct PairMap {
    src_to_replay: HashMap<SocketAddr, SocketAddr>,
    replay_to_src: HashMap<SocketAddr, SocketAddr>,
    pub pairs: HashMap<SocketAddr, ComparePair>,
}

impl PairMap {
    pub fn new(file: File) -> anyhow::Result<Self> {
        let reader = BufReader::new(file);
        let mut src_to_replay = HashMap::new();
        let mut replay_to_src = HashMap::new();

        for line_result in reader.lines() {
            let line = line_result?;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let mut parts = trimmed.split(",");
            let src_str = parts.next().ok_or(anyhow!("Missing source addr"))?.trim();
            let replay_str = parts.next().ok_or(anyhow!("Missing replay addr"))?.trim();

            let src_addr: SocketAddr = src_str.parse()?;
            let replay_addr: SocketAddr = replay_str.parse()?;

            src_to_replay.insert(src_addr, replay_addr);
            replay_to_src.insert(replay_addr, src_addr);
        }

        Ok(Self {
            src_to_replay,
            replay_to_src,
            pairs: HashMap::new(),
        })
    }

    fn get_or_create_pair(
        &mut self,
        src_addr: SocketAddr,
        replay_addr: SocketAddr,
    ) -> &mut ComparePair {
        self.pairs.entry(src_addr).or_insert_with(|| ComparePair {
            src: Client::new(src_addr),
            replay: Client::new(replay_addr),
            stats: CompareStats::default(),
        })
    }

    pub fn find_from_src(&mut self, src_addr: SocketAddr) -> Option<&mut ComparePair> {
        if let Some(replay_addr) = self.src_to_replay.get(&src_addr) {
            return Some(self.get_or_create_pair(src_addr, replay_addr.clone()));
        }
        return None;
    }

    pub fn find_from_replay(&mut self, replay_addr: SocketAddr) -> Option<&mut ComparePair> {
        if let Some(src_addr) = self.replay_to_src.get(&replay_addr) {
            return Some(self.get_or_create_pair(src_addr.clone(), replay_addr));
        }
        return None;
    }
}
