use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader},
    net::SocketAddr,
};

use anyhow::anyhow;

use crate::capture::reader::ClientId;

pub struct AddrMapReader {
    replay_to_src: HashMap<SocketAddr, ClientId>,
}

impl AddrMapReader {
    pub fn new(file: File) -> anyhow::Result<Self> {
        let reader = BufReader::new(file);
        let mut replay_to_src = HashMap::new();

        for line_result in reader.lines() {
            let line = line_result?;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let mut parts = trimmed.split(",");
            let src_str = parts.next().ok_or(anyhow!("Missing source id"))?.trim();
            let replay_str = parts.next().ok_or(anyhow!("Missing replay addr"))?.trim();

            let src_id: ClientId = src_str.parse()?;
            let replay_addr: SocketAddr = replay_str.parse()?;

            replay_to_src.insert(replay_addr, src_id);
        }

        Ok(Self { replay_to_src })
    }

    pub fn map_addr(&self, addr: &SocketAddr) -> Option<ClientId> {
        self.replay_to_src.get(addr).copied()
    }
}
