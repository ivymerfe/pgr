use std::{
    collections::{BTreeMap, VecDeque},
    net::SocketAddr,
};

use tracing::info;

use crate::{
    capture::{
        frame_buffer::{ConnState, FrameBuffer, FrameInfo, FrameResult},
        reader::ClientId,
    },
    compare::addr_map::AddrMapReader,
};

pub struct Client {
    pub id: ClientId,
    pub frame_count: u64,
    connect_ts: Option<u64>,
    pending: VecDeque<(FrameInfo, u64)>,
}

impl Client {
    pub fn new(id: ClientId) -> Self {
        Self {
            id,
            connect_ts: None,
            frame_count: 0,
            pending: VecDeque::new(),
        }
    }

    pub fn read_buf(&mut self, ts: u64, buf: &mut FrameBuffer) {
        if self.connect_ts.is_none() {
            self.connect_ts = Some(ts);
        }
        loop {
            match buf.find_frame() {
                FrameResult::Complete(info) => {
                    if buf.state == ConnState::Normal || buf.state == ConnState::CopyIn {
                        self.pending.push_back((info, ts));
                        self.frame_count += 1;
                    }
                    buf.consume_frame(&info);
                }
                FrameResult::Incomplete => break,
                FrameResult::Desync => {
                    info!("[{}] desync", self.id);
                    buf.resync();
                }
            }
        }
    }

    pub fn connect_time(&self) -> u64 {
        self.connect_ts.unwrap_or(0)
    }

    pub fn has_frame(&self) -> bool {
        !self.pending.is_empty()
    }

    pub fn pop_frame(&mut self) -> (FrameInfo, u64) {
        return self.pending.pop_front().unwrap();
    }
}

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
    pub replay_id: Option<ClientId>,
    pub stats: CompareStats,
}

pub struct CompareMap<'a> {
    addr_map: &'a AddrMapReader,
    pub pairs: BTreeMap<ClientId, ComparePair>,
}

impl<'a> CompareMap<'a> {
    pub fn new(addr_map: &'a AddrMapReader) -> Self {
        Self {
            addr_map,
            pairs: BTreeMap::new(),
        }
    }

    pub fn get(&mut self, id: ClientId) -> &mut ComparePair {
        self.pairs.entry(id).or_insert_with(|| ComparePair {
            src: Client::new(id),
            replay: Client::new(id),
            replay_id: None,
            stats: CompareStats::default(),
        })
    }

    pub fn map_addr(&mut self, replay_addr: &SocketAddr) -> Option<u32> {
        self.addr_map.map_addr(replay_addr)
    }
}
