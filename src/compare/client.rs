use std::{collections::VecDeque, net::SocketAddr};

use tracing::info;

use crate::parser::pq_stream::{ConnState, FrameInfo, FrameResult, PqStream};

pub struct Client {
    pub addr: SocketAddr,
    pub stream: PqStream,
    pub connect_ts: u64,
    pub timings: Vec<u64>,
    pending: VecDeque<(FrameInfo, u64)>,
}

impl Client {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            stream: PqStream::default(),
            connect_ts: 0,
            timings: Vec::new(),
            pending: VecDeque::new(),
        }
    }

    pub fn read_stream(&mut self, ts: u64) {
        if self.connect_ts == 0 {
            self.connect_ts = ts;
        }
        loop {
            match self.stream.find_frame() {
                FrameResult::Complete(info) => {
                    if self.stream.state == ConnState::Normal
                        || self.stream.state == ConnState::CopyIn
                    {
                        self.pending.push_back((info, ts));
                        self.timings.push(ts);
                    }
                    self.stream.consume_frame(&info);
                }
                FrameResult::Incomplete => break,
                FrameResult::Desync => {
                    info!("[{}] desync", self.addr);
                    self.stream.resync();
                }
            }
        }
    }

    pub fn has_frame(&self) -> bool {
        !self.pending.is_empty()
    }

    pub fn get_frame(&self) -> (&FrameInfo, u64, &[u8]) {
        let (info, ts) = &self.pending[0];
        return (info, *ts, self.stream.read_frame(&info));
    }

    pub fn next_frame(&mut self) {
        if let Some((info, _ts)) = self.pending.pop_front() {
            self.stream.mark_read(info.stream_end);
        }
    }
}
