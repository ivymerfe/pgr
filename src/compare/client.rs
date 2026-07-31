use std::{collections::VecDeque, net::SocketAddr};

use tracing::info;

use crate::parser::pq_stream::{ConnState, FrameContent, FrameInfo, FrameResult, PqStream};

pub struct Client {
    pub addr: SocketAddr,
    pub stream: PqStream,
    pub timings: Vec<u64>,
    pending: VecDeque<FrameInfo>,
}

impl Client {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            stream: PqStream::default(),
            timings: Vec::new(),
            pending: VecDeque::new(),
        }
    }

    pub fn read_stream(&mut self, ts: u64) {
        loop {
            match self.stream.find_frame() {
                FrameResult::Complete(info) => {
                    if self.stream.state == ConnState::Normal
                        || self.stream.state == ConnState::CopyIn
                    {
                        self.pending.push_back(info);
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

    pub fn get_frame(&self) -> (&FrameInfo, FrameContent<'_>) {
        let info = &self.pending[0];
        return (info, self.stream.read_frame(&info));
    }

    pub fn next_frame(&mut self) {
        if let Some(info) = self.pending.pop_front() {
            self.stream.mark_read(info.stream_end);
        }
    }
}
