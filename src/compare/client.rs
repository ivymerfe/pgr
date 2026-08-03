use std::{collections::VecDeque, net::SocketAddr};

use tracing::info;

use crate::capture::frame_buffer::{ConnState, FrameBuffer, FrameInfo, FrameResult};

pub struct Client {
    pub addr: SocketAddr,
    pub connect_ts: u64,
    pub frame_count: u64,
    pending: VecDeque<(FrameInfo, u64)>,
}

impl Client {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            connect_ts: 0,
            frame_count: 0,
            pending: VecDeque::new(),
        }
    }

    pub fn read_buf(&mut self, ts: u64, buf: &mut FrameBuffer) {
        if self.connect_ts == 0 {
            self.connect_ts = ts;
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
                    info!("[{}] desync", self.addr);
                    buf.resync();
                }
            }
        }
    }

    pub fn has_frame(&self) -> bool {
        !self.pending.is_empty()
    }

    pub fn pop_frame(&mut self) -> (FrameInfo, u64) {
        return self.pending.pop_front().unwrap();
    }
}
