use std::net::SocketAddr;

use crate::capture::frame_buffer::FrameBuffer;

pub enum ReadResult<'a> {
    Ok {
        addr: SocketAddr,
        ts: u64,
        buf: &'a mut FrameBuffer,
    },
    Continue,
    Eof,
    Error(String),
}

pub trait CaptureReader {
    fn get_buffer(&mut self, addr: SocketAddr) -> Option<&mut FrameBuffer>;
    fn next(&mut self) -> ReadResult<'_>;
}
