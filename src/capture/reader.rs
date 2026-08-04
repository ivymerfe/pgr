use std::{io, net::SocketAddr};

use crate::capture::frame_buffer::FrameBuffer;

pub struct ReadData<'a> {
    pub addr: SocketAddr,
    pub ts: u64,
    pub buf: &'a mut FrameBuffer,
}

pub enum ReadError {
    Continue,
    Eof,
    Error(String),
}

pub type ReadResult<'a> = Result<ReadData<'a>, ReadError>;

pub trait CaptureReader {
    fn get_buffer(&mut self, addr: SocketAddr) -> Option<&mut FrameBuffer>;
    fn next(&mut self) -> ReadResult<'_>;
}

impl From<io::Error> for ReadError {
    fn from(value: io::Error) -> Self {
        Self::Error(value.to_string())
    }
}
