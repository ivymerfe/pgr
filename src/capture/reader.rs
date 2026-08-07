use std::{io, net::SocketAddr};

use crate::capture::frame_buffer::FrameBuffer;

pub type ClientId = u32;

pub struct ReadData<'a> {
    pub id: ClientId,
    pub ts: u64,
    pub addr: Option<SocketAddr>,
    pub buf: &'a mut FrameBuffer,
}

pub enum ReadError {
    Continue,
    Eof,
    Error(String),
}

pub type ReadResult<'a> = Result<ReadData<'a>, ReadError>;

pub trait CaptureReader {
    fn get_buffer(&mut self, id: ClientId) -> Option<&mut FrameBuffer>;
    fn next(&mut self, want_addr: bool) -> ReadResult<'_>;
}

impl From<io::Error> for ReadError {
    fn from(value: io::Error) -> Self {
        Self::Error(value.to_string())
    }
}
