use std::io;

pub type ClientId = u32;

pub enum CaptureEvent {
    Connect,
    Disconnect,
    PqFrame {
        tag: u8,
        offset: usize,
        frame: Vec<u8>,
    },
}

pub struct CaptureMessage {
    pub client: ClientId,
    pub ts: u64,
    pub event: CaptureEvent,
}

pub enum ReadError {
    Eof,
    Error(String),
}

pub trait CaptureReader {
    fn next(&mut self) -> Result<CaptureMessage, ReadError>;
}

impl From<io::Error> for ReadError {
    fn from(value: io::Error) -> Self {
        Self::Error(value.to_string())
    }
}
