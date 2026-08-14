use std::io;

pub type ClientId = u32;

pub struct CaptureData<'a> {
    pub id: ClientId,
    pub ts: u64,
    pub connect: bool,
    pub buf: &'a [u8],
}

pub enum ReadError {
    Eof,
    Error(String),
}

pub type ReadResult<'a> = Result<CaptureData<'a>, ReadError>;

pub trait CaptureReader {
    fn next(&mut self) -> ReadResult<'_>;
}

impl From<io::Error> for ReadError {
    fn from(value: io::Error) -> Self {
        Self::Error(value.to_string())
    }
}
