use std::io;

pub type ClientId = u32;

pub enum Command {
    Connect,
    Disconnect,
    PqFrame {
        tag: u8,
        offset: usize,
        frame: Vec<u8>,
    },
}

pub struct ClientCommand {
    pub client: ClientId,
    pub ts: u64,
    pub event: Command,
}

pub enum ReadError {
    Eof,
    Error(String),
}

pub trait CommandSource {
    fn next(&mut self) -> Result<ClientCommand, ReadError>;
}

impl From<io::Error> for ReadError {
    fn from(value: io::Error) -> Self {
        Self::Error(value.to_string())
    }
}
