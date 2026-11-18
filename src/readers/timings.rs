use std::{
    fs::File,
    io::{self, Read},
};

use crate::readers::{
    capture::ClientId,
    zstd::{ZReader, open_zstd},
};

pub struct TimingData {
    pub id: ClientId,
    pub event_type: u8,
    pub ts: u64,
}

pub struct TimingReader {
    reader: ZReader,
}

impl TimingReader {
    pub fn new(file: File) -> io::Result<Self> {
        Ok(Self {
            reader: open_zstd(file)?,
        })
    }

    pub fn next(&mut self) -> io::Result<Option<TimingData>> {
        let mut buf = [0u8; 13];
        match self.reader.read_exact(&mut buf) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }
        Ok(Some(TimingData {
            id: u32::from_le_bytes(buf[0..4].try_into().unwrap()),
            event_type: buf[4],
            ts: u64::from_le_bytes(buf[5..13].try_into().unwrap()),
        }))
    }
}
