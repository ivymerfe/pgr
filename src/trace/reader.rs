use std::{
    fs::File,
    io::{self, BufReader, Read},
};

use crate::capture::reader::ClientId;

#[derive(Clone, Copy)]
pub struct TraceData {
    pub id: ClientId,
    pub frame_index: u32,
    pub duration_us: u32,
    pub event_type: u8,
}

pub struct TraceReader {
    reader: BufReader<File>,
}

impl TraceReader {
    pub fn new(file: File) -> Self {
        Self {
            reader: BufReader::new(file),
        }
    }

    pub fn next(&mut self) -> io::Result<TraceData> {
        let mut id_buf = [0u8; 4];
        let mut index_buf = [0u8; 4];
        let mut duration_buf = [0u8; 4];
        let mut type_buf = [0u8; 1];
        self.reader.read_exact(&mut id_buf)?;
        self.reader.read_exact(&mut index_buf)?;
        self.reader.read_exact(&mut duration_buf)?;
        self.reader.read_exact(&mut type_buf)?;

        Ok(TraceData {
            id: u32::from_le_bytes(id_buf),
            frame_index: u32::from_le_bytes(index_buf),
            duration_us: u32::from_le_bytes(duration_buf),
            event_type: type_buf[0],
        })
    }
}
