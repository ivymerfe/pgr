use std::{fs::File, io::Write, net::SocketAddr};

use crate::capture::reader::ClientId;

pub struct AddrMapWriter {
    file: File,
}

impl AddrMapWriter {
    pub fn new(file: File) -> Self {
        Self { file }
    }

    pub fn write(&mut self, id: ClientId, replay_addr: SocketAddr) -> Result<(), std::io::Error> {
        let entry = format!("{id},{replay_addr}\n");
        self.file.write_all(entry.as_bytes())?;
        Ok(())
    }
}
