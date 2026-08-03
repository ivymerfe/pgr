use std::net::SocketAddr;
use tokio::{fs::File, io::AsyncWriteExt};

pub struct AddrMap {
    file: File,
}

impl AddrMap {
    pub fn new(file: File) -> Self {
        Self { file }
    }

    pub async fn write(
        &mut self,
        pcap_addr: SocketAddr,
        replay_addr: SocketAddr,
    ) -> Result<(), std::io::Error> {
        let entry = format!("{pcap_addr},{replay_addr}\n");
        self.file.write_all(entry.as_bytes()).await?;
        Ok(())
    }
}
