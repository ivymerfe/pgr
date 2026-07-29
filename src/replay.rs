use std::{
    collections::HashMap,
    error::Error,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use pgwire::api::client::Config;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::time::Instant;
use tracing::{error, info};

use crate::replay_client::ReplayClient;
use crate::{
    parser::{
        pcap::{CaptureReader, ReadState},
        pq_stream::PqFrame,
    },
    replay_client::spawn_client,
};

pub struct ReplayState {
    config: Arc<Config>,
    clients: HashMap<SocketAddr, ReplayClient>,
    capture_start: Option<Instant>,
    capture_start_ts: Option<u64>,
    rps_counter: Arc<AtomicU64>,
}

impl ReplayState {
    pub fn new(
        host: String,
        port: u16,
        dbname: String,
        user: String,
        password: Option<String>,
    ) -> Result<Self, Box<dyn Error>> {
        let addr: IpAddr = host.parse()?;
        let mut config = Config::new();
        config.hostaddr(addr);
        config.port(port);
        config.dbname(dbname);
        config.user(user);
        if password.is_some() {
            config.password(password.unwrap());
        }
        config.application_name("pgr");
        Ok(Self {
            config: Arc::new(config),
            clients: HashMap::new(),
            capture_start: None,
            capture_start_ts: None,
            rps_counter: Arc::new(AtomicU64::new(0)),
        })
    }

    pub async fn replay(
        &mut self,
        input_path: std::path::PathBuf,
        cap_port: u16,
    ) -> Result<(), Box<dyn Error>> {
        let counter = self.rps_counter.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            interval.tick().await;

            loop {
                interval.tick().await;
                let rps = counter.swap(0, Ordering::Relaxed);
                info!("RPS: {rps}");
            }
        });

        let input_file = std::fs::File::open(input_path)?;
        let reader = std::io::BufReader::with_capacity(131072, input_file);
        let mut capture_reader = CaptureReader::new(reader, cap_port)?;

        loop {
            match capture_reader.next() {
                ReadState::Ok(stream) => {
                    while let Some((length, frame)) = stream.peek_frame(true) {
                        self.pace(frame.ts).await;
                        self.process_frame(frame).await?;
                        stream.consume(length);
                    }
                }
                ReadState::Eof => break,
                ReadState::ReadFail(e) => {
                    error!("Failed to read pcap: {e}");
                    break;
                }
                ReadState::RefillFail(e) => {
                    error!("Failed to refill pcap: {e}");
                    break;
                }
            }
        }
        info!("Done");
        Ok(())
    }

    async fn pace(&mut self, frame_ts: u64) {
        let now = Instant::now();
        match (self.capture_start, self.capture_start_ts) {
            (None, _) => {
                self.capture_start = Some(now);
                self.capture_start_ts = Some(frame_ts);
            }
            (Some(start), Some(start_ts)) => {
                let capture_elapsed = frame_ts.saturating_sub(start_ts);
                let real_elapsed = now.duration_since(start).as_micros() as u64;
                if capture_elapsed > real_elapsed {
                    let wait = capture_elapsed - real_elapsed;
                    tokio::time::sleep(Duration::from_micros(wait)).await;
                }
            }
            _ => {}
        }
    }

    fn check_tag(tag: u8) -> bool {
        matches!(tag, b'Q' | b'P' | b'B' | b'D' | b'E' | b'S')
    }

    async fn process_frame(&mut self, frame: PqFrame<'_>) -> Result<(), Box<dyn Error>> {
        let tag = frame.tag;
        let addr = frame.addr;

        if tag == b'X' {
            if let Some(client) = self.clients.remove(&addr) {
                let _ = client.tx.send(frame.payload.to_vec());
            }
            return Ok(());
        }
        if !self.clients.contains_key(&addr) {
            match spawn_client(self.config.clone()).await {
                Ok(handle) => {
                    self.clients.insert(addr, handle);
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
        if !Self::check_tag(tag) {
            return Ok(());
        }
        if let Some(client) = self.clients.get(&addr) {
            match client.tx.send(frame.payload.to_vec()) {
                Ok(()) => {
                    self.rps_counter.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    error!("Failed to send frame: {e}");
                    self.clients.remove(&addr);
                }
            }
        }
        return Ok(());
    }
}
