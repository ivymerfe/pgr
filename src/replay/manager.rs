use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use tokio::{
    sync::{Mutex, mpsc},
    task::JoinSet,
    time::sleep,
};
use tracing::{error, info};

use crate::{
    capture::reader::{CaptureReader, ClientId, ReadError},
    pg_client::PgClientConfig,
    replay::{
        addr_map::AddrMapWriter,
        client::{ClientInfo, ReplayClient},
        latency::LatencyMap,
        pacer::Pacer,
        stats::ReplayStats,
    },
};

pub struct ReplayManager {
    server_addr: SocketAddr,
    config: PgClientConfig,
    addr_map: Arc<Mutex<AddrMapWriter>>,
    disconnect_timeout: Duration,
    clients: HashMap<ClientId, ReplayClient>,
}

impl ReplayManager {
    pub async fn new(
        addr_map: AddrMapWriter,
        host: String,
        port: u16,
        dbname: String,
        user: String,
        password: Option<String>,
        disconnect_timeout: Duration,
    ) -> anyhow::Result<Self> {
        let addr: IpAddr = host.parse()?;
        let config = PgClientConfig {
            user: user,
            password: password.map(|s| s.as_bytes().to_vec()),
            dbname: dbname,
            application_name: "pgr".to_string(),
        };
        Ok(Self {
            server_addr: SocketAddr::new(addr, port),
            config,
            addr_map: Arc::new(Mutex::new(addr_map)),
            disconnect_timeout,
            clients: HashMap::new(),
        })
    }

    pub async fn replay(
        &mut self,
        mut reader: Box<dyn CaptureReader>,
        lat_map: Option<LatencyMap>,
    ) -> anyhow::Result<()> {
        let (lat_tx, mut lat_rx) = mpsc::unbounded_channel();
        let info = ClientInfo {
            server_addr: self.server_addr,
            config: self.config.clone(),
            addr_map: self.addr_map.clone(),
            should_send_lat: lat_map.is_some(),
            lat_tx,
            stats: Arc::new(ReplayStats::new()),
            disconnect_timeout: self.disconnect_timeout,
        };
        let stats = info.stats.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            interval.tick().await;

            loop {
                interval.tick().await;
                let total = stats.read_total_sent();
                let pps = stats.read_delta_sent();
                let recv = stats.read_delta_recv();
                info!("Total sent: {total} Delta sent: {pps} Delta recv: {recv}");
            }
        });
        if let Some(mut map) = lat_map {
            tokio::spawn(async move {
                loop {
                    match lat_rx.recv().await {
                        Some(msg) => {
                            if msg.response {
                                if let Err(e) = map.on_response(msg.id, msg.tag, msg.ts).await {
                                    error!("Failed to write latency: {e}");
                                    break;
                                }
                            } else {
                                if let Err(e) = map.on_send(msg.id, msg.tag, msg.ts).await {
                                    error!("Failed to write latency: {e}");
                                    break;
                                }
                            }
                        }
                        None => break,
                    }
                }
            });
        }

        let pacer = Pacer::start(0);
        let mut tasks = JoinSet::new();
        loop {
            match reader.next(false) {
                Ok(data) => {
                    if let Some(client) = self.ensure_client(data.id, &info, &pacer, data.ts) {
                        client.update(data.ts, data.buf, &mut tasks);
                    }
                    if pacer.time_to(data.ts) > 2_000_000 {
                        sleep(Duration::from_micros(1_000_000)).await;
                    }
                }
                Err(ReadError::Continue) => (),
                Err(ReadError::Eof) => break,
                Err(ReadError::Error(e)) => {
                    error!("Failed to read pcap: {e}");
                    break;
                }
            }
        }
        for client in self.clients.values_mut() {
            client.close();
        }
        info!("Finished reading, waiting for clients");
        tasks.join_all().await;
        Ok(())
    }

    fn ensure_client(
        &mut self,
        id: ClientId,
        info: &ClientInfo,
        pacer: &Pacer,
        first_ts: u64,
    ) -> Option<&mut ReplayClient> {
        let client = self
            .clients
            .entry(id)
            .or_insert_with(|| ReplayClient::new(id, info.clone(), pacer.clone(), first_ts));
        if client.is_dead() {
            return None;
        }
        return Some(client);
    }
}
