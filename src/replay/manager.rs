use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use tokio::{sync::Mutex, task::JoinSet, time::sleep};
use tracing::{error, info};

use crate::{
    capture::reader::{CaptureReader, ClientId, ReadError},
    pg_client::PgClientConfig,
    replay::{
        addr_map::AddrMapWriter,
        client::{ClientInfo, ReplayClient},
        pacer::Pacer,
        stats::ReplayStats,
    },
};

pub struct ReplayManager {
    info: ClientInfo,
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
        let info = ClientInfo {
            server_addr: SocketAddr::new(addr, port),
            config: config,
            addr_map: Arc::new(Mutex::new(addr_map)),
            stats: Arc::new(ReplayStats::new()),
            disconnect_timeout,
        };
        Ok(Self {
            info,
            clients: HashMap::new(),
        })
    }

    pub async fn replay(&mut self, mut reader: Box<dyn CaptureReader>) -> anyhow::Result<()> {
        let stats = self.info.stats.clone();
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

        let pacer = Pacer::start(0);
        let mut tasks = JoinSet::new();
        loop {
            match reader.next(false) {
                Ok(data) => {
                    if let Some(client) = self.ensure_client(data.id, data.ts, &pacer) {
                        client.update(data.ts, data.buf, &mut tasks);
                    }
                    if pacer.time_to(data.ts) > 4_000_000 {
                        sleep(Duration::from_secs(3)).await;
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
        first_ts: u64,
        pacer: &Pacer,
    ) -> Option<&mut ReplayClient> {
        let client = self
            .clients
            .entry(id)
            .or_insert_with(|| ReplayClient::new(id, self.info.clone(), pacer.clone(), first_ts));
        if client.is_dead() {
            return None;
        }
        return Some(client);
    }
}
