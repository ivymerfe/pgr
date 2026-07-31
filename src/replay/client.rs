use std::{
    collections::HashMap,
    error::Error,
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::Arc,
    time::Duration,
};

use tokio::{
    sync::{Mutex, mpsc},
    task::JoinSet,
};
use tracing::{error, info, warn};

use crate::{
    parser::{
        pcap::{CaptureReader, ReadState},
        pq_stream::{ConnState, FrameResult, PqStream},
    },
    replay::{
        addr_map::AddrMap,
        socket::{Config, ReplayConnection, ReplayError},
        stats::ReplayStats,
        wait::WaitInfo,
    },
};

struct ClientMessage {
    ts: u64,
    buf: Vec<u8>,
}

#[derive(Clone)]
struct ClientInfo {
    server_addr: SocketAddr,
    config: Config,
    addr_map: Arc<Mutex<AddrMap>>,
    stats: Arc<ReplayStats>,
}

#[derive(Default)]
struct ReplayClient {
    stream: PqStream,
    sent_offset: usize,
    chan: Option<mpsc::UnboundedSender<ClientMessage>>,
    dead: bool,
    connected: bool,
}

pub struct ReplayManager {
    info: ClientInfo,
    clients: HashMap<SocketAddr, ReplayClient>,
}

impl ReplayManager {
    pub async fn new<P: AsRef<Path>>(
        addr_map_path: P,
        host: String,
        port: u16,
        dbname: String,
        user: String,
        password: Option<String>,
    ) -> Result<Self, Box<dyn Error>> {
        let addr: IpAddr = host.parse()?;
        let addr_map = AddrMap::new(addr_map_path).await?;
        let config = Config {
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
        };
        Ok(Self {
            info,
            clients: HashMap::new(),
        })
    }

    pub async fn replay(
        &mut self,
        input_path: std::path::PathBuf,
        cap_port: u16,
    ) -> Result<(), Box<dyn Error>> {
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

        let mut capture_reader = CaptureReader::new(std::fs::File::open(input_path)?)?;

        let mut wait = WaitInfo::new();
        let mut tasks = JoinSet::new();
        loop {
            match capture_reader.next() {
                ReadState::Ok(packet) => {
                    if packet.tcp.destination_port() != cap_port {
                        continue;
                    }
                    wait.pcap_ts(packet.ts);
                    if let Some(client) =
                        self.ensure_client(packet.addr, packet.ts, &mut tasks, &wait)
                    {
                        if client.stream.process_packet(packet.tcp) {
                            Self::update_client(client, packet.addr, packet.ts);
                        }
                    }
                }
                ReadState::Continue => (),
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
        self.clients.clear();
        info!("Finished reading, waiting for clients");
        tasks.join_all().await;
        Ok(())
    }

    fn ensure_client(
        &mut self,
        pcap_addr: SocketAddr,
        start_ts: u64,
        tasks: &mut JoinSet<()>,
        wait: &WaitInfo,
    ) -> Option<&mut ReplayClient> {
        let client = self.clients.entry(pcap_addr).or_default();
        if client.dead {
            return None;
        }
        if !client.connected {
            let (tx, rx) = mpsc::unbounded_channel();
            client.chan = Some(tx);
            tasks.spawn(client_proc(
                pcap_addr,
                self.info.clone(),
                wait.clone(),
                start_ts,
                rx,
            ));
            client.connected = true;
        }
        return Some(client);
    }

    fn update_client(client: &mut ReplayClient, pcap_addr: SocketAddr, ts: u64) {
        let stream = &mut client.stream;

        while stream.state != ConnState::Normal && stream.state != ConnState::CopyIn {
            match stream.find_frame() {
                FrameResult::Complete(info) => {
                    client.sent_offset = client.sent_offset.max(info.stream_end);
                    stream.consume_frame(&info);
                }
                FrameResult::Incomplete => {
                    return;
                }
                FrameResult::Desync => {
                    warn!("[{}] desync", pcap_addr);
                    stream.resync();
                }
            }
        }
        if let Some(rem) = stream.read_remaining(client.sent_offset) {
            if let Some(chan) = &client.chan {
                let msg = ClientMessage {
                    ts,
                    buf: rem.to_vec(),
                };
                match chan.send(msg) {
                    Ok(()) => {
                        client.sent_offset += rem.len();
                        stream.mark_read(client.sent_offset);
                    }
                    Err(_e) => {
                        info!("Removed client");
                        client.dead = true;
                    }
                }
            }
        }
    }
}

async fn client_proc(
    me: SocketAddr,
    info: ClientInfo,
    wait: WaitInfo,
    start_ts: u64,
    mut rx: mpsc::UnboundedReceiver<ClientMessage>,
) {
    wait.until(start_ts).await;

    info!("[{me}] Connecting");
    let mut socket = match ReplayConnection::connect(info.server_addr, info.config.clone()).await {
        Ok(s) => s,
        Err(e) => {
            error!("[{me}] Connection failed: {e}");
            return;
        }
    };
    let local_addr = socket.addr;
    info!("[{me}] Connected: {local_addr}");

    let mut addr_map = info.addr_map.lock().await;
    match addr_map.write(me, local_addr).await {
        Ok(()) => (),
        Err(e) => {
            error!("[{me}] Failed to write addr: {e}");
        }
    }
    drop(addr_map);

    loop {
        tokio::select! {
            result = rx.recv() => {
                match result {
                    Some(msg) => {
                        wait.until(msg.ts).await;
                        if let Err(e) = socket.send_packet(&msg.buf).await {
                            error!("[{me}] send failed: {e}");
                            break;
                        }
                        info.stats.log_send();
                    }
                    None => break,
                }
            }
            result = socket.read_dont_care() => {
                match result {
                    Ok(sz) => {
                        info.stats.log_recv(sz);
                    }
                    Err(ReplayError::ConnectionClosed) => {
                        info!("[{me}] Disconnected");
                        break;
                    }
                    Err(e) => {
                        error!("[{me}] recv failed: {e}");
                        break;
                    }
                }
            }
        }
    }
}
