use std::{
    collections::HashMap,
    error::Error,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Mutex, mpsc},
    task::JoinSet,
    time::sleep,
};
use tracing::{error, info, warn};

use crate::{
    capture::{
        frame_buffer::{ConnState, FrameBuffer, FrameResult},
        pcap::{CaptureReader, ReadState},
    },
    replay::{
        addr_map::AddrMap,
        connection::{ReplayConfig, ReplayConnection},
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
    config: ReplayConfig,
    addr_map: Arc<Mutex<AddrMap>>,
    stats: Arc<ReplayStats>,
}

#[derive(Default)]
struct ReplayClient {
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
    pub async fn new(
        addr_map: AddrMap,
        host: String,
        port: u16,
        dbname: String,
        user: String,
        password: Option<String>,
    ) -> Result<Self, Box<dyn Error>> {
        let addr: IpAddr = host.parse()?;
        let config = ReplayConfig {
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
        input: std::fs::File,
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

        let mut reader = CaptureReader::new(input, cap_port)?;
        let mut wait = None;
        let mut tasks = JoinSet::new();
        loop {
            match reader.next() {
                ReadState::Ok { addr, ts, buf } => {
                    let wait = wait.get_or_insert_with(|| WaitInfo::start(ts));
                    if let Some(client) = self.ensure_client(addr, ts, &mut tasks, wait) {
                        Self::update_client(client, addr, ts, buf);
                    }
                    if wait.time_to(ts) > 4_000_000 {
                        sleep(Duration::from_secs(3)).await;
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
        conn_ts: u64,
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
                conn_ts,
                rx,
            ));
            client.connected = true;
        }
        return Some(client);
    }

    fn update_client(client: &mut ReplayClient, addr: SocketAddr, ts: u64, buf: &mut FrameBuffer) {
        while buf.state != ConnState::Normal && buf.state != ConnState::CopyIn {
            match buf.find_frame() {
                FrameResult::Complete(info) => {
                    client.sent_offset = client.sent_offset.max(info.stream_end);
                    buf.consume_frame(&info);
                }
                FrameResult::Incomplete => {
                    return;
                }
                FrameResult::Desync => {
                    warn!("[{}] desync", addr);
                    buf.resync();
                }
            }
        }
        if let Some(rem) = buf.read_remaining(client.sent_offset) {
            if let Some(chan) = &client.chan {
                let msg = ClientMessage {
                    ts,
                    buf: rem.to_vec(),
                };
                match chan.send(msg) {
                    Ok(()) => {
                        client.sent_offset += rem.len();
                        buf.mark_read(client.sent_offset);
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
    mut conn_wait: WaitInfo,
    conn_ts: u64,
    mut rx: mpsc::UnboundedReceiver<ClientMessage>,
) {
    conn_wait.until(conn_ts).await;

    let mut wait = WaitInfo::start(conn_ts);
    info!("[{me}] Connecting");
    let socket = match ReplayConnection::connect(info.server_addr, info.config.clone()).await {
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

    let (mut read, mut write) = socket.stream.into_split();
    let read_stats = info.stats.clone();
    let read_handle = tokio::spawn(async move {
        let mut chunk = [0u8; 65536];
        loop {
            match read.read(&mut chunk).await {
                Ok(sz) => {
                    if sz == 0 {
                        break;
                    }
                    read_stats.log_recv(sz);
                }
                Err(e) => {
                    error!("[{}] read error: {}", me, e);
                }
            }
        }
    });
    while let Some(msg) = rx.recv().await {
        wait.until(msg.ts).await;
        if let Err(e) = write.write_all(&msg.buf).await {
            error!("[{me}] send failed: {e}");
            break;
        }
        info.stats.log_send();
    }
    match read_handle.await {
        Ok(()) => (),
        Err(e) => error!("[{}] wait error: {}", me, e),
    };
    info!("[{}] Disconnected", me);
}
