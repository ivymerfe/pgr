use std::{
    collections::HashMap,
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
        reader::{CaptureReader, ReadError},
    },
    replay::{
        addr_map::AddrMap,
        connection::{ReplayConfig, ReplayConnection},
        pacer::Pacer,
        stats::ReplayStats,
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

struct ReplayClient {
    addr: SocketAddr,
    info: ClientInfo,
    pacer: Pacer,
    first_ts: u64,
    chan: Option<mpsc::UnboundedSender<ClientMessage>>,
    sent_offset: usize,
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
    ) -> anyhow::Result<Self> {
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
            match reader.next() {
                Ok(data) => {
                    if let Some(client) = self.ensure_client(data.addr, data.ts, &pacer) {
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
        addr: SocketAddr,
        first_ts: u64,
        pacer: &Pacer,
    ) -> Option<&mut ReplayClient> {
        let client = self
            .clients
            .entry(addr)
            .or_insert_with(|| ReplayClient::new(addr, self.info.clone(), pacer.clone(), first_ts));
        if client.dead {
            return None;
        }
        return Some(client);
    }
}

impl ReplayClient {
    pub fn new(addr: SocketAddr, info: ClientInfo, pacer: Pacer, first_ts: u64) -> Self {
        Self {
            addr,
            info,
            pacer,
            first_ts,
            chan: None,
            sent_offset: 0,
            connected: false,
            dead: false,
        }
    }
    pub fn update(&mut self, ts: u64, buf: &mut FrameBuffer, tasks: &mut JoinSet<()>) {
        let mut conn_ts = 0;
        while buf.state != ConnState::Normal && buf.state != ConnState::CopyIn {
            match buf.find_frame() {
                FrameResult::Complete(info) => {
                    if info.tag == 0 {
                        // found startup -> wait for delay and skip startup frame
                        // no startup -> connect immediately
                        conn_ts = self.first_ts;
                        self.sent_offset = self.sent_offset.max(info.stream_end);
                    }
                    buf.consume_frame(&info);
                }
                FrameResult::Incomplete => {
                    return;
                }
                FrameResult::Desync => {
                    warn!("[{}] desync", self.addr);
                    buf.resync();
                }
            }
        }
        if !self.connected {
            let (tx, rx) = mpsc::unbounded_channel();
            self.chan = Some(tx);
            tasks.spawn(client_proc(
                self.addr,
                self.info.clone(),
                self.pacer.clone(),
                conn_ts,
                rx,
            ));
            self.connected = true;
        }
        if let Some(rem) = buf.read_remaining(self.sent_offset) {
            if let Some(chan) = &self.chan {
                let msg = ClientMessage {
                    ts,
                    buf: rem.to_vec(),
                };
                match chan.send(msg) {
                    Ok(()) => {
                        self.sent_offset += rem.len();
                        buf.mark_read(self.sent_offset);
                    }
                    Err(_e) => {
                        info!("[{}] removed", self.addr);
                        self.dead = true;
                    }
                }
            }
        }
    }

    pub fn close(&mut self) {
        self.chan = None
    }
}

async fn client_proc(
    me: SocketAddr,
    info: ClientInfo,
    pacer: Pacer,
    conn_ts: u64,
    mut rx: mpsc::UnboundedReceiver<ClientMessage>,
) {
    if let Err(e) = pacer.until(conn_ts).await {
        error!("[{me}] wait failed: {e}");
        return;
    }
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
    let mut read_handle = tokio::spawn(async move {
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
                    error!("[{me}] read error: {e}");
                }
            }
        }
    });
    let write_loop = async {
        while let Some(msg) = rx.recv().await {
            if let Err(e) = pacer.until(msg.ts).await {
                error!("[{me}] wait failed: {e}");
                break;
            }
            if let Err(e) = write.write_all(&msg.buf).await {
                error!("[{me}] send failed: {e}");
                break;
            }
            info.stats.log_send();
        }
    };
    tokio::select! {
        _ = write_loop => {
            read_handle.abort();
        }
        res = &mut read_handle => {
            match res {
                Ok(()) => (),
                Err(e) => error!("[{me}] read task error: {e}"),
            }
        }
    }
    info!("[{me}] Disconnected");
}
