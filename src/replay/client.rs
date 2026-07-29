use std::{
    collections::HashMap,
    error::Error,
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::Arc,
    time::Duration,
};

use pgwire::api::client::Config;
use tokio::{sync::mpsc, task::JoinSet};
use tokio_stream::StreamExt;
use tracing::{error, info};

use crate::{
    parser::pcap::{CaptureReader, ReadState},
    replay::{
        addr_map::AddrMap, frame_tags::should_replay_frame, socket::ReplaySocket,
        stats::ReplayStats, wait::WaitInfo,
    },
};

pub struct ReplayClient {
    addr_map: AddrMap,
    config: Arc<Config>,
    wait_info: WaitInfo,
    channels: HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>,
    stats: Arc<ReplayStats>,
}

impl ReplayClient {
    pub async fn new<P: AsRef<Path>>(
        addr_map_path: P,
        host: String,
        port: u16,
        dbname: String,
        user: String,
        password: Option<String>,
    ) -> Result<Self, Box<dyn Error>> {
        let addr_map = AddrMap::new(addr_map_path).await?;

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
            addr_map,
            config: Arc::new(config),
            wait_info: WaitInfo::new(),
            channels: HashMap::new(),
            stats: Arc::new(ReplayStats::new()),
        })
    }

    pub async fn replay(
        &mut self,
        input_path: std::path::PathBuf,
        cap_port: u16,
    ) -> Result<(), Box<dyn Error>> {
        let stats = self.stats.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            interval.tick().await;

            loop {
                interval.tick().await;
                let rps = stats.read_pps();
                info!("PPS: {rps}");
            }
        });

        let input_file = std::fs::File::open(input_path)?;
        let reader = std::io::BufReader::with_capacity(131072, input_file);
        let mut capture_reader = CaptureReader::new(reader, cap_port)?;

        self.wait_info.reset();
        let mut tasks = JoinSet::new();
        loop {
            match capture_reader.next() {
                ReadState::Ok(stream) => {
                    while let Some((length, frame)) = stream.read_frame() {
                        if should_replay_frame(frame.tag) {
                            break;
                        } else {
                            stream.consume(length);
                        }
                    }
                    if stream.len() > 5 && should_replay_frame(stream.read_tag()) {
                        if let Some(ts) = stream.take_ts()
                            && let Some(packet) = stream.read_packet()
                        {
                            self.wait_info.pcap_ts(ts);
                            self.send_buf(stream.addr, packet.to_vec(), ts, &mut tasks)
                                .await?;
                        }
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
        tasks.join_all().await;
        Ok(())
    }

    async fn send_buf(
        &mut self,
        pcap_addr: SocketAddr,
        buf: Vec<u8>,
        ts: u64,
        tasks: &mut JoinSet<()>,
    ) -> Result<(), Box<dyn Error>> {
        if !self.channels.contains_key(&pcap_addr) {
            info!("Connecting: {pcap_addr}");
            let socket = connect(self.config.clone()).await?;
            let local_addr = socket.addr;
            self.addr_map.write(pcap_addr, local_addr).await?;

            let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
            self.channels.insert(pcap_addr, tx);
            tasks.spawn(client_proc(socket, rx));
        }
        if let Some(chan) = self.channels.get_mut(&pcap_addr) {
            self.wait_info.until(ts).await;
            if let Err(e) = chan.send(buf) {
                error!("Failed to send packet to channel: {e}");
                self.channels.remove(&pcap_addr);
            }
            self.stats.count_packet();
        }
        return Ok(());
    }
}

async fn connect(config: Arc<Config>) -> Result<ReplaySocket, Box<dyn Error>> {
    let addr = *config.get_hostaddrs().first().expect("no hostaddr");
    let port = *config.get_ports().first().expect("no port");
    let socket_addr = SocketAddr::new(addr, port);
    ReplaySocket::connect(socket_addr, config).await
}

async fn client_proc(mut socket: ReplaySocket, mut rx: mpsc::UnboundedReceiver<Vec<u8>>) {
    loop {
        tokio::select! {
            result = rx.recv() => {
                match result {
                    Some(packet) => {
                        if let Err(e) = socket.send_packet(&packet).await {
                            error!("[{}] send failed: {e}", socket.addr);
                            break;
                        }
                    }
                    None => break,
                }
            }
            result = socket.next() => {
                match result {
                    Some(Ok(_backend_msg)) => {}
                    Some(Err(e)) => {
                        error!("[{}] recv failed: {e}", socket.addr);
                        break;
                    }
                    None => break,
                }
            }
        }
    }
}
