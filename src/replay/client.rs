use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::{
    sync::{
        Mutex,
        mpsc::{self, UnboundedSender},
    },
    task::JoinSet,
    time::timeout,
};
use tracing::{error, info, warn};

use crate::{
    capture::{
        frame_buffer::{ConnState, FrameBuffer, FrameResult},
        reader::ClientId,
    },
    pg_client::{PgClient, PgClientConfig, error::PgClientError},
    replay::{addr_map::AddrMapWriter, pacer::Pacer, stats::ReplayStats},
    utils::timerfd::Timer,
};

pub struct ClientMessage {
    ts: u64,
    tag: u8,
    data: Vec<u8>,
    flush: bool,
}

pub struct LatMessage {
    pub id: ClientId,
    pub tag: u8,
    pub response: bool,
    pub ts: u64,
}

#[derive(Clone)]
pub struct ClientInfo {
    pub server_addr: SocketAddr,
    pub config: PgClientConfig,
    pub addr_map: Arc<Mutex<AddrMapWriter>>,
    pub lat_tx: UnboundedSender<LatMessage>,
    pub should_send_lat: bool,
    pub stats: Arc<ReplayStats>,
    pub disconnect_timeout: Duration,
}

pub struct ReplayClient {
    id: ClientId,
    info: ClientInfo,
    pacer: Pacer,
    first_ts: u64,
    chan: Option<mpsc::UnboundedSender<ClientMessage>>,
    sent_offset: usize,
    dead: bool,
    connected: bool,
}

impl ReplayClient {
    pub fn new(id: ClientId, info: ClientInfo, pacer: Pacer, first_ts: u64) -> Self {
        Self {
            id,
            info,
            pacer,
            first_ts,
            chan: None,
            sent_offset: 0,
            connected: false,
            dead: false,
        }
    }

    pub fn is_dead(&self) -> bool {
        self.dead
    }

    pub fn send(&self, msg: ClientMessage) -> bool {
        if let Some(chan) = &self.chan {
            match chan.send(msg) {
                Ok(()) => (),
                Err(_) => {
                    warn!("[{}] channel send failed", self.id);
                    return false;
                }
            }
        }
        true
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
                    warn!("[{}] desync", self.id);
                    buf.resync();
                }
            }
        }
        if self.dead {
            return;
        }
        if !self.connected {
            let (tx, rx) = mpsc::unbounded_channel();
            self.chan = Some(tx);
            tasks.spawn(client_proc(
                self.id,
                self.info.clone(),
                self.pacer.clone(),
                conn_ts,
                rx,
            ));
            self.connected = true;
        }
        let mut ready_msg: Option<ClientMessage> = None;
        while !self.dead {
            match buf.find_frame() {
                FrameResult::Complete(info) => {
                    if let Some(msg) = ready_msg.take() {
                        if !self.send(msg) {
                            self.dead = true;
                            return;
                        }
                    }
                    let data = buf.read_frame_full(&info);
                    ready_msg = Some(ClientMessage {
                        ts,
                        tag: info.tag,
                        data: data.to_vec(),
                        flush: false,
                    });
                    buf.consume_frame(&info);
                }
                FrameResult::Incomplete => {
                    if let Some(mut msg) = ready_msg.take() {
                        msg.flush = true;
                        if !self.send(msg) {
                            self.dead = true;
                        }
                    }
                    return;
                }
                FrameResult::Desync => {
                    warn!("[{}] desync", self.id);
                    buf.resync();
                }
            }
        }
    }

    pub fn close(&mut self) {
        self.chan = None;
        self.dead = true;
    }
}

async fn client_proc(
    me: ClientId,
    info: ClientInfo,
    pacer: Pacer,
    conn_ts: u64,
    mut rx: mpsc::UnboundedReceiver<ClientMessage>,
) {
    let mut timer = match Timer::new() {
        Ok(t) => t,
        Err(e) => {
            error!("[{me}] failed to create timer: {e}");
            return;
        }
    };

    if let Err(e) = pacer.until(conn_ts, &mut timer).await {
        error!("[{me}] wait failed: {e}");
        return;
    }
    info!("[{me}] Connecting");
    let client = match PgClient::connect(info.server_addr, info.config.clone()).await {
        Ok(s) => s,
        Err(e) => {
            error!("[{me}] Connection failed: {e}");
            return;
        }
    };
    let local_addr = client.addr;
    info!("[{me}] Connected: {local_addr}");

    let mut addr_map = info.addr_map.lock().await;
    match addr_map.write(me, local_addr).await {
        Ok(()) => (),
        Err(e) => {
            error!("[{me}] Failed to write addr: {e}");
        }
    }
    drop(addr_map);

    let (mut reader, mut writer) = client.split();

    let read_stats = info.stats.clone();
    let reader_lat_tx = info.lat_tx.clone();
    let start_time = quanta::Instant::now();

    let mut read_handle = tokio::spawn(async move {
        let mut lat_send_error = false;
        loop {
            match reader.next_frame().await {
                Ok(frame) => {
                    if info.should_send_lat && !lat_send_error {
                        let ts = start_time.elapsed().as_micros() as u64;
                        let lat_msg = LatMessage {
                            id: me,
                            tag: frame.tag,
                            response: true,
                            ts,
                        };
                        if let Err(e) = reader_lat_tx.send(lat_msg) {
                            error!("[{me}] reader failed to send latency: {e}");
                            lat_send_error = true;
                        }
                    }
                    read_stats.log_recv(frame.data.len());
                }
                Err(PgClientError::ConnectionClosed) => {
                    info!("[{me}] Disconnected");
                    break;
                }
                Err(e) => {
                    error!("[{me}] read error: {e}");
                    break;
                }
            }
        }
    });
    let write_loop = async {
        let mut lat_send_error = false;
        while let Some(msg) = rx.recv().await {
            if let Err(e) = pacer.until(msg.ts, &mut timer).await {
                error!("[{me}] wait failed: {e}");
                break;
            }
            if info.should_send_lat && !lat_send_error {
                let ts = start_time.elapsed().as_micros() as u64;
                let lat_msg = LatMessage {
                    id: me,
                    tag: msg.tag,
                    response: false,
                    ts,
                };
                if let Err(e) = info.lat_tx.send(lat_msg) {
                    error!("[{me}] writer failed to send latency: {e}");
                    lat_send_error = true;
                }
            }
            if let Err(e) = writer.send(&msg.data).await {
                error!("[{me}] send failed: {e}");
                break;
            }
            if msg.flush {
                if let Err(e) = writer.flush().await {
                    error!("[{me}] flush failed: {e}");
                    break;
                }
            }
            info.stats.log_send();
        }
    };
    tokio::select! {
        _ = write_loop => {
            info!("[{me}] Sent all");
            match timeout(info.disconnect_timeout, &mut read_handle).await {
                Ok(Ok(())) => (),
                Ok(Err(e)) => error!("[{me}] Read task error: {e}"),
                Err(_) => {
                    warn!("[{me}] Force disconnect after {:.2}s", info.disconnect_timeout.as_secs_f64());
                    read_handle.abort();
                }
            }
        }
        res = &mut read_handle => {
            match res {
                Ok(()) => (),
                Err(e) => error!("[{me}] read task error: {e}"),
            }
        }
    }
}
