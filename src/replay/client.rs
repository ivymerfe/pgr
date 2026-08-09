use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use mio::Token;
use mio::net::TcpStream;
use tracing::{error, info};

use crate::capture::reader::ClientId;
use crate::proto::{self, Authentication, BackendMessage, tags};
use crate::replay::stats::ReplayStats;

#[derive(Clone)]
pub struct ReplayConfig {
    pub server: SocketAddr,
    pub user: String,
    pub password: Option<String>,
    pub dbname: String,
    pub application_name: String,
    pub disconnect_timeout: Duration,
}

#[derive(PartialEq)]
pub enum ClientState {
    Connecting,
    Normal,
    Dead,
}

struct PendingFrame {
    tag: u8,
    data: Vec<u8>,
}

pub struct ReplayClient {
    pub id: ClientId,
    pub stream: TcpStream,
    pub token: Token,
    pub config: ReplayConfig,
    pub addr: SocketAddr,
    pub state: ClientState,
    pub stats: Arc<ReplayStats>,

    pending_frames: VecDeque<PendingFrame>,
    waiting_for_sync: bool,

    read_buf: Vec<u8>,
    parsed: usize,
    write_buf: Vec<u8>,
    write_pos: usize,
}

impl ReplayConfig {
    pub fn new(
        host: IpAddr,
        port: u16,
        dbname: String,
        user: String,
        password: Option<String>,
        disconnect_timeout: Duration,
    ) -> Self {
        ReplayConfig {
            server: SocketAddr::new(host, port),
            user,
            password,
            dbname,
            application_name: "pgr".to_string(),
            disconnect_timeout,
        }
    }
}

impl ReplayClient {
    pub fn connect(
        id: ClientId,
        config: ReplayConfig,
        stats: Arc<ReplayStats>,
    ) -> Result<Self, std::io::Error> {
        let stream = TcpStream::connect(config.server)?;
        stream.set_nodelay(true)?;
        let local_addr = stream.local_addr()?;

        let mut client = ReplayClient {
            id,
            stream,
            token: Token(id as usize),
            config,
            stats,
            addr: local_addr,
            state: ClientState::Connecting,
            pending_frames: VecDeque::new(),
            waiting_for_sync: false,
            read_buf: Vec::with_capacity(65536),
            parsed: 0,
            write_buf: Vec::with_capacity(65536),
            write_pos: 0,
        };
        client.send_startup();
        Ok(client)
    }

    fn handle_frame(&mut self, tag: u8, offset: usize, len: usize) {
        let data = &self.read_buf[self.parsed + offset..self.parsed + len];
        if self.state == ClientState::Connecting {
            match proto::parse_message(tag, data) {
                Ok(msg) => match msg {
                    BackendMessage::Authentication(auth) => self.handle_auth(auth),
                    BackendMessage::ErrorResponse(e) => {
                        error!("[{}] auth failed: {e}", self.id);
                    }
                    BackendMessage::ReadyForQuery => {
                        info!("[{}] connected: {}", self.id, self.addr);
                        self.state = ClientState::Normal;
                        self.send_pending();
                    }
                    _ => {}
                },
                Err(()) => {
                    error!("[{}] malformed server message", self.id);
                }
            }
        }
        if self.state == ClientState::Normal {
            self.stats.log_recv();
            if tag == tags::B_READY_FOR_QUERY {
                self.waiting_for_sync = false;
                self.send_pending();
            }
            // future latency measurements
        }
    }

    pub fn send_frame(&mut self, tag: u8, data: Vec<u8>) {
        if self.state == ClientState::Dead {
            return;
        }
        if self.waiting_for_sync || self.state == ClientState::Connecting {
            self.pending_frames.push_back(PendingFrame { tag, data });
        } else {
            if tag == tags::F_SYNC {
                self.waiting_for_sync = true;
            }
            self.send(&data);
        }
    }

    fn send_pending(&mut self) {
        while let Some(frame) = self.pending_frames.pop_front() {
            self.send(&frame.data);
            if frame.tag == tags::F_SYNC {
                self.waiting_for_sync = true;
                break;
            }
        }
    }

    fn send(&mut self, bytes: &[u8]) {
        self.stats.log_send();
        self.write_buf.extend_from_slice(bytes);
    }

    pub fn has_pending_write(&self) -> bool {
        self.write_pos < self.write_buf.len()
    }

    pub fn try_read(&mut self) {
        let mut chunk = [0u8; 4096];
        loop {
            match self.stream.read(&mut chunk) {
                Ok(0) => {
                    info!("[{}] disconnected", self.id);
                    self.state = ClientState::Dead;
                    return;
                }
                Ok(n) => {
                    self.read_buf.extend_from_slice(&chunk[..n]);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    if self.parsed > 65536 {
                        self.read_buf.drain(..self.parsed);
                        self.parsed = 0;
                    }
                    while let Some((tag, frame_len)) =
                        proto::try_read_frame(&self.read_buf[self.parsed..])
                    {
                        self.handle_frame(tag, 5, frame_len);
                        self.parsed += frame_len;
                        if self.state == ClientState::Dead {
                            return;
                        }
                    }
                    return;
                }
                Err(e) => {
                    error!("[{}] read failed: {e}", self.id);
                    self.state = ClientState::Dead;
                    return;
                }
            }
        }
    }

    pub fn try_flush(&mut self) {
        while self.write_pos < self.write_buf.len() {
            match self.stream.write(&self.write_buf[self.write_pos..]) {
                Ok(0) => {
                    info!("[{}] disconnected", self.id);
                    self.state = ClientState::Dead;
                    return;
                }
                Ok(n) => {
                    self.write_pos += n;
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    return;
                }
                Err(e) => {
                    error!("[{}] write failed: {e}", self.id);
                    self.state = ClientState::Dead;
                    return;
                }
            }
        }
        self.write_buf.clear();
        self.write_pos = 0;
    }

    fn send_startup(&mut self) {
        let mut params = Vec::new();
        params.push((
            "application_name".to_string(),
            self.config.application_name.clone(),
        ));
        params.push(("user".to_string(), self.config.user.clone()));
        params.push(("database".to_string(), self.config.dbname.clone()));
        self.send(&proto::encode_startup(&params));
        self.try_flush();
    }

    fn handle_auth(&mut self, auth: Authentication) {
        match auth {
            Authentication::Ok => {}
            Authentication::Cleartext => match &self.config.password {
                Some(pass) => {
                    self.send(&proto::encode_password(pass));
                    self.try_flush();
                }
                None => {
                    error!("[{}] server wants password but its not specified", self.id);
                    self.state = ClientState::Dead;
                }
            },
            Authentication::Md5 { salt } => match &self.config.password {
                Some(pass) => {
                    let hashed = proto::hash_md5_password(&self.config.user, &pass, &salt);
                    self.send(&proto::encode_password(&hashed));
                    self.try_flush();
                }
                None => {
                    error!("[{}] server wants password but its not specified", self.id);
                    self.state = ClientState::Dead;
                }
            },
            Authentication::Unsupported(code) => {
                error!("[{}] unsupported auth: {code}", self.id);
                self.state = ClientState::Dead;
            }
        }
    }
}
