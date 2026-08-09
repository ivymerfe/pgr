use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use socket2::{Domain, Socket, Type};
use tracing::{error, info};

use crate::capture::reader::ClientId;
use crate::proto::{self, Authentication, BackendMessage, tags};
use crate::replay::stats::ReplayStats;
use crate::utils::stream::Stream;

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

struct PendingFrame {
    tag: u8,
    len: usize,
}

struct PendingFrameData {
    tag: u8,
    data: Vec<u8>,
}

pub struct ReplayClient {
    pub id: ClientId,
    pub config: ReplayConfig,
    pub addr: SocketAddr,
    pub state: ClientState,
    pub stats: Arc<ReplayStats>,

    pre_connect_frames: Vec<PendingFrameData>,
    pending_frames: VecDeque<PendingFrame>,
    waiting_for_sync: bool,

    parse_stream: Stream,
    outbox: Stream,
}

pub struct NewConnection {
    pub client: ReplayClient,
    pub socket: Socket,
}

impl ReplayClient {
    pub fn connect(
        id: ClientId,
        config: ReplayConfig,
        stats: Arc<ReplayStats>,
    ) -> std::io::Result<NewConnection> {
        let domain = match config.server {
            SocketAddr::V4(_) => Domain::IPV4,
            SocketAddr::V6(_) => Domain::IPV6,
        };
        let socket = Socket::new(domain, Type::STREAM, None)?;
        socket.set_tcp_nodelay(true)?;
        socket.set_nonblocking(true)?;

        let addr = config.server;
        let mut client = ReplayClient {
            id,
            config,
            stats,
            addr,
            state: ClientState::Connecting,
            pre_connect_frames: Vec::new(),
            pending_frames: VecDeque::new(),
            waiting_for_sync: false,
            parse_stream: Stream::new(65536),
            outbox: Stream::new(65536),
        };
        client.queue_startup();

        Ok(NewConnection { client, socket })
    }

    pub fn on_connected(&mut self, local_addr: SocketAddr) {
        self.addr = local_addr;
    }

    fn handle_frame(&mut self, tag: u8, offset: usize, len: usize) {
        let data = &self.parse_stream.data()[offset..len];
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
                        let frames = std::mem::take(&mut self.pre_connect_frames);
                        for frame in frames {
                            self.send_frame(frame.tag, &frame.data);
                        }
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
        }
    }

    pub fn on_read(&mut self, data: &[u8]) {
        self.parse_stream.write(data);
        while let Some((tag, frame_len)) = proto::try_read_frame(self.parse_stream.data()) {
            self.handle_frame(tag, 5, frame_len);
            self.parse_stream.mark_read(frame_len);
            if self.state == ClientState::Dead {
                return;
            }
        }
    }

    pub fn on_eof(&mut self) {
        info!("[{}] disconnected", self.id);
        self.state = ClientState::Dead;
    }

    pub fn on_io_error(&mut self, e: std::io::Error) {
        error!("[{}] io failed: {e}", self.id);
        self.state = ClientState::Dead;
    }

    pub fn send_frame(&mut self, tag: u8, data: &[u8]) {
        if self.state == ClientState::Dead {
            return;
        }
        if self.state == ClientState::Connecting {
            self.pre_connect_frames.push(PendingFrameData {
                tag,
                data: data.to_vec(),
            });
            return;
        }
        self.outbox.write_no_commit(data);
        self.pending_frames.push_back(PendingFrame {
            tag,
            len: data.len(),
        });
        self.send_pending();
    }

    fn send_pending(&mut self) {
        if self.waiting_for_sync {
            return;
        }
        while let Some(frame) = self.pending_frames.pop_front() {
            self.stats.log_send();
            self.outbox.commit(frame.len);
            if frame.tag == tags::F_SYNC {
                self.waiting_for_sync = true;
                break;
            }
        }
    }

    pub fn read_outbox(&self) -> &[u8] {
        self.outbox.data()
    }

    pub fn clear_outbox(&mut self) {
        self.outbox.mark_read_all();
    }

    fn queue_startup(&mut self) {
        let mut params = Vec::new();
        params.push((
            "application_name".to_string(),
            self.config.application_name.clone(),
        ));
        params.push(("user".to_string(), self.config.user.clone()));
        params.push(("database".to_string(), self.config.dbname.clone()));
        let msg = proto::encode_startup(&params);
        self.outbox.write(&msg);
    }

    fn handle_auth(&mut self, auth: Authentication) {
        match auth {
            Authentication::Ok => {}
            Authentication::Cleartext => match &self.config.password {
                Some(pass) => {
                    let msg = proto::encode_password(pass);
                    self.outbox.write(&msg);
                }
                None => {
                    error!("[{}] server wants password but its not specified", self.id);
                    self.state = ClientState::Dead;
                }
            },
            Authentication::Md5 { salt } => match &self.config.password {
                Some(pass) => {
                    let hashed = proto::hash_md5_password(&self.config.user, pass, &salt);
                    let msg = proto::encode_password(&hashed);
                    self.outbox.write(&msg);
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
