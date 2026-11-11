use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;

use mio::event::Event;
use mio::net::TcpStream;
use mio::{Interest, Registry, Token};
use tracing::{error, info};

use crate::capture::{ClientEvent, ClientId};
use crate::proto::{self, Authentication, BackendMessage, Frame};
use crate::utils::{ReplayStats, Stream};

const APPLICATION_NAME: &str = "pgr";
const BUF_SIZE: usize = 65536;

pub struct ReplayConfig {
    pub server: SocketAddr,
    pub user: String,
    pub password: Option<String>,
    pub dbname: String,
    pub speed: f64,
    pub threads: usize,
    pub max_conns: usize,
    pub max_rps: u32,
}

#[derive(Clone, Copy, PartialEq)]
enum State {
    Connecting,
    Startup,
    Ready,
    Dead,
}

pub struct ReplayClient {
    id: ClientId,
    config: Arc<ReplayConfig>,
    stats: Arc<ReplayStats>,
    stream: TcpStream,
    state: State,
    waiting: bool,
    restore: Option<String>,
    rbuf: Stream,
    wbuf: Stream,
}

impl ReplayClient {
    pub fn connect(
        id: ClientId,
        config: Arc<ReplayConfig>,
        stats: Arc<ReplayStats>,
        session_id: String,
        registry: &Registry,
    ) -> io::Result<Self> {
        let mut stream = TcpStream::connect(config.server)?;
        stream.set_nodelay(true)?;
        registry.register(
            &mut stream,
            Token(id as usize),
            Interest::READABLE | Interest::WRITABLE,
        )?;
        let restore = (!session_id.is_empty())
            .then(|| format!("SELECT pgr.srestore('{}')", session_id.replace('\'', "''")));
        let startup = proto::encode_startup(&[
            ("application_name", APPLICATION_NAME.to_string()),
            ("user", config.user.clone()),
            ("database", config.dbname.clone()),
            ("pgr.client_id", id.to_string()),
        ]);
        let mut client = Self {
            id,
            config,
            stats,
            stream,
            state: State::Connecting,
            waiting: true,
            restore,
            rbuf: Stream::new(BUF_SIZE),
            wbuf: Stream::new(BUF_SIZE),
        };
        client.send(&startup);
        Ok(client)
    }

    pub fn waiting(&self) -> bool {
        self.waiting
    }

    pub fn is_dead(&self) -> bool {
        self.state == State::Dead
    }

    pub fn replay(&mut self, event: ClientEvent) {
        if self.state != State::Ready {
            return;
        }
        if let Some(frame) = encode(event) {
            self.send(&frame);
            self.flush();
        }
    }

    pub fn on_event(&mut self, ev: &Event, buf: &mut [u8]) {
        if self.state == State::Connecting {
            if !(ev.is_writable() || ev.is_error() || ev.is_write_closed()) {
                return;
            }
            match self.stream.take_error() {
                Ok(None) => {}
                Ok(Some(e)) | Err(e) => return self.fail(e),
            }
            match self.stream.peer_addr() {
                Ok(_) => self.state = State::Startup,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::NotConnected | io::ErrorKind::WouldBlock
                    ) =>
                {
                    return;
                }
                Err(e) => return self.fail(e),
            }
        }
        self.read(buf);
        self.flush();
    }

    fn send(&mut self, frame: &[u8]) {
        self.wbuf.write(frame);
        self.stats.log_send();
        if matches!(frame[0], proto::F_QUERY | proto::F_SYNC) {
            self.waiting = true;
        }
    }

    fn fail(&mut self, e: io::Error) {
        error!("[{}] io failed: {e}", self.id);
        self.state = State::Dead;
    }

    fn read(&mut self, buf: &mut [u8]) {
        while self.state != State::Dead {
            match self.stream.read(buf) {
                Ok(0) => {
                    info!("[{}] disconnected", self.id);
                    self.state = State::Dead;
                }
                Ok(n) => self.on_data(&buf[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => self.fail(e),
            }
        }
    }

    fn flush(&mut self) {
        if self.state == State::Connecting {
            return;
        }
        while self.state != State::Dead && !self.wbuf.data().is_empty() {
            match self.stream.write(self.wbuf.data()) {
                Ok(0) => return,
                Ok(n) => self.wbuf.mark_read(n),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => self.fail(e),
            }
        }
    }

    fn on_data(&mut self, data: &[u8]) {
        self.rbuf.write(data);
        while self.state != State::Dead {
            let Some((tag, len)) = proto::try_read_frame(self.rbuf.data()) else {
                break;
            };
            self.on_frame(tag, len);
            self.rbuf.mark_read(len);
        }
    }

    fn on_frame(&mut self, tag: u8, len: usize) {
        use State::*;
        let msg = proto::parse_message(tag, &self.rbuf.data()[5..len]);
        let counted = self.state == Ready;
        match (self.state, msg) {
            (_, Err(())) => error!("[{}] malformed server message", self.id),
            (_, Ok(BackendMessage::ErrorResponse(e))) => {
                error!("[{}] server error: {e}", self.id);
                if self.state != Ready {
                    self.state = Dead;
                }
            }
            (_, Ok(BackendMessage::Authentication(auth))) => self.on_auth(auth),
            (Startup, Ok(BackendMessage::ReadyForQuery)) => {
                info!("[{}] connected", self.id);
                self.state = Ready;
                match self.restore.take() {
                    Some(q) => self.send(&query_frame(&q)),
                    None => self.waiting = false,
                }
            }
            (Ready, Ok(BackendMessage::ReadyForQuery)) => self.waiting = false,
            _ => {}
        }
        if counted {
            self.stats.log_recv();
        }
    }

    fn on_auth(&mut self, auth: Authentication) {
        let password = match auth {
            Authentication::Ok => return,
            Authentication::Cleartext => self.config.password.clone(),
            Authentication::Md5 { salt } => self
                .config
                .password
                .as_ref()
                .map(|p| proto::hash_md5_password(&self.config.user, p, &salt)),
            Authentication::Unsupported(code) => {
                error!("[{}] unsupported auth: {code}", self.id);
                self.state = State::Dead;
                return;
            }
        };
        match password {
            Some(p) => self.send(&proto::encode_password(&p)),
            None => {
                error!("[{}] server requires a password", self.id);
                self.state = State::Dead;
            }
        }
    }
}

fn query_frame(q: &str) -> Vec<u8> {
    let mut b = Frame::new(proto::F_QUERY);
    b.cstr(q);
    b.finish()
}

fn encode(event: ClientEvent) -> Option<Vec<u8>> {
    Some(match event {
        ClientEvent::Lsn { .. } | ClientEvent::TxEnd { .. } | ClientEvent::Connect { .. } => {
            return None;
        }
        ClientEvent::Disconnect => proto::TERMINATE_MSG.to_vec(),
        ClientEvent::SimpleQuery { text } => query_frame(&text),
        ClientEvent::Parse {
            name,
            query,
            param_types,
        } => {
            let mut b = Frame::new(proto::F_PARSE);
            b.cstr(&name).cstr(&query).i16(param_types.len() as i16);
            for t in param_types {
                b.u32(t);
            }
            b.finish()
        }
        ClientEvent::Bind {
            portal,
            statement,
            result_formats,
            params,
        } => {
            let mut b = Frame::new(proto::F_BIND);
            b.cstr(&portal)
                .cstr(&statement)
                .i16(0)
                .i16(params.len() as i16);
            for p in params {
                match p.value {
                    Some(v) => b.i32(v.len() as i32).raw(&v),
                    None => b.i32(-1),
                };
            }
            b.i16(result_formats.len() as i16);
            for f in result_formats {
                b.i16(f as i16);
            }
            b.finish()
        }
        ClientEvent::Execute { portal, max_rows } => {
            let mut b = Frame::new(proto::F_EXECUTE);
            b.cstr(&portal)
                .i32(max_rows.clamp(0, i32::MAX as i64) as i32);
            b.finish()
        }
        ClientEvent::Sync => Frame::new(proto::F_SYNC).finish(),
        ClientEvent::Close { kind, name } => {
            let mut b = Frame::new(proto::F_CLOSE);
            b.u8(kind).cstr(&name);
            b.finish()
        }
    })
}
