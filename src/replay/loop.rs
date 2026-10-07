use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::sync::Arc;
use std::time::Duration;

use crossbeam_channel::Receiver;
use mio::event::Event;
use mio::net::TcpStream;
use mio::{Events, Interest, Poll, Token};
use quanta::Instant;
use socket2::Socket;
use tracing::error;

use crate::capture::reader::ClientId;
use crate::replay::client::{ClientState, NewConnection, ReplayClient, ReplayConfig};
use crate::replay::stats::ReplayStats;
use crate::utils::stream::Stream;

const WAKER_TOKEN: Token = Token(usize::MAX);

pub const READ_BUF_SIZE: usize = 65536;

pub enum ConnCommand {
    Connect {
        id: ClientId,
        ts: u64,
    },
    Send {
        id: ClientId,
        ts: u64,
        tag: u8,
        data: Vec<u8>,
    },
    Terminate {
        ts: u64,
    },
}

impl ConnCommand {
    fn ts(&self) -> u64 {
        match self {
            ConnCommand::Connect { ts, .. } => *ts,
            ConnCommand::Send { ts, .. } => *ts,
            ConnCommand::Terminate { ts } => *ts,
        }
    }
}

struct Connection {
    stream: TcpStream,
    client: ReplayClient,
    read_buf: Vec<u8>,
    write_stream: Stream,
    connected: bool,
}

pub struct ReplayLoop {
    config: ReplayConfig,
    server_addr: socket2::SockAddr,

    rx: Receiver<ConnCommand>,
    stats: Arc<ReplayStats>,

    poll: Poll,
    waker: Arc<mio::Waker>,

    start: Instant,
    started: bool,
    pending_commands: VecDeque<ConnCommand>,
    rx_closed: bool,
}

impl ReplayLoop {
    pub fn new(
        config: ReplayConfig,
        rx: Receiver<ConnCommand>,
        stats: Arc<ReplayStats>,
    ) -> io::Result<Self> {
        let poll = Poll::new()?;
        let waker = Arc::new(mio::Waker::new(poll.registry(), WAKER_TOKEN)?);
        let server_addr = socket2::SockAddr::from(config.server);

        Ok(Self {
            config,
            server_addr,
            rx,
            stats,
            poll,
            waker,
            start: Instant::now(),
            started: false,
            pending_commands: VecDeque::new(),
            rx_closed: false,
        })
    }

    pub fn waker(&self) -> Arc<mio::Waker> {
        self.waker.clone()
    }

    fn now_us(&self) -> u64 {
        self.start.elapsed().as_micros() as u64
    }

    fn next_timeout(&self) -> Option<Duration> {
        self.pending_commands
            .front()
            .map(|c| Duration::from_micros(c.ts().saturating_sub(self.now_us())))
    }

    pub fn run(&mut self) {
        let mut events = Events::with_capacity(1024);
        let mut connections: HashMap<ClientId, Connection> = HashMap::new();

        loop {
            self.drain_commands();

            let timeout = self.next_timeout();
            if let Err(e) = self.poll.poll(&mut events, timeout) {
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                error!("poll failed: {e}");
                break;
            }
            if !self.started {
                self.start = Instant::now();
                self.started = true;
            }

            for event in events.iter() {
                self.handle_event(&mut connections, event);
            }

            self.drain_commands();
            self.dispatch_ready(&mut connections);

            if self.rx_closed && self.pending_commands.is_empty() && connections.is_empty() {
                break;
            }
        }
    }

    fn drain_commands(&mut self) {
        loop {
            match self.rx.try_recv() {
                Ok(cmd) => self.pending_commands.push_back(cmd),
                Err(crossbeam_channel::TryRecvError::Empty) => break,
                Err(crossbeam_channel::TryRecvError::Disconnected) => {
                    self.rx_closed = true;
                    break;
                }
            }
        }
    }

    fn dispatch_ready(&mut self, conns: &mut HashMap<ClientId, Connection>) {
        let now = self.now_us();
        while let Some(front) = self.pending_commands.front() {
            if front.ts() > now {
                break;
            }
            let cmd = self.pending_commands.pop_front().unwrap();
            self.dispatch_command(conns, cmd);
        }
    }

    fn dispatch_command(
        &mut self,
        conns: &mut HashMap<ClientId, Connection>,
        command: ConnCommand,
    ) {
        match command {
            ConnCommand::Connect { id, .. } => {
                self.connect_client(conns, id);
            }
            ConnCommand::Send { id, tag, data, .. } => {
                if let Some(conn) = conns.get_mut(&id) {
                    conn.client.replay_frame(tag, &data);
                    flush_conn(conn);
                }
                self.remove_if_dead(conns, id);
            }
            ConnCommand::Terminate { .. } => {
                for conn in conns.values_mut() {
                    conn.client.on_replay_end();
                    flush_conn(conn);
                }
                let dead: Vec<ClientId> = conns
                    .iter()
                    .filter(|(_, c)| c.client.state == ClientState::Dead)
                    .map(|(id, _)| *id)
                    .collect();
                for id in dead {
                    self.remove_if_dead(conns, id);
                }
            }
        }
    }

    fn connect_client(&mut self, conns: &mut HashMap<ClientId, Connection>, id: ClientId) {
        let NewConnection { client, socket } =
            match ReplayClient::connect(id, self.config.clone(), self.stats.clone()) {
                Ok(c) => c,
                Err(e) => {
                    error!("[ctl] failed to connect client {id}: {e}");
                    return;
                }
            };

        let mut stream = match self.start_connect(socket) {
            Ok(s) => s,
            Err(e) => {
                error!("[{id}] connect failed: {e}");
                return;
            }
        };

        if let Err(e) = self.poll.registry().register(
            &mut stream,
            Token(id as usize),
            Interest::READABLE | Interest::WRITABLE,
        ) {
            error!("[{id}] register failed: {e}");
            return;
        }

        conns.insert(
            id,
            Connection {
                stream,
                client,
                read_buf: vec![0; READ_BUF_SIZE],
                write_stream: Stream::new(READ_BUF_SIZE),
                connected: false,
            },
        );
    }

    fn start_connect(&self, socket: Socket) -> io::Result<TcpStream> {
        socket.set_nonblocking(true)?;
        match socket.connect(&self.server_addr) {
            Ok(()) => {}
            Err(e) if is_in_progress(&e) => {}
            Err(e) => return Err(e),
        }
        let std_stream: std::net::TcpStream = socket.into();
        Ok(TcpStream::from_std(std_stream))
    }

    fn handle_event(&mut self, conns: &mut HashMap<ClientId, Connection>, event: &Event) {
        let token = event.token();
        if token == WAKER_TOKEN {
            return;
        }
        let id = token.0 as ClientId;
        let Some(conn) = conns.get_mut(&id) else {
            return;
        };

        let mut failed = false;

        if !conn.connected {
            if !(event.is_writable() || event.is_error() || event.is_write_closed()) {
                return;
            }
            match conn.stream.take_error() {
                Ok(None) => {}
                Ok(Some(e)) | Err(e) => {
                    error!("[{id}] connect failed: {e}");
                    failed = true;
                }
            }
            if !failed {
                match conn.stream.peer_addr() {
                    Ok(_) => {}
                    Err(e)
                        if e.kind() == io::ErrorKind::NotConnected
                            || e.kind() == io::ErrorKind::WouldBlock =>
                    {
                        return;
                    }
                    Err(e) => {
                        error!("[{id}] connect failed: {e}");
                        failed = true;
                    }
                }
            }
            if !failed {
                let local_addr = conn.stream.local_addr().unwrap_or(self.config.server);
                conn.client.on_connected(local_addr);
                conn.connected = true;
            }
        }

        if !failed {
            read_conn(conn);
            flush_conn(conn);
        }

        if failed {
            if let Some(mut c) = conns.remove(&id) {
                let _ = self.poll.registry().deregister(&mut c.stream);
            }
        } else {
            self.remove_if_dead(conns, id);
        }
    }

    fn remove_if_dead(&self, conns: &mut HashMap<ClientId, Connection>, id: ClientId) {
        let dead = conns
            .get(&id)
            .is_some_and(|c| c.client.state == ClientState::Dead);
        if dead {
            if let Some(mut c) = conns.remove(&id) {
                let _ = self.poll.registry().deregister(&mut c.stream);
            }
        }
    }
}

fn read_conn(conn: &mut Connection) {
    loop {
        if conn.client.state == ClientState::Dead {
            return;
        }
        match conn.stream.read(&mut conn.read_buf) {
            Ok(0) => {
                conn.client.on_eof();
                return;
            }
            Ok(n) => conn.client.on_read(&conn.read_buf[..n]),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                conn.client.on_io_error(e);
                return;
            }
        }
    }
}

fn flush_conn(conn: &mut Connection) {
    if !conn.connected {
        return;
    }
    conn.write_stream.write(conn.client.read_outbox());
    conn.client.clear_outbox();
    loop {
        let buf = conn.write_stream.data();
        if buf.is_empty() {
            return;
        }
        match conn.stream.write(buf) {
            Ok(0) => return,
            Ok(n) => conn.write_stream.mark_read(n),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                conn.client.on_io_error(e);
                return;
            }
        }
    }
}

#[cfg(unix)]
fn is_in_progress(e: &io::Error) -> bool {
    e.raw_os_error() == Some(libc::EINPROGRESS) || e.kind() == io::ErrorKind::WouldBlock
}

#[cfg(not(unix))]
fn is_in_progress(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::WouldBlock
}
