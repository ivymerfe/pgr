use std::collections::{HashMap, VecDeque};
use std::io;
use std::os::fd::AsRawFd;
use std::sync::Arc;

use crossbeam_channel::Receiver;
use io_uring::{IoUring, opcode, types};
use quanta::Instant;
use socket2::Socket;
use tracing::error;

use crate::capture::reader::ClientId;
use crate::replay::client::{ClientState, NewConnection, ReplayClient, ReplayConfig};
use crate::replay::stats::ReplayStats;
use crate::utils::stream::Stream;
use crate::utils::waker::Waker;

const OP_WAKE: u64 = u64::MAX;
const OP_TIMEOUT: u64 = u64::MAX - 1;

const KIND_CONNECT: u64 = 1 << 32;
const KIND_READ: u64 = 2 << 32;
const KIND_WRITE: u64 = 3 << 32;
const KIND_MASK: u64 = 0xFFFF_FFFF_0000_0000;

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
        flush: bool,
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
    id: ClientId,
    socket: Socket,
    client: ReplayClient,
    read_buf: Vec<u8>,
    read_in_flight: bool,
    read_pending: bool,
    write_stream: Stream,
    write_in_flight: bool,
    write_pending: bool,
}

pub struct ReplayLoop {
    config: ReplayConfig,
    server_addr: socket2::SockAddr,

    rx: Receiver<ConnCommand>,
    stats: Arc<ReplayStats>,

    ring: IoUring,
    waker: Arc<Waker>,
    wake_buf: [u8; 8],

    start: Instant,
    started: bool,
    pending_commands: VecDeque<ConnCommand>,
    rx_closed: bool,
    timeout_ts: types::Timespec,
    timer_armed: bool,
}

impl ReplayLoop {
    pub fn new(
        config: ReplayConfig,
        rx: Receiver<ConnCommand>,
        stats: Arc<ReplayStats>,
    ) -> io::Result<Self> {
        let ring = IoUring::new(config.ring_size)?;
        let waker = Arc::new(Waker::new()?);

        let server_addr = socket2::SockAddr::from(config.server);

        Ok(Self {
            config,
            server_addr,
            rx,
            stats,
            ring,
            waker,
            wake_buf: [0u8; 8],
            start: Instant::now(),
            started: false,
            pending_commands: VecDeque::new(),
            rx_closed: false,
            timeout_ts: types::Timespec::new(),
            timer_armed: false,
        })
    }

    pub fn waker(&self) -> Arc<Waker> {
        self.waker.clone()
    }

    fn now_us(&self) -> u64 {
        self.start.elapsed().as_micros() as u64
    }

    pub fn run(&mut self) {
        self.submit_wake_read();

        let mut connections = HashMap::new();
        loop {
            self.drain_commands();

            self.arm_timeout();

            if let Err(e) = self.ring.submit_and_wait(1) {
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                error!("io_uring submit_and_wait failed: {e}");
                break;
            }
            if !self.started {
                self.start = Instant::now();
                self.started = true;
            }

            self.check_cq_overflow();
            self.process_completions(&mut connections);
            self.retry_pending_io(&mut connections);

            self.drain_commands();
            self.dispatch_ready(&mut connections);
            self.retry_pending_io(&mut connections);

            if self.rx_closed && self.pending_commands.is_empty() && connections.is_empty() {
                break;
            }
        }
    }

    fn check_cq_overflow(&mut self) {
        if self.ring.completion().overflow() > 0 {
            error!(
                "io_uring CQ overflow detected, {} events dropped by kernel",
                self.ring.completion().overflow()
            );
        }
    }

    fn flush_submissions(&mut self) {
        if let Err(e) = self.ring.submit() {
            error!("submit failed while flushing SQ: {e}");
        }
    }

    fn retry_pending_io(&mut self, conns: &mut HashMap<ClientId, Connection>) {
        for conn in conns.values_mut() {
            if conn.read_pending {
                self.submit_read(conn);
            }
            if conn.write_pending {
                self.submit_write(conn);
            }
        }
    }

    fn submit_wake_read(&mut self) {
        let entry = opcode::Read::new(
            types::Fd(self.waker.fd()),
            self.wake_buf.as_mut_ptr(),
            self.wake_buf.len() as u32,
        )
        .build()
        .user_data(OP_WAKE);
        unsafe {
            if self.ring.submission().push(&entry).is_err() {
                self.flush_submissions();
                if self.ring.submission().push(&entry).is_err() {
                    error!("failed to queue waker read even after flush");
                }
            }
        }
    }

    fn arm_timeout(&mut self) {
        if self.timer_armed {
            let cancel = opcode::AsyncCancel::new(OP_TIMEOUT).build();
            unsafe {
                let _ = self.ring.submission().push(&cancel);
            }
            self.timer_armed = false;
        }

        let Some(ts) = self.pending_commands.front().map(|c| c.ts()) else {
            return;
        };
        let now = self.now_us();
        let delta_us = ts.saturating_sub(now);

        self.timeout_ts = types::Timespec::new()
            .sec(delta_us / 1_000_000)
            .nsec(((delta_us % 1_000_000) * 1000) as u32);

        let entry = opcode::Timeout::new(&self.timeout_ts as *const _)
            .build()
            .user_data(OP_TIMEOUT);
        unsafe {
            if self.ring.submission().push(&entry).is_err() {
                error!("failed to queue timeout");
            } else {
                self.timer_armed = true;
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
        let mut count: u32 = 0;
        while let Some(front) = self.pending_commands.front() {
            if front.ts() > now {
                break;
            }
            let cmd = self.pending_commands.pop_front().unwrap();
            self.dispatch_command(conns, cmd);
            count += 1;

            if count % 256 == 0 {
                self.flush_submissions();
            }
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
            ConnCommand::Send {
                id,
                tag,
                data,
                flush,
                ..
            } => {
                if let Some(conn) = conns.get_mut(&id) {
                    conn.client.replay_frame(tag, &data);
                    if flush {
                        self.submit_write(conn);
                    }
                }
            }
            ConnCommand::Terminate { .. } => {
                for conn in conns.values_mut() {
                    conn.client.on_replay_end();
                    self.submit_write(conn);
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

        let fd = socket.as_raw_fd();
        let entry = opcode::Connect::new(
            types::Fd(fd),
            self.server_addr.as_ptr() as *const _,
            self.server_addr.len(),
        )
        .build()
        .user_data(make_ud(KIND_CONNECT, id));

        let pushed = unsafe { self.ring.submission().push(&entry) };
        if pushed.is_err() {
            self.flush_submissions();
            let retried = unsafe { self.ring.submission().push(&entry) };
            if retried.is_err() {
                error!("[{id}] failed to submit connect even after flush");
                return;
            }
        }
        let conn = Connection {
            id,
            socket,
            client,
            read_buf: vec![0; READ_BUF_SIZE],
            read_in_flight: false,
            read_pending: false,
            write_stream: Stream::new(READ_BUF_SIZE),
            write_in_flight: false,
            write_pending: false,
        };
        conns.insert(id, conn);
    }

    fn submit_read(&mut self, conn: &mut Connection) {
        if conn.read_in_flight || conn.client.state == ClientState::Dead {
            return;
        }
        let fd = conn.socket.as_raw_fd();
        let ptr = conn.read_buf.as_mut_ptr();

        let entry = opcode::Read::new(types::Fd(fd), ptr, READ_BUF_SIZE as u32)
            .build()
            .user_data(make_ud(KIND_READ, conn.id));
        unsafe {
            if self.ring.submission().push(&entry).is_err() {
                conn.read_pending = true;
                return;
            }
        }
        conn.read_in_flight = true;
        conn.read_pending = false;
    }

    fn submit_write(&mut self, conn: &mut Connection) {
        if conn.write_in_flight {
            return;
        }
        conn.write_stream.write(conn.client.read_outbox());
        conn.client.clear_outbox();
        let buf = &conn.write_stream.data();
        if buf.is_empty() {
            return;
        }
        let fd = conn.socket.as_raw_fd();
        let ptr = buf.as_ptr();
        let len = buf.len() as u32;

        let entry = opcode::Write::new(types::Fd(fd), ptr, len)
            .build()
            .user_data(make_ud(KIND_WRITE, conn.id));
        unsafe {
            if self.ring.submission().push(&entry).is_err() {
                conn.write_pending = true;
                return;
            }
        }
        conn.write_in_flight = true;
        conn.write_pending = false;
    }

    fn process_completions(&mut self, conns: &mut HashMap<ClientId, Connection>) {
        let cqes: Vec<(u64, i32)> = self
            .ring
            .completion()
            .map(|cqe| (cqe.user_data(), cqe.result()))
            .collect();

        for (ud, result) in cqes {
            match ud {
                OP_WAKE => {
                    self.submit_wake_read();
                }
                OP_TIMEOUT => {
                    self.timer_armed = false;
                }
                _ => self.handle_conn_completion(conns, ud, result),
            }
        }
    }

    fn handle_conn_completion(
        &mut self,
        conns: &mut HashMap<ClientId, Connection>,
        ud: u64,
        result: i32,
    ) {
        let id = ud_id(ud);
        let conn = match conns.get_mut(&id) {
            Some(conn) => conn,
            None => return,
        };

        let success = match ud_kind(ud) {
            KIND_CONNECT => self.handle_connect_completion(conn, result),
            KIND_READ => self.handle_read_completion(conn, result),
            KIND_WRITE => self.handle_write_completion(conn, result),
            _ => true,
        };
        if !success {
            conns.remove(&id);
        }
    }

    fn handle_connect_completion(&mut self, conn: &mut Connection, result: i32) -> bool {
        let id = conn.id;
        if result < 0 {
            let e = io::Error::from_raw_os_error(-result);
            error!("[{id}] connect failed: {e}");
            return false;
        }

        let local_addr = conn
            .socket
            .local_addr()
            .ok()
            .and_then(|a| a.as_socket())
            .unwrap_or(self.config.server);
        conn.client.on_connected(local_addr);

        self.submit_read(conn);
        self.submit_write(conn);
        return true;
    }

    fn handle_read_completion(&mut self, conn: &mut Connection, result: i32) -> bool {
        conn.read_in_flight = false;

        if result < 0 {
            let e = io::Error::from_raw_os_error(-result);
            conn.client.on_io_error(e);
        } else if result == 0 {
            conn.client.on_eof();
        } else {
            let n = result as usize;
            conn.client.on_read(&conn.read_buf[..n]);
        }
        if conn.client.state == ClientState::Dead {
            return false;
        }
        self.submit_read(conn);
        self.submit_write(conn);
        return true;
    }

    fn handle_write_completion(&mut self, conn: &mut Connection, result: i32) -> bool {
        conn.write_in_flight = false;

        if result < 0 {
            let e = io::Error::from_raw_os_error(-result);
            conn.client.on_io_error(e);
        } else {
            let n = result as usize;
            conn.write_stream.mark_read(n);
        }

        if conn.client.state == ClientState::Dead {
            return false;
        }
        self.submit_write(conn);
        return true;
    }
}

fn make_ud(kind: u64, id: ClientId) -> u64 {
    kind | (id as u64 & 0xFFFF_FFFF)
}

fn ud_kind(ud: u64) -> u64 {
    ud & KIND_MASK
}

fn ud_id(ud: u64) -> ClientId {
    (ud & 0xFFFF_FFFF) as ClientId
}
