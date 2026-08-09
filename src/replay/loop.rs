use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;

use crossbeam_channel::Receiver;
use io_uring::{IoUring, opcode, types};
use quanta::Instant;
use socket2::Socket;
use tracing::error;

use crate::capture::reader::ClientId;
use crate::replay::addr_map::AddrMapWriter;
use crate::replay::client::{ClientState, NewConnection, ReplayClient, ReplayConfig};
use crate::replay::stats::ReplayStats;
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
}

impl ConnCommand {
    fn ts(&self) -> u64 {
        match self {
            ConnCommand::Connect { ts, .. } => *ts,
            ConnCommand::Send { ts, .. } => *ts,
        }
    }
}

struct Connection {
    socket: Socket,
    client: ReplayClient,
    read_buf: Vec<u8>,
    read_in_flight: bool,
    write_in_flight: Option<Vec<u8>>,
}

pub struct ReplayLoop {
    config: ReplayConfig,
    rx: Receiver<ConnCommand>,
    stats: Arc<ReplayStats>,
    addr_map: AddrMapWriter,

    ring: IoUring,
    waker: Arc<Waker>,
    wake_buf: [u8; 8],

    connections: HashMap<ClientId, Connection>,
    start: Instant,
    pending_commands: VecDeque<ConnCommand>,
    rx_closed: bool,
    timeout_ts: types::Timespec,
    timer_armed: bool,

    pending_reads: VecDeque<ClientId>,
    pending_writes: VecDeque<ClientId>,
}

impl ReplayLoop {
    pub fn new(
        config: ReplayConfig,
        rx: Receiver<ConnCommand>,
        stats: Arc<ReplayStats>,
        addr_map: AddrMapWriter,
    ) -> io::Result<Self> {
        let ring = IoUring::new(1024)?;
        let waker = Arc::new(Waker::new()?);

        Ok(Self {
            config,
            rx,
            stats,
            addr_map,
            ring,
            waker,
            wake_buf: [0u8; 8],
            connections: HashMap::new(),
            start: Instant::now(),
            pending_commands: VecDeque::new(),
            rx_closed: false,
            timeout_ts: types::Timespec::new(),
            timer_armed: false,
            pending_reads: VecDeque::new(),
            pending_writes: VecDeque::new(),
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

            self.check_cq_overflow();
            self.process_completions();
            self.retry_pending_io();

            self.drain_commands();
            self.dispatch_ready();
            self.retry_pending_io();

            if self.rx_closed
                && self.pending_commands.is_empty()
                && self.connections.is_empty()
                && self.pending_reads.is_empty()
                && self.pending_writes.is_empty()
            {
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

    fn retry_pending_io(&mut self) {
        if !self.pending_reads.is_empty() {
            self.flush_submissions();
            let retry: Vec<ClientId> = self.pending_reads.drain(..).collect();
            for id in retry {
                self.submit_read(id);
            }
        }
        if !self.pending_writes.is_empty() {
            self.flush_submissions();
            let retry: Vec<ClientId> = self.pending_writes.drain(..).collect();
            for id in retry {
                self.submit_write(id);
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

    fn dispatch_ready(&mut self) {
        let now = self.now_us();
        let mut count: u32 = 0;
        while let Some(front) = self.pending_commands.front() {
            if front.ts() > now {
                break;
            }
            let cmd = self.pending_commands.pop_front().unwrap();
            self.dispatch_command(cmd);
            count += 1;

            if count % 256 == 0 {
                self.flush_submissions();
                self.retry_pending_io();
            }
        }
    }

    fn dispatch_command(&mut self, command: ConnCommand) {
        match command {
            ConnCommand::Connect { id, .. } => {
                self.connect_client(id);
            }
            ConnCommand::Send {
                id,
                tag,
                data,
                flush,
                ..
            } => {
                if let Some(conn) = self.connections.get_mut(&id) {
                    conn.client.send_frame(tag, data);
                    if flush {
                        self.submit_write(id);
                    }
                }
            }
        }
    }

    fn connect_client(&mut self, id: ClientId) {
        let NewConnection { client, socket } =
            match ReplayClient::connect(id, self.config.clone(), self.stats.clone()) {
                Ok(c) => c,
                Err(e) => {
                    error!("[ctl] failed to connect client {id}: {e}");
                    return;
                }
            };

        let fd = socket.as_raw_fd();
        let server_addr = self.config.server;
        let (sockaddr, sockaddr_len) = socket2_addr(server_addr);

        let conn = Connection {
            socket,
            client,
            read_buf: vec![0u8; READ_BUF_SIZE],
            read_in_flight: false,
            write_in_flight: None,
        };
        self.connections.insert(id, conn);

        let boxed = Box::new(sockaddr);
        let addr_ptr = Box::into_raw(boxed);

        let entry = opcode::Connect::new(types::Fd(fd), addr_ptr as *const _, sockaddr_len)
            .build()
            .user_data(make_ud(KIND_CONNECT, id));

        let pushed = unsafe { self.ring.submission().push(&entry) };
        if pushed.is_err() {
            self.flush_submissions();
            let retried = unsafe { self.ring.submission().push(&entry) };
            if retried.is_err() {
                error!("[{id}] failed to submit connect even after flush");
                unsafe { drop(Box::from_raw(addr_ptr)) };
                self.connections.remove(&id);
            }
        }
    }

    fn submit_read(&mut self, id: ClientId) {
        let conn = match self.connections.get_mut(&id) {
            Some(c) => c,
            None => return,
        };
        if conn.read_in_flight || conn.client.state == ClientState::Dead {
            return;
        }
        let fd = conn.socket.as_raw_fd();
        let ptr = conn.read_buf.as_mut_ptr();

        let entry = opcode::Read::new(types::Fd(fd), ptr, READ_BUF_SIZE as u32)
            .build()
            .user_data(make_ud(KIND_READ, id));
        unsafe {
            if self.ring.submission().push(&entry).is_err() {
                self.pending_reads.push_back(id);
                return;
            }
        }
        conn.read_in_flight = true;
    }

    fn submit_write(&mut self, id: ClientId) {
        let conn = match self.connections.get_mut(&id) {
            Some(c) => c,
            None => return,
        };
        if conn.write_in_flight.is_some() || !conn.client.has_pending_write() {
            return;
        }
        let buf = conn.client.take_outbox();
        if buf.is_empty() {
            return;
        }
        let fd = conn.socket.as_raw_fd();
        let ptr = buf.as_ptr();
        let len = buf.len() as u32;

        let entry = opcode::Write::new(types::Fd(fd), ptr, len)
            .build()
            .user_data(make_ud(KIND_WRITE, id));
        unsafe {
            if self.ring.submission().push(&entry).is_err() {
                conn.client.requeue_unwritten(buf);
                self.pending_writes.push_back(id);
                return;
            }
        }
        conn.write_in_flight = Some(buf);
    }

    fn process_completions(&mut self) {
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
                _ => self.handle_conn_completion(ud, result),
            }
        }
    }

    fn handle_conn_completion(&mut self, ud: u64, result: i32) {
        let id = ud_id(ud);
        match ud_kind(ud) {
            KIND_CONNECT => self.handle_connect_completion(id, result),
            KIND_READ => self.handle_read_completion(id, result),
            KIND_WRITE => self.handle_write_completion(id, result),
            _ => {}
        }
    }

    fn handle_connect_completion(&mut self, id: ClientId, result: i32) {
        let conn = match self.connections.get_mut(&id) {
            Some(c) => c,
            None => return,
        };
        if result < 0 {
            let e = io::Error::from_raw_os_error(-result);
            error!("[{id}] connect failed: {e}");
            self.connections.remove(&id);
            return;
        }

        let local_addr = conn
            .socket
            .local_addr()
            .ok()
            .and_then(|a| a.as_socket())
            .unwrap_or(self.config.server);
        conn.client.on_connected(local_addr);

        if let Err(e) = self.addr_map.write(id, local_addr) {
            error!("[{id}] failed to write addr: {e}");
        }

        self.submit_read(id);
        self.submit_write(id);
    }

    fn handle_read_completion(&mut self, id: ClientId, result: i32) {
        let conn = match self.connections.get_mut(&id) {
            Some(c) => c,
            None => return,
        };
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
            self.connections.remove(&id);
            return;
        }
        self.submit_read(id);
        self.submit_write(id);
    }

    fn handle_write_completion(&mut self, id: ClientId, result: i32) {
        let conn = match self.connections.get_mut(&id) {
            Some(c) => c,
            None => return,
        };
        let sent = conn.write_in_flight.take().unwrap_or_default();
        conn.write_in_flight = None;

        if result < 0 {
            let e = io::Error::from_raw_os_error(-result);
            conn.client.on_io_error(e);
        } else {
            let n = result as usize;
            if n < sent.len() {
                conn.client.requeue_unwritten(sent[n..].to_vec());
            }
        }

        if conn.client.state == ClientState::Dead {
            self.connections.remove(&id);
            return;
        }

        self.submit_write(id);
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

fn socket2_addr(addr: SocketAddr) -> (socket2::SockAddr, u32) {
    let sockaddr = socket2::SockAddr::from(addr);
    let len = sockaddr.len();
    (sockaddr, len)
}
