use std::cmp::Reverse;
use std::collections::hash_map::Entry;
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::sync::Arc;
use std::time::Duration;

use crossbeam_channel::{Receiver, TryRecvError};
use mio::event::Event;
use mio::net::TcpStream;
use mio::{Events, Interest, Poll, Token};
use quanta::Instant;
use socket2::Socket;
use tracing::{error, info};

use crate::capture::ClientId;
use crate::client::{ClientState, NewConnection, ReplayClient, ReplayConfig};
use crate::proto;
use crate::utils::{ReplayStats, Stream};

const WAKER_TOKEN: Token = Token(usize::MAX);
const HORIZON_US: u64 = 1_000_000;
const IDLE_POLL_US: u64 = 5_000;
const DECAY_RATE: f64 = 1.0;

pub const READ_BUF_SIZE: usize = 65536;

pub enum CmdKind {
    Connect,
    Send { tag: u8, data: Vec<u8> },
    End,
}

pub struct ConnCommand {
    pub id: ClientId,
    pub ts: u64,
    pub kind: CmdKind,
}

impl ConnCommand {
    pub fn connect(id: ClientId, ts: u64) -> Self {
        Self {
            id,
            ts,
            kind: CmdKind::Connect,
        }
    }

    pub fn send(id: ClientId, ts: u64, tag: u8, data: Vec<u8>) -> Self {
        Self {
            id,
            ts,
            kind: CmdKind::Send { tag, data },
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

struct Slot {
    queue: VecDeque<ConnCommand>,
    awaiting: bool,
    rebase: bool,
    burst: bool,
    ready_at: u64,
    conn: Option<Connection>,
}

impl Slot {
    fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            awaiting: false,
            rebase: false,
            burst: false,
            ready_at: 0,
            conn: None,
        }
    }

    fn blocked(&self) -> bool {
        self.conn.is_some() && self.awaiting
    }
}

pub struct ReplayLoop {
    config: ReplayConfig,
    server_addr: socket2::SockAddr,

    rx: Receiver<ConnCommand>,
    stats: Arc<ReplayStats>,

    poll: Poll,
    waker: Arc<mio::Waker>,

    start: Option<Instant>,
    lookahead: Option<ConnCommand>,
    rx_closed: bool,
    ended: bool,
    last_ts: u64,

    slots: HashMap<ClientId, Slot>,
    timers: BinaryHeap<Reverse<(u64, ClientId)>>,

    shift: u64,
    last_tick: u64,

    lag_sum: u64,
    lag_max: u64,
    lag_n: u64,
    shift_max: u64,
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
            start: None,
            lookahead: None,
            rx_closed: false,
            ended: false,
            last_ts: 0,
            slots: HashMap::new(),
            timers: BinaryHeap::new(),
            shift: 0,
            last_tick: 0,
            lag_sum: 0,
            lag_max: 0,
            lag_n: 0,
            shift_max: 0,
        })
    }

    pub fn waker(&self) -> Arc<mio::Waker> {
        self.waker.clone()
    }

    fn now_us(&self) -> u64 {
        self.start.map_or(0, |s| s.elapsed().as_micros() as u64)
    }

    fn decay(&mut self, now: u64) {
        if self.shift == 0 {
            self.last_tick = now;
            return;
        }
        let d = (now.saturating_sub(self.last_tick) as f64 * DECAY_RATE) as u64;
        if d > 0 {
            self.shift = self.shift.saturating_sub(d);
            self.last_tick = now;
        }
    }

    fn next_timeout(&self) -> Option<Duration> {
        let now = self.now_us();
        let mut t = self.timers.peek().map(|Reverse((ts, _))| {
            let wait = (ts + self.shift).saturating_sub(now);
            (wait as f64 / (1.0 + DECAY_RATE)) as u64
        });
        if let Some(c) = &self.lookahead {
            let d = c.ts.saturating_sub(HORIZON_US).saturating_sub(now);
            t = Some(t.map_or(d, |x| x.min(d)));
        }
        if !self.rx_closed {
            t = Some(t.map_or(IDLE_POLL_US, |x| x.min(IDLE_POLL_US)));
        }
        t.map(Duration::from_micros)
    }

    pub fn run(&mut self) {
        let mut events = Events::with_capacity(1024);

        loop {
            self.pull();

            let timeout = self.next_timeout();
            if let Err(e) = self.poll.poll(&mut events, timeout) {
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                error!("poll failed: {e}");
                break;
            }

            for event in events.iter() {
                self.handle_event(event);
            }

            self.pull();
            self.dispatch_ready();

            if self.rx_closed && self.lookahead.is_none() && !self.ended {
                self.finish_clients();
            }
            if self.ended && self.slots.is_empty() {
                break;
            }
        }
        if self.lag_n > 0 {
            info!(
                "send lag avg={:.3}ms max={:.3}ms, max shift={:.3}ms",
                self.lag_sum as f64 / self.lag_n as f64 / 1e3,
                self.lag_max as f64 / 1e3,
                self.shift_max as f64 / 1e3
            );
        }
    }

    fn pull(&mut self) {
        loop {
            let cmd = match self.lookahead.take() {
                Some(c) => c,
                None => match self.rx.try_recv() {
                    Ok(c) => c,
                    Err(TryRecvError::Empty) => return,
                    Err(TryRecvError::Disconnected) => {
                        self.rx_closed = true;
                        return;
                    }
                },
            };
            if self.start.is_none() {
                self.start = Some(Instant::now());
            }
            if cmd.ts > self.now_us() + HORIZON_US {
                self.lookahead = Some(cmd);
                return;
            }
            self.last_ts = cmd.ts;
            self.enqueue(cmd);
        }
    }

    fn enqueue(&mut self, cmd: ConnCommand) {
        let id = cmd.id;
        let slot = match self.slots.entry(id) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => {
                if !matches!(cmd.kind, CmdKind::Connect) {
                    return;
                }
                e.insert(Slot::new())
            }
        };
        slot.queue.push_back(cmd);
        if slot.queue.len() == 1 {
            self.schedule(id);
        }
    }

    fn schedule(&mut self, id: ClientId) {
        if let Some(slot) = self.slots.get(&id) {
            if slot.blocked() {
                return;
            }
            if let Some(head) = slot.queue.front() {
                let key = if slot.burst { 0 } else { head.ts };
                self.timers.push(Reverse((key, id)));
            }
        }
    }

    fn finish_clients(&mut self) {
        self.ended = true;
        let ts = self.last_ts;
        let ids: Vec<ClientId> = self.slots.keys().copied().collect();
        for id in ids {
            if let Some(slot) = self.slots.get_mut(&id) {
                slot.queue.push_back(ConnCommand {
                    id,
                    ts,
                    kind: CmdKind::End,
                });
                let first = slot.queue.len() == 1;
                if first {
                    self.schedule(id);
                }
            }
        }
    }

    fn dispatch_ready(&mut self) {
        let now = self.now_us();
        self.decay(now);
        while let Some(&Reverse((ts, id))) = self.timers.peek() {
            if ts + self.shift > now {
                break;
            }
            self.timers.pop();
            self.try_dispatch(id, now);
        }
    }

    fn try_dispatch(&mut self, id: ClientId, now: u64) {
        loop {
            let Some(slot) = self.slots.get_mut(&id) else {
                return;
            };
            if slot.blocked() {
                return;
            }
            let Some(head) = slot.queue.front() else {
                return;
            };
            let ts = head.ts;
            let burst = slot.burst;
            if slot.rebase && !burst {
                slot.rebase = false;
                let need = slot.ready_at.saturating_sub(ts);
                if need > self.shift {
                    self.shift = need;
                    self.shift_max = self.shift_max.max(need);
                }
            }
            let at = if burst { now } else { ts + self.shift };
            if at > now {
                self.timers.push(Reverse((ts, id)));
                return;
            }
            let cmd = slot.queue.pop_front().unwrap();
            if !burst {
                let lag = now - at;
                self.lag_sum += lag;
                self.lag_n += 1;
                self.lag_max = self.lag_max.max(lag);
            }
            self.execute(id, cmd);
        }
    }

    fn execute(&mut self, id: ClientId, cmd: ConnCommand) {
        match cmd.kind {
            CmdKind::Connect => self.connect_client(id),
            CmdKind::Send { tag, data } => {
                if let Some(slot) = self.slots.get_mut(&id) {
                    if let Some(conn) = slot.conn.as_mut() {
                        conn.client.replay_frame(tag, &data);
                        flush_conn(conn);
                        let blocking = tag == proto::F_QUERY || tag == proto::F_SYNC;
                        if blocking {
                            slot.awaiting = true;
                        }
                        slot.burst = !blocking;
                    }
                }
                self.remove_if_dead(id);
            }
            CmdKind::End => {
                if let Some(conn) = self.slots.get_mut(&id).and_then(|s| s.conn.as_mut()) {
                    conn.client.on_replay_end();
                    flush_conn(conn);
                }
                self.remove_if_dead(id);
            }
        }
    }

    fn connect_client(&mut self, id: ClientId) {
        match self.open(id) {
            Ok(conn) => {
                if let Some(slot) = self.slots.get_mut(&id) {
                    slot.conn = Some(conn);
                    slot.awaiting = true;
                }
            }
            Err(e) => {
                error!("[{id}] connect failed: {e}");
                self.drop_slot(id);
            }
        }
    }

    fn open(&mut self, id: ClientId) -> io::Result<Connection> {
        let NewConnection { client, socket } =
            ReplayClient::connect(id, self.config.clone(), self.stats.clone())?;
        let mut stream = self.start_connect(socket)?;
        self.poll.registry().register(
            &mut stream,
            Token(id as usize),
            Interest::READABLE | Interest::WRITABLE,
        )?;
        Ok(Connection {
            stream,
            client,
            read_buf: vec![0; READ_BUF_SIZE],
            write_stream: Stream::new(READ_BUF_SIZE),
            connected: false,
        })
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

    fn handle_event(&mut self, event: &Event) {
        let token = event.token();
        if token == WAKER_TOKEN {
            return;
        }
        let id = token.0 as ClientId;
        let now = self.now_us();
        self.decay(now);
        let fallback = self.config.server;
        let Some(slot) = self.slots.get_mut(&id) else {
            return;
        };
        let Some(conn) = slot.conn.as_mut() else {
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
                let local_addr = conn.stream.local_addr().unwrap_or(fallback);
                conn.client.on_connected(local_addr);
                conn.connected = true;
            }
        }

        if !failed {
            read_conn(conn);
            flush_conn(conn);
            if conn.client.rfq {
                conn.client.rfq = false;
                slot.awaiting = false;
                slot.rebase = true;
                slot.ready_at = now;
            }
        }

        if failed {
            self.drop_slot(id);
        } else if !self.remove_if_dead(id) {
            self.try_dispatch(id, now);
        }
    }

    fn drop_slot(&mut self, id: ClientId) {
        if let Some(mut slot) = self.slots.remove(&id) {
            if let Some(mut c) = slot.conn.take() {
                let _ = self.poll.registry().deregister(&mut c.stream);
            }
        }
    }

    fn remove_if_dead(&mut self, id: ClientId) -> bool {
        let dead = self
            .slots
            .get(&id)
            .and_then(|s| s.conn.as_ref())
            .is_some_and(|c| c.client.state == ClientState::Dead);
        if dead {
            self.drop_slot(id);
        }
        dead
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
