use std::collections::{HashMap, VecDeque};
use std::io::ErrorKind;
use std::sync::Arc;
use std::time::Duration;

use crossbeam_channel::Receiver;
use mio::event::Event;
use mio::{Events, Interest, Poll, Token, Waker};
use quanta::Instant;
use tracing::error;

use crate::capture::reader::ClientId;
use crate::replay::addr_map::AddrMapWriter;
use crate::replay::client::{ClientState, ReplayClient, ReplayConfig};
use crate::replay::stats::ReplayStats;

const WAKE_TOKEN: Token = Token(usize::MAX);

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

pub struct ReplayLoop {
    config: ReplayConfig,
    rx: Receiver<ConnCommand>,
    stats: Arc<ReplayStats>,
    addr_map: AddrMapWriter,

    poll: Poll,
    waker: Arc<Waker>,
    clients: HashMap<ClientId, ReplayClient>,
    start: Instant,
    pending_commands: VecDeque<ConnCommand>,
    rx_closed: bool,
}

impl ReplayLoop {
    pub fn new(
        config: ReplayConfig,
        rx: Receiver<ConnCommand>,
        stats: Arc<ReplayStats>,
        addr_map: AddrMapWriter,
    ) -> std::io::Result<Self> {
        let poll = Poll::new()?;
        let waker = Arc::new(Waker::new(poll.registry(), WAKE_TOKEN)?);
        Ok(Self {
            config,
            rx,
            stats,
            addr_map,
            poll,
            waker,
            clients: HashMap::new(),
            start: Instant::now(),
            pending_commands: VecDeque::new(),
            rx_closed: false,
        })
    }

    pub fn waker(&self) -> Arc<Waker> {
        self.waker.clone()
    }

    fn now_us(&self) -> u64 {
        self.start.elapsed().as_micros() as u64
    }

    pub fn run(&mut self) {
        let mut events = Events::with_capacity(1024);
        loop {
            self.drain_commands();

            let timeout = self.next_timeout();

            if let Err(e) = self.poll.poll(&mut events, timeout) {
                if e.kind() == ErrorKind::Interrupted {
                    continue;
                }
                error!("poll failed: {e}");
                break;
            }

            for event in events.iter() {
                if event.token() == WAKE_TOKEN {
                    continue;
                }
                self.handle_event(event);
            }

            self.drain_commands();
            self.dispatch_ready();

            if self.rx_closed && self.pending_commands.is_empty() && self.clients.is_empty() {
                break;
            }
        }
    }

    fn next_timeout(&self) -> Option<Duration> {
        let ts = self.pending_commands.front()?.ts();
        let now = self.now_us();
        if ts <= now {
            Some(Duration::ZERO)
        } else {
            Some(Duration::from_micros(ts - now))
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
        while let Some(front) = self.pending_commands.front() {
            if front.ts() > now {
                break;
            }
            let cmd = self.pending_commands.pop_front().unwrap();
            self.dispatch_command(cmd);
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
                let client = match self.clients.get_mut(&id) {
                    Some(c) => c,
                    None => {
                        error!("[{id}] send for unknown client");
                        return;
                    }
                };
                client.send_frame(tag, data);
                if flush {
                    client.try_flush();
                    self.update_writable_interest(id);
                }
            }
        }
    }

    fn connect_client(&mut self, id: ClientId) {
        let mut client = match ReplayClient::connect(id, self.config.clone(), self.stats.clone()) {
            Ok(c) => c,
            Err(e) => {
                error!("[ctl] failed to connect client {id}: {e}");
                return;
            }
        };
        if let Err(e) =
            self.poll
                .registry()
                .register(&mut client.stream, client.token, Interest::READABLE)
        {
            error!("[{id}] register failed: {e}");
            return;
        }
        if let Err(e) = self.addr_map.write(id, client.addr) {
            error!("[{id}] failed to write addr: {e}");
        }

        self.clients.insert(id, client);
        self.update_writable_interest(id);
    }

    fn update_writable_interest(&mut self, id: ClientId) {
        let client = match self.clients.get_mut(&id) {
            Some(c) => c,
            None => return,
        };
        let wants_write = client.has_pending_write();
        let interest = if wants_write {
            Interest::READABLE | Interest::WRITABLE
        } else {
            Interest::READABLE
        };
        if let Err(e) = self
            .poll
            .registry()
            .reregister(&mut client.stream, client.token, interest)
        {
            error!("[{id}] reregister failed: {e}");
        }
    }

    fn handle_event(&mut self, event: &Event) {
        let id = event.token().0 as ClientId;
        let client = match self.clients.get_mut(&id) {
            Some(c) => c,
            None => return,
        };

        if event.is_writable() {
            client.try_flush();
        }

        if event.is_readable() {
            client.try_read();
            if client.state == ClientState::Dead {
                let _ = self.poll.registry().deregister(&mut client.stream);
                self.clients.remove(&id);
                return;
            }
        }

        self.update_writable_interest(id);
    }
}
