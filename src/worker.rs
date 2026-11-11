use std::cmp::Reverse;
use std::collections::hash_map::Entry;
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::io;
use std::sync::Arc;
use std::time::Duration;

use crossbeam_channel::{Receiver, TryRecvError};
use mio::event::Event;
use mio::{Events, Poll};
use quanta::Instant;
use tracing::{error, info};

use crate::capture::{CaptureMessage, ClientEvent, ClientId};
use crate::client::{ReplayClient, ReplayConfig};
use crate::utils::ReplayStats;

const HORIZON_US: u64 = 1_000_000;
const IDLE: Duration = Duration::from_millis(1);
const READ_BUF: usize = 65536;

#[derive(Default)]
struct Slot {
    queue: VecDeque<CaptureMessage>,
    client: Option<ReplayClient>,
    timer: Option<u64>,
}

#[derive(Default)]
struct Lag {
    sum: u64,
    max: u64,
    n: u64,
}

impl Lag {
    fn add(&mut self, v: u64) {
        self.sum += v;
        self.max = self.max.max(v);
        self.n += 1;
    }
}

struct Limiter {
    rate: f64,
    cap: f64,
    tokens: f64,
    last: u64,
}

impl Limiter {
    fn new(rps: f64) -> Self {
        let cap = (rps * 0.01).max(1.0);
        Self {
            rate: rps,
            cap,
            tokens: cap,
            last: 0,
        }
    }

    fn acquire(&mut self, now: u64) -> u64 {
        if self.rate <= 0.0 {
            return 0;
        }
        let gained = now.saturating_sub(self.last) as f64 * self.rate / 1e6;
        self.tokens = (self.tokens + gained).min(self.cap);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            0
        } else {
            ((1.0 - self.tokens) * 1e6 / self.rate).ceil() as u64
        }
    }
}

pub struct Worker {
    idx: usize,
    config: Arc<ReplayConfig>,
    stats: Arc<ReplayStats>,
    rx: Receiver<CaptureMessage>,
    start: Instant,
    poll: Poll,
    pending: Option<CaptureMessage>,
    closed: bool,
    slots: HashMap<ClientId, Slot>,
    timers: BinaryHeap<Reverse<(u64, ClientId)>>,
    limiter: Limiter,
    lag: Lag,
    buf: Vec<u8>,
}

impl Worker {
    pub fn new(
        idx: usize,
        config: Arc<ReplayConfig>,
        rx: Receiver<CaptureMessage>,
        stats: Arc<ReplayStats>,
        start: Instant,
    ) -> io::Result<Self> {
        let rate = config.max_rps as f64 / config.threads as f64;
        Ok(Self {
            idx,
            config,
            stats,
            rx,
            start,
            poll: Poll::new()?,
            pending: None,
            closed: false,
            slots: HashMap::new(),
            timers: BinaryHeap::new(),
            limiter: Limiter::new(rate),
            lag: Lag::default(),
            buf: vec![0; READ_BUF],
        })
    }

    pub fn run(&mut self) {
        let mut events = Events::with_capacity(1024);
        loop {
            self.pull();
            if let Err(e) = self.poll.poll(&mut events, Some(self.timeout())) {
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                error!("poll failed: {e}");
                break;
            }
            for ev in events.iter() {
                self.on_event(ev);
            }
            self.pull();
            self.dispatch_due();
            if self.closed && self.pending.is_none() && self.slots.is_empty() {
                break;
            }
        }
        if self.lag.n > 0 {
            info!(
                "[worker {}] send lag avg={:.3}ms max={:.3}ms",
                self.idx,
                self.lag.sum as f64 / self.lag.n as f64 / 1e3,
                self.lag.max as f64 / 1e3
            );
        }
    }

    fn now(&self) -> u64 {
        self.start.elapsed().as_micros() as u64
    }

    fn timeout(&self) -> Duration {
        let now = self.now();
        self.timers
            .peek()
            .map_or(IDLE, |Reverse((t, _))| {
                Duration::from_micros(t.saturating_sub(now))
            })
            .min(IDLE)
    }

    fn pull(&mut self) {
        loop {
            let msg = match self.pending.take() {
                Some(m) => m,
                None => match self.rx.try_recv() {
                    Ok(m) => m,
                    Err(TryRecvError::Empty) => return,
                    Err(TryRecvError::Disconnected) => {
                        self.closed = true;
                        return;
                    }
                },
            };
            if msg.ts > self.now() + HORIZON_US {
                self.pending = Some(msg);
                return;
            }
            self.enqueue(msg);
        }
    }

    fn enqueue(&mut self, msg: CaptureMessage) {
        let id = msg.id;
        let slot = match self.slots.entry(id) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) if matches!(msg.event, ClientEvent::Connect { .. }) => {
                e.insert(Slot::default())
            }
            Entry::Vacant(_) => return,
        };
        slot.queue.push_back(msg);
        self.drive(id);
    }

    fn dispatch_due(&mut self) {
        let now = self.now();
        while let Some(&Reverse((t, id))) = self.timers.peek() {
            if t > now {
                break;
            }
            self.timers.pop();
            if let Some(slot) = self.slots.get_mut(&id) {
                if slot.timer.is_some_and(|x| x <= t) {
                    slot.timer = None;
                }
            }
            self.drive(id);
        }
    }

    fn drive(&mut self, id: ClientId) {
        let now = self.now();
        loop {
            let Some(slot) = self.slots.get_mut(&id) else {
                return;
            };
            if slot.client.as_ref().is_some_and(ReplayClient::waiting) {
                return;
            }
            let Some(head) = slot.queue.front() else {
                return;
            };
            let at = if head.ts > now {
                head.ts
            } else if matches!(head.event, ClientEvent::Connect { .. }) {
                now
            } else {
                now + self.limiter.acquire(now)
            };
            if at > now {
                if slot.timer.map_or(true, |t| t > at) {
                    slot.timer = Some(at);
                    self.timers.push(Reverse((at, id)));
                }
                return;
            }
            let msg = slot.queue.pop_front().unwrap();
            self.lag.add(now - msg.ts);
            self.execute(msg);
        }
    }

    fn execute(&mut self, msg: CaptureMessage) {
        let id = msg.id;
        match msg.event {
            ClientEvent::Connect { session_id } => {
                let client = ReplayClient::connect(
                    id,
                    self.config.clone(),
                    self.stats.clone(),
                    session_id,
                    self.poll.registry(),
                );
                match client {
                    Ok(c) => {
                        if let Some(slot) = self.slots.get_mut(&id) {
                            slot.client = Some(c);
                        }
                    }
                    Err(e) => {
                        error!("[{id}] connect failed: {e}");
                        self.slots.remove(&id);
                    }
                }
            }
            event => {
                if let Some(c) = self.slots.get_mut(&id).and_then(|s| s.client.as_mut()) {
                    c.replay(event);
                }
                self.reap(id);
            }
        }
    }

    fn on_event(&mut self, ev: &Event) {
        let id = ev.token().0 as ClientId;
        let Some(client) = self.slots.get_mut(&id).and_then(|s| s.client.as_mut()) else {
            return;
        };
        client.on_event(ev, &mut self.buf);
        if !self.reap(id) {
            self.drive(id);
        }
    }

    fn reap(&mut self, id: ClientId) -> bool {
        let dead = self
            .slots
            .get(&id)
            .and_then(|s| s.client.as_ref())
            .is_some_and(ReplayClient::is_dead);
        if dead {
            self.slots.remove(&id);
        }
        dead
    }
}
