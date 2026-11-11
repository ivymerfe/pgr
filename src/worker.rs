use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
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
const IDLE_US: u64 = 1_000;
const LEAD_EMA_DIV: i64 = 16;
const MAX_LEAD_US: u64 = 1_000_000;
const READ_BUF: usize = 65536;

pub struct Clock {
    start: Instant,
    lead: AtomicU64,
}

impl Clock {
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
            lead: AtomicU64::new(0),
        }
    }

    fn now(&self) -> u64 {
        self.start.elapsed().as_micros() as u64
    }

    fn lead(&self) -> u64 {
        self.lead.load(Relaxed)
    }

    fn virt(&self) -> u64 {
        self.now() + self.lead()
    }

    fn adjust(&self, late: u64) {
        let _ = self.lead.fetch_update(Relaxed, Relaxed, |l| {
            let l = l as i64;
            let next = l + (late as i64 - l) / LEAD_EMA_DIV;
            Some((next.max(0) as u64).min(MAX_LEAD_US))
        });
    }
}

#[derive(Default)]
struct Slot {
    queue: VecDeque<CaptureMessage>,
    client: Option<ReplayClient>,
}

impl Slot {
    fn blocked(&self) -> bool {
        self.client.as_ref().is_some_and(ReplayClient::waiting)
    }

    fn head_ts(&self) -> Option<u64> {
        self.queue.front().map(|m| m.ts)
    }
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
    clock: Arc<Clock>,
    poll: Poll,
    pending: Option<CaptureMessage>,
    closed: bool,
    slots: HashMap<ClientId, Slot>,
    limiter: Limiter,
    lag: Lag,
    buf: Vec<u8>,
    due: Vec<(u64, ClientId)>,
}

impl Worker {
    pub fn new(
        idx: usize,
        config: Arc<ReplayConfig>,
        rx: Receiver<CaptureMessage>,
        stats: Arc<ReplayStats>,
        clock: Arc<Clock>,
    ) -> io::Result<Self> {
        let rate = config.max_rps as f64 / config.threads as f64;
        Ok(Self {
            idx,
            config,
            stats,
            rx,
            clock,
            poll: Poll::new()?,
            pending: None,
            closed: false,
            slots: HashMap::new(),
            limiter: Limiter::new(rate),
            lag: Lag::default(),
            buf: vec![0; READ_BUF],
            due: Vec::new(),
        })
    }

    pub fn run(&mut self) {
        let mut events = Events::with_capacity(1024);
        let mut timeout = IDLE_US;
        loop {
            if let Err(e) = self
                .poll
                .poll(&mut events, Some(Duration::from_micros(timeout)))
            {
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
            timeout = self.dispatch();
            if self.closed && self.pending.is_none() && self.slots.is_empty() {
                break;
            }
        }
        if self.lag.n > 0 {
            let k = self.config.speed / 1e3;
            info!(
                "[worker {}] lag avg={:.3}ms max={:.3}ms lead={:.3}ms",
                self.idx,
                self.lag.sum as f64 / self.lag.n as f64 * k,
                self.lag.max as f64 * k,
                self.clock.lead() as f64 * k
            );
        }
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
            if msg.ts > self.clock.virt() + HORIZON_US {
                self.pending = Some(msg);
                return;
            }
            self.enqueue(msg);
        }
    }

    fn enqueue(&mut self, msg: CaptureMessage) {
        let slot = match self.slots.entry(msg.id) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) if matches!(msg.event, ClientEvent::Connect { .. }) => {
                e.insert(Slot::default())
            }
            Entry::Vacant(_) => return,
        };
        slot.queue.push_back(msg);
    }

    fn dispatch(&mut self) -> u64 {
        loop {
            let v = self.clock.virt();
            let mut next = IDLE_US;
            let mut due = std::mem::take(&mut self.due);
            due.clear();
            for (&id, slot) in &self.slots {
                if slot.blocked() {
                    continue;
                }
                match slot.head_ts() {
                    Some(ts) if ts <= v => due.push((ts, id)),
                    Some(ts) => next = next.min(ts - v),
                    None => {}
                }
            }
            if due.is_empty() {
                self.due = due;
                return next;
            }
            due.sort_unstable();
            let mut throttled = None;
            for &(_, id) in &due {
                if let Some(wait) = self.send_next(id) {
                    throttled = Some(wait);
                    break;
                }
            }
            self.due = due;
            if let Some(wait) = throttled {
                return wait.max(1);
            }
        }
    }

    fn send_next(&mut self, id: ClientId) -> Option<u64> {
        let now = self.clock.now();
        let head = self.slots.get(&id)?.queue.front()?;
        if !matches!(head.event, ClientEvent::Connect { .. }) {
            let wait = self.limiter.acquire(now);
            if wait > 0 {
                return Some(wait);
            }
        }
        let msg = self.slots.get_mut(&id)?.queue.pop_front()?;
        self.clock.adjust(now.saturating_sub(msg.ts));
        self.lag.add(now.saturating_sub(msg.ts));
        self.execute(msg);
        None
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
        if let Some(client) = self.slots.get_mut(&id).and_then(|s| s.client.as_mut()) {
            client.on_event(ev, &mut self.buf);
            self.reap(id);
        }
    }

    fn reap(&mut self, id: ClientId) {
        let dead = self
            .slots
            .get(&id)
            .and_then(|s| s.client.as_ref())
            .is_some_and(ReplayClient::is_dead);
        if dead {
            self.slots.remove(&id);
        }
    }
}
