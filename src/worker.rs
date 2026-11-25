use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::sync::Arc;
use std::time::Duration;

use crossbeam_channel::{Receiver, TryRecvError};
use mio::event::Event;
use mio::{Events, Poll};
use quanta::Instant;
use tracing::error;

use crate::client::{ReplayClient, ReplayConfig};
use crate::readers::capture::{CaptureMessage, ClientEvent, ClientId};
use crate::utils::ReplayStats;

const IDLE_US: u64 = 1_000;
const MAX_QUEUED: usize = 65536;
const READ_BUF: usize = 65536;

#[derive(Default)]
struct Slot {
    queue: VecDeque<CaptureMessage>,
    client: Option<ReplayClient>,
    free_at: Option<u64>,
}

impl Slot {
    fn blocked(&self) -> bool {
        self.client.as_ref().is_some_and(ReplayClient::waiting)
    }

    fn due_at(&self) -> Option<u64> {
        let head = self.queue.front()?;
        if matches!(head.event, ClientEvent::Connect { .. }) {
            return Some(0);
        }
        self.free_at.map(|f| f + head.think_us)
    }
}

pub struct Worker {
    config: Arc<ReplayConfig>,
    stats: Arc<ReplayStats>,
    rx: Receiver<CaptureMessage>,
    poll: Poll,
    start: Instant,
    closed: bool,
    queued: usize,
    slots: HashMap<ClientId, Slot>,
    buf: Vec<u8>,
    ids: Vec<ClientId>,
}

impl Worker {
    pub fn new(
        config: Arc<ReplayConfig>,
        rx: Receiver<CaptureMessage>,
        stats: Arc<ReplayStats>,
    ) -> io::Result<Self> {
        Ok(Self {
            config,
            stats,
            rx,
            poll: Poll::new()?,
            start: Instant::now(),
            closed: false,
            queued: 0,
            slots: HashMap::new(),
            buf: vec![0; READ_BUF],
            ids: Vec::new(),
        })
    }

    fn now(&self) -> u64 {
        self.start.elapsed().as_micros() as u64
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
            if self.closed && self.slots.is_empty() {
                break;
            }
        }
    }

    fn pull(&mut self) {
        while self.queued < MAX_QUEUED {
            match self.rx.try_recv() {
                Ok(m) => self.enqueue(m),
                Err(TryRecvError::Empty) => return,
                Err(TryRecvError::Disconnected) => {
                    self.closed = true;
                    return;
                }
            }
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
        self.queued += 1;
    }

    fn dispatch(&mut self) -> u64 {
        let now = self.now();
        let mut next = IDLE_US;
        let mut ids = std::mem::take(&mut self.ids);
        ids.clear();
        for (&id, slot) in &self.slots {
            if slot.blocked() {
                continue;
            }
            match slot.due_at() {
                Some(t) if t <= now => ids.push(id),
                Some(t) => next = next.min(t - now),
                None => {}
            }
        }
        let sent = !ids.is_empty();
        for &id in &ids {
            self.send_next(id);
        }
        self.ids = ids;
        if sent { 0 } else { next }
    }

    fn send_next(&mut self, id: ClientId) {
        let Some(slot) = self.slots.get_mut(&id) else {
            return;
        };
        let Some(msg) = slot.queue.pop_front() else {
            return;
        };
        slot.free_at = None;
        self.queued -= 1;
        self.execute(msg);
        self.settle(id);
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
                        self.remove(id);
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

    fn settle(&mut self, id: ClientId) {
        let now = self.now();
        if let Some(slot) = self.slots.get_mut(&id) {
            if slot.blocked() {
                slot.free_at = None;
            } else if slot.free_at.is_none() {
                slot.free_at = Some(now);
            }
        }
    }

    fn on_event(&mut self, ev: &Event) {
        let id = ev.token().0 as ClientId;
        if let Some(client) = self.slots.get_mut(&id).and_then(|s| s.client.as_mut()) {
            client.on_event(ev, &mut self.buf);
            self.reap(id);
            self.settle(id);
        }
    }

    fn remove(&mut self, id: ClientId) {
        if let Some(slot) = self.slots.remove(&id) {
            self.queued -= slot.queue.len();
        }
    }

    fn reap(&mut self, id: ClientId) {
        let dead = self
            .slots
            .get(&id)
            .and_then(|s| s.client.as_ref())
            .is_some_and(ReplayClient::is_dead);
        if dead {
            self.remove(id);
        }
    }
}
