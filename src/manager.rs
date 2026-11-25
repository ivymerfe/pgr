use std::collections::HashMap;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use crate::worker::Worker;
use crossbeam_channel::{Sender, bounded};
use tracing::{error, info};

use crate::client::ReplayConfig;
use crate::readers::capture::{
    CaptureMessage, CaptureReader, ClientEvent, ClientId, MSG_DISCONNECT,
};
use crate::utils::ReplayStats;

const QUEUE_CAP: usize = 16384;

struct Router {
    txs: Vec<Sender<CaptureMessage>>,
    load: Vec<usize>,
    owner: HashMap<ClientId, usize>,
}

impl Router {
    fn route(&mut self, msg: CaptureMessage) -> bool {
        let idx = match msg.event {
            ClientEvent::Connect { .. } => {
                let idx = (0..self.txs.len()).min_by_key(|&i| self.load[i]).unwrap();
                self.owner.insert(msg.id, idx);
                self.load[idx] += 1;
                idx
            }
            ClientEvent::Disconnect => match self.owner.remove(&msg.id) {
                Some(idx) => {
                    self.load[idx] -= 1;
                    idx
                }
                None => return true,
            },
            _ => match self.owner.get(&msg.id) {
                Some(&idx) => idx,
                None => return true,
            },
        };
        self.txs[idx].send(msg).is_ok()
    }

    fn finish(self) {
        for (id, idx) in self.owner {
            let _ = self.txs[idx].send(CaptureMessage {
                id,
                ts: 0,
                duration_us: 0,
                think_us: 0,
                event_type: MSG_DISCONNECT,
                event: ClientEvent::Disconnect,
            });
        }
    }
}

fn spawn_reporter(stats: Arc<ReplayStats>) {
    std::thread::spawn(move || {
        loop {
            sleep(Duration::from_secs(1));
            info!(
                "Total sent: {} Delta sent: {} Delta recv: {}",
                stats.read_total_sent(),
                stats.read_delta_sent(),
                stats.read_delta_recv()
            );
        }
    });
}

pub fn replay(config: ReplayConfig, mut reader: CaptureReader) -> anyhow::Result<()> {
    let config = Arc::new(config);
    let stats = Arc::new(ReplayStats::new());
    spawn_reporter(stats.clone());

    let mut txs = Vec::new();
    let mut handles = Vec::new();
    for _ in 0..config.threads {
        let (tx, rx) = bounded::<CaptureMessage>(QUEUE_CAP);
        let mut worker = Worker::new(config.clone(), rx, stats.clone())?;
        handles.push(std::thread::spawn(move || worker.run()));
        txs.push(tx);
    }

    let mut router = Router {
        load: vec![0; txs.len()],
        txs,
        owner: HashMap::new(),
    };

    let speed = config.speed.max(0.01);
    let lat_us = config.latency.max(0.0) as u64 * 1000;
    let mut ends: HashMap<ClientId, u64> = HashMap::new();

    let mut total_think = 0u64;
    let mut total_dur = 0u64;
    loop {
        match reader.read_event() {
            Ok(Some(mut msg)) => {
                if matches!(msg.event, ClientEvent::Lsn { .. }) {
                    continue;
                }
                let prev = ends.get(&msg.id).copied().unwrap_or(msg.ts);
                msg.think_us = (msg.ts.saturating_sub(prev) as f64 / speed) as u64;
                msg.think_us = msg.think_us.saturating_sub(lat_us);
                total_think += msg.think_us;
                total_dur += msg.duration_us as u64;
                if matches!(msg.event, ClientEvent::Disconnect) {
                    ends.remove(&msg.id);
                } else {
                    ends.insert(msg.id, msg.ts.saturating_add(msg.duration_us as u64));
                }
                if !router.route(msg) {
                    error!("worker thread gone");
                    break;
                }
            }
            Ok(None) => break,
            Err(e) => {
                error!("Failed to read capture: {e}");
                break;
            }
        }
    }
    router.finish();
    info!("think={}ms duration={}ms", total_think / 1000, total_dur / 1000);
    info!("Finished reading");

    for h in handles {
        if h.join().is_err() {
            error!("worker panicked");
        }
    }
    Ok(())
}
