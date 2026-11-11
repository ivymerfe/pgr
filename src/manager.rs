use std::collections::HashMap;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use crossbeam_channel::{Sender, bounded};
use quanta::Instant;
use tracing::{error, info};

use crate::capture::{CaptureMessage, CaptureReader, ClientEvent, ClientId};
use crate::client::ReplayConfig;
use crate::utils::ReplayStats;
use crate::worker::Worker;

const QUEUE_CAP: usize = 16384;

struct Router {
    txs: Vec<Sender<CaptureMessage>>,
    load: Vec<usize>,
    owner: HashMap<ClientId, usize>,
    max_conns: usize,
    skipped: u64,
}

impl Router {
    fn route(&mut self, msg: CaptureMessage) -> bool {
        let idx = match msg.event {
            ClientEvent::Connect { .. } => {
                if self.max_conns > 0 && self.owner.len() >= self.max_conns {
                    self.skipped += 1;
                    return true;
                }
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

    fn finish(self, ts: u64) {
        if self.skipped > 0 {
            info!("skipped {} clients over the connection limit", self.skipped);
        }
        for (id, idx) in self.owner {
            let event = ClientEvent::Disconnect;
            let _ = self.txs[idx].send(CaptureMessage { id, ts, event });
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

    let start = Instant::now();
    let mut txs = Vec::new();
    let mut handles = Vec::new();
    for idx in 0..config.threads {
        let (tx, rx) = bounded::<CaptureMessage>(QUEUE_CAP);
        let mut worker = Worker::new(idx, config.clone(), rx, stats.clone(), start)?;
        handles.push(std::thread::spawn(move || worker.run()));
        txs.push(tx);
    }

    let mut router = Router {
        load: vec![0; txs.len()],
        txs,
        owner: HashMap::new(),
        max_conns: config.max_conns,
        skipped: 0,
    };

    let base = reader.start_ts;
    let speed = config.speed.max(0.01);
    let mut last = 0u64;
    loop {
        match reader.read_event() {
            Ok(Some(mut msg)) => {
                if matches!(
                    msg.event,
                    ClientEvent::Lsn { .. } | ClientEvent::TxEnd { .. }
                ) {
                    continue;
                }
                last = ((msg.ts.saturating_sub(base) as f64 / speed) as u64).max(last);
                msg.ts = last;
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
    router.finish(last);
    info!("Finished reading");

    for h in handles {
        if h.join().is_err() {
            error!("worker panicked");
        }
    }
    Ok(())
}
