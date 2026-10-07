use std::{collections::HashMap, sync::Arc, thread::sleep, time::Duration};

use crossbeam_channel::{Sender, unbounded};
use quanta::Instant;
use tracing::{error, info};

use crate::{
    capture::reader::{CaptureEvent, CaptureReader, ClientId, ReadError},
    replay::{
        client::ReplayConfig,
        r#loop::{ConnCommand, ReplayLoop},
        stats::ReplayStats,
    },
};

struct ClientInfo {
    _id: ClientId,
    connected: bool,
}

impl ClientInfo {
    pub fn new(_id: ClientId) -> Self {
        Self {
            _id,
            connected: false,
        }
    }
}

pub struct ReplayManager {
    clients: HashMap<ClientId, ClientInfo>,
}

impl ReplayManager {
    pub fn new() -> Self {
        Self {
            clients: HashMap::new(),
        }
    }

    pub fn replay(
        &mut self,
        config: ReplayConfig,
        mut reader: Box<dyn CaptureReader>,
    ) -> anyhow::Result<()> {
        let stats = Arc::new(ReplayStats::new());

        let stats_clone = stats.clone();
        std::thread::spawn(move || {
            sleep(Duration::from_secs(1));
            loop {
                let total = stats_clone.read_total_sent();
                let pps = stats_clone.read_delta_sent();
                let recv = stats_clone.read_delta_recv();
                info!("Total sent: {total} Delta sent: {pps} Delta recv: {recv}");
                sleep(Duration::from_secs(1));
            }
        });

        let (cmd_tx, cmd_rx) = unbounded::<ConnCommand>();

        let mut conn = ReplayLoop::new(config, cmd_rx, stats)?;
        let waker = conn.waker();
        let conn_handle = std::thread::spawn(move || conn.run());

        let start = Instant::now();
        loop {
            match reader.next() {
                Ok(msg) => {
                    let id = msg.client;
                    let client = self
                        .clients
                        .entry(id)
                        .or_insert_with(|| ClientInfo::new(id));
                    match msg.event {
                        CaptureEvent::Connect => {
                            if !Self::send_cmd(
                                &cmd_tx,
                                &waker,
                                ConnCommand::Connect { id, ts: msg.ts },
                            ) {
                                break;
                            }
                            client.connected = true;
                        }
                        CaptureEvent::Disconnect => {
                            self.clients.remove(&id);
                        }
                        CaptureEvent::PqFrame { tag, frame, .. } => {
                            if !client.connected {
                                if !Self::send_cmd(
                                    &cmd_tx,
                                    &waker,
                                    ConnCommand::Connect { id, ts: msg.ts },
                                ) {
                                    break;
                                }
                                client.connected = true;
                            }
                            if !Self::send_cmd(
                                &cmd_tx,
                                &waker,
                                ConnCommand::Send {
                                    id,
                                    ts: msg.ts,
                                    tag,
                                    data: frame,
                                },
                            ) {
                                break;
                            }
                        }
                    }
                    let elapsed_us = start.elapsed().as_micros() as u64;
                    if msg.ts.saturating_sub(elapsed_us) > 1_000_000 {
                        sleep(Duration::from_micros(500_000));
                    }
                }
                Err(ReadError::Eof) => break,
                Err(ReadError::Error(e)) => {
                    error!("Failed to read pcap: {e}");
                    break;
                }
            }
        }
        Self::send_cmd(&cmd_tx, &waker, ConnCommand::Terminate { ts: 0 });
        drop(cmd_tx);

        info!("Finished reading");
        if let Err(_) = conn_handle.join() {
            error!("join failed, conn thread gone");
        }

        Ok(())
    }

    fn send_cmd(cmd_tx: &Sender<ConnCommand>, waker: &Arc<mio::Waker>, cmd: ConnCommand) -> bool {
        if cmd_tx.send(cmd).is_err() {
            error!("ctl thread gone, dropping command");
            return false;
        }
        if let Err(e) = waker.wake() {
            error!("failed to wake ctl: {e}");
            return false;
        }
        return true;
    }
}
