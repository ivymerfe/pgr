use std::{collections::HashMap, sync::Arc, thread::sleep, time::Duration};

use crossbeam_channel::{Sender, unbounded};
use quanta::Instant;
use tracing::{error, info, warn};

use crate::{
    capture::{
        frame_buffer::{ConnState, FrameResult},
        reader::{CaptureReader, ClientId, ReadError},
    },
    replay::{
        addr_map::AddrMapWriter,
        client::ReplayConfig,
        r#loop::{ConnCommand, ReplayLoop},
        stats::ReplayStats,
    },
    utils::waker::Waker,
};

struct ClientInfo {
    id: ClientId,
    first_ts: u64,
    found_startup: bool,
    connected: bool,
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
        addr_map: AddrMapWriter,
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

        let mut conn = ReplayLoop::new(config, cmd_rx, stats, addr_map)?;
        let waker = conn.waker();
        let conn_handle = std::thread::spawn(move || conn.run());

        let start = Instant::now();
        loop {
            match reader.next(false) {
                Ok(data) => {
                    let client = self.clients.entry(data.id).or_insert_with(|| ClientInfo {
                        id: data.id,
                        first_ts: data.ts,
                        found_startup: false,
                        connected: false,
                    });
                    if !Self::forward_frames(client, data.ts, data.buf, &cmd_tx, &waker) {
                        break;
                    }
                    let elapsed_us = start.elapsed().as_micros() as u64;
                    if data.ts.saturating_sub(elapsed_us) > 1_000_000 {
                        sleep(Duration::from_micros(500_000));
                    }
                }
                Err(ReadError::Continue) => (),
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

    fn send_cmd(cmd_tx: &Sender<ConnCommand>, waker: &Arc<Waker>, cmd: ConnCommand) -> bool {
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

    fn forward_frames(
        client: &mut ClientInfo,
        ts: u64,
        buf: &mut crate::capture::frame_buffer::FrameBuffer,
        cmd_tx: &Sender<ConnCommand>,
        waker: &Arc<Waker>,
    ) -> bool {
        while buf.state != ConnState::Normal && buf.state != ConnState::CopyIn {
            match buf.find_frame() {
                FrameResult::Complete(info) => {
                    if info.tag == 0 {
                        client.found_startup = true;
                    }
                    buf.consume_frame(&info);
                }
                FrameResult::Incomplete => {
                    return true;
                }
                FrameResult::Desync => {
                    warn!("[{}] desync", client.id);
                    buf.resync();
                }
            }
        }
        if !client.connected {
            let ts = if client.found_startup {
                client.first_ts
            } else {
                0
            };
            if !Self::send_cmd(cmd_tx, waker, ConnCommand::Connect { id: client.id, ts }) {
                return false;
            }
            client.connected = true;
        }
        let mut ready_frame: Option<(u8, Vec<u8>)> = None;
        loop {
            match buf.find_frame() {
                FrameResult::Complete(info) => {
                    if let Some((tag, data)) = ready_frame.take() {
                        let cmd = ConnCommand::Send {
                            id: client.id,
                            ts,
                            tag,
                            data,
                            flush: false,
                        };
                        if !Self::send_cmd(cmd_tx, waker, cmd) {
                            return false;
                        }
                    }
                    let data = buf.read_frame_full(&info).to_vec();
                    ready_frame = Some((info.tag, data));
                    buf.consume_frame(&info);
                    buf.mark_read(info.stream_end);
                }
                FrameResult::Incomplete => {
                    if let Some((tag, data)) = ready_frame.take() {
                        let cmd = ConnCommand::Send {
                            id: client.id,
                            ts,
                            tag,
                            data,
                            flush: true,
                        };
                        if !Self::send_cmd(cmd_tx, waker, cmd) {
                            return false;
                        }
                    }
                    break;
                }
                FrameResult::Desync => buf.resync(),
            }
        }
        return true;
    }
}
