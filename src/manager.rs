use std::{sync::Arc, thread::sleep, time::Duration};

use crossbeam_channel::{Sender, unbounded};
use quanta::Instant;
use tracing::{error, info};

use crate::{
    capture::{CaptureMessage, CaptureReader, ClientEvent},
    client::ReplayConfig,
    r#loop::{ConnCommand, ReplayLoop},
    proto,
    utils::ReplayStats,
};

const WAKE_BATCH: u32 = 256;

struct Sink<'a> {
    tx: &'a Sender<ConnCommand>,
    waker: &'a Arc<mio::Waker>,
    unwoken: u32,
    ok: bool,
}

impl Sink<'_> {
    fn push(&mut self, cmd: ConnCommand) {
        if self.tx.send(cmd).is_err() {
            error!("ctl thread gone, dropping command");
            self.ok = false;
            return;
        }
        self.unwoken += 1;
        if self.unwoken >= WAKE_BATCH {
            self.wake();
        }
    }

    fn wake(&mut self) {
        if self.unwoken == 0 {
            return;
        }
        self.unwoken = 0;
        if let Err(e) = self.waker.wake() {
            error!("failed to wake ctl: {e}");
            self.ok = false;
        }
    }
}

fn begin(tag: u8, cap: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(5 + cap);
    v.push(tag);
    v.extend_from_slice(&[0; 4]);
    v
}

fn end(mut v: Vec<u8>) -> Vec<u8> {
    let n = (v.len() - 1) as i32;
    v[1..5].copy_from_slice(&n.to_be_bytes());
    v
}

fn cstr(v: &mut Vec<u8>, s: &str) {
    v.extend_from_slice(s.as_bytes());
    v.push(0);
}

fn query_frame(q: &str) -> Vec<u8> {
    let mut v = begin(proto::F_QUERY, q.len() + 1);
    cstr(&mut v, q);
    end(v)
}

fn emit(msg: CaptureMessage, ts: u64, out: &mut Sink) {
    let id = msg.id;
    let (tag, data) = match msg.event {
        ClientEvent::Lsn { .. } | ClientEvent::TxEnd { .. } => return,
        ClientEvent::Connect { session_id } => {
            out.push(ConnCommand::Connect { id, ts });
            if session_id.is_empty() {
                return;
            }
            let q = format!("SELECT pgr.srestore('{}')", session_id.replace('\'', "''"));
            (proto::F_QUERY, query_frame(&q))
        }
        ClientEvent::Disconnect => (proto::F_TERMINATE, proto::TERMINATE_MSG.to_vec()),
        ClientEvent::SimpleQuery { text } => (proto::F_QUERY, query_frame(&text)),
        ClientEvent::Parse {
            name,
            query,
            param_types,
        } => {
            let mut v = begin(
                proto::F_PARSE,
                name.len() + query.len() + 4 + param_types.len() * 4,
            );
            cstr(&mut v, &name);
            cstr(&mut v, &query);
            v.extend_from_slice(&(param_types.len() as i16).to_be_bytes());
            for t in param_types {
                v.extend_from_slice(&t.to_be_bytes());
            }
            (proto::F_PARSE, end(v))
        }
        ClientEvent::Bind {
            portal,
            statement,
            result_formats,
            params,
        } => {
            let vals: usize = params
                .iter()
                .map(|p| 4 + p.value.as_ref().map_or(0, |v| v.len()))
                .sum();
            let mut v = begin(
                proto::F_BIND,
                portal.len() + statement.len() + 8 + vals + result_formats.len() * 2,
            );
            cstr(&mut v, &portal);
            cstr(&mut v, &statement);
            v.extend_from_slice(&0i16.to_be_bytes());
            v.extend_from_slice(&(params.len() as i16).to_be_bytes());
            for p in params {
                match p.value {
                    Some(b) => {
                        v.extend_from_slice(&(b.len() as i32).to_be_bytes());
                        v.extend_from_slice(&b);
                    }
                    None => v.extend_from_slice(&(-1i32).to_be_bytes()),
                }
            }
            v.extend_from_slice(&(result_formats.len() as i16).to_be_bytes());
            for f in result_formats {
                v.extend_from_slice(&(f as i16).to_be_bytes());
            }
            (proto::F_BIND, end(v))
        }
        ClientEvent::Execute { portal, max_rows } => {
            let mut v = begin(proto::F_EXECUTE, portal.len() + 5);
            cstr(&mut v, &portal);
            v.extend_from_slice(&(max_rows.clamp(0, i32::MAX as i64) as i32).to_be_bytes());
            (proto::F_EXECUTE, end(v))
        }
        ClientEvent::Sync => (proto::F_SYNC, end(begin(proto::F_SYNC, 0))),
    };
    out.push(ConnCommand::Send { id, ts, tag, data });
}

pub struct ReplayManager {}

impl ReplayManager {
    pub fn new() -> Self {
        Self {}
    }

    pub fn replay(
        &mut self,
        config: ReplayConfig,
        mut reader: CaptureReader,
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

        let mut out = Sink {
            tx: &cmd_tx,
            waker: &waker,
            unwoken: 0,
            ok: true,
        };

        let base = reader.start_ts;
        let mut last = 0u64;
        let start = Instant::now();
        while out.ok {
            match reader.read_event() {
                Ok(Some(msg)) => {
                    let rel = msg.ts.saturating_sub(base).max(last);
                    last = rel;
                    emit(msg, rel, &mut out);
                    if rel.saturating_sub(start.elapsed().as_micros() as u64) > 1_000_000 {
                        out.wake();
                        while rel.saturating_sub(start.elapsed().as_micros() as u64) > 1_000_000 {
                            sleep(Duration::from_millis(500));
                        }
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    error!("Failed to read capture: {e}");
                    break;
                }
            }
        }
        out.push(ConnCommand::Terminate { ts: last });
        out.wake();
        drop(out);
        drop(cmd_tx);

        info!("Finished reading");
        if conn_handle.join().is_err() {
            error!("join failed, conn thread gone");
        }

        Ok(())
    }
}
