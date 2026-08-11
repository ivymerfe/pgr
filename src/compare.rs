mod pair;

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs::File,
    io::BufWriter,
};

use crate::{
    capture::{
        frame_buffer::{ConnState, FrameBuffer, FrameResult},
        reader::{CaptureReader, ClientId, ReadError},
    },
    compare::pair::ComparePair,
    parser::c2s::{PgC2S::StartupMessage, RawParams, parse_pg_message},
};

use tracing::{error, info, warn};

pub fn compare(
    mut src_reader: Box<dyn CaptureReader>,
    mut replay_reader: Box<dyn CaptureReader>,
    mut delta_writer: Option<BufWriter<File>>,
) -> anyhow::Result<()> {
    let (mut src_eof, mut replay_eof) = (false, false);
    let mut pairs = BTreeMap::<ClientId, ComparePair>::new();
    let mut replay_map = HashMap::new();
    let mut replay_ignore = HashSet::new();

    while !src_eof || !replay_eof {
        if !src_eof {
            match src_reader.next() {
                Ok(mut data) => {
                    let id = data.id;
                    let src_buf = &mut data.buf;
                    let pair = pairs.entry(id).or_insert_with(|| ComparePair::new(id));
                    pair.read_src(data.ts, src_buf);
                    if let Some(replay_id) = pair.replay_id {
                        if let Some(replay_buf) = replay_reader.get_buffer(replay_id) {
                            pair.compare(src_buf, replay_buf, &mut delta_writer)?;
                        }
                    }
                }
                Err(ReadError::Continue) => (),
                Err(ReadError::Eof) => {
                    src_eof = true;
                }
                Err(ReadError::Error(e)) => {
                    error!("Failed to read source capture: {e}");
                    return Ok(());
                }
            }
        }
        if !replay_eof {
            match replay_reader.next() {
                Ok(mut data) => {
                    let replay_id = data.id;
                    if replay_ignore.contains(&replay_id) {
                        continue;
                    }
                    let id = match replay_map.get(&replay_id) {
                        Some(id) => *id,
                        None => match try_find_id(replay_id, data.buf) {
                            FindResult::Ok(id) => {
                                replay_map.insert(replay_id, id);
                                id
                            }
                            FindResult::NotReady => continue,
                            FindResult::NotFound => {
                                info!("[{}:replay] pgr.client_id not found", replay_id);
                                replay_ignore.insert(replay_id);
                                continue;
                            }
                        },
                    };
                    let pair = pairs.entry(id).or_insert_with(|| ComparePair::new(id));
                    pair.replay_id = Some(replay_id);
                    let replay_buf = &mut data.buf;
                    pair.read_replay(data.ts, replay_buf);
                    if let Some(src_buf) = src_reader.get_buffer(id) {
                        pair.compare(src_buf, replay_buf, &mut delta_writer)?;
                    }
                }
                Err(ReadError::Continue) => (),
                Err(ReadError::Eof) => {
                    replay_eof = true;
                }
                Err(ReadError::Error(e)) => {
                    error!("Failed to read replay capture: {e}");
                    return Ok(());
                }
            }
        }
    }
    analyze(&pairs);
    Ok(())
}

enum FindResult {
    Ok(ClientId),
    NotReady,
    NotFound,
}

fn try_find_id(replay_id: ClientId, buf: &mut FrameBuffer) -> FindResult {
    while buf.state == ConnState::AwaitingStartup {
        match buf.find_frame() {
            FrameResult::Complete(info) => {
                let mut result = FindResult::NotReady;
                if info.tag == 0 {
                    let data = buf.read_frame(&info);
                    match parse_pg_message(info.tag, data) {
                        Ok(msg) => {
                            if let StartupMessage {
                                version: _,
                                parameters,
                            } = msg
                            {
                                if let Some(id) = find_pgr_client_id(parameters) {
                                    result = FindResult::Ok(id);
                                } else {
                                    result = FindResult::NotFound;
                                }
                            }
                        }
                        Err(e) => {
                            error!("[{replay_id}:replay] failed to parse postgres message: {e}");
                            result = FindResult::NotFound;
                        }
                    }
                }
                buf.consume_frame(&info);
                return result;
            }
            FrameResult::Incomplete => {
                return FindResult::NotReady;
            }
            FrameResult::Desync => {
                warn!("[{}:find_id] desync", replay_id);
                buf.resync();
            }
        }
    }
    FindResult::NotFound
}

fn find_pgr_client_id(params: RawParams) -> Option<ClientId> {
    for (k, v) in params.iter() {
        if k == "pgr.client_id" {
            if let Ok(id) = v.parse() {
                return Some(id);
            }
            return None;
        }
    }
    None
}

fn divide_or_zero(a: f64, b: f64) -> f64 {
    if b != 0.0 { a / b } else { 0.0 }
}

fn analyze(map: &BTreeMap<ClientId, ComparePair>) {
    for pair in map.values() {
        let stats = &pair.stats;
        if stats.src_frames != stats.replay_frames {
            warn!(
                "{}: frame count mismatch: {} / {}",
                pair.id, stats.src_frames, stats.replay_frames
            )
        }
        info!(
            "{}: conn {:.2}ms; avg {:.2}ms; max {:.2}ms <{}/{}> avg {:.2}ms; max {:.2}ms",
            pair.id,
            pair.connect_delta() as f64 / 1e3,
            divide_or_zero(stats.sum_behind, stats.cnt_behind) / 1e3,
            stats.max_behind / 1e3,
            stats.cnt_behind,
            stats.cnt_ahead,
            divide_or_zero(stats.sum_ahead, stats.cnt_ahead) / 1e3,
            stats.max_ahead / 1e3,
        );
    }
}
