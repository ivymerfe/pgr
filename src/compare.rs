mod client;
pub mod pair;

use std::collections::HashSet;
use std::fs::File;
use std::io::BufWriter;
use std::io::Write;
use std::net::SocketAddr;

use anyhow::anyhow;
use tracing::{error, info, warn};

use crate::capture::frame_buffer::FrameBuffer;
use crate::capture::frame_buffer::FrameInfo;
use crate::capture::reader::CaptureReader;
use crate::capture::reader::ReadError;
use crate::compare::pair::{ComparePair, PairMap};
use crate::parser::c2s_display::TagFrame;

pub fn compare(
    map: &mut PairMap,
    mut src_reader: Box<dyn CaptureReader>,
    mut replay_reader: Box<dyn CaptureReader>,
    mut delta_writer: Option<BufWriter<File>>,
) -> anyhow::Result<()> {
    let (mut src_eof, mut replay_eof) = (false, false);
    let mut src_ignore = HashSet::new();
    let mut replay_ignore = HashSet::new();
    while !src_eof || !replay_eof {
        if !src_eof {
            match src_reader.next() {
                Ok(mut data) => {
                    let addr = data.addr;
                    let src_buf = &mut data.buf;
                    if src_ignore.contains(&addr) {
                        continue;
                    }
                    if let Some(pair) = map.find_from_src(addr) {
                        pair.src.read_buf(data.ts, src_buf);
                        if let Some(replay_buf) = replay_reader.get_buffer(pair.replay.addr) {
                            check_pair(pair, src_buf, replay_buf, &mut delta_writer)?;
                        }
                    } else {
                        warn!("Cannot find pair src->replay: {addr}");
                        src_ignore.insert(addr);
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
                    let addr = data.addr;
                    let replay_buf = &mut data.buf;
                    if replay_ignore.contains(&addr) {
                        continue;
                    }
                    if let Some(pair) = map.find_from_replay(addr) {
                        pair.replay.read_buf(data.ts, replay_buf);
                        if let Some(src_buf) = src_reader.get_buffer(pair.src.addr) {
                            check_pair(pair, src_buf, replay_buf, &mut delta_writer)?;
                        }
                    } else {
                        warn!("Cannot find pair replay->src: {addr}");
                        replay_ignore.insert(addr);
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
    analyze(map);
    Ok(())
}

fn check_pair(
    pair: &mut ComparePair,
    src_buf: &mut FrameBuffer,
    replay_buf: &mut FrameBuffer,
    delta_writer: &mut Option<BufWriter<File>>,
) -> anyhow::Result<()> {
    while pair.src.has_frame() && pair.replay.has_frame() {
        let (src_info, src_ts) = pair.src.pop_frame();
        let (replay_info, replay_ts) = pair.replay.pop_frame();
        let src_frame = src_buf.read_frame(&src_info);
        let replay_frame = replay_buf.read_frame(&replay_info);

        let src_time = src_ts.saturating_sub(pair.src.connect_time()) as f64;
        let replay_time = replay_ts.saturating_sub(pair.replay.connect_time()) as f64;
        let min_time = (src_time.min(replay_time) as f64) / 1e6;
        let delta = (replay_time - src_time) / 1e3;
        if let Some(writer) = delta_writer {
            writeln!(
                writer,
                "{:.6},{:.3},{},{}",
                min_time,
                delta,
                pair.src.addr,
                TagFrame(src_info.tag, src_frame)
            )?;
        }
        if src_frame != replay_frame {
            if let Some(writer) = delta_writer {
                writeln!(
                    writer,
                    "{:.6},{:.3},{},{}",
                    min_time,
                    delta,
                    pair.replay.addr,
                    TagFrame(replay_info.tag, replay_frame)
                )?;
            }
            let e = format_frame_mismatch(
                pair.src.addr,
                &src_info,
                src_frame,
                pair.replay.addr,
                &replay_info,
                replay_frame,
            );
            return Err(anyhow!(e));
        }
        pair.stats.update_ts(src_time, replay_time);
    }
    Ok(())
}

fn divide_or_zero(a: f64, b: f64) -> f64 {
    if b != 0.0 { a / b } else { 0.0 }
}

fn analyze(map: &PairMap) {
    for pair in map.pairs.values() {
        let stats = &pair.stats;
        let src_frame_count = pair.src.frame_count;
        let replay_frame_count = pair.replay.frame_count;
        if src_frame_count != replay_frame_count {
            warn!(
                "{} / {}: frame count mismatch: {} / {}",
                pair.replay.addr, pair.src.addr, src_frame_count, replay_frame_count
            )
        }
        let src_connect = pair.src.connect_time() as f64;
        let replay_connect = pair.replay.connect_time() as f64;
        info!(
            "{} / {}: conn {:.2}ms; avg {:.2}ms; max {:.2}ms <{}/{}> avg {:.2}ms; max {:.2}ms",
            pair.replay.addr,
            pair.src.addr,
            (replay_connect - src_connect) / 1e3,
            divide_or_zero(stats.sum_behind, stats.cnt_behind) / 1e3,
            stats.max_behind / 1e3,
            stats.cnt_behind,
            stats.cnt_ahead,
            divide_or_zero(stats.sum_ahead, stats.cnt_ahead) / 1e3,
            stats.max_ahead / 1e3,
        );
    }
}

pub fn format_frame_mismatch(
    src_addr: SocketAddr,
    src_info: &FrameInfo,
    src_frame: &[u8],
    replay_addr: SocketAddr,
    replay_info: &FrameInfo,
    replay_frame: &[u8],
) -> String {
    format!(
        "Frame contents do not match:\n{} at {}:{} <=> {} at {}:{}\n{}\n{}",
        src_addr,
        src_info.stream_start,
        src_info.stream_end,
        replay_addr,
        replay_info.stream_start,
        replay_info.stream_end,
        TagFrame(src_info.tag, src_frame),
        TagFrame(replay_info.tag, replay_frame)
    )
}
