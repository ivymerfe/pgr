mod client;
pub mod pair;

use std::collections::HashSet;
use std::error::Error;
use std::fs::File;
use std::io::BufWriter;
use std::io::Write;
use std::net::SocketAddr;

use tracing::{error, info, warn};

use crate::compare::pair::{ComparePair, PairMap};
use crate::parser::c2s_display::TagFrame;
use crate::parser::pcap::{CaptureReader, ReadState};
use crate::parser::pq_stream::FrameInfo;

pub fn compare(
    map: &mut PairMap,
    file1: File,
    file2: File,
    port1: u16,
    port2: u16,
    delta_file: Option<File>,
) -> Result<(), Box<dyn Error>> {
    let meta1 = file1.metadata()?;
    let meta2 = file2.metadata()?;

    let mut c1_reader = CaptureReader::new(file1)?;
    let mut c2_reader = CaptureReader::new(file2)?;
    let mut delta_writer = delta_file.map(|f| BufWriter::new(f));

    let (mut c1_packets, mut c2_packets) = (0, 0);
    let (mut c1_eof, mut c2_eof) = (false, false);
    let mut c1_ignore = HashSet::new();
    let mut c2_ignore = HashSet::new();
    let mut c1_first_ts: Option<u64> = None;
    let mut c2_first_ts: Option<u64> = None;

    while !c1_eof || !c2_eof {
        if !c1_eof {
            match c1_reader.next() {
                ReadState::Ok(packet) => {
                    if packet.tcp.destination_port() != port1 {
                        continue;
                    }
                    c1_first_ts.get_or_insert(packet.ts);
                    c1_packets += 1;
                    let addr = packet.addr;
                    if c1_ignore.contains(&addr) {
                        continue;
                    }
                    if let Some(pair) = map.find_c1(addr) {
                        let stream = &mut pair.c1.stream;
                        if stream.process_packet(packet.tcp) {
                            pair.c1.read_stream(packet.ts);
                            check_pair(pair, &mut delta_writer)?;
                        }
                    } else {
                        warn!("Cannot find pair s1->s2: {addr}");
                        c1_ignore.insert(addr);
                    }
                }
                ReadState::Continue => (),
                ReadState::Eof => {
                    c1_eof = true;
                }
                ReadState::ReadFail(e) => {
                    error!("Failed to read capture1: {e}");
                    return Ok(());
                }
                ReadState::RefillFail(e) => {
                    error!("Failed to refill capture1: {e}");
                    return Ok(());
                }
            }
        }
        if !c2_eof {
            match c2_reader.next() {
                ReadState::Ok(packet) => {
                    if packet.tcp.destination_port() != port2 {
                        continue;
                    }
                    c2_first_ts.get_or_insert(packet.ts);
                    c2_packets += 1;
                    let addr = packet.addr;
                    if c2_ignore.contains(&addr) {
                        continue;
                    }
                    if let Some(pair) = map.find_c2(addr) {
                        let stream = &mut pair.c2.stream;
                        if stream.process_packet(packet.tcp) {
                            pair.c2.read_stream(packet.ts);
                            check_pair(pair, &mut delta_writer)?;
                        }
                    } else {
                        warn!("Cannot find pair s2->s1: {addr}");
                        c2_ignore.insert(addr);
                    }
                }
                ReadState::Continue => (),
                ReadState::Eof => {
                    c2_eof = true;
                }
                ReadState::ReadFail(e) => {
                    error!("Failed to read capture2: {e}");
                    return Ok(());
                }
                ReadState::RefillFail(e) => {
                    error!("Failed to refill capture2: {e}");
                    return Ok(());
                }
            }
        }
    }
    info!(
        "C1: {} packets, {}/{} bytes",
        c1_packets,
        c1_reader.bytes_read,
        meta1.len()
    );
    info!(
        "C2: {} packets, {}/{} bytes",
        c2_packets,
        c2_reader.bytes_read,
        meta2.len()
    );
    if let Some(c1_first_ts) = c1_first_ts
        && let Some(c2_first_ts) = c2_first_ts
    {
        analyze(map, c1_first_ts, c2_first_ts);
    }
    Ok(())
}

fn check_pair(
    pair: &mut ComparePair,
    delta_writer: &mut Option<BufWriter<File>>,
) -> Result<(), Box<dyn Error>> {
    while pair.c1.has_frame() && pair.c2.has_frame() {
        let (info1, ts1, frame1) = pair.c1.get_frame();
        let (info2, ts2, frame2) = pair.c2.get_frame();
        let rel_1 = ts1.saturating_sub(pair.c1.connect_ts) as f64;
        let rel_2 = ts2.saturating_sub(pair.c2.connect_ts) as f64;
        let ts = (rel_1.min(rel_2) as f64) / 1e6;
        let delta = (rel_2 - rel_1) / 1e3;
        if let Some(writer) = delta_writer {
            writeln!(
                writer,
                "{:.6},{:.3},{},{}",
                ts,
                delta,
                pair.c1.addr,
                TagFrame(info1.tag, frame1)
            )?;
        }
        if frame1 != frame2 {
            if let Some(writer) = delta_writer {
                writeln!(
                    writer,
                    "{:.6},{:.3},{},{}",
                    ts,
                    delta,
                    pair.c2.addr,
                    TagFrame(info2.tag, frame2)
                )?;
            }
            let e = format_frame_mismatch(pair.c1.addr, info1, frame1, pair.c2.addr, info2, frame2);
            return Err(e.into());
        }
        pair.stats.update_ts(
            ts1.saturating_sub(pair.c1.connect_ts),
            ts2.saturating_sub(pair.c2.connect_ts),
        );
        pair.c1.next_frame();
        pair.c2.next_frame();
    }
    Ok(())
}

fn divide_or_zero(a: f64, b: f64) -> f64 {
    if b != 0.0 { a / b } else { 0.0 }
}

fn analyze(map: &PairMap, c1_first_ts: u64, c2_first_ts: u64) {
    for pair in map.clients.values() {
        let stats = &pair.stats;
        let frame_count_c1 = pair.c1.frame_count;
        let frame_count_c2 = pair.c2.frame_count;
        if frame_count_c1 != frame_count_c2 {
            warn!(
                "{} / {}: frame count mismatch: {} / {}",
                pair.c2.addr, pair.c1.addr, frame_count_c1, frame_count_c2
            )
        }
        let rel_1 = (pair.c1.connect_ts - c1_first_ts) as f64;
        let rel_2 = (pair.c2.connect_ts - c2_first_ts) as f64;
        info!(
            "{} / {}: conn {:.2}ms; avg {:.2}ms; max {:.2}ms <{}/{}> avg {:.2}ms; max {:.2}ms",
            pair.c2.addr,
            pair.c1.addr,
            (rel_2 - rel_1) / 1e3,
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
    addr1: SocketAddr,
    info1: &FrameInfo,
    frame1: &[u8],
    addr2: SocketAddr,
    info2: &FrameInfo,
    frame2: &[u8],
) -> String {
    format!(
        "Frame contents do not match:\n{} at {}:{} <=> {} at {}:{}\n{}\n{}",
        addr1,
        info1.stream_start,
        info1.stream_end,
        addr2,
        info2.stream_start,
        info2.stream_end,
        TagFrame(info1.tag, frame1),
        TagFrame(info2.tag, frame2)
    )
}
