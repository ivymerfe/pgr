use std::collections::HashMap;
use std::io::BufWriter;
use std::io::Write;
use std::{fs::File, path::PathBuf};
use tracing::warn;
use tracing::{error, info};

use crate::parser::c2s_display::TagFrame;
use crate::parser::pcap::CaptureReader;
use crate::parser::pcap::ReadState;
use crate::parser::pq_stream::FrameResult;
use crate::parser::pq_stream::PqStream;

pub fn run(
    input_path: &PathBuf,
    output_path: &PathBuf,
    cap_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut capture_reader = CaptureReader::new(File::open(input_path)?)?;
    let mut writer = BufWriter::with_capacity(131072, File::create(output_path)?);

    let mut streams = HashMap::new();
    loop {
        match capture_reader.next() {
            ReadState::Ok(packet) => {
                if packet.tcp.destination_port() != cap_port {
                    continue;
                }
                let stream: &mut PqStream = streams.entry(packet.addr).or_default();
                if stream.process_packet(packet.tcp) {
                    loop {
                        match stream.find_frame() {
                            FrameResult::Complete(info) => {
                                let frame = stream.read_frame(&info);
                                writeln!(
                                    writer,
                                    "{},{},{},{}",
                                    packet.addr,
                                    stream.packet_count,
                                    packet.ts,
                                    TagFrame(info.tag, frame)
                                )?;
                                stream.consume_frame(&info);
                                stream.mark_read(info.stream_end);
                            }
                            FrameResult::Incomplete => break,
                            FrameResult::Desync => {
                                warn!("[{}] desync", packet.addr);
                                stream.resync();
                            }
                        }
                    }
                }
            }
            ReadState::Continue => continue,
            ReadState::Eof => break,
            ReadState::ReadFail(e) => {
                error!("Failed to read pcap: {e}");
                break;
            }
            ReadState::RefillFail(e) => {
                error!("Failed to refill pcap: {e}");
                break;
            }
        }
    }
    info!("Failed to parse: {}", capture_reader.fail_count);
    for (addr, stream) in &streams {
        info!("{addr}: Reorder count = {}", stream.reorder_count);
    }
    info!("Done");
    Ok(())
}
