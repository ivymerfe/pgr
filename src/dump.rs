use std::collections::HashMap;
use std::io::BufWriter;
use std::io::Write;
use std::{fs::File, path::PathBuf};
use tracing::warn;
use tracing::{error, info};

use crate::parser::pcap::ReadState;
use crate::parser::pq_stream::PqStream;
use crate::parser::{c2s::parse_pg_message, pcap::CaptureReader};

pub fn dump(
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
                    let skip = stream.find_frame(true);
                    if skip > 0 {
                        warn!("[{}] Corrupted stream, resync", packet.addr);
                        stream.consume(skip);
                    }
                    while let Some((length, frame)) = stream.read_frame() {
                        match parse_pg_message(frame.tag, &frame.payload[frame.offset..]) {
                            Ok(msg) => {
                                writeln!(writer, "[{}] ({}) -> {}", packet.addr, packet.ts, msg)?;
                            }
                            Err(e) => {
                                error!("Failed to parse message: {e}");
                            }
                        }
                        stream.consume(length);
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
    info!("Done");
    Ok(())
}
