use std::io::BufWriter;
use std::io::Write;
use std::{fs::File, io::BufReader, path::PathBuf};
use tracing::{error, info};

use crate::parser::pcap::ReadState;
use crate::parser::{c2s::parse_pg_message, pcap::CaptureReader};

pub fn dump(
    input_path: &PathBuf,
    output_path: &PathBuf,
    cap_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let reader = BufReader::with_capacity(131072, File::open(input_path)?);
    let mut writer = BufWriter::with_capacity(131072, File::create(output_path)?);

    let mut capture_reader = CaptureReader::new(reader, cap_port)?;
    loop {
        match capture_reader.next() {
            ReadState::Ok(stream) => {
                while let Some((length, frame)) = stream.peek_frame(true) {
                    match parse_pg_message(frame.tag, &frame.payload[frame.offset..]) {
                        Ok(msg) => {
                            writeln!(writer, "[{}] ({}) -> {}", frame.addr, frame.ts, msg);
                        }
                        Err(e) => {
                            error!("Failed to parse message: {e}");
                        }
                    }
                    stream.consume(length);
                }
            }
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
