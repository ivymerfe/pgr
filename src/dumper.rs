use std::io::BufWriter;
use std::io::Write;
use std::{fs::File, io::BufReader, path::PathBuf};
use tracing::{error, info};

use crate::parser::{c2s::parse_pg_message, pcap::CaptureReader};

pub fn dump(
    input_path: &PathBuf,
    output_path: &PathBuf,
    cap_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let input_file = File::open(input_path)?;
    let reader = BufReader::with_capacity(131072, input_file);

    let out_file = File::create(output_path)?;
    let mut writer = BufWriter::with_capacity(131072, out_file);

    let mut capture_reader = CaptureReader::new(reader, cap_port)?;
    capture_reader.read(&mut |event| {
        let frame = event.frame;
        match parse_pg_message(frame.tag, &frame.payload) {
            Ok(msg) => {
                writeln!(writer, "[{}] ({}) -> {}", event.addr, event.timestamp, msg);
            }
            Err(e) => {
                error!("Failed to parse message: {}", e);
            }
        }
    })?;

    info!("Done");
    Ok(())
}
