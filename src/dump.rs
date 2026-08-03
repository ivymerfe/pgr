use std::fs::File;
use std::io::BufWriter;
use std::io::Write;
use tracing::warn;
use tracing::{error, info};

use crate::parser::c2s_display::TagFrame;
use crate::capture::frame_buffer::FrameResult;
use crate::capture::pcap::CaptureReader;
use crate::capture::pcap::ReadState;

pub fn dump(input: File, output: File, cap_port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let mut reader = CaptureReader::new(input, cap_port)?;
    let mut writer = BufWriter::with_capacity(131072, output);

    let mut start_ts = 0;
    loop {
        match reader.next() {
            ReadState::Ok { addr, ts, buf } => {
                if start_ts == 0 {
                    start_ts = ts;
                }
                loop {
                    match buf.find_frame() {
                        FrameResult::Complete(info) => {
                            let frame = buf.read_frame(&info);
                            writeln!(
                                writer,
                                "{:.6},{},{}",
                                ts.saturating_sub(start_ts) as f64 / 1e6,
                                addr,
                                TagFrame(info.tag, frame)
                            )?;
                            buf.consume_frame(&info);
                            buf.mark_read(info.stream_end);
                        }
                        FrameResult::Incomplete => break,
                        FrameResult::Desync => {
                            warn!("[{}] desync", addr);
                            buf.resync();
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
    info!("Ignored packets: {}", reader.fail_count);
    for (addr, stream) in &reader.handlers {
        info!(
            "{addr}: Packets = {} / Reorder = {}",
            stream.packet_count, stream.reorder_count
        );
    }
    info!("Done");
    Ok(())
}
