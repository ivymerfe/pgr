use std::fs::File;
use std::io::BufWriter;
use std::io::Write;
use tracing::warn;
use tracing::{error, info};

use crate::capture::frame_buffer::FrameResult;
use crate::capture::reader::CaptureReader;
use crate::capture::reader::ReadError;
use crate::proto::format::DisplayFrame;

pub fn dump(mut reader: Box<dyn CaptureReader>, output: File) -> anyhow::Result<()> {
    let mut writer = BufWriter::with_capacity(131072, output);

    loop {
        match reader.next() {
            Ok(mut data) => loop {
                let offset = data.buf.frame_offset();
                let buf = &mut data.buf;
                match buf.find_frame() {
                    FrameResult::Complete(info) => {
                        let frame = buf.read_frame(&info);
                        writeln!(
                            writer,
                            "{:.6},{},{}",
                            data.ts as f64 / 1e6,
                            data.id,
                            DisplayFrame(info.tag, frame)
                        )?;
                        buf.consume_frame(&info);
                        buf.mark_read(info.stream_end);
                    }
                    FrameResult::Incomplete => break,
                    FrameResult::Desync => {
                        warn!("[{}] desync at {}", data.id, offset);
                        buf.resync();
                    }
                }
            },
            Err(ReadError::Continue) => continue,
            Err(ReadError::Eof) => break,
            Err(ReadError::Error(e)) => {
                error!("Failed to read capture: {e}");
                break;
            }
        }
    }
    info!("Done");
    Ok(())
}
