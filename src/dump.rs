use std::collections::HashMap;
use std::fs::File;
use std::io::BufWriter;
use std::io::Write;
use tracing::{error, info};

use crate::capture::frame_buffer::FrameBuffer;
use crate::capture::reader::CaptureReader;
use crate::capture::reader::ReadError;
use crate::proto::c2s::PgMsgParser;
use crate::utils::format::DisplayBytes;

pub fn dump(mut reader: Box<dyn CaptureReader>, output: File) -> anyhow::Result<()> {
    let mut writer = BufWriter::with_capacity(131072, output);

    let mut frame_buffers = HashMap::new();
    let mut parser = PgMsgParser::new();
    loop {
        match reader.next() {
            Ok(data) => {
                let buf = frame_buffers
                    .entry(data.id)
                    .or_insert_with(|| FrameBuffer::new(data.id));
                buf.on_capture(&data);
                while let Some(info) = buf.frames.pop_front() {
                    let frame = buf.read_frame(&info);
                    write!(writer, "{:.6},{},", data.ts as f64 / 1e6, data.id,)?;
                    match parser.parse(frame) {
                        Ok(msg) => {
                            writeln!(writer, "{}", msg)?;
                        }
                        Err(e) => {
                            writeln!(writer, "({}),{}", e, DisplayBytes(frame))?;
                        }
                    }
                }
            }
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
