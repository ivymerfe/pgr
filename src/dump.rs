use std::fs::File;
use std::io::BufWriter;
use std::io::Write;
use tracing::{error, info};

use crate::replay::source::{CommandSource, Command, ReadError};
use crate::proto::c2s::PgMsgParser;
use crate::utils::format::DisplayBytes;

pub fn dump(mut reader: Box<dyn CommandSource>, output: File) -> anyhow::Result<()> {
    let mut writer = BufWriter::with_capacity(131072, output);

    let mut parser = PgMsgParser::new();
    loop {
        match reader.next() {
            Ok(msg) => match msg.event {
                Command::Connect => {
                    writeln!(writer, "connect,{},{},", msg.ts as f64 / 1e6, msg.client)?;
                }
                Command::Disconnect => {
                    writeln!(writer, "disconnect,{},{},", msg.ts as f64 / 1e6, msg.client)?;
                }
                Command::PqFrame { frame, .. } => {
                    write!(writer, "frame,{:.6},{},", msg.ts as f64 / 1e6, msg.client)?;
                    match parser.parse(&frame) {
                        Ok(msg) => {
                            writeln!(writer, "{}", msg)?;
                        }
                        Err(e) => {
                            writeln!(writer, "({}),{}", e, DisplayBytes(&frame))?;
                        }
                    }
                }
            },
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
