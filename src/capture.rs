use std::path::{self};

use crate::capture::acap::AcapReader;
use crate::capture::pcap::PcapReader;
use crate::capture::reader::CaptureReader;
use crate::capture::{self, acap::AcapWriter};
use crate::capture_desc::CaptureDesc;
use crate::utils::files;

use anyhow::anyhow;
use tracing::{error, info};

pub mod acap;
pub mod ebpf;
pub mod frame_buffer;
pub mod pcap;
pub mod reader;
pub mod reassembler;

pub async fn run_capture(mut writer: AcapWriter, interface: &str, port: u16) -> anyhow::Result<()> {
    let (handle, rx) = capture::ebpf::start_capture(interface, port).await?;
    info!("Capture started");
    let writer_handle = tokio::task::spawn_blocking(move || {
        loop {
            match rx.recv() {
                Ok(event) => {
                    if let Err(e) = writer.write(&event.addr, event.ts, &event.data) {
                        error!("Failed to write event: {e}");
                        break;
                    }
                }
                Err(_e) => break,
            }
        }
        if let Err(e) = writer.finish() {
            error!("Failed to finish writing: {e}");
        }
    });
    tokio::signal::ctrl_c().await?;
    handle.token.cancel();
    drop(handle.ebpf);
    writer_handle.await?;
    Ok(())
}

pub fn read_capture(desc: &CaptureDesc) -> anyhow::Result<Box<dyn CaptureReader>> {
    let path = &desc.path;
    if path.is_file() {
        let file = files::try_open(path)?;
        let reader = PcapReader::new(file, desc.port, desc.ts_offset, desc.max_duration)?;
        Ok(Box::new(reader))
    } else if path.is_dir() {
        let abs_path = path::absolute(path)?;
        let reader = AcapReader::new(&abs_path, desc.ts_offset, desc.max_duration)?;
        Ok(Box::new(reader))
    } else {
        let abs_path = path::absolute(path)?;
        Err(anyhow!("File does not exist: {}", abs_path.display()))
    }
}
