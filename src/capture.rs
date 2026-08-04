use std::error::Error;
use std::{fs::File, net::IpAddr};

use crate::capture::{self, zcap::ZcapWriter};

use tracing::{error, info};

pub mod ebpf;
pub mod frame_buffer;
pub mod pcap;
pub mod reader;
pub mod reassembler;
pub mod zcap;

pub async fn run_capture(
    out_file: File,
    iface: &str,
    dst_ip: IpAddr,
    port: u16,
    zstd_level: i32,
    zstd_workers: u8,
) -> Result<(), Box<dyn Error>> {
    let mut writer = ZcapWriter::new(out_file, zstd_level, zstd_workers)?;
    let (handle, rx) = capture::ebpf::start_capture(iface, dst_ip, port).await?;
    info!("Capture started");
    let writer_handle = tokio::task::spawn_blocking(move || {
        loop {
            match rx.recv() {
                Ok(event) => {
                    if let Err(e) = writer.write_event(event) {
                        error!("Failed to write event: {e}");
                        break;
                    }
                }
                Err(_e) => break,
            }
        }
        if let Err(e) = writer.finish() {
            error!("Writer finish failed: {e}");
        }
    });
    tokio::signal::ctrl_c().await?;
    handle.token.cancel();
    drop(handle.ebpf);
    writer_handle.await?;
    Ok(())
}
