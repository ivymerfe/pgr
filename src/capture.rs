use std::path::{self};

use crate::capture::pcap::PcapReader;
use crate::capture::reader::CaptureReader;
use crate::capture_desc::CaptureDesc;
use crate::utils::files;

use anyhow::anyhow;

mod frame_buffer;
pub mod pcap;
pub mod reader;

pub fn read_capture(desc: &CaptureDesc) -> anyhow::Result<Box<dyn CaptureReader>> {
    let path = &desc.path;
    if !path.exists() {
        return Err(anyhow!("Capture file does not exist: {}", path.display()));
    }
    if path.extension().map_or(false, |ext| ext == "pcap") {
        let file = files::try_open(path)?;
        let reader = PcapReader::new(file, desc.port, desc.ts_offset, desc.max_duration)?;
        Ok(Box::new(reader))
    } else {
        let abs_path = path::absolute(path)?;
        Err(anyhow!("Unknown file type: {}", abs_path.display()))
    }
}
