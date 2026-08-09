use std::path::{self};

use crate::capture::acap::AcapReader;
use crate::capture::pcap::PcapReader;
use crate::capture::reader::CaptureReader;
use crate::capture_desc::CaptureDesc;
use crate::utils::files;

use anyhow::anyhow;

pub mod acap;
pub mod ebpf;
pub mod frame_buffer;
pub mod pcap;
pub mod reader;
pub mod reassembler;

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
