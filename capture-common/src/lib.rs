#![no_std]

pub const CHUNK_SIZE: usize = 1480;

#[repr(C)]
pub struct CaptureEvent {
    pub timestamp_ns: u64,
    pub src_ip: [u8; 16],
    pub is_v6: u8,
    pub _pad: [u8; 3],
    pub src_port: u16,
    pub seq: u32,
    pub flags: u8,
    pub _pad2: [u8; 1],
    pub chunk_len: u16,
    pub payload: [u8; CHUNK_SIZE],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Config {
    pub dst_ip: [u8; 16],
    pub is_v6: u8,
    pub _pad: [u8; 3],
    pub dst_port: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Config {}
