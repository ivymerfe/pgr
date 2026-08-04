use aya_ebpf::{
    macros::map,
    maps::{Array, RingBuf},
};
use capture_common::Config;

#[map]
pub static CONFIG: Array<Config> = Array::with_max_entries(1, 0);

#[map]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(32 * 1024 * 1024, 0);
