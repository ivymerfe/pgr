use aya_ebpf::{
    bindings::BPF_RB_NO_WAKEUP, cty::c_void, helpers::generated::{bpf_ktime_get_ns, bpf_loop, bpf_skb_load_bytes}, programs::TcContext,
};
use aya_log_ebpf::info;
use capture_common::{CHUNK_SIZE, CaptureEvent};

use crate::global::{EVENTS, MAX_CHUNKS};

struct LoopCtx<'a> {
    ctx: &'a TcContext,
    src_ip: [u8; 16],
    is_v6: u8,
    src_port: u16,
    seq: u32,
    flags: u8,
    payload_off: usize,
    payload_len: usize,
    failed: bool,
}

extern "C" fn send_chunk(index: u64, data: *mut c_void) -> i32 {
    let lctx = unsafe { &mut *(data as *mut LoopCtx) };

    let off = index as usize * CHUNK_SIZE;
    if off >= lctx.payload_len {
        return 1;
    }
    let chunk = core::cmp::min(CHUNK_SIZE, lctx.payload_len - off);
    if chunk == 0 || chunk > CHUNK_SIZE {
        return 1;
    }
    let mut entry = match EVENTS.reserve::<CaptureEvent>(0) {
        Some(e) => e,
        None => {
            lctx.failed = true;
            return 1;
        }
    };
    let event = entry.as_mut_ptr();
    unsafe {
        (*event).timestamp_ns = bpf_ktime_get_ns();
        (*event).src_ip = lctx.src_ip;
        (*event).is_v6 = lctx.is_v6;
        (*event).src_port = lctx.src_port;
        (*event).seq = lctx.seq.wrapping_add(off as u32);
        (*event).flags = lctx.flags;
        (*event).chunk_len = chunk as u16;
    }
    let payload_ptr = unsafe { (*event).payload.as_mut_ptr() as *mut _ };
    let len = chunk as u32;
    if len > 0 {
        let ret = unsafe {
            bpf_skb_load_bytes(
                lctx.ctx.skb.skb as *const c_void,
                (lctx.payload_off + off) as u32,
                payload_ptr,
                len,
            )
        };
        if ret < 0 {
            entry.discard(0);
            lctx.failed = true;
            return 1;
        }
    }
    entry.submit(BPF_RB_NO_WAKEUP as u64);
    0
}

#[inline(always)]
pub fn emit_capture(
    ctx: &TcContext,
    src_ip: [u8; 16],
    is_v6: u8,
    src_port: u16,
    seq: u32,
    flags: u8,
    payload_off: usize,
    payload_len: usize,
) -> Result<(), ()> {
    if payload_len == 0 {
        let mut entry = EVENTS.reserve::<CaptureEvent>(0).ok_or(())?;

        let event = entry.as_mut_ptr();
        unsafe {
            (*event).timestamp_ns = bpf_ktime_get_ns();
            (*event).src_ip = src_ip;
            (*event).is_v6 = is_v6;
            (*event).src_port = src_port;
            (*event).seq = seq;
            (*event).flags = flags;
            (*event).chunk_len = 0;
        }

        entry.submit(0);
        return Ok(());
    }
    let needed_chunks = payload_len.div_ceil(CHUNK_SIZE);
    if needed_chunks > MAX_CHUNKS {
        info!(ctx, "Dropping payload of size {}", payload_len);
        return Err(());
    }
    let mut lctx = LoopCtx {
        ctx,
        src_ip,
        is_v6,
        src_port,
        seq,
        flags,
        payload_off,
        payload_len,
        failed: false,
    };
    unsafe {
        bpf_loop(
            needed_chunks as u32,
            send_chunk as *mut c_void,
            &mut lctx as *mut _ as *mut c_void,
            0,
        );
    }
    if lctx.failed {
        return Err(());
    }
    Ok(())
}
