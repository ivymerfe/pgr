use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    cty::c_void,
    helpers::generated::{bpf_ktime_get_ns, bpf_skb_load_bytes},
    macros::classifier,
    programs::TcContext,
};
use capture_common::{CHUNK_SIZE, CaptureEvent};

use crate::global::{CONFIG, EVENTS};

const ETH_HDR_LEN: usize = 14;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;

#[classifier]
pub fn tc_capture(ctx: TcContext) -> i32 {
    match try_tc_capture(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_PIPE,
    }
}

#[inline(always)]
fn check_bounds(ctx: &TcContext, offset: usize, len: usize) -> Result<*const u8, ()> {
    let start = ctx.data();
    let end = ctx.data_end();

    if start + offset + len > end || start + offset < start {
        return Err(());
    }

    Ok((start + offset) as *const u8)
}

struct IpInfo {
    is_v6: u8,
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    tcp_hdr_off: usize,
    ip_payload_len: u32,
}

#[inline(always)]
fn parse_ip(ctx: &TcContext) -> Result<Option<IpInfo>, ()> {
    let eth_proto_ptr = check_bounds(ctx, 12, 2)?;
    let eth_proto = u16::from_be(unsafe { *(eth_proto_ptr as *const u16) });

    if eth_proto == ETH_P_IP {
        let ip_hdr_off = ETH_HDR_LEN;

        let ihl_ptr = check_bounds(ctx, ip_hdr_off, 1)?;
        let ihl = (unsafe { *ihl_ptr } & 0x0f) as usize * 4;
        if ihl < 20 {
            return Ok(None);
        }

        let proto_ptr = check_bounds(ctx, ip_hdr_off + 9, 1)?;
        let ip_proto = unsafe { *proto_ptr };
        if ip_proto != 6 {
            return Ok(None);
        }

        let total_len_ptr = check_bounds(ctx, ip_hdr_off + 2, 2)?;
        let ip_total_len = u16::from_be(unsafe { *(total_len_ptr as *const u16) });

        let src_ptr = check_bounds(ctx, ip_hdr_off + 12, 4)?;
        let dst_ptr = check_bounds(ctx, ip_hdr_off + 16, 4)?;

        let mut src_ip = [0u8; 16];
        let mut dst_ip = [0u8; 16];
        unsafe {
            core::ptr::copy_nonoverlapping(src_ptr, src_ip.as_mut_ptr(), 4);
            core::ptr::copy_nonoverlapping(dst_ptr, dst_ip.as_mut_ptr(), 4);
        }

        if (ip_total_len as usize) < ihl {
            return Ok(None);
        }

        Ok(Some(IpInfo {
            is_v6: 0,
            src_ip,
            dst_ip,
            tcp_hdr_off: ip_hdr_off + ihl,
            ip_payload_len: ip_total_len as u32 - ihl as u32,
        }))
    } else if eth_proto == ETH_P_IPV6 {
        let ip_hdr_off = ETH_HDR_LEN;

        let next_hdr_ptr = check_bounds(ctx, ip_hdr_off + 6, 1)?;
        let ip_proto = unsafe { *next_hdr_ptr };
        if ip_proto != 6 {
            return Ok(None);
        }

        let payload_len_ptr = check_bounds(ctx, ip_hdr_off + 4, 2)?;
        let payload_len = u16::from_be(unsafe { *(payload_len_ptr as *const u16) });

        let src_ptr = check_bounds(ctx, ip_hdr_off + 8, 16)?;
        let dst_ptr = check_bounds(ctx, ip_hdr_off + 24, 16)?;

        let mut src_ip = [0u8; 16];
        let mut dst_ip = [0u8; 16];
        unsafe {
            core::ptr::copy_nonoverlapping(src_ptr, src_ip.as_mut_ptr(), 16);
            core::ptr::copy_nonoverlapping(dst_ptr, dst_ip.as_mut_ptr(), 16);
        }

        Ok(Some(IpInfo {
            is_v6: 1,
            src_ip,
            dst_ip,
            tcp_hdr_off: ip_hdr_off + 40,
            ip_payload_len: payload_len as u32,
        }))
    } else {
        Ok(None)
    }
}

fn try_tc_capture(ctx: TcContext) -> Result<i32, ()> {
    let cfg = CONFIG.get(0).ok_or(())?;

    let ip = match parse_ip(&ctx)? {
        Some(ip) => ip,
        None => return Ok(TC_ACT_PIPE),
    };

    if cfg.is_v6 != ip.is_v6 || ip.dst_ip != cfg.dst_ip {
        return Ok(TC_ACT_PIPE);
    }

    let tcp_hdr_off = ip.tcp_hdr_off;

    let sport_ptr = check_bounds(&ctx, tcp_hdr_off, 2)?;
    let dport_ptr = check_bounds(&ctx, tcp_hdr_off + 2, 2)?;
    let src_port = u16::from_be(unsafe { *(sport_ptr as *const u16) });
    let dst_port = u16::from_be(unsafe { *(dport_ptr as *const u16) });

    if dst_port != u16::from_be(cfg.dst_port) {
        return Ok(TC_ACT_PIPE);
    }

    let seq_ptr = check_bounds(&ctx, tcp_hdr_off + 4, 4)?;
    let seq = u32::from_be(unsafe { *(seq_ptr as *const u32) });

    let doff_ptr = check_bounds(&ctx, tcp_hdr_off + 12, 1)?;
    let doff = ((unsafe { *doff_ptr } >> 4) as usize) * 4;
    if doff < 20 || doff > 60 {
        return Ok(TC_ACT_PIPE);
    }

    let flags_ptr = check_bounds(&ctx, tcp_hdr_off + 13, 1)?;
    let flags = unsafe { *flags_ptr };

    if (ip.ip_payload_len as usize) < doff {
        return Ok(TC_ACT_PIPE);
    }
    let payload_len = ip.ip_payload_len as usize - doff;
    let payload_off = tcp_hdr_off + doff;

    let clamped_len = if payload_len > CHUNK_SIZE {
        CHUNK_SIZE
    } else {
        payload_len
    };

    let mut entry = match EVENTS.reserve::<CaptureEvent>(0) {
        Some(e) => e,
        None => return Ok(TC_ACT_PIPE),
    };

    let event = entry.as_mut_ptr();
    unsafe {
        (*event).timestamp_ns = bpf_ktime_get_ns();
        (*event).src_ip = ip.src_ip;
        (*event).is_v6 = ip.is_v6;
        (*event).src_port = src_port;
        (*event).seq = seq;
        (*event).flags = flags;
        (*event).chunk_len = clamped_len as u16;
        core::ptr::write_bytes((*event).payload.as_mut_ptr(), 0, CHUNK_SIZE);
    }

    if clamped_len > 0 && clamped_len <= CHUNK_SIZE {
        let payload_ptr = unsafe { (*event).payload.as_mut_ptr() as *mut _ };
        let len = clamped_len as u32;
        if len > 0 && len <= CHUNK_SIZE as u32 {
            let ret = unsafe {
                bpf_skb_load_bytes(
                    ctx.skb.skb as *const c_void,
                    payload_off as u32,
                    payload_ptr,
                    len,
                )
            };
            if ret < 0 {
                entry.discard(0);
                return Ok(TC_ACT_PIPE);
            }
        }
    }

    entry.submit(0);
    Ok(TC_ACT_PIPE)
}
