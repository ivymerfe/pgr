use aya_ebpf::{bindings::TC_ACT_PIPE, macros::classifier, programs::TcContext};

use crate::emit::emit_capture;
use crate::global::CONFIG;

const ETH_HDR_LEN: usize = 14;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;

struct IpInfo {
    is_v6: u8,
    src_ip: [u8; 16],
    _dst_ip: [u8; 16],
    tcp_hdr_off: usize,
    ip_payload_len: u32,
}

#[classifier]
pub fn tc_capture(ctx: TcContext) -> i32 {
    match try_tc_capture(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_PIPE,
    }
}

fn try_tc_capture(ctx: TcContext) -> Result<i32, ()> {
    let cfg = CONFIG.get(0).ok_or(())?;

    let ip = match parse_ip(&ctx)? {
        Some(ip) => ip,
        None => return Ok(TC_ACT_PIPE),
    };
    let tcp_hdr_off = ip.tcp_hdr_off;

    let tcp_base = check_bounds(&ctx, tcp_hdr_off, 14)?;
    let src_port = u16::from_be(unsafe { *(tcp_base as *const u16) });
    let dst_port = u16::from_be(unsafe { *(tcp_base.add(2) as *const u16) });

    if dst_port != cfg.dst_port {
        return Ok(TC_ACT_PIPE);
    }
    let seq = u32::from_be(unsafe { *(tcp_base.add(4) as *const u32) });

    let doff = ((unsafe { *tcp_base.add(12) } >> 4) as usize) * 4;
    if doff < 20 || doff > 60 {
        return Ok(TC_ACT_PIPE);
    }
    let flags = unsafe { *tcp_base.add(13) };

    if (ip.ip_payload_len as usize) < doff {
        return Ok(TC_ACT_PIPE);
    }
    let payload_len = ip.ip_payload_len as usize - doff;
    let payload_off = tcp_hdr_off + doff;

    let _ = emit_capture(
        &ctx,
        ip.src_ip,
        ip.is_v6,
        src_port,
        seq,
        flags,
        payload_off,
        payload_len,
    );

    Ok(TC_ACT_PIPE)
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

#[inline(always)]
fn parse_ip(ctx: &TcContext) -> Result<Option<IpInfo>, ()> {
    let eth_proto_ptr = check_bounds(ctx, 12, 2)?;
    let eth_proto = u16::from_be(unsafe { *(eth_proto_ptr as *const u16) });

    if eth_proto == ETH_P_IP {
        let ip_hdr_off = ETH_HDR_LEN;

        let ip_base = check_bounds(ctx, ip_hdr_off, 20)?;

        let ihl = (unsafe { *ip_base } & 0x0f) as usize * 4;
        if ihl < 20 {
            return Ok(None);
        }

        let ip_proto = unsafe { *ip_base.add(9) };
        if ip_proto != 6 {
            return Ok(None);
        }

        let ip_total_len = u16::from_be(unsafe { *(ip_base.add(2) as *const u16) });

        let mut src_ip = [0u8; 16];
        let mut dst_ip = [0u8; 16];
        unsafe {
            core::ptr::copy_nonoverlapping(ip_base.add(12), src_ip.as_mut_ptr(), 4);
            core::ptr::copy_nonoverlapping(ip_base.add(16), dst_ip.as_mut_ptr(), 4);
        }
        if (ip_total_len as usize) < ihl {
            return Ok(None);
        }
        Ok(Some(IpInfo {
            is_v6: 0,
            src_ip,
            _dst_ip: dst_ip,
            tcp_hdr_off: ip_hdr_off + ihl,
            ip_payload_len: ip_total_len as u32 - ihl as u32,
        }))
    } else if eth_proto == ETH_P_IPV6 {
        let ip_hdr_off = ETH_HDR_LEN;

        let ip6_base = check_bounds(ctx, ip_hdr_off, 40)?;

        let ip_proto = unsafe { *ip6_base.add(6) };
        if ip_proto != 6 {
            return Ok(None);
        }

        let payload_len = u16::from_be(unsafe { *(ip6_base.add(4) as *const u16) });

        let mut src_ip = [0u8; 16];
        let mut dst_ip = [0u8; 16];
        unsafe {
            core::ptr::copy_nonoverlapping(ip6_base.add(8), src_ip.as_mut_ptr(), 16);
            core::ptr::copy_nonoverlapping(ip6_base.add(24), dst_ip.as_mut_ptr(), 16);
        }

        Ok(Some(IpInfo {
            is_v6: 1,
            src_ip,
            _dst_ip: dst_ip,
            tcp_hdr_off: ip_hdr_off + 40,
            ip_payload_len: payload_len as u32,
        }))
    } else {
        Ok(None)
    }
}
