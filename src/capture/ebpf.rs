use aya::Ebpf;
use aya::maps::{Array, RingBuf};
use aya::programs::{SchedClassifier, TcAttachType, tc};

use crossbeam_channel::{Receiver, Sender};

use tokio::io::Interest;
use tokio_util::sync::CancellationToken;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::io::AsRawFd;

use tokio::io::unix::AsyncFd;

use capture_common::{CHUNK_SIZE, CaptureEvent, Config};
use tracing::{error, info};

use crate::capture::reassembler::Reassembler;

const TCP_FLAG_SYN: u8 = 0x02;

pub struct WireEvent {
    pub addr: SocketAddr,
    pub ts: u32,
    pub data: Vec<u8>,
}

pub struct CaptureHandle {
    pub ebpf: Ebpf,
    pub token: CancellationToken,
}

pub async fn start_capture(
    iface: &str,
    dst_ip: IpAddr,
    dst_port: u16,
) -> Result<(CaptureHandle, Receiver<WireEvent>), Box<dyn std::error::Error>> {
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/capture-ebpf"
    )))?;
    let mut config: Array<_, Config> = Array::try_from(ebpf.map_mut("CONFIG").unwrap())?;
    config.set(0, parse_dst(dst_ip, dst_port), 0)?;

    let _ = tc::qdisc_add_clsact(iface);
    let program: &mut SchedClassifier = ebpf.program_mut("tc_capture").unwrap().try_into()?;
    program.load()?;
    program.attach(iface, TcAttachType::Ingress)?;

    let ring_buf = RingBuf::try_from(ebpf.take_map("EVENTS").unwrap())?;
    let baseline_ns = monotonic_ns();
    info!("Loaded program");

    let (tx, rx) = crossbeam_channel::unbounded();
    let shutdown = CancellationToken::new();
    tokio::spawn(reader_loop(ring_buf, tx, baseline_ns, shutdown.clone()));

    Ok((
        CaptureHandle {
            ebpf,
            token: shutdown,
        },
        rx,
    ))
}

#[derive(Default)]
struct CaptureClient {
    re: Reassembler,
    buf: Vec<u8>,
}

async fn reader_loop(
    ring_buf: RingBuf<aya::maps::MapData>,
    tx: Sender<WireEvent>,
    baseline_ns: u64,
    shutdown: CancellationToken,
) {
    let event_size = std::mem::size_of::<CaptureEvent>();
    let fd = ring_buf.as_raw_fd();

    let mut async_fd = match AsyncFd::with_interest(ring_buf, Interest::READABLE) {
        Ok(f) => f,
        Err(e) => {
            error!("failed to register ring buffer fd {fd}: {e}");
            return;
        }
    };
    let mut clients: HashMap<SocketAddr, CaptureClient> = HashMap::new();

    loop {
        let mut guard = tokio::select! {
            _ = shutdown.cancelled() => {
                return;
            }
            readable = async_fd.readable_mut() => {
                match readable {
                    Ok(g) => g,
                    Err(e) => {
                        error!("ring buffer poll error: {e}");
                        return;
                    }
                }
            }
        };
        let rb = guard.get_inner_mut();
        while let Some(item) = rb.next() {
            let bytes = &*item;
            if bytes.len() < event_size {
                continue;
            }
            let event = unsafe { &*(bytes.as_ptr() as *const CaptureEvent) };

            let chunk_len = std::cmp::min(event.chunk_len as usize, CHUNK_SIZE);
            let payload = &event.payload[..chunk_len];

            let ip: IpAddr = if event.is_v6 != 0 {
                IpAddr::V6(Ipv6Addr::from(event.src_ip))
            } else {
                let mut v4 = [0u8; 4];
                v4.copy_from_slice(&event.src_ip[0..4]);
                IpAddr::V4(Ipv4Addr::from(v4))
            };
            let src_port = u16::from_be(event.src_port);
            let addr = SocketAddr::new(ip, src_port);
            let is_syn = event.flags & TCP_FLAG_SYN != 0;
            let ts = (event.timestamp_ns.saturating_sub(baseline_ns) / 1000) as u32;

            let client = clients.entry(addr).or_default();
            let buf = &mut client.buf;
            buf.clear();

            if is_syn {
                let wire = WireEvent {
                    addr,
                    ts,
                    data: Vec::new(),
                };
                if tx.try_send(wire).is_err() {
                    error!("channel full, dropping event");
                }
            }
            if client.re.feed(event.seq, is_syn, payload, buf) {
                if buf.len() > 0 {
                    let wire = WireEvent {
                        addr,
                        ts,
                        data: buf.clone(),
                    };
                    if tx.try_send(wire).is_err() {
                        error!("channel full, dropping event");
                    }
                }
            }
        }
        guard.clear_ready();
    }
}

fn parse_dst(ip: IpAddr, port: u16) -> Config {
    match ip {
        IpAddr::V4(v4) => {
            let mut buf = [0u8; 16];
            buf[0..4].copy_from_slice(&v4.octets());
            Config {
                dst_ip: buf,
                is_v6: 0,
                _pad: [0; 3],
                dst_port: port.to_be(),
            }
        }
        IpAddr::V6(v6) => Config {
            dst_ip: v6.octets(),
            is_v6: 1,
            _pad: [0; 3],
            dst_port: port.to_be(),
        },
    }
}

fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}
