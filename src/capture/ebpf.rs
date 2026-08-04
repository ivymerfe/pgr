use aya::Ebpf;
use aya::maps::{Array, RingBuf};
use aya::programs::{SchedClassifier, TcAttachType, tc};
use tokio::io::Interest;
use tokio_util::sync::CancellationToken;

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::io::AsRawFd;

use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{self, Receiver, Sender};

use capture_common::{CHUNK_SIZE, CaptureEvent, Config};
use tracing::{error, info};

const TCP_FLAG_SYN: u8 = 0x02;

pub struct WireEvent {
    pub addr: SocketAddr,
    pub relative_ts_us: u32,
    pub len: u32,
    pub payload: Vec<u8>,
}

struct Reassembler {
    next_seq: Option<u32>,
    out_of_order: BTreeMap<u32, Vec<u8>>,
}

impl Reassembler {
    fn new() -> Self {
        Self {
            next_seq: None,
            out_of_order: BTreeMap::new(),
        }
    }

    fn feed(&mut self, seq: u32, is_syn: bool, mut data: &[u8]) -> Option<Vec<u8>> {
        if is_syn {
            self.next_seq = Some(seq.wrapping_add(1));
            if data.is_empty() {
                return None;
            }
        }

        let next_seq = match self.next_seq {
            Some(n) => n,
            None => {
                self.next_seq = Some(seq);
                seq
            }
        };

        let mut seq = seq;

        let delta = next_seq.wrapping_sub(seq) as i32;
        if delta > 0 {
            let delta = delta as usize;
            if delta >= data.len() {
                return None;
            }
            data = &data[delta..];
            seq = next_seq;
        }

        if seq == next_seq {
            let mut out = data.to_vec();
            let mut cur = next_seq.wrapping_add(data.len() as u32);

            while let Some((&buf_seq, _)) = self.out_of_order.range(cur..).next() {
                if buf_seq != cur {
                    break;
                }
                let buf = self.out_of_order.remove(&buf_seq).unwrap();
                cur = cur.wrapping_add(buf.len() as u32);
                out.extend_from_slice(&buf);
            }

            self.next_seq = Some(cur);
            if out.is_empty() { None } else { Some(out) }
        } else {
            self.out_of_order.insert(seq, data.to_vec());
            None
        }
    }
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

    let (tx, rx) = mpsc::channel::<WireEvent>(65536);
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

    let mut reassemblers: HashMap<SocketAddr, Reassembler> = HashMap::new();

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
            let reassembler = reassemblers.entry(addr).or_insert_with(Reassembler::new);

            if let Some(ordered) = reassembler.feed(event.seq, is_syn, payload) {
                let relative_ts_us = (event.timestamp_ns.saturating_sub(baseline_ns) / 1000) as u32;
                let wire = WireEvent {
                    addr,
                    relative_ts_us,
                    len: ordered.len() as u32,
                    payload: ordered,
                };
                if tx.try_send(wire).is_err() {
                    error!("channel full, dropping event");
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
