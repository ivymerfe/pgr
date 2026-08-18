use ahash::AHashMap;
use aya::Ebpf;
use aya::maps::{Array, MapData, RingBuf};
use aya::programs::{SchedClassifier, TcAttachType, tc};

use aya_log::EbpfLogger;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;

use capture_common::{CHUNK_SIZE, CaptureEvent, Config};
use tracing::{error, info};

use crate::capture::acap::AcapWriter;
use crate::capture::reassembler::Reassembler;
use crate::utils::waker::Waker;

const TCP_FLAG_SYN: u8 = 0x02;

pub struct CaptureHandle {
    pub _ebpf: Ebpf,
    pub buf: RingBuf<MapData>,
    pub baseline_ns: u64,
    pub stop_waker: Arc<Waker>,
}

pub fn run_capture(writer: AcapWriter, interface: &str, port: u16, poll_timeout: i32) -> anyhow::Result<()> {
    let capture = start_capture(interface, port)?;
    info!("Capture started");

    let waker = capture.stop_waker.clone();
    ctrlc::set_handler(move || {
        if let Err(e) = waker.wake() {
            error!("Failed to stop capture: {e}");
        }
    })
    .expect("Error setting Ctrl-C handler");

    write_capture(capture, writer, poll_timeout);
    Ok(())
}

fn start_capture(iface: &str, dst_port: u16) -> anyhow::Result<CaptureHandle> {
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/target/bpfel-unknown-none/release/capture-ebpf"
    )))?;
    let mut config: Array<_, Config> = Array::try_from(ebpf.map_mut("CONFIG").unwrap())?;
    config.set(0, Config { dst_port }, 0)?;

    let _ = tc::qdisc_add_clsact(iface);
    let program: &mut SchedClassifier = ebpf.program_mut("tc_capture").unwrap().try_into()?;
    program.load()?;
    program.attach(iface, TcAttachType::Ingress)?;

    let ring_buf = RingBuf::try_from(ebpf.take_map("EVENTS").unwrap())?;
    let baseline_ns = monotonic_ns();
    info!("Loaded program");

    let stop_waker = Arc::new(Waker::new()?);

    let mut logger = EbpfLogger::init(&mut ebpf).unwrap();
    let logger_fd = logger.as_raw_fd();
    let logger_stop = stop_waker.dup()?;

    std::thread::spawn(move || {
        let mut fds = [
            libc::pollfd {
                fd: logger_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: logger_stop.fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        loop {
            fds[0].revents = 0;
            fds[1].revents = 0;
            let ret = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
            if fds[1].revents & libc::POLLIN != 0 {
                break;
            }
            if fds[0].revents & libc::POLLIN != 0 {
                logger.flush();
            }
        }
    });
    Ok(CaptureHandle {
        _ebpf: ebpf,
        buf: ring_buf,
        baseline_ns,
        stop_waker,
    })
}

struct CaptureClient {
    id: u32,
    re: Reassembler,
    buf: Vec<u8>,
}

fn write_capture(capture: CaptureHandle, mut writer: AcapWriter, poll_timeout: i32) {
    let mut buf = capture.buf;
    let event_size = std::mem::size_of::<CaptureEvent>();
    let fd = buf.as_raw_fd();
    let mut clients = AHashMap::new();
    let mut next_client_id = 0;
    let mut total_recv = 0;

    let mut pfd = [
        libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: capture.stop_waker.fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];

    'outer: loop {
        pfd[0].revents = 0;
        pfd[1].revents = 0;
        let ret = unsafe { libc::poll(pfd.as_mut_ptr(), 2, poll_timeout) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            error!("ring buffer poll error: {err}");
            break;
        }

        if pfd[1].revents & libc::POLLIN != 0 {
            break;
        }

        if pfd[0].revents & libc::POLLIN != 0 {
            while let Some(item) = buf.next() {
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
                let src_port = event.src_port;
                let addr = SocketAddr::new(ip, src_port);
                let is_syn = event.flags & TCP_FLAG_SYN != 0;
                let ts = (event.timestamp_ns.saturating_sub(capture.baseline_ns) / 1000) as u32;

                let client = clients.entry(addr).or_insert_with(|| {
                    let id = next_client_id;
                    next_client_id += 1;
                    if let Err(e) = writer.write_addr(&addr) {
                        error!(
                            "Failed to write client addr: {e}, id = {} addr = {}",
                            id, addr
                        );
                    }
                    CaptureClient {
                        id,
                        re: Reassembler::default(),
                        buf: Vec::with_capacity(16384),
                    }
                });
                let cbuf = &mut client.buf;
                cbuf.clear();

                if is_syn {
                    if let Err(e) = writer.write(client.id, ts, &[]) {
                        error!("Failed to write capture: {e}");
                        break 'outer;
                    }
                }
                total_recv += payload.len();
                if client.re.feed(event.seq, is_syn, payload, cbuf) {
                    if !cbuf.is_empty() {
                        if let Err(e) = writer.write(client.id, ts, &cbuf) {
                            error!("Failed to write capture: {e}");
                            break 'outer;
                        }
                    }
                }
            }
        }
    }
    if let Err(e) = writer.finish() {
        error!("Failed to finish writing: {e}");
    }
    info!("Received: {}", total_recv);
}

fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}
