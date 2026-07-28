use crate::parser::pq_stream::PqStream;

use core::fmt;
use etherparse::{InternetSlice, SlicedPacket, TcpSlice, TransportSlice};
use pcap_parser::{traits::PcapReaderIterator, *};
use std::collections::HashMap;
use std::error::Error;
use std::io::Read;
use std::net::SocketAddr;
use tracing::info;

#[derive(Debug)]
pub enum ReadError {
    Continue,
    Eof,
    RefillFail(String),
    ReadFail(String),
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadError::Continue => write!(f, "operation needs to continue"),
            ReadError::Eof => write!(f, "reached end of file"),
            ReadError::RefillFail(msg) => write!(f, "failed to refill buffer: {msg}"),
            ReadError::ReadFail(msg) => write!(f, "failed to read data: {msg}"),
        }
    }
}

impl Error for ReadError {}

pub struct CaptureReader<'a> {
    pcap: Box<dyn PcapReaderIterator + Send + 'a>,
    port: u16,
    c2s_buffers: HashMap<SocketAddr, PqStream>,
    next_consume: usize,
}

impl<'a> CaptureReader<'a> {
    pub fn new<R: Read + Send + 'a>(
        reader: R,
        port: u16,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            pcap: create_reader(131072, reader)?,
            port,
            c2s_buffers: HashMap::new(),
            next_consume: 0,
        })
    }

    pub fn next(&mut self) -> Result<&mut PqStream, ReadError> {
        if self.next_consume > 0 {
            self.pcap.consume(self.next_consume);
            self.next_consume = 0;
        }
        match self.pcap.next() {
            Ok((consumed, block)) => {
                self.next_consume = consumed;

                let (packet_data, ts) = match block {
                    PcapBlockOwned::Legacy(p) => {
                        let ts = (p.ts_sec as u64) * 1_000_000 + (p.ts_usec as u64);
                        (p.data, ts)
                    }
                    PcapBlockOwned::NG(Block::EnhancedPacket(p)) => {
                        // EPB timestamp resolution depends on option block,
                        // default is usually 10^-6 seconds (microseconds)
                        let ts = ((p.ts_high as u64) << 32) | (p.ts_low as u64);
                        (p.data, ts)
                    }
                    PcapBlockOwned::NG(Block::SimplePacket(p)) => {
                        (p.data, 0) // Simple Packet blocks lack timestamps
                    }
                    _ => {
                        return Err(ReadError::Continue);
                    }
                };
                if !packet_data.is_empty() {
                    if let Some(packet) = parse_packet(&packet_data) {
                        if let Some(info) = filter_packet(packet, ts, self.port) {
                            if let Some(stream) = process_packet(&mut self.c2s_buffers, info) {
                                return Ok(stream);
                            }
                        }
                    }
                }
                return Err(ReadError::Continue);
            }
            Err(PcapError::Eof) => Err(ReadError::Eof),
            Err(PcapError::Incomplete(_sz)) => {
                if let Err(e) = self.pcap.refill() {
                    return Err(ReadError::RefillFail(e.to_string()));
                }
                Err(ReadError::Continue)
            }
            Err(e) => Err(ReadError::ReadFail(e.to_string())),
        }
    }
}

fn process_packet<'b>(
    c2s_buffers: &'b mut HashMap<SocketAddr, PqStream>,
    info: PacketInfo,
) -> Option<&'b mut PqStream> {
    let client = info.addr;
    let tcp = info.tcp;
    let seq = tcp.sequence_number();
    let tcp_payload = tcp.payload();
    let stream = c2s_buffers
        .entry(client)
        .or_insert_with(|| PqStream::new(client));
    stream.set_ts(info.ts);

    let effective_seq = if tcp.syn() {
        stream.set_isn(seq);
        // RFC 793: when SYN is set, `seq` is the ISN itself and the
        // first data octet is ISN+1, even though a data-bearing SYN
        // (rare; some TFO setups) carries its payload immediately
        // after the TCP header on the wire. Offsetting here keeps
        // the sequence math exact instead of relying on `ingest`'s
        // overlap-trim path to paper over an off-by-one.
        seq.wrapping_add(1)
    } else {
        seq
    };
    if tcp_payload.is_empty() {
        return None;
    }
    stream.ingest(effective_seq, tcp_payload);
    return Some(stream);
}

struct PacketInfo<'a> {
    addr: SocketAddr,
    ts: u64,
    tcp: TcpSlice<'a>,
}

fn filter_packet<'a>(packet: SlicedPacket<'a>, ts: u64, tcp_port: u16) -> Option<PacketInfo<'a>> {
    let src_ip = match &packet.net {
        Some(InternetSlice::Ipv4(ipv4)) => std::net::IpAddr::V4(ipv4.header().source_addr()),
        Some(InternetSlice::Ipv6(ipv6)) => std::net::IpAddr::V6(ipv6.header().source_addr()),
        _ => return None,
    };
    if let Some(TransportSlice::Tcp(tcp)) = packet.transport {
        let src_port = tcp.source_port();
        let dst_port = tcp.destination_port();
        if dst_port != tcp_port {
            return None;
        }
        let addr = SocketAddr::new(src_ip, src_port);
        return Some(PacketInfo { addr, ts, tcp });
    }
    None
}

fn parse_packet<'a>(packet_data: &'a [u8]) -> Option<SlicedPacket<'a>> {
    if packet_data.len() > 20 {
        let protocol = u16::from_be_bytes([packet_data[0], packet_data[1]]);

        // 0x86DD = IPv6, 0x0800 = IPv4
        if protocol == 0x86DD || protocol == 0x0800 {
            // Skip the 20-byte SLL2 header and parse the underlying IP packet
            if let Ok(p) = SlicedPacket::from_ip(&packet_data[20..]) {
                return Some(p);
            }
        }
    }
    if let Ok(p) = SlicedPacket::from_ethernet(packet_data) {
        return Some(p);
    }
    if let Ok(p) = SlicedPacket::from_linux_sll(packet_data) {
        return Some(p);
    }
    if let Ok(p) = SlicedPacket::from_ip(packet_data) {
        return Some(p);
    }
    None
}
