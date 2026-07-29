use crate::parser::pq_stream::PqStream;

use etherparse::{InternetSlice, SlicedPacket, TcpSlice, TransportSlice};
use pcap_parser::{traits::PcapReaderIterator, *};
use std::collections::HashMap;
use std::io::Read;
use std::net::SocketAddr;

pub enum ReadState<'a> {
    Ok(&'a mut PqStream),
    Eof,
    RefillFail(String),
    ReadFail(String),
}

struct PacketInfo<'a> {
    addr: SocketAddr,
    ts: u64,
    tcp: TcpSlice<'a>,
}

pub struct CaptureReader<'a> {
    pcap: Box<dyn PcapReaderIterator + Send + 'a>,
    port: u16,
    pub streams: HashMap<SocketAddr, PqStream>,
    pub packets_read: usize,
    pub bytes_read: usize,
}

impl<'a> CaptureReader<'a> {
    pub fn new<R: Read + Send + 'a>(
        reader: R,
        port: u16,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            pcap: create_reader(131072, reader)?,
            port,
            streams: HashMap::new(),
            packets_read: 0,
            bytes_read: 0,
        })
    }

    pub fn get_stream(&mut self, addr: &SocketAddr) -> Option<&mut PqStream> {
        return self.streams.get_mut(addr);
    }

    pub fn next(&mut self) -> ReadState<'_> {
        loop {
            match self.pcap.next() {
                Ok((consumed, block)) => {
                    self.bytes_read += consumed;
                    if let Some(info) = process_block(block, self.port) {
                        if !info.tcp.payload().is_empty() {
                            self.packets_read += 1;
                        }
                        let stream = process_packet(info, &mut self.streams);
                        self.pcap.consume_noshift(consumed);
                        return ReadState::Ok(stream);
                    }
                    self.pcap.consume_noshift(consumed);
                }
                Err(PcapError::Eof) => {
                    return ReadState::Eof;
                }
                Err(PcapError::Incomplete(_sz)) => {
                    if let Err(e) = self.pcap.refill() {
                        return ReadState::RefillFail(e.to_string());
                    }
                }
                Err(e) => return ReadState::ReadFail(e.to_string()),
            };
        }
    }
}

fn process_packet<'a, 'b>(
    info: PacketInfo<'b>,
    buffers: &'a mut HashMap<SocketAddr, PqStream>,
) -> &'a mut PqStream {
    let client = info.addr;
    let tcp = info.tcp;
    let seq = tcp.sequence_number();
    let tcp_payload = tcp.payload();
    let stream = buffers
        .entry(client)
        .or_insert_with(|| PqStream::new(client));

    let effective_seq = if tcp.syn() {
        stream.set_isn(seq);
        // RFC 793
        seq.wrapping_add(1)
    } else {
        seq
    };
    stream.ingest(effective_seq, tcp_payload, info.ts);
    stream.sync(true);
    return stream;
}

fn process_block(block: PcapBlockOwned, port: u16) -> Option<PacketInfo> {
    let (packet_data, ts) = match block {
        PcapBlockOwned::Legacy(p) => {
            let ts = (p.ts_sec as u64) * 1_000_000 + (p.ts_usec as u64);
            (p.data, ts)
        }
        PcapBlockOwned::NG(Block::EnhancedPacket(p)) => {
            let ts = ((p.ts_high as u64) << 32) | (p.ts_low as u64);
            (p.data, ts)
        }
        PcapBlockOwned::NG(Block::SimplePacket(p)) => (p.data, 0),
        _ => {
            return None;
        }
    };
    if !packet_data.is_empty() {
        if let Some(packet) = parse_packet(&packet_data) {
            return filter_packet(packet, ts, port);
        }
    }
    return None;
}

fn filter_packet(packet: SlicedPacket<'_>, ts: u64, tcp_port: u16) -> Option<PacketInfo<'_>> {
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
