use etherparse::{InternetSlice, SlicedPacket, TcpSlice, TransportSlice};
use pcap_parser::{traits::PcapReaderIterator, *};
use std::{io::Read, net::SocketAddr};

pub enum ReadState<'a> {
    Ok(TsPacket<'a>),
    Continue,
    Eof,
    RefillFail(String),
    ReadFail(String),
}

pub struct TsPacket<'a> {
    pub addr: SocketAddr,
    pub ts: u64,
    pub tcp: TcpSlice<'a>,
}

pub struct CaptureReader<'a> {
    pcap: Box<dyn PcapReaderIterator + Send + 'a>,
    consume: usize,
    refill: bool,
    pub bytes_read: usize,
}

impl<'a> CaptureReader<'a> {
    pub fn new<R: Read + Send + 'a>(reader: R) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            pcap: create_reader(131072, reader)?,
            consume: 0,
            refill: false,
            bytes_read: 0,
        })
    }

    pub fn next(&mut self) -> ReadState<'_> {
        if self.consume > 0 {
            self.pcap.consume_noshift(self.consume);
            self.consume = 0;
        }
        if self.refill {
            if let Err(e) = self.pcap.refill() {
                return ReadState::RefillFail(e.to_string());
            }
            self.refill = false;
        }
        match self.pcap.next() {
            Ok((consumed, block)) => {
                self.bytes_read += consumed;
                self.consume += consumed;
                if let Some(packet) = process_block(block) {
                    return ReadState::Ok(packet);
                }
            }
            Err(PcapError::Eof) => return ReadState::Eof,
            Err(PcapError::Incomplete(_sz)) => {
                self.refill = true;
            }
            Err(e) => return ReadState::ReadFail(e.to_string()),
        }
        return ReadState::Continue;
    }
}

pub fn process_block(block: PcapBlockOwned) -> Option<TsPacket> {
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
            if let Some((addr, tcp)) = filter_packet(packet) {
                return Some(TsPacket { addr, ts, tcp });
            }
        }
    }
    return None;
}

fn filter_packet(packet: SlicedPacket) -> Option<(SocketAddr, TcpSlice)> {
    let src_ip = match &packet.net {
        Some(InternetSlice::Ipv4(ipv4)) => std::net::IpAddr::V4(ipv4.header().source_addr()),
        Some(InternetSlice::Ipv6(ipv6)) => std::net::IpAddr::V6(ipv6.header().source_addr()),
        _ => return None,
    };
    if let Some(TransportSlice::Tcp(tcp)) = packet.transport {
        let src_port = tcp.source_port();
        let addr = SocketAddr::new(src_ip, src_port);
        return Some((addr, tcp));
    }
    None
}

fn parse_packet(packet_data: &'_ [u8]) -> Option<SlicedPacket<'_>> {
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
