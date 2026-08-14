use etherparse::{InternetSlice, SlicedPacket, TcpSlice, TransportSlice};
use pcap_parser::{traits::PcapReaderIterator, *};
use std::{collections::HashMap, io::Read, net::SocketAddr};

use crate::capture::{
    reader::{CaptureData, CaptureReader, ClientId, ReadError, ReadResult},
    reassembler::Reassembler,
};

pub struct TsPacket<'a> {
    pub addr: SocketAddr,
    pub ts: u64,
    pub tcp: TcpSlice<'a>,
}

pub struct PcapReader<'a> {
    pcap: Box<dyn PcapReaderIterator + Send + 'a>,
    port: u16,
    ts_offset: u64,
    max_duration: u64,
    buffer: Vec<u8>,
    reassemblers: HashMap<ClientId, Reassembler>,
    addr_map: HashMap<SocketAddr, ClientId>,
    next_id: u32,
    pub first_ts: u64,
}

impl<'a> PcapReader<'a> {
    pub fn new<R: Read + Send + 'a>(
        reader: R,
        port: u16,
        ts_offset: u64,
        max_duration: u64,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            pcap: create_reader(131072, reader)?,
            port,
            ts_offset,
            max_duration,
            buffer: Vec::new(),
            reassemblers: HashMap::new(),
            addr_map: HashMap::new(),
            next_id: 0,
            first_ts: 0,
        })
    }
}

impl From<PcapError<&[u8]>> for ReadError {
    fn from(value: PcapError<&[u8]>) -> Self {
        Self::Error(value.to_string())
    }
}

impl<'a> CaptureReader for PcapReader<'a> {
    fn next(&mut self) -> ReadResult<'_> {
        loop {
            match self.pcap.next() {
                Ok((consumed, block)) => {
                    if let Some(packet) = process_block(block, self.port) {
                        if self.first_ts == 0 {
                            self.first_ts = packet.ts;
                        }
                        let ts_abs = packet.ts.saturating_sub(self.first_ts);
                        if ts_abs < self.ts_offset {
                            self.pcap.consume_noshift(consumed);
                            continue;
                        }
                        let ts_relative = ts_abs - self.ts_offset;
                        if ts_relative > self.max_duration {
                            return Err(ReadError::Eof);
                        }
                        let addr = packet.addr;
                        let id = *self.addr_map.entry(addr).or_insert_with(|| {
                            let id = self.next_id;
                            self.next_id += 1;
                            id
                        });
                        let tcp = packet.tcp;
                        let re = self.reassemblers.entry(id).or_default();
                        self.buffer.clear();
                        re.feed(
                            tcp.sequence_number(),
                            tcp.syn(),
                            tcp.payload(),
                            &mut self.buffer,
                        );
                        let is_connect = tcp.syn();
                        self.pcap.consume_noshift(consumed);
                        return Ok(CaptureData {
                            id,
                            ts: ts_relative,
                            connect: is_connect,
                            buf: &self.buffer,
                        });
                    }
                    self.pcap.consume_noshift(consumed);
                }
                Err(PcapError::Eof) => return Err(ReadError::Eof),
                Err(PcapError::Incomplete(_sz)) => {
                    self.pcap.refill()?;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
}

pub fn process_block(block: PcapBlockOwned, port: u16) -> Option<TsPacket> {
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
            if let Some((addr, tcp)) = filter_packet(packet, port) {
                return Some(TsPacket { addr, ts, tcp });
            }
        }
    }
    return None;
}

fn filter_packet(packet: SlicedPacket, port: u16) -> Option<(SocketAddr, TcpSlice)> {
    if let Some(TransportSlice::Tcp(tcp)) = packet.transport {
        if tcp.destination_port() != port {
            return None;
        }
        let src_ip = match &packet.net {
            Some(InternetSlice::Ipv4(ipv4)) => std::net::IpAddr::V4(ipv4.header().source_addr()),
            Some(InternetSlice::Ipv6(ipv6)) => std::net::IpAddr::V6(ipv6.header().source_addr()),
            _ => return None,
        };
        let src_port = tcp.source_port();
        let addr = SocketAddr::new(src_ip, src_port);
        Some((addr, tcp))
    } else {
        None
    }
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
