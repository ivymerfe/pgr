use etherparse::{InternetSlice, SlicedPacket, TcpSlice, TransportSlice};
use pcap_parser::{traits::PcapReaderIterator, *};
use std::{collections::HashMap, io::Read, net::SocketAddr};

use crate::capture::{
    frame_buffer::FrameBuffer,
    reader::{CaptureReader, ReadData, ReadError, ReadResult},
    reassembler::Reassembler,
};

#[derive(Default)]
struct PcapClient {
    re: Reassembler,
    fb: FrameBuffer,
}

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
    consume: usize,
    refill: bool,
    handlers: HashMap<SocketAddr, PcapClient>,
    pub first_ts: u64,
    pub packet_count: usize,
    pub bytes_read: usize,
    pub fail_count: usize,
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
            consume: 0,
            refill: false,
            handlers: HashMap::new(),
            first_ts: 0,
            packet_count: 0,
            bytes_read: 0,
            fail_count: 0,
        })
    }
}

impl From<PcapError<&[u8]>> for ReadError {
    fn from(value: PcapError<&[u8]>) -> Self {
        Self::Error(value.to_string())
    }
}

impl<'a> CaptureReader for PcapReader<'a> {
    fn get_buffer(&mut self, addr: SocketAddr) -> Option<&mut FrameBuffer> {
        self.handlers.get_mut(&addr).map(|h| &mut h.fb)
    }

    fn next(&mut self) -> ReadResult<'_> {
        if self.consume > 0 {
            self.pcap.consume_noshift(self.consume);
            self.consume = 0;
        }
        if self.refill {
            self.pcap.refill()?;
            self.refill = false;
        }
        match self.pcap.next() {
            Ok((consumed, block)) => {
                self.bytes_read += consumed;
                self.consume += consumed;
                if let Some(packet) = process_block(block, self.port) {
                    self.packet_count += 1;
                    if self.first_ts == 0 {
                        self.first_ts = packet.ts;
                    }
                    let ts_abs = packet.ts.saturating_sub(self.first_ts);
                    if ts_abs < self.ts_offset {
                        return Err(ReadError::Continue);
                    }
                    let ts_relative = ts_abs - self.ts_offset;
                    if ts_relative > self.max_duration {
                        return Err(ReadError::Eof);
                    }
                    let client = self.handlers.entry(packet.addr).or_default();
                    let tcp = packet.tcp;
                    let fb = &mut client.fb;
                    if tcp.syn() {
                        fb.mark_connection_start();
                    }
                    if client.re.feed(
                        tcp.sequence_number(),
                        tcp.syn(),
                        tcp.payload(),
                        &mut fb.data,
                    ) {
                        return Ok(ReadData {
                            addr: packet.addr,
                            ts: ts_relative,
                            buf: fb,
                        });
                    }
                } else {
                    self.fail_count += 1;
                }
            }
            Err(PcapError::Eof) => return Err(ReadError::Eof),
            Err(PcapError::Incomplete(_sz)) => {
                self.refill = true;
            }
            Err(e) => return Err(e.into()),
        }
        return Err(ReadError::Continue);
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
