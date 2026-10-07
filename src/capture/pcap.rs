use etherparse::{InternetSlice, SlicedPacket, TcpSlice, TransportSlice};
use pcap_parser::{
    Block, Linktype, PcapBlockOwned, PcapError, create_reader, traits::PcapReaderIterator,
};
use std::{
    collections::{HashMap, VecDeque},
    io::Read,
    net::SocketAddr,
};

use crate::capture::{
    frame_buffer::FrameBuffer,
    reader::{CaptureEvent, CaptureMessage, CaptureReader, ClientId, ReadError, ReadResult},
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
    buffers: HashMap<ClientId, FrameBuffer>,
    addr_map: HashMap<SocketAddr, ClientId>,
    next_id: u32,
    pub first_ts: u64,
    messages: VecDeque<CaptureMessage>,

    interfaces: Vec<Linktype>,
    legacy_linktype: Option<Linktype>,
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
            buffers: HashMap::new(),
            addr_map: HashMap::new(),
            next_id: 0,
            first_ts: 0,
            messages: VecDeque::new(),
            interfaces: Vec::new(),
            legacy_linktype: None,
        })
    }

    pub fn read_pcap(&mut self) -> Result<(), ReadError> {
        loop {
            match self.pcap.next() {
                Ok((consumed, block)) => {
                    let packet_info = match &block {
                        PcapBlockOwned::LegacyHeader(hdr) => {
                            self.legacy_linktype = Some(hdr.network);
                            None
                        }
                        PcapBlockOwned::Legacy(p) => {
                            let ts = (p.ts_sec as u64) * 1_000_000 + (p.ts_usec as u64);
                            let linktype = self.legacy_linktype.unwrap_or(Linktype::NULL);
                            Some((p.data, linktype, ts))
                        }
                        PcapBlockOwned::NG(Block::InterfaceDescription(idb)) => {
                            self.interfaces.push(idb.linktype);
                            None
                        }
                        PcapBlockOwned::NG(Block::EnhancedPacket(p)) => {
                            let ts = ((p.ts_high as u64) << 32) | (p.ts_low as u64);
                            let if_id = p.if_id as usize;
                            let linktype = self
                                .interfaces
                                .get(if_id)
                                .copied()
                                .unwrap_or(Linktype::NULL);
                            Some((p.data, linktype, ts))
                        }
                        PcapBlockOwned::NG(Block::SimplePacket(p)) => {
                            let linktype =
                                self.interfaces.first().copied().unwrap_or(Linktype::NULL);
                            Some((p.data, linktype, 0))
                        }
                        _ => None,
                    };
                    if let Some((packet_data, linktype, ts)) = packet_info {
                        if let Some(packet) = process_packet(packet_data, linktype, ts, self.port) {
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
                            let next_id = self.next_id;
                            let id = *self.addr_map.entry(addr).or_insert_with(|| {
                                let assigned = next_id;
                                self.next_id += 1;
                                assigned
                            });

                            let tcp = packet.tcp;
                            if tcp.syn() {
                                let msg = CaptureMessage {
                                    client: id,
                                    ts: ts_relative,
                                    event: CaptureEvent::Connect,
                                };
                                self.messages.push_back(msg);
                            }
                            if tcp.fin() {
                                let msg = CaptureMessage {
                                    client: id,
                                    ts: ts_relative,
                                    event: CaptureEvent::Disconnect,
                                };
                                self.messages.push_back(msg);
                            }
                            let buf = self
                                .buffers
                                .entry(id)
                                .or_insert_with(|| FrameBuffer::new(id));
                            buf.on_capture(
                                ts_relative,
                                tcp.sequence_number(),
                                tcp.syn(),
                                tcp.payload(),
                            );
                            while let Some(info) = buf.frames.pop_front() {
                                let msg = CaptureMessage {
                                    client: id,
                                    ts: info.ts,
                                    event: CaptureEvent::PqFrame {
                                        tag: info.tag,
                                        offset: info.offset,
                                        frame: buf.read_frame(&info).to_vec(),
                                    },
                                };
                                self.messages.push_back(msg);
                            }
                            self.pcap.consume_noshift(consumed);
                            return Ok(());
                        }
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

impl From<PcapError<&[u8]>> for ReadError {
    fn from(value: PcapError<&[u8]>) -> Self {
        Self::Error(value.to_string())
    }
}

impl<'a> CaptureReader for PcapReader<'a> {
    fn next(&mut self) -> ReadResult {
        while self.messages.is_empty() {
            self.read_pcap()?;
        }
        if let Some(msg) = self.messages.pop_front() {
            Ok(msg)
        } else {
            Err(ReadError::Eof)
        }
    }
}

pub fn process_packet<'a>(
    packet_data: &'a [u8],
    linktype: Linktype,
    ts: u64,
    port: u16,
) -> Option<TsPacket<'a>> {
    if !packet_data.is_empty() {
        if let Some(packet) = parse_packet_by_linktype(packet_data, linktype) {
            if let Some((addr, tcp)) = filter_packet(packet, port) {
                return Some(TsPacket { addr, ts, tcp });
            }
        }
    }
    None
}

fn parse_packet_by_linktype<'a>(data: &'a [u8], linktype: Linktype) -> Option<SlicedPacket<'a>> {
    match linktype {
        Linktype::ETHERNET => SlicedPacket::from_ethernet(data).ok(),

        Linktype::NULL => {
            if data.len() < 4 {
                return None;
            }
            let family = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
            if family == 2 || family == 24 || family == 30 {
                SlicedPacket::from_ip(&data[4..]).ok()
            } else {
                None
            }
        }

        Linktype::RAW => SlicedPacket::from_ip(data).ok(),

        Linktype::LINUX_SLL => SlicedPacket::from_linux_sll(data).ok(),

        Linktype(149) => {
            if data.len() >= 8 && &data[0..4] == b"PKT1" {
                let pkt_len = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
                if data.len() > pkt_len {
                    let payload = &data[pkt_len..];
                    return SlicedPacket::from_ethernet(payload)
                        .or_else(|_| SlicedPacket::from_ip(payload))
                        .ok();
                }
            }
            None
        }

        _ => SlicedPacket::from_ip(data)
            .or_else(|_| SlicedPacket::from_ethernet(data))
            .ok(),
    }
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
