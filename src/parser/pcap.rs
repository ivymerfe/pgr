use crate::parser::pq_stream::{PqFrame, PqStream};
use etherparse::{InternetSlice, SlicedPacket, TransportSlice};
use pcap_parser::{traits::PcapReaderIterator, *};
use std::collections::HashMap;
use std::io::Read;
use std::net::SocketAddr;
use tracing::warn;

pub struct CaptureEvent {
    pub addr: SocketAddr,
    pub timestamp: u64,
    pub frame: PqFrame,
}

pub struct CaptureReader<'a> {
    pcap: Box<dyn PcapReaderIterator + Send + 'a>,
    port: u16,
    c2s_buffers: HashMap<SocketAddr, PqStream>,
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
        })
    }

    pub fn read<F>(&mut self, cb: &mut F) -> Result<(), String>
    where
        F: FnMut(CaptureEvent),
    {
        loop {
            match self.pcap.next() {
                Ok((consumed, block)) => {
                    let (packet_data, ts_us) = match block {
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
                            self.pcap.consume(consumed);
                            continue;
                        }
                    };
                    if !packet_data.is_empty() {
                        if let Some(packet) = parse_packet(&packet_data) {
                            CaptureReader::process_packet(
                                &mut self.c2s_buffers,
                                self.port,
                                packet,
                                ts_us,
                                cb,
                            );
                        }
                    }
                    self.pcap.consume(consumed);
                }
                Err(PcapError::Eof) => break,
                Err(PcapError::Incomplete(_sz)) => {
                    if let Err(e) = self.pcap.refill() {
                        return Err(e.to_string());
                    }
                }
                Err(e) => return Err(e.to_string()),
            };
        }
        return Ok(());
    }

    fn process_packet<'b, F>(
        c2s_buffers: &'b mut HashMap<SocketAddr, PqStream>,
        port: u16,
        packet: SlicedPacket,
        timestamp: u64,
        cb: &mut F,
    ) where
        F: FnMut(CaptureEvent),
    {
        let src_ip = match &packet.net {
            Some(InternetSlice::Ipv4(ipv4)) => std::net::IpAddr::V4(ipv4.header().source_addr()),
            Some(InternetSlice::Ipv6(ipv6)) => std::net::IpAddr::V6(ipv6.header().source_addr()),
            _ => return,
        };
        if let Some(TransportSlice::Tcp(tcp)) = &packet.transport {
            let src_port = tcp.source_port();
            let dst_port = tcp.destination_port();
            if dst_port != port {
                return;
            }
            let client = SocketAddr::new(src_ip, src_port);
            let seq = tcp.sequence_number();
            let tcp_payload = tcp.payload();
            let client_stream = c2s_buffers.entry(client).or_default();

            let effective_seq = if tcp.syn() {
                client_stream.set_isn(seq);
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
                return;
            }
            client_stream.ingest(effective_seq, tcp_payload);
            let frame_ts = *client_stream.frame_ts.get_or_insert(timestamp);
            let mut frame_count = 0;

            loop {
                match client_stream.pop_frame() {
                    Ok(None) => break,
                    Ok(Some(frame)) => {
                        cb(CaptureEvent {
                            addr: client,
                            timestamp: frame_ts,
                            frame: frame,
                        });
                        frame_count += 1;
                    }
                    Err(_corrupt) => {
                        warn!("Corrupted stream -> resync");
                        client_stream.resync(true);
                        if client_stream.len() < 5 {
                            break;
                        }
                    }
                }
            }
            if frame_count > 0 {
                client_stream.frame_ts.take();
            }
        }
    }
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
