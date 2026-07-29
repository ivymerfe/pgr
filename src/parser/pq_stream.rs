use std::{collections::BTreeMap, net::SocketAddr};

use tracing::warn;

pub struct PqStream {
    buf: Vec<u8>,
    head: usize,
    packet_head: usize,
    drained: usize,
    next_seq: Option<u32>,
    reorder: BTreeMap<u32, Vec<u8>>,
    packet_ts: Option<u64>,
    pub addr: SocketAddr,
}

pub struct PqFrame<'a> {
    pub tag: u8,
    pub offset: usize,
    pub payload: &'a [u8],
}

impl PqStream {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            buf: Vec::new(),
            head: 0,
            packet_head: 0,
            drained: 0,
            next_seq: None,
            reorder: BTreeMap::new(),
            addr,
            packet_ts: None,
        }
    }

    pub fn set_isn(&mut self, syn_seq: u32) {
        if self.next_seq.is_none() {
            self.next_seq = Some(syn_seq.wrapping_add(1));
        }
    }

    pub fn ingest(&mut self, seq: u32, payload: &[u8], ts: u64) {
        if payload.is_empty() {
            return;
        }
        let next = match self.next_seq {
            None => {
                self.next_seq = Some(seq);
                seq
            }
            Some(n) => n,
        };

        let delta = seq.wrapping_sub(next) as i32;

        if delta == 0 {
            self.packet_ts = Some(ts);
            self.packet_head = self.buf.len();

            self.buf.extend_from_slice(payload);

            let mut new_next = next.wrapping_add(payload.len() as u32);
            while let Some(pending) = self.reorder.remove(&new_next) {
                new_next = new_next.wrapping_add(pending.len() as u32);
                self.buf.extend_from_slice(&pending);
            }
            self.next_seq = Some(new_next);
        } else if delta < 0 {
            let overlap = (-delta) as usize;
            if overlap < payload.len() {
                self.ingest(next, &payload[overlap..], ts);
            }
        } else {
            self.reorder.insert(seq, payload.to_vec());
        }
    }

    pub fn len(&self) -> usize {
        self.buf.len().saturating_sub(self.head)
    }

    pub fn offset(&self) -> usize {
        self.drained + self.head
    }

    pub fn read_ts(&mut self) -> Option<u64> {
        return self.packet_ts;
    }

    pub fn take_ts(&mut self) -> Option<u64> {
        return self.packet_ts.take();
    }

    pub fn read_packet(&self) -> Option<&[u8]> {
        let head = self.head.max(self.packet_head);
        if self.buf.len() - head < 5 {
            return None;
        }
        return Some(&self.buf[head..]);
    }

    pub fn read_tag(&self) -> u8 {
        return self.buf[self.head];
    }

    pub fn read_frame(&self) -> Option<(usize, PqFrame<'_>)> {
        if self.len() < 4 {
            return None;
        }
        let buf = &self.buf[self.head..];

        let (tag, frame_offset, frame_length) = if buf[0] == 0x00 {
            // 1. Headerless messages (SSLRequest, StartupMessage, CancelRequest)
            let length = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
            if !(8..=10_000_000).contains(&length) {
                return None;
            }
            if buf.len() < length {
                return None;
            }
            (0, 4, length)
        } else {
            // 2. [Tag: 1 byte][Length: 4 bytes][Payload: Length - 4]
            if buf.len() < 5 {
                return None;
            }
            let length = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
            if !(4..=10_000_000).contains(&length) {
                return None;
            }
            let frame_length = 1 + length;
            if buf.len() < frame_length {
                return None;
            }
            (buf[0], 5, frame_length)
        };
        let buf = &self.buf[self.head..self.head + frame_length];
        let frame = PqFrame {
            tag,
            offset: frame_offset,
            payload: buf,
        };
        return Some((frame_length, frame));
    }

    fn compact_if_needed(&mut self) {
        if self.head > 65_536 && self.head >= self.buf.len() / 2 {
            self.buf.drain(0..self.head);
            self.head = 0;
            self.packet_head = self.packet_head.saturating_sub(self.head);
            self.drained += self.head;
        }
    }

    pub fn consume(&mut self, length: usize) {
        self.head += length;
        self.compact_if_needed();
    }

    pub fn sync(&mut self, is_frontend: bool) {
        let valid_tags: &[u8] = if is_frontend {
            b"QPBDECfcpSHX\0"
        } else {
            b"RKZCS123nsITtDEAN\0"
        };
        let mut offset = self.head;
        while offset + 4 < self.buf.len() {
            let tag = self.buf[self.head];
            let len = u32::from_be_bytes([
                self.buf[self.head + 1],
                self.buf[self.head + 2],
                self.buf[self.head + 3],
                self.buf[self.head + 4],
            ]) as usize;

            if valid_tags.contains(&tag) && (4..=10_000_000).contains(&len) {
                break;
            }
            offset += 1;
        }
        if offset > self.head {
            warn!("[{}] corrupted stream: resync", self.addr);
        }
        self.head = offset;
    }
}
