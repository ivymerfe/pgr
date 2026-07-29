use std::{collections::BTreeMap, net::SocketAddr};

use tracing::warn;

pub struct PqStream {
    buf: Vec<u8>,
    head: usize,
    next_seq: Option<u32>,
    reorder: BTreeMap<u32, Vec<u8>>,
    pub addr: SocketAddr,
    frame_ts: u64,
    update_ts: bool,
}

pub struct PqFrame<'a> {
    pub addr: SocketAddr,
    pub ts: u64,
    pub tag: u8,
    pub offset: usize,
    pub payload: &'a [u8],
}

impl PqStream {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            buf: Vec::new(),
            head: 0,
            next_seq: None,
            reorder: BTreeMap::new(),
            addr,
            frame_ts: 0,
            update_ts: true,
        }
    }

    pub fn set_isn(&mut self, syn_seq: u32) {
        if self.next_seq.is_none() {
            self.next_seq = Some(syn_seq.wrapping_add(1));
        }
    }

    pub fn set_ts(&mut self, ts: u64) {
        if self.update_ts {
            self.frame_ts = ts;
            self.update_ts = false;
        }
    }

    pub fn ingest(&mut self, seq: u32, payload: &[u8]) {
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
                self.ingest(next, &payload[overlap..]);
            }
        } else {
            self.reorder.insert(seq, payload.to_vec());
        }
    }

    pub fn len(&self) -> usize {
        self.buf.len().saturating_sub(self.head)
    }

    pub fn peek_frame(&mut self, is_frontend: bool) -> Option<(usize, PqFrame<'_>)> {
        if self.len() < 4 {
            return None;
        }
        let buf = &self.buf[self.head..];

        let (tag, frame_offset, frame_length) = if buf[0] == 0x00 {
            // 1. Headerless messages (SSLRequest, StartupMessage, CancelRequest)
            let length = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
            if !(8..=10_000_000).contains(&length) {
                self.head += 4;
                self.head = self.resync(is_frontend);
                return self.peek_frame(is_frontend);
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
                self.head += 5;
                self.head = self.resync(is_frontend);
                return self.peek_frame(is_frontend);
            }
            let frame_length = 1 + length;
            if buf.len() < frame_length {
                return None;
            }
            (buf[0], 5, frame_length)
        };
        let buf = &self.buf[self.head..self.head + frame_length];
        self.update_ts = true;
        let frame = PqFrame {
            addr: self.addr,
            ts: self.frame_ts,
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
        }
    }

    pub fn consume(&mut self, length: usize) {
        self.head += length;
        self.compact_if_needed();
    }

    fn resync(&self, is_frontend: bool) -> usize {
        warn!("[{}] corrupted stream: resync", self.addr);

        let valid_tags: &[u8] = if is_frontend {
            b"QPBDECfcpSHX"
        } else {
            b"RKZCS123nsITtDEAN"
        };
        let mut offset = self.head;
        while offset <= self.buf.len() {
            let tag = self.buf[self.head];
            let len = u32::from_be_bytes([
                self.buf[self.head + 1],
                self.buf[self.head + 2],
                self.buf[self.head + 3],
                self.buf[self.head + 4],
            ]) as usize;

            if valid_tags.contains(&tag) && (4..=10_000_000).contains(&len) {
                return offset;
            }
            offset += 1;
        }
        return offset;
    }
}
