use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct PqStream {
    buf: Vec<u8>,
    /// Points to the first unconsumed/unparsed byte in `buf`.
    head: usize,
    next_seq: Option<u32>,
    reorder: HashMap<u32, Vec<u8>>,
    pub last_ts_us: u64,
}

pub struct PqFrame<'a> {
    pub tag: u8,
    pub payload: &'a [u8],
}

impl PqStream {
    pub fn set_isn(&mut self, syn_seq: u32) {
        if self.next_seq.is_none() {
            self.next_seq = Some(syn_seq.wrapping_add(1));
        }
    }

    pub fn ingest(&mut self, seq: u32, payload: &[u8], ts_us: u64) {
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
            self.last_ts_us = ts_us;
            let mut new_next = next.wrapping_add(payload.len() as u32);
            while let Some(pending) = self.reorder.remove(&new_next) {
                new_next = new_next.wrapping_add(pending.len() as u32);
                self.buf.extend_from_slice(&pending);
            }
            self.next_seq = Some(new_next);
        } else if delta < 0 {
            let overlap = (-delta) as usize;
            if overlap < payload.len() {
                self.ingest(next, &payload[overlap..], ts_us);
            }
        } else {
            self.reorder.insert(seq, payload.to_vec());
        }
    }

    pub fn len(&self) -> usize {
        return self.buf.len() - self.head;
    }

    fn drain(&mut self, length: usize) -> &[u8] {
        let head = self.head;
        self.head = (self.head + length).min(self.buf.len());
        return &self.buf[head..head + length];
    }

    pub fn pop_frame<'a>(&'a mut self) -> Result<Option<PqFrame<'a>>, &'static str> {
        if self.len() < 4 {
            return Ok(None);
        }
        let tag;
        let frame_offset;
        let frame_length;
        let buf = &self.buf[self.head..];
        // 1. Headerless messages (SSLRequest, StartupMessage, CancelRequest)
        // ALWAYS start with 0x00 because the first 4 bytes are big-endian packet length.
        if buf[0] == 0x00 {
            let length = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
            if length < 8 || length > 10_000_000 {
                return Err("Invalid headerless packet length");
            }
            if buf.len() < length {
                return Ok(None);
            }
            // Headerless payload starts at offset 4 (after length header)
            tag = 0;
            frame_offset = 4;
            frame_length = length;
        } else {
            // 2. Standard Tagged Message: [Tag: 1 byte][Length: 4 bytes][Payload: Length - 4]
            if buf.len() < 5 {
                return Ok(None);
            }
            let payload_len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
            if payload_len < 4 || payload_len > 10_000_000 {
                return Err("Invalid tagged payload length");
            }
            let total_frame_len = 1 + payload_len;
            if buf.len() < total_frame_len {
                return Ok(None);
            }
            // Tagged payload starts at offset 5 (after tag + length header)
            tag = buf[0];
            frame_offset = 5;
            frame_length = total_frame_len;
        }
        let payload = self.drain(frame_length);
        Ok(Some(PqFrame {
            tag,
            payload: &payload[frame_offset..],
        }))
    }

    /// Advance `head` byte-by-byte until a valid frame signature is found.
    pub fn resync(&mut self, is_frontend: bool) {
        let valid_tags: &[u8] = if is_frontend {
            b"QPBDECfcpSHX"
        } else {
            b"RKZCS123nsITtDEAN"
        };

        while self.head + 5 <= self.buf.len() {
            let tag = self.buf[self.head];
            let len = u32::from_be_bytes([
                self.buf[self.head + 1],
                self.buf[self.head + 2],
                self.buf[self.head + 3],
                self.buf[self.head + 4],
            ]) as usize;

            if valid_tags.contains(&tag) && (4..=10_000_000).contains(&len) {
                return;
            }

            // Move the pointer forward instead of `self.buf.remove(0)`
            self.head += 1;
        }
    }
}
