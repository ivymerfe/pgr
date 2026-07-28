use bytes::{Buf, Bytes, BytesMut};
use std::{collections::BTreeMap, net::SocketAddr};

#[derive(Debug)]
pub struct PqStream {
    staging: BytesMut,
    next_seq: Option<u32>,
    unordered_chunks: BTreeMap<u32, Bytes>,
    pub addr: SocketAddr,
    last_ts: u64,
    frame_ts: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct PqFrame {
    pub ts: u64,
    pub tag: u8,
    pub payload: Bytes,
}

impl PqStream {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            staging: BytesMut::new(),
            next_seq: None,
            unordered_chunks: BTreeMap::new(),
            addr,
            last_ts: 0,
            frame_ts: None,
        }
    }

    pub fn set_isn(&mut self, syn_seq: u32) {
        if self.next_seq.is_none() {
            self.next_seq = Some(syn_seq.wrapping_add(1));
        }
    }

    pub fn set_ts(&mut self, ts: u64) {
        self.last_ts = ts;
    }

    pub fn ingest(&mut self, seq: u32, payload: &[u8]) {
        let next = match self.next_seq {
            None => {
                self.next_seq = Some(seq);
                seq
            }
            Some(n) => n,
        };

        let delta = seq.wrapping_sub(next) as i32;

        if delta == 0 {
            // 1. In-order arrival: Extend staging buffer directly
            self.staging.extend_from_slice(payload);
            let mut current_next = next.wrapping_add(payload.len() as u32);

            // Drain any pending out-of-order chunks that connect to current_next
            self.drain_matching_chunks(&mut current_next);
            self.next_seq = Some(current_next);
        } else if delta < 0 {
            // 2. Old/Overlapping packet: Trim overlap and re-ingest
            let overlap = (-delta) as usize;
            if overlap < payload.len() {
                self.ingest(next, &payload[overlap..]);
            }
        } else {
            self.unordered_chunks
                .entry(seq)
                .or_insert_with(|| Bytes::copy_from_slice(payload));
        }
    }

    fn drain_matching_chunks(&mut self, current_next: &mut u32) {
        while let Some(entry) = self.unordered_chunks.first_entry() {
            let chunk_seq = *entry.key();
            let delta = chunk_seq.wrapping_sub(*current_next) as i32;

            if delta <= 0 {
                let chunk = entry.remove();
                let overlap = (-delta) as usize;

                if overlap < chunk.len() {
                    let valid_slice = &chunk[overlap..];
                    self.staging.extend_from_slice(valid_slice);
                    *current_next = current_next.wrapping_add(valid_slice.len() as u32);
                }
            } else {
                // Next required sequence isn't in tree yet; gap still exists
                break;
            }
        }
    }

    pub fn len(&self) -> usize {
        self.staging.len()
    }

    pub fn pop_frame(&mut self) -> Result<Option<PqFrame>, &'static str> {
        let ts = self.frame_ts.take().unwrap_or(self.last_ts);

        if self.len() < 4 {
            return Ok(None);
        }

        let (tag, frame_offset, frame_length) = if self.staging[0] == 0x00 {
            let length = u32::from_be_bytes([
                self.staging[0],
                self.staging[1],
                self.staging[2],
                self.staging[3],
            ]) as usize;
            if !(8..=10_000_000).contains(&length) {
                return Err("Invalid headerless packet length");
            }
            if self.len() < length {
                return Ok(None);
            }
            (0, 4, length)
        } else {
            if self.len() < 5 {
                return Ok(None);
            }
            let payload_len = u32::from_be_bytes([
                self.staging[1],
                self.staging[2],
                self.staging[3],
                self.staging[4],
            ]) as usize;
            if !(4..=10_000_000).contains(&payload_len) {
                return Err("Invalid tagged payload length");
            }
            let total_frame_len = 1 + payload_len;
            if self.len() < total_frame_len {
                return Ok(None);
            }
            (self.staging[0], 5, total_frame_len)
        };
        let mut frame_bytes = self.staging.split_to(frame_length).freeze();
        frame_bytes.advance(frame_offset);

        self.frame_ts = Some(ts);
        Ok(Some(PqFrame {
            ts,
            tag,
            payload: frame_bytes,
        }))
    }

    /// Advance staging byte-by-byte until a valid frame signature is found.
    pub fn resync(&mut self, is_frontend: bool) {
        let valid_tags: &[u8] = if is_frontend {
            b"QPBDECfcpSHX"
        } else {
            b"RKZCS123nsITtDEAN"
        };

        let mut drop_bytes = 0;
        while self.staging.len() - drop_bytes >= 5 {
            let slice = &self.staging[drop_bytes..];
            let tag = slice[0];
            let len = u32::from_be_bytes([slice[1], slice[2], slice[3], slice[4]]) as usize;

            if valid_tags.contains(&tag) && (4..=10_000_000).contains(&len) {
                break;
            }

            drop_bytes += 1;
        }

        if drop_bytes > 0 {
            self.staging.advance(drop_bytes);
        }
    }
}
