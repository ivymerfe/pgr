use std::collections::BTreeMap;

use etherparse::TcpSlice;

use crate::capture::frame_buffer::FrameBuffer;

#[derive(Default)]
pub struct TcpHandler {
    pub buf: FrameBuffer,
    next_seq: Option<u32>,
    reorder: BTreeMap<u32, Vec<u8>>,
    pub packet_count: usize,
    pub reorder_count: usize,
}

impl TcpHandler {
    pub fn set_isn(&mut self, syn_seq: u32) {
        if self.next_seq.is_none() {
            self.next_seq = Some(syn_seq.wrapping_add(1));
        }
        self.buf.set_connected();
    }

    pub fn process_packet(&mut self, tcp: TcpSlice) -> bool {
        let seq = tcp.sequence_number();
        let effective_seq = if tcp.syn() {
            self.set_isn(seq);
            seq.wrapping_add(1)
        } else {
            seq
        };
        if self.ingest(effective_seq, tcp.payload()) {
            self.packet_count += 1;
            return true;
        }
        return false;
    }

    pub fn ingest(&mut self, seq: u32, payload: &[u8]) -> bool {
        if payload.is_empty() {
            return false;
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
            self.buf.extend(payload);

            let mut new_next = next.wrapping_add(payload.len() as u32);
            while let Some(pending) = self.reorder.remove(&new_next) {
                new_next = new_next.wrapping_add(pending.len() as u32);
                self.buf.extend(&pending);
            }
            self.next_seq = Some(new_next);
            return true;
        } else if delta < 0 {
            let overlap = (-delta) as usize;
            if overlap < payload.len() {
                return self.ingest(next, &payload[overlap..]);
            }
        } else {
            self.reorder_count += 1;
            self.reorder.insert(seq, payload.to_vec());
        }
        return false;
    }
}
