use std::collections::BTreeMap;

#[derive(Default)]
pub struct Reassembler {
    next_seq: Option<u32>,
    out_of_order: BTreeMap<u32, Vec<u8>>,
}

impl Reassembler {
    pub fn feed(&mut self, seq: u32, is_syn: bool, mut data: &[u8], out: &mut Vec<u8>) -> bool {
        if is_syn {
            self.next_seq = Some(seq.wrapping_add(1));
            if data.is_empty() {
                return false;
            }
        }
        let next_seq = match self.next_seq {
            Some(n) => n,
            None => {
                self.next_seq = Some(seq);
                seq
            }
        };
        let mut seq = seq;
        let delta = next_seq.wrapping_sub(seq) as i32;
        if delta > 0 {
            let delta = delta as usize;
            if delta >= data.len() {
                return false;
            }
            data = &data[delta..];
            seq = next_seq;
        }
        if seq == next_seq {
            out.extend_from_slice(data);
            let mut cur = next_seq.wrapping_add(data.len() as u32);

            while let Some((&buf_seq, _)) = self.out_of_order.range(cur..).next() {
                if buf_seq != cur {
                    break;
                }
                let buf = self.out_of_order.remove(&buf_seq).unwrap();
                cur = cur.wrapping_add(buf.len() as u32);
                out.extend_from_slice(&buf);
            }

            self.next_seq = Some(cur);
            return true;
        } else {
            self.out_of_order.insert(seq, data.to_vec());
            return false;
        }
    }
}
