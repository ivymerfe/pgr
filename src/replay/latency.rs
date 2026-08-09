use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{BufWriter, Write};

use crate::capture::reader::ClientId;
use crate::proto::tags::*;

pub struct LatencyMap {
    writer: BufWriter<File>,
    monitors: HashMap<ClientId, LatencyMonitor>,
}

impl LatencyMap {
    pub fn new(file: File) -> Self {
        Self {
            writer: BufWriter::new(file),
            monitors: HashMap::new(),
        }
    }

    pub async fn on_send(&mut self, id: ClientId, tag: u8, ts: u64) -> std::io::Result<()> {
        let mon = self.monitors.entry(id).or_default();
        mon.on_send(tag, ts);
        Ok(())
    }

    pub async fn on_response(&mut self, id: ClientId, tag: u8, ts: u64) -> std::io::Result<()> {
        let mon = self.monitors.entry(id).or_default();
        if let Some((f_tag, lat)) = mon.on_response(tag, ts) {
            let pending = mon.pending.len();
            self.write(id, f_tag, lat, pending).await?;
        }
        Ok(())
    }

    pub async fn write(
        &mut self,
        id: ClientId,
        tag: u8,
        lat_us: u32,
        pending: usize,
    ) -> std::io::Result<()> {
        // self.writer.write_u32(id).await?;
        // self.writer.write_u32(lat_us).await?
        self.writer.write_all(
            format!(
                "{},{},{:.3},{}\n",
                id,
                tag as char,
                (lat_us as f32) / 1e3,
                pending
            )
            .as_bytes(),
        )?;
        Ok(())
    }
}

#[derive(Default)]
pub struct LatencyMonitor {
    pending: VecDeque<(u8, u64)>,
    in_error: bool,
    expect_describe_second_frame: bool,
}

impl LatencyMonitor {
    pub fn on_send(&mut self, f_tag: u8, ts: u64) {
        self.pending.push_back((f_tag, ts));
    }

    pub fn on_response(&mut self, b_tag: u8, ts: u64) -> Option<(u8, u32)> {
        if matches!(b_tag, B_NOTICE | B_NOTIFICATION | B_DATA_ROW) {
            return None;
        }

        if b_tag == B_ERROR {
            self.in_error = true;
            let (f_tag, sent_ts) = self.pending.pop_front()?;
            return Some((f_tag, ts.saturating_sub(sent_ts) as u32));
        }

        if b_tag == B_READY_FOR_QUERY {
            if self.in_error {
                self.in_error = false;
                while let Some((req_tag, _)) = self.pending.pop_front() {
                    if req_tag == F_SYNC || req_tag == F_QUERY {
                        break;
                    }
                }
                return None;
            }

            let (f_tag, sent_ts) = self.pending.pop_front()?;
            if f_tag == F_SYNC || f_tag == F_QUERY {
                return Some((f_tag, ts.saturating_sub(sent_ts) as u32));
            }
            while let Some((sub_tag, sub_ts)) = self.pending.pop_front() {
                if sub_tag == F_SYNC || sub_tag == F_QUERY {
                    return Some((f_tag, ts.saturating_sub(sub_ts) as u32));
                }
            }
            return None;
        }

        if self.in_error {
            return None;
        }

        match b_tag {
            B_PARSE_COMPLETE => self.pop_if_front_is(F_PARSE, ts),
            B_BIND_COMPLETE => self.pop_if_front_is(F_BIND, ts),
            B_CLOSE_COMPLETE => self.pop_if_front_is(F_CLOSE, ts),

            B_COMMAND_COMPLETE | B_PORTAL_SUSPENDED | B_EMPTY_QUERY => match self.pending.front() {
                Some(&(f_tag, _)) if f_tag == F_EXECUTE || f_tag == F_QUERY => {
                    let (_, sent_ts) = self.pending.pop_front().unwrap();
                    Some((f_tag, ts.saturating_sub(sent_ts) as u32))
                }
                _ => None,
            },

            B_PARAMETER_DESC => {
                if let Some(&(F_DESCRIBE, _)) = self.pending.front() {
                    self.expect_describe_second_frame = true;
                }
                None
            }
            B_ROW_DESC | B_NO_DATA => {
                if self.expect_describe_second_frame {
                    self.expect_describe_second_frame = false;
                    let (f_tag, sent_ts) = self.pending.pop_front().unwrap();
                    Some((f_tag, ts.saturating_sub(sent_ts) as u32))
                } else if let Some(&(F_DESCRIBE, _)) = self.pending.front() {
                    let (f_tag, sent_ts) = self.pending.pop_front().unwrap();
                    Some((f_tag, ts.saturating_sub(sent_ts) as u32))
                } else {
                    None
                }
            }

            _ => None,
        }
    }

    fn pop_if_front_is(&mut self, expected: u8, ts: u64) -> Option<(u8, u32)> {
        match self.pending.front() {
            Some(&(f_tag, _)) if f_tag == expected => {
                let (_, sent_ts) = self.pending.pop_front().unwrap();
                Some((f_tag, ts.saturating_sub(sent_ts) as u32))
            }
            _ => None,
        }
    }
}
