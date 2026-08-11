use std::{collections::VecDeque, fs::File, io::BufWriter, io::Write};

use anyhow::anyhow;
use tracing::info;

use crate::{
    capture::{
        frame_buffer::{ConnState, FrameBuffer, FrameInfo, FrameResult},
        reader::ClientId,
    },
    parser::c2s_display::TagFrame,
};

#[derive(Default)]
pub struct CompareStats {
    pub src_frames: u64,
    pub replay_frames: u64,

    pub cnt_behind: f64,
    pub sum_behind: f64,
    pub max_behind: f64,
    pub cnt_ahead: f64,
    pub sum_ahead: f64,
    pub max_ahead: f64,
    pub total_updates: u64,
}

impl CompareStats {
    pub fn pair_ts(&mut self, src_ts: u64, replay_ts: u64) {
        self.total_updates += 1;

        let delta = replay_ts as f64 - src_ts as f64;
        if delta > 0.0 {
            self.cnt_behind += 1.0;
            self.sum_behind += delta;
            self.max_behind = self.max_behind.max(delta);
        } else {
            self.cnt_ahead += 1.0;
            self.sum_ahead += delta;
            self.max_ahead = self.max_ahead.min(delta);
        }
    }
}

pub struct ComparePair {
    pub id: ClientId,
    pub replay_id: Option<ClientId>,
    pub stats: CompareStats,
    pub src_connect_ts: u64,
    pub replay_connect_ts: u64,
    src_connected: bool,
    replay_connected: bool,
    src_pending: VecDeque<(FrameInfo, u64)>,
    replay_pending: VecDeque<(FrameInfo, u64)>,
}

pub struct CompareFrame {
    pub src_info: FrameInfo,
    pub replay_info: FrameInfo,
    pub src_ts: u64,
    pub replay_ts: u64,
}

impl ComparePair {
    pub fn new(id: ClientId) -> Self {
        Self {
            id,
            replay_id: None,
            stats: CompareStats::default(),
            src_connect_ts: 0,
            src_connected: false,
            replay_connect_ts: 0,
            replay_connected: false,
            src_pending: VecDeque::new(),
            replay_pending: VecDeque::new(),
        }
    }

    pub fn read_src(&mut self, ts: u64, buf: &mut FrameBuffer) {
        if !self.src_connected {
            self.src_connect_ts = buf.connect_ts;
            self.src_connected = true;
        }
        loop {
            match buf.find_frame() {
                FrameResult::Complete(info) => {
                    if buf.state == ConnState::Normal || buf.state == ConnState::CopyIn {
                        self.src_pending
                            .push_back((info, ts.saturating_sub(self.src_connect_ts)));
                        self.stats.src_frames += 1;
                    }
                    buf.consume_frame(&info);
                }
                FrameResult::Incomplete => break,
                FrameResult::Desync => {
                    info!("[{}:src] desync", self.id);
                    buf.resync();
                }
            }
        }
    }

    pub fn read_replay(&mut self, ts: u64, buf: &mut FrameBuffer) {
        if !self.replay_connected {
            self.replay_connect_ts = buf.connect_ts;
            self.replay_connected = true;
        }
        loop {
            match buf.find_frame() {
                FrameResult::Complete(info) => {
                    if buf.state == ConnState::Normal || buf.state == ConnState::CopyIn {
                        self.replay_pending
                            .push_back((info, ts.saturating_sub(self.replay_connect_ts)));
                        self.stats.replay_frames += 1;
                    }
                    buf.consume_frame(&info);
                }
                FrameResult::Incomplete => break,
                FrameResult::Desync => {
                    info!("[{}:replay] desync", self.id);
                    buf.resync();
                }
            }
        }
    }

    pub fn connect_delta(&self) -> f64 {
        self.replay_connect_ts as f64 - self.src_connect_ts as f64
    }

    pub fn pop_frame(&mut self) -> Option<CompareFrame> {
        if !self.src_pending.is_empty() && !self.replay_pending.is_empty() {
            let (src_info, src_ts) = self.src_pending.pop_front().unwrap();
            let (replay_info, replay_ts) = self.replay_pending.pop_front().unwrap();
            Some(CompareFrame {
                src_info,
                src_ts,
                replay_info,
                replay_ts,
            })
        } else {
            None
        }
    }

    pub fn compare(
        &mut self,
        src_buf: &mut FrameBuffer,
        replay_buf: &mut FrameBuffer,
        delta_writer: &mut Option<BufWriter<File>>,
    ) -> anyhow::Result<()> {
        while let Some(cmp) = self.pop_frame() {
            let src_frame = src_buf.read_frame(&cmp.src_info);
            let replay_frame = replay_buf.read_frame(&cmp.replay_info);

            let min_time = cmp.src_ts.min(cmp.replay_ts) as f64;
            let delta = cmp.replay_ts as f64 - cmp.src_ts as f64;
            if let Some(writer) = delta_writer {
                writeln!(
                    writer,
                    "{:.6},{:.3},{},{}",
                    min_time / 1e6,
                    delta / 1e3,
                    self.id,
                    TagFrame(cmp.src_info.tag, src_frame)
                )?;
            }
            if src_frame != replay_frame {
                if let Some(writer) = delta_writer {
                    writeln!(
                        writer,
                        "{:.6},{:.3},{},{}",
                        min_time / 1e6,
                        delta / 1e3,
                        self.replay_id.unwrap(),
                        TagFrame(cmp.replay_info.tag, replay_frame)
                    )?;
                }
                let e = format_frame_mismatch(
                    self.id,
                    &cmp.src_info,
                    src_frame,
                    self.replay_id.unwrap(),
                    &cmp.replay_info,
                    replay_frame,
                );
                return Err(anyhow!(e));
            }
            self.stats.pair_ts(cmp.src_ts, cmp.replay_ts);
        }
        Ok(())
    }
}

pub fn format_frame_mismatch(
    src_id: ClientId,
    src_info: &FrameInfo,
    src_frame: &[u8],
    replay_id: ClientId,
    replay_info: &FrameInfo,
    replay_frame: &[u8],
) -> String {
    format!(
        "Frame contents do not match:\n{} at {}:{} <=> {} at {}:{}\n{}\n{}",
        src_id,
        src_info.stream_start,
        src_info.stream_end,
        replay_id,
        replay_info.stream_start,
        replay_info.stream_end,
        TagFrame(src_info.tag, src_frame),
        TagFrame(replay_info.tag, replay_frame)
    )
}
