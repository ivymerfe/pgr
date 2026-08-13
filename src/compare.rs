use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    fs::File,
    io::{BufWriter, Write},
};

use crate::{
    capture::{
        frame_buffer::{ConnState, FrameBuffer, FrameInfo, FrameResult},
        reader::{CaptureReader, ClientId, ReadError},
    },
    proto::{
        c2s::PgC2S::{self, StartupMessage},
        format::DisplayFrame,
    },
};

use anyhow::anyhow;
use tracing::{error, info, warn};

pub fn compare(
    mut src_reader: Box<dyn CaptureReader>,
    mut replay_reader: Box<dyn CaptureReader>,
    mut delta_writer: Option<BufWriter<File>>,
) -> anyhow::Result<()> {
    let (mut src_eof, mut replay_eof) = (false, false);
    let mut pairs = BTreeMap::<ClientId, ComparePair>::new();
    let mut replay_map = HashMap::new();
    let mut replay_ignore = HashSet::new();

    while !src_eof || !replay_eof {
        if !src_eof {
            match src_reader.next() {
                Ok(mut data) => {
                    let id = data.id;
                    let src_buf = &mut data.buf;
                    let pair = pairs.entry(id).or_insert_with(|| ComparePair::new(id));
                    pair.read_src(data.ts, src_buf);
                    if let Some(replay_id) = pair.replay_id {
                        if let Some(replay_buf) = replay_reader.get_buffer(replay_id) {
                            pair.compare(src_buf, replay_buf, &mut delta_writer)?;
                        }
                    }
                }
                Err(ReadError::Continue) => (),
                Err(ReadError::Eof) => {
                    src_eof = true;
                }
                Err(ReadError::Error(e)) => {
                    error!("Failed to read source capture: {e}");
                    return Ok(());
                }
            }
        }
        if !replay_eof {
            match replay_reader.next() {
                Ok(mut data) => {
                    let replay_id = data.id;
                    if replay_ignore.contains(&replay_id) {
                        continue;
                    }
                    let id = match replay_map.get(&replay_id) {
                        Some(id) => *id,
                        None => match try_find_id(replay_id, data.buf) {
                            FindResult::Ok(id) => {
                                replay_map.insert(replay_id, id);
                                id
                            }
                            FindResult::NotReady => continue,
                            FindResult::NotFound => {
                                info!("[{}:replay] pgr.client_id not found", replay_id);
                                replay_ignore.insert(replay_id);
                                continue;
                            }
                        },
                    };
                    let pair = pairs.entry(id).or_insert_with(|| ComparePair::new(id));
                    pair.replay_id = Some(replay_id);
                    let replay_buf = &mut data.buf;
                    pair.read_replay(data.ts, replay_buf);
                    if let Some(src_buf) = src_reader.get_buffer(id) {
                        pair.compare(src_buf, replay_buf, &mut delta_writer)?;
                    }
                }
                Err(ReadError::Continue) => (),
                Err(ReadError::Eof) => {
                    replay_eof = true;
                }
                Err(ReadError::Error(e)) => {
                    error!("Failed to read replay capture: {e}");
                    return Ok(());
                }
            }
        }
    }
    for pair in pairs.values() {
        let stats = &pair.stats;
        if stats.src_frames != stats.replay_frames {
            warn!(
                "{}: frame count mismatch: {} / {}",
                pair.id, stats.src_frames, stats.replay_frames
            )
        }
        info!(
            "{}: conn {:.2}ms; avg {:.2}ms; max {:.2}ms <{}/{}> avg {:.2}ms; max {:.2}ms",
            pair.id,
            pair.connect_delta() as f64 / 1e3,
            divide_or_zero(stats.sum_behind, stats.cnt_behind) / 1e3,
            stats.max_behind / 1e3,
            stats.cnt_behind,
            stats.cnt_ahead,
            divide_or_zero(stats.sum_ahead, stats.cnt_ahead) / 1e3,
            stats.max_ahead / 1e3,
        );
    }
    Ok(())
}

fn divide_or_zero(a: f64, b: f64) -> f64 {
    if b != 0.0 { a / b } else { 0.0 }
}

enum FindResult {
    Ok(ClientId),
    NotReady,
    NotFound,
}

fn try_find_id(replay_id: ClientId, buf: &mut FrameBuffer) -> FindResult {
    while buf.state == ConnState::AwaitingStartup {
        match buf.find_frame() {
            FrameResult::Complete(info) => {
                let mut result = FindResult::NotReady;
                if info.tag == 0 {
                    let data = buf.read_frame(&info);
                    match PgC2S::parse(info.tag, data) {
                        Ok(msg) => {
                            if let StartupMessage {
                                version: _,
                                parameters,
                            } = msg
                            {
                                result = FindResult::NotFound;
                                for (k, v) in parameters.iter() {
                                    if k == "pgr.client_id" {
                                        if let Ok(id) = v.parse() {
                                            result = FindResult::Ok(id);
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error!("[{replay_id}:replay] failed to parse postgres message: {e}");
                            result = FindResult::NotFound;
                        }
                    }
                }
                buf.consume_frame(&info);
                return result;
            }
            FrameResult::Incomplete => {
                return FindResult::NotReady;
            }
            FrameResult::Desync => {
                warn!("[{}:find_id] desync", replay_id);
                buf.resync();
            }
        }
    }
    FindResult::NotFound
}

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
                    DisplayFrame(cmp.src_info.tag, src_frame)
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
                        DisplayFrame(cmp.replay_info.tag, replay_frame)
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
        DisplayFrame(src_info.tag, src_frame),
        DisplayFrame(replay_info.tag, replay_frame)
    )
}
