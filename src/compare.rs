use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
    fs::File,
    io::{BufWriter, Write},
};

use crate::{
    capture::{
        frame_buffer::{ConnState, FrameBuffer},
        reader::{CaptureReader, ClientId, ReadError},
    },
    proto::c2s::{
        PgMsg::{self},
        PgMsgParser,
    },
    utils::format::DisplayBytes,
};

use anyhow::anyhow;
use tracing::{error, info, warn};

pub fn compare(
    mut src_reader: Box<dyn CaptureReader>,
    mut replay_reader: Box<dyn CaptureReader>,
    mut delta_writer: Option<BufWriter<File>>,
) -> anyhow::Result<()> {
    let mut source_map = BTreeMap::new();
    let mut replay_map = HashMap::new();
    let mut replay_ignore = HashSet::new();

    let (mut src_eof, mut replay_eof) = (false, false);
    while !src_eof || !replay_eof {
        if !src_eof {
            match src_reader.next() {
                Ok(data) => {
                    let id = data.id;
                    let source = source_map
                        .entry(id)
                        .or_insert_with(|| CompareSource::new(id));
                    source.buf.on_capture(&data);
                    if let Some(replay_id) = source.replay_id {
                        if let Some(replay) = replay_map.get_mut(&replay_id) {
                            source.compare(replay, &mut delta_writer)?;
                        }
                    }
                }
                Err(ReadError::Eof) => src_eof = true,
                Err(ReadError::Error(e)) => {
                    error!("Failed to read source capture: {e}");
                    return Ok(());
                }
            }
        }
        if !replay_eof {
            match replay_reader.next() {
                Ok(data) => {
                    let replay_id = data.id;
                    if replay_ignore.contains(&replay_id) {
                        continue;
                    }
                    let replay = replay_map
                        .entry(replay_id)
                        .or_insert_with(|| CompareReplay::new(replay_id));
                    replay.buf.on_capture(&data);
                    let id = match replay.find_id() {
                        FindResult::Ok(id) => id,
                        FindResult::NotReady => continue,
                        FindResult::NotFound => {
                            info!("[{}:replay] pgr.client_id not found", replay_id);
                            replay_ignore.insert(replay_id);
                            continue;
                        }
                    };
                    let pair = source_map
                        .entry(id)
                        .or_insert_with(|| CompareSource::new(id));
                    pair.replay_id = Some(replay_id);
                    pair.compare(replay, &mut delta_writer)?;
                }
                Err(ReadError::Eof) => replay_eof = true,
                Err(ReadError::Error(e)) => {
                    error!("Failed to read replay capture: {e}");
                    return Ok(());
                }
            }
        }
    }
    for pair in source_map.values() {
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

struct CompareReplay {
    src_id: Option<u32>,
    buf: FrameBuffer,
}

enum FindResult {
    Ok(ClientId),
    NotReady,
    NotFound,
}

impl CompareReplay {
    pub fn new(replay_id: ClientId) -> Self {
        Self {
            src_id: None,
            buf: FrameBuffer::new(replay_id),
        }
    }

    pub fn find_id(&mut self) -> FindResult {
        if let Some(id) = self.src_id {
            return FindResult::Ok(id);
        }
        let buf = &mut self.buf;
        let mut parser = PgMsgParser::new();

        while let Some(info) = buf.frames.pop_front() {
            if info.tag != 0 {
                return FindResult::NotFound;
            }
            let data = buf.read_frame(&info);
            match parser.parse(data) {
                Ok(msg) => {
                    if let PgMsg::StartupMessage { params, .. } = &msg {
                        for i in 0..params.len() {
                            if let Some((k, v)) = msg.startup_param(i) {
                                if k == "pgr.client_id" {
                                    if let Ok(id) = v.parse() {
                                        self.src_id = Some(id);
                                        return FindResult::Ok(id);
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("[{}:replay] failed to parse postgres message: {e}", buf.id);
                    return FindResult::NotFound;
                }
            }
        }
        if buf.state == ConnState::Normal {
            FindResult::NotFound
        } else {
            FindResult::NotReady
        }
    }
}

struct CompareSource {
    pub id: ClientId,
    pub buf: FrameBuffer,
    parser: PgMsgParser,
    pub stats: CompareStats,
    pub replay_connect_ts: u64,
    pub replay_id: Option<ClientId>,
}

impl CompareSource {
    pub fn new(id: ClientId) -> Self {
        Self {
            id,
            buf: FrameBuffer::new(id),
            parser: PgMsgParser::default(),
            stats: CompareStats::default(),
            replay_connect_ts: 0,
            replay_id: None,
        }
    }

    pub fn connect_delta(&self) -> f64 {
        self.replay_connect_ts as f64 - self.buf.connect_ts as f64
    }

    pub fn compare(
        &mut self,
        replay: &mut CompareReplay,
        delta_writer: &mut Option<BufWriter<File>>,
    ) -> anyhow::Result<()> {
        let src = &mut self.buf;
        let replay = &mut replay.buf;
        self.replay_connect_ts = replay.connect_ts;

        while let Some(info) = src.frames.front()
            && info.tag == 0
        {
            src.frames.pop_front();
        }
        while let Some(info) = replay.frames.front()
            && info.tag == 0
        {
            replay.frames.pop_front();
        }

        while !src.frames.is_empty() && !replay.frames.is_empty() {
            let src_info = src.frames.pop_front().unwrap();
            let replay_info = replay.frames.pop_front().unwrap();

            let src_frame = src.read_frame(&src_info);
            let replay_frame = replay.read_frame(&replay_info);

            let src_ts = src_info.ts.saturating_sub(src.connect_ts);
            let replay_ts = replay_info.ts.saturating_sub(replay.connect_ts);

            let min_time = src_ts.min(replay_ts) as f64;
            let delta = replay_ts as f64 - src_ts as f64;
            if let Some(writer) = delta_writer {
                writeln!(
                    writer,
                    "{:.6},{:.3},{},{}",
                    min_time / 1e6,
                    delta / 1e3,
                    self.id,
                    DisplayFrame(self.parser.parse(src_frame), src_frame)
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
                        DisplayFrame(self.parser.parse(replay_frame), replay_frame)
                    )?;
                }
                let e = format!(
                    "Frame contents do not match:\n{} at {} <=> {} at {}\n{}",
                    src.id,
                    src_info.offset,
                    self.replay_id.unwrap(),
                    replay_info.offset,
                    DisplayFrame(self.parser.parse(src_frame), src_frame),
                );
                let e = format!(
                    "{e}\n{}",
                    DisplayFrame(self.parser.parse(replay_frame), replay_frame)
                );
                return Err(anyhow!(e));
            }
            self.stats.pair_ts(src_ts, replay_ts);
        }
        Ok(())
    }
}

struct DisplayFrame<'a, 'b>(Result<PgMsg<'a>, &'static str>, &'b [u8]);

impl<'a, 'b> fmt::Display for DisplayFrame<'a, 'b> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Ok(msg) => write!(f, "{}", msg),
            Err(e) => write!(f, "({}),{}", e, DisplayBytes(self.1)),
        }
    }
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
