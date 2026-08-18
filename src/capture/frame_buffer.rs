use std::collections::VecDeque;

use crate::capture::reader::{CaptureData, ClientId};
use tracing::warn;

const CLIENT_TAGS: &[u8] = b"QPBDECfcpSHX";
const RESYNC_CHAIN_LEN: usize = 3;
const SSL_REQUEST_CODE: u32 = 80877103;
const GSS_REQUEST_CODE: u32 = 80877104;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnState {
    Unknown,
    AwaitingStartup,
    Normal,
    CopyIn,
}

impl Default for ConnState {
    fn default() -> Self {
        ConnState::Unknown
    }
}

pub struct FrameInfo {
    pub offset: usize,
    pub len: usize,
    pub ts: u64,
    pub tag: u8,
}

struct RawFrame {
    offset: usize,
    len: usize,
    tag: u8,
    code: Option<u32>,
}

pub struct FrameBuffer {
    pub id: ClientId,
    pub data: Vec<u8>,
    pub state: ConnState,
    pub connect_ts: u64,
    pub frame_ts: Option<u64>,
    pub frames: VecDeque<FrameInfo>,
    buf_offset: usize,
    frame_offset: usize,
}

impl FrameBuffer {
    pub fn new(id: ClientId) -> Self {
        Self {
            id,
            data: Vec::new(),
            state: ConnState::Unknown,
            connect_ts: 0,
            frame_ts: None,
            frames: VecDeque::new(),
            buf_offset: 0,
            frame_offset: 0,
        }
    }

    pub fn on_capture(&mut self, data: &CaptureData) {
        if data.connect && self.state == ConnState::Unknown {
            self.state = ConnState::AwaitingStartup;
            self.connect_ts = data.ts;
        }
        self.compact_buffer();
        self.data.extend_from_slice(data.buf);

        if self.frame_ts.is_none() {
            self.frame_ts = Some(data.ts);
        }
        let frame_ts = self.frame_ts.unwrap();

        loop {
            if self.frame_offset >= self.buf_offset + self.data.len() {
                break;
            }
            let parsed = match self.state {
                ConnState::AwaitingStartup => self.parse_startup(self.frame_offset),
                ConnState::Normal | ConnState::CopyIn => self.parse_tagged(self.frame_offset),
                ConnState::Unknown => Ok(self.resync(self.frame_offset)),
            };
            let raw = match parsed {
                Ok(Some(raw)) => raw,
                Ok(None) => break,
                Err(()) => {
                    self.state = ConnState::Unknown;
                    continue;
                }
            };

            self.advance_state(&raw);
            self.frame_offset = raw.offset + raw.len;
            self.frames.push_back(FrameInfo {
                offset: raw.offset,
                len: raw.len,
                ts: frame_ts,
                tag: raw.tag,
            });
        }
        if self.frame_offset < self.buf_offset + self.data.len() {
            self.frame_ts = Some(data.ts);
        } else {
            self.frame_ts = None;
        }
    }

    pub fn read_frame(&self, info: &FrameInfo) -> &[u8] {
        let start = info.offset - self.buf_offset;
        &self.data[start..start + info.len]
    }

    fn compact_buffer(&mut self) {
        let offset = match self.frames.front() {
            Some(frame) => frame.offset,
            None => self.frame_offset,
        };
        let garbage_size = offset - self.buf_offset;
        if garbage_size > 65536 {
            let remaining = self.data.len() - garbage_size;
            self.data.copy_within(garbage_size.., 0);
            self.data.truncate(remaining);
            self.buf_offset = offset;
        }
    }

    fn advance_state(&mut self, raw: &RawFrame) {
        match self.state {
            ConnState::AwaitingStartup => match raw.code {
                Some(c) if c == SSL_REQUEST_CODE || c == GSS_REQUEST_CODE => {}
                _ => self.state = ConnState::Normal,
            },
            ConnState::Normal if raw.tag == b'd' => self.state = ConnState::CopyIn,
            ConnState::CopyIn if raw.tag == b'c' || raw.tag == b'f' => {
                self.state = ConnState::Normal
            }
            ConnState::Unknown => {
                warn!("[{}] sync to valid frame", self.id);
                self.state = ConnState::Normal
            }
            _ => {}
        }
    }

    fn parse_startup(&self, offset: usize) -> Result<Option<RawFrame>, ()> {
        let pos = offset - self.buf_offset;
        let remaining = self.data.len() - pos;
        if remaining < 4 {
            return Ok(None);
        }
        if self.data[pos] != 0x00 {
            return Err(());
        }
        let length = u32::from_be_bytes([
            self.data[pos + 0],
            self.data[pos + 1],
            self.data[pos + 2],
            self.data[pos + 3],
        ]) as usize;
        if !(8..=10_000_000).contains(&length) {
            return Err(());
        }
        if remaining < length {
            return Ok(None);
        }
        let code = (length >= 8).then(|| {
            u32::from_be_bytes([
                self.data[pos + 4],
                self.data[pos + 5],
                self.data[pos + 6],
                self.data[pos + 7],
            ])
        });
        Ok(Some(RawFrame {
            offset,
            len: length,
            tag: 0,
            code,
        }))
    }

    fn parse_tagged(&self, offset: usize) -> Result<Option<RawFrame>, ()> {
        let pos = offset - self.buf_offset;
        let remaining = self.data.len() - pos;
        if remaining < 5 {
            return Ok(None);
        }
        let tag = self.data[pos];
        if !CLIENT_TAGS.contains(&tag) {
            return Err(());
        }
        let length = u32::from_be_bytes([
            self.data[pos + 1],
            self.data[pos + 2],
            self.data[pos + 3],
            self.data[pos + 4],
        ]) as usize;
        if !(4..=10_000_000).contains(&length) {
            return Err(());
        }
        let frame_len = 1 + length;
        if remaining < frame_len {
            return Ok(None);
        }
        Ok(Some(RawFrame {
            offset,
            len: frame_len,
            tag,
            code: None,
        }))
    }

    fn resync(&self, start_offset: usize) -> Option<RawFrame> {
        let end_offset = self.buf_offset + self.data.len();
        let mut offset = start_offset;
        while offset < end_offset {
            if self.chain_valid(offset, RESYNC_CHAIN_LEN) {
                return self.parse_tagged(offset).unwrap();
            }
            offset += 1;
        }
        None
    }

    fn chain_valid(&self, mut offset: usize, count: usize) -> bool {
        for _ in 0..count {
            match self.parse_tagged(offset) {
                Ok(Some(raw)) => offset += raw.len,
                _ => return false,
            }
        }
        true
    }
}
