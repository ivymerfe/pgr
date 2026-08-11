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

#[derive(Default)]
pub struct FrameBuffer {
    pub data: Vec<u8>,
    pub state: ConnState,
    buf_offset: usize,
    read_offset: usize,
    frame_offset: usize,
}

#[derive(Debug, Copy, Clone)]
pub struct FrameInfo {
    pub stream_start: usize,
    pub stream_end: usize,
    pub body_offset: usize,
    pub tag: u8,
    pub code: Option<u32>,
}

pub enum FrameResult {
    Complete(FrameInfo),
    Incomplete,
    Desync,
}

impl FrameBuffer {
    pub fn mark_connection_start(&mut self) {
        if self.state == ConnState::Unknown {
            self.state = ConnState::AwaitingStartup;
            self.frame_offset = self.buf_offset + self.data.len();
        }
    }

    pub fn extend(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }

    fn compact_buffer(&mut self) {
        let read_size = self.read_offset.saturating_sub(self.buf_offset);
        if read_size > 65_536 {
            self.data.drain(0..read_size);
            self.buf_offset = self.read_offset;
        }
    }

    pub fn mark_read(&mut self, offset: usize) {
        self.read_offset = self.read_offset.max(offset.min(self.frame_offset));
        self.compact_buffer();
    }

    pub fn frame_offset(&self) -> usize {
        self.frame_offset
    }

    pub fn read_frame(&self, info: &FrameInfo) -> &[u8] {
        assert!(
            info.stream_start >= self.buf_offset,
            "read_frame has been called on destroyed frame"
        );
        assert!(
            info.stream_end <= self.buf_offset + self.data.len(),
            "read_frame has been called on incomplete frame"
        );
        let start_offset = info.stream_start - self.buf_offset;
        let end_offset = info.stream_end - self.buf_offset;
        return &self.data[start_offset + info.body_offset..end_offset];
    }

    pub fn read_frame_full(&self, info: &FrameInfo) -> &[u8] {
        assert!(
            info.stream_start >= self.buf_offset,
            "read_frame has been called on destroyed frame"
        );
        assert!(
            info.stream_end <= self.buf_offset + self.data.len(),
            "read_frame has been called on incomplete frame"
        );
        let start_offset = info.stream_start - self.buf_offset;
        let end_offset = info.stream_end - self.buf_offset;
        return &self.data[start_offset..end_offset];
    }

    pub fn find_frame(&self) -> FrameResult {
        if self.frame_offset < self.buf_offset {
            unreachable!(
                "content at self.frame_offset was destroyed, read offset could have been modified outside of mark_read"
            );
        }
        let start = self.frame_offset;
        if start > self.buf_offset + self.data.len() {
            return FrameResult::Incomplete;
        }

        let parsed = match self.state {
            ConnState::AwaitingStartup => self.try_parse_startup(start),
            ConnState::Normal | ConnState::CopyIn => self.try_parse_tagged(start),
            ConnState::Unknown => return self.read_frame_resync(start),
        };

        match parsed {
            Ok(Some(info)) => FrameResult::Complete(info),
            Ok(None) => FrameResult::Incomplete,
            Err(()) => FrameResult::Desync,
        }
    }

    pub fn consume_frame(&mut self, info: &FrameInfo) {
        self.frame_offset = info.stream_end;

        match self.state {
            ConnState::AwaitingStartup => {
                self.advance_state_from_startup(info.code);
            }
            ConnState::Unknown => {
                self.state = ConnState::Normal;
            }
            ConnState::Normal | ConnState::CopyIn => {
                self.advance_state_from_tag(info.tag);
            }
        }
    }

    fn read_frame_resync(&self, start_offset: usize) -> FrameResult {
        let end_offset = self.buf_offset + self.data.len();
        let mut offset = start_offset;
        while offset < end_offset {
            if self.chain_valid(offset, RESYNC_CHAIN_LEN) {
                match self.try_parse_tagged(offset) {
                    Ok(Some(info)) => return FrameResult::Complete(info),
                    _ => unreachable!("chain_valid guarantees a valid first frame"),
                }
            }
            offset += 1;
        }
        FrameResult::Incomplete
    }

    pub fn resync(&mut self) {
        self.state = ConnState::Unknown;
    }

    fn try_parse_startup(&self, offset: usize) -> Result<Option<FrameInfo>, ()> {
        let pos = offset - self.buf_offset;

        let remaining = self.data.len() - pos;
        if remaining < 4 {
            return Ok(None);
        }
        if self.data[pos] != 0x00 {
            return Err(());
        }
        let length = u32::from_be_bytes([
            self.data[pos],
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
        let code = if length >= 8 {
            Some(u32::from_be_bytes([
                self.data[pos + 4],
                self.data[pos + 5],
                self.data[pos + 6],
                self.data[pos + 7],
            ]))
        } else {
            None
        };
        Ok(Some(FrameInfo {
            stream_start: offset,
            stream_end: offset + length,
            body_offset: 4,
            tag: 0,
            code,
        }))
    }

    // (frame_len, tag, body_start)
    fn try_parse_tagged(&self, offset: usize) -> Result<Option<FrameInfo>, ()> {
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
        let frame_length = 1 + length;
        if remaining < frame_length {
            return Ok(None);
        }
        Ok(Some(FrameInfo {
            stream_start: offset,
            stream_end: offset + frame_length,
            body_offset: 5,
            tag,
            code: None,
        }))
    }

    fn chain_valid(&self, mut offset: usize, count: usize) -> bool {
        for _ in 0..count {
            match self.try_parse_tagged(offset) {
                Ok(Some(info)) => offset = info.stream_end,
                _ => return false,
            }
        }
        true
    }

    fn advance_state_from_startup(&mut self, code: Option<u32>) {
        match code {
            Some(c) if c == SSL_REQUEST_CODE || c == GSS_REQUEST_CODE => {}
            _ => self.state = ConnState::Normal,
        }
    }

    fn advance_state_from_tag(&mut self, tag: u8) {
        match self.state {
            ConnState::Normal if tag == b'd' => self.state = ConnState::CopyIn,
            ConnState::CopyIn if tag == b'c' || tag == b'f' => self.state = ConnState::Normal,
            _ => {}
        }
    }
}
