use std::io::{self, BufReader, Read, Write};

use zstd::{Decoder, Encoder};

use crate::capture::reader::{CaptureEvent, CaptureMessage, CaptureReader, ReadError, ReadResult};

const CONNECT: u8 = 0;
const DISCONNECT: u8 = 1;
const FRAME: u8 = 2;
const MAX_FRAME: usize = 1 << 28;

pub fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

pub trait ReadExt: Read + Sized {
    fn vec(&mut self, n: usize) -> io::Result<Vec<u8>> {
        if n > MAX_FRAME {
            return Err(invalid("record too large"));
        }
        let mut v = vec![0; n];
        self.read_exact(&mut v)?;
        Ok(v)
    }

    fn array<const N: usize>(&mut self) -> io::Result<[u8; N]> {
        let mut a = [0; N];
        self.read_exact(&mut a)?;
        Ok(a)
    }

    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> io::Result<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }
}

impl<R: Read> ReadExt for R {}

pub struct MiniWriter<W: Write> {
    enc: Encoder<'static, W>,
    buf: Vec<u8>,
}

impl<W: Write> MiniWriter<W> {
    pub fn new(w: W) -> io::Result<Self> {
        Ok(Self {
            enc: Encoder::new(w, 3)?,
            buf: Vec::new(),
        })
    }

    pub fn write(&mut self, msg: &CaptureMessage) -> io::Result<()> {
        let (kind, frame) = match &msg.event {
            CaptureEvent::Connect => (CONNECT, None),
            CaptureEvent::Disconnect => (DISCONNECT, None),
            CaptureEvent::PqFrame { frame, .. } => (FRAME, Some(frame)),
        };
        self.buf.clear();
        self.buf.push(kind);
        self.buf.extend_from_slice(&msg.client.to_le_bytes());
        self.buf.extend_from_slice(&msg.ts.to_le_bytes());
        if let Some(f) = frame {
            self.buf.extend_from_slice(&(f.len() as u32).to_le_bytes());
            self.buf.extend_from_slice(f);
        }
        self.enc.write_all(&self.buf)
    }

    pub fn finish(self) -> io::Result<W> {
        self.enc.finish()
    }
}

pub struct MiniReader<R: Read> {
    dec: Decoder<'static, BufReader<R>>,
    ts_offset: u64,
    max_duration: u64,
    pos: usize,
}

impl<R: Read> MiniReader<R> {
    pub fn new(r: R, ts_offset: u64, max_duration: u64) -> io::Result<Self> {
        Ok(Self {
            dec: Decoder::new(r)?,
            ts_offset,
            max_duration,
            pos: 0,
        })
    }

    fn read_msg(&mut self) -> io::Result<Option<CaptureMessage>> {
        let mut kind = [0u8; 1];
        if self.dec.read(&mut kind)? == 0 {
            return Ok(None);
        }
        let client = self.dec.u32()?;
        let ts = self.dec.u64()?;
        let offset = self.pos;
        self.pos += 13;
        let event = match kind[0] {
            CONNECT => CaptureEvent::Connect,
            DISCONNECT => CaptureEvent::Disconnect,
            FRAME => {
                let len = self.dec.u32()? as usize;
                let frame = self.dec.vec(len)?;
                self.pos += 4 + len;
                let tag = *frame.first().ok_or_else(|| invalid("empty frame"))?;
                CaptureEvent::PqFrame { tag, offset, frame }
            }
            _ => return Err(invalid("unknown record kind")),
        };
        Ok(Some(CaptureMessage { client, ts, event }))
    }
}

impl<R: Read> CaptureReader for MiniReader<R> {
    fn next(&mut self) -> ReadResult {
        loop {
            let msg = match self.read_msg() {
                Ok(Some(m)) => m,
                Ok(None) => return Err(ReadError::Eof),
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Err(ReadError::Eof),
                Err(e) => return Err(e.into()),
            };
            if msg.ts < self.ts_offset {
                continue;
            }
            let ts = msg.ts - self.ts_offset;
            if ts > self.max_duration {
                return Err(ReadError::Eof);
            }
            return Ok(CaptureMessage { ts, ..msg });
        }
    }
}
