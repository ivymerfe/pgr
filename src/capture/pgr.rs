use std::collections::{HashMap, VecDeque};
use std::io::{self, BufReader, Read, Seek};

use anyhow::anyhow;

use crate::capture::mini::{ReadExt, invalid};
use crate::capture::reader::{
    CaptureEvent, CaptureMessage, CaptureReader, ClientId, ReadError, ReadResult,
};

const SESSION_INFO: u8 = 1;
const PARSE: u8 = 2;
const QUERY: u8 = 3;
const BIND: u8 = 4;
const EXECUTE: u8 = 5;
const SYNC: u8 = 6;
const TX_START: u8 = 7;
const LSN: u8 = 8;
const TX_END: u8 = 9;
const MAX_FRAME: usize = 1 << 28;

struct Src<R: Read + Seek> {
    r: BufReader<R>,
    pos: u64,
}

impl<R: Read + Seek> Src<R> {
    fn new(r: R) -> Self {
        Self {
            r: BufReader::new(r),
            pos: 0,
        }
    }

    fn skip(&mut self, n: u64) -> io::Result<()> {
        self.r.seek_relative(n as i64)?;
        self.pos += n;
        Ok(())
    }

    fn skip_str(&mut self) -> io::Result<()> {
        let n = self.u32()?;
        self.skip(n as u64)
    }

    fn rewind(&mut self) -> io::Result<()> {
        self.r.rewind()?;
        self.pos = 0;
        Ok(())
    }

    fn append(&mut self, buf: &mut Vec<u8>, n: usize) -> io::Result<()> {
        if n > MAX_FRAME {
            return Err(invalid("record too large"));
        }
        let at = buf.len();
        buf.resize(at + n, 0);
        self.read_exact(&mut buf[at..])
    }
}

impl<R: Read + Seek> Read for Src<R> {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        let n = self.r.read(b)?;
        self.pos += n as u64;
        Ok(n)
    }
}

enum Body {
    Session(Vec<Vec<u8>>),
    Frame(Vec<u8>),
    TxStart,
    TxEnd,
    Ignore,
}

struct Record {
    client: ClientId,
    ts: u64,
    body: Body,
}

enum Scan {
    TxStart,
    TxEnd(u64),
    Lsn(u64),
    Other,
}

#[derive(Default)]
struct Client {
    skip: Vec<bool>,
    next: usize,
    skipping: bool,
    connected: bool,
}

fn eof_ok<T>(r: io::Result<Option<T>>) -> io::Result<Option<T>> {
    match r {
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
        other => other,
    }
}

fn blob<R: Read + Seek>(s: &mut Src<R>) -> io::Result<Vec<u8>> {
    let n = s.u32()? as usize;
    s.vec(n)
}

fn begin(tag: u8, cap: usize) -> Vec<u8> {
    let mut f = Vec::with_capacity(cap + 5);
    f.extend_from_slice(&[tag, 0, 0, 0, 0]);
    f
}

fn end(mut f: Vec<u8>) -> Vec<u8> {
    let n = (f.len() - 1) as u32;
    f[1..5].copy_from_slice(&n.to_be_bytes());
    f
}

fn put_cstr(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(s);
    out.push(0);
}

fn put_quoted(out: &mut Vec<u8>, s: &[u8]) {
    out.push(b'\'');
    for &b in s {
        if b == b'\'' {
            out.push(b'\'');
        }
        out.push(b);
    }
    out.push(b'\'');
}

fn query_frame(query: &[u8]) -> Vec<u8> {
    let mut f = begin(b'Q', query.len() + 1);
    put_cstr(&mut f, query);
    end(f)
}

fn set_config_frame(name: &[u8], value: &[u8]) -> Vec<u8> {
    let mut f = begin(b'Q', name.len() + value.len() + 32);
    f.extend_from_slice(b"SELECT set_config(");
    put_quoted(&mut f, name);
    f.push(b',');
    put_quoted(&mut f, value);
    f.extend_from_slice(b",false)\0");
    end(f)
}

fn parse_frame<R: Read + Seek>(s: &mut Src<R>, name: &[u8], query: &[u8]) -> io::Result<Vec<u8>> {
    let n = s.u16()? as usize;
    let mut f = begin(b'P', name.len() + query.len() + 4 + 4 * n);
    put_cstr(&mut f, name);
    put_cstr(&mut f, query);
    f.extend_from_slice(&(n as u16).to_be_bytes());
    for _ in 0..n {
        let t = s.u32()?;
        f.extend_from_slice(&t.to_be_bytes());
    }
    Ok(end(f))
}

fn scan<R: Read + Seek>(s: &mut Src<R>) -> io::Result<Option<(ClientId, Scan)>> {
    let mut k = [0u8; 1];
    if s.read(&mut k)? == 0 {
        return Ok(None);
    }
    let client = s.u32()?;
    s.skip(8)?;
    let ev = match k[0] {
        SESSION_INFO => {
            for _ in 0..s.u32()? {
                s.skip_str()?;
                s.skip_str()?;
                s.skip(1)?;
            }
            for _ in 0..s.u32()? {
                s.skip_str()?;
                s.skip(1)?;
                s.skip_str()?;
                let n = s.u16()?;
                s.skip(4 * n as u64)?;
            }
            Scan::Other
        }
        PARSE => {
            s.skip_str()?;
            s.skip_str()?;
            let n = s.u16()?;
            s.skip(4 * n as u64)?;
            Scan::Other
        }
        QUERY => {
            s.skip_str()?;
            Scan::Other
        }
        BIND => {
            s.skip_str()?;
            s.skip_str()?;
            let n = s.u16()?;
            s.skip(2 * n as u64)?;
            for _ in 0..s.u16()? {
                s.skip(4)?;
                let len = s.u32()?;
                if len != u32::MAX {
                    s.skip(len as u64)?;
                }
            }
            Scan::Other
        }
        EXECUTE => {
            s.skip_str()?;
            s.skip(8)?;
            Scan::Other
        }
        SYNC => Scan::Other,
        TX_START => Scan::TxStart,
        LSN => Scan::Lsn(s.u64()?),
        TX_END => {
            s.skip(5)?;
            Scan::TxEnd(s.u64()?)
        }
        _ => return Err(invalid("unknown record type")),
    };
    Ok(Some((client, ev)))
}

fn read_record<R: Read + Seek>(s: &mut Src<R>) -> io::Result<Option<Record>> {
    let mut k = [0u8; 1];
    if s.read(&mut k)? == 0 {
        return Ok(None);
    }
    let client = s.u32()?;
    let ts = s.u64()?;
    let body = match k[0] {
        SESSION_INFO => {
            let mut frames = Vec::new();
            for _ in 0..s.u32()? {
                let name = blob(s)?;
                let val = blob(s)?;
                s.skip(1)?;
                frames.push(set_config_frame(&name, &val));
            }
            for _ in 0..s.u32()? {
                let name = blob(s)?;
                let sql = s.u8()? != 0;
                let query = blob(s)?;
                frames.push(if sql {
                    let n = s.u16()?;
                    s.skip(4 * n as u64)?;
                    query_frame(&query)
                } else {
                    parse_frame(s, &name, &query)?
                });
            }
            Body::Session(frames)
        }
        PARSE => {
            let name = blob(s)?;
            let query = blob(s)?;
            Body::Frame(parse_frame(s, &name, &query)?)
        }
        QUERY => {
            let n = s.u32()? as usize;
            let mut f = begin(b'Q', n + 1);
            s.append(&mut f, n)?;
            f.push(0);
            Body::Frame(end(f))
        }
        BIND => {
            let portal = blob(s)?;
            let stmt = blob(s)?;
            let nrf = s.u16()? as usize;
            let rf = (0..nrf).map(|_| s.u16()).collect::<io::Result<Vec<_>>>()?;
            let np = s.u16()?;
            let mut f = begin(b'B', portal.len() + stmt.len() + 8 + 2 * nrf);
            put_cstr(&mut f, &portal);
            put_cstr(&mut f, &stmt);
            f.extend_from_slice(&0u16.to_be_bytes());
            f.extend_from_slice(&np.to_be_bytes());
            for _ in 0..np {
                s.skip(4)?;
                let len = s.u32()?;
                if len == u32::MAX {
                    f.extend_from_slice(&(-1i32).to_be_bytes());
                } else {
                    f.extend_from_slice(&len.to_be_bytes());
                    s.append(&mut f, len as usize)?;
                }
            }
            f.extend_from_slice(&(nrf as u16).to_be_bytes());
            for x in rf {
                f.extend_from_slice(&x.to_be_bytes());
            }
            Body::Frame(end(f))
        }
        EXECUTE => {
            let portal = blob(s)?;
            let max = (s.u64()? as i64).clamp(0, i32::MAX as i64) as i32;
            let mut f = begin(b'E', portal.len() + 5);
            put_cstr(&mut f, &portal);
            f.extend_from_slice(&max.to_be_bytes());
            Body::Frame(end(f))
        }
        SYNC => Body::Frame(end(begin(b'S', 0))),
        TX_START => Body::TxStart,
        LSN => {
            s.skip(8)?;
            Body::Ignore
        }
        TX_END => {
            s.skip(13)?;
            Body::TxEnd
        }
        _ => return Err(invalid("unknown record type")),
    };
    Ok(Some(Record { client, ts, body }))
}

fn connect(q: &mut VecDeque<CaptureMessage>, c: &mut Client, client: ClientId, ts: u64) {
    if !c.connected {
        c.connected = true;
        q.push_back(CaptureMessage {
            client,
            ts,
            event: CaptureEvent::Connect,
        });
    }
}

fn frame_msg(client: ClientId, ts: u64, offset: usize, frame: Vec<u8>) -> CaptureMessage {
    CaptureMessage {
        client,
        ts,
        event: CaptureEvent::PqFrame {
            tag: frame[0],
            offset,
            frame,
        },
    }
}

pub fn sync_lsn<R: Read + Seek>(r: R) -> anyhow::Result<u64> {
    let mut s = Src::new(r);
    while let Some((_, ev)) = eof_ok(scan(&mut s))? {
        if let Scan::Lsn(l) = ev {
            return Ok(l);
        }
    }
    Err(anyhow!("no sync point"))
}

pub struct PgrReader<R: Read + Seek> {
    src: Src<R>,
    clients: HashMap<ClientId, Client>,
    base: Option<u64>,
    queue: VecDeque<CaptureMessage>,
    max_duration: u64,
}

impl<R: Read + Seek> PgrReader<R> {
    pub fn new(r: R, max_duration: u64) -> anyhow::Result<Self> {
        let mut src = Src::new(r);
        let mut sync = None;
        let mut ends: HashMap<ClientId, Vec<Option<u64>>> = HashMap::new();
        while let Some((client, ev)) = eof_ok(scan(&mut src))? {
            match ev {
                Scan::TxStart => ends.entry(client).or_default().push(None),
                Scan::TxEnd(l) => {
                    if let Some(last) = ends.get_mut(&client).and_then(|v| v.last_mut()) {
                        *last = Some(l);
                    }
                }
                Scan::Lsn(l) => {
                    sync.get_or_insert(l);
                }
                Scan::Other => {}
            }
        }
        let sync = sync.ok_or_else(|| anyhow!("no sync point"))?;
        src.rewind()?;
        let clients = ends
            .into_iter()
            .map(|(k, v)| {
                let skip = v
                    .into_iter()
                    .map(|l| l.is_some_and(|l| l <= sync))
                    .collect();
                (
                    k,
                    Client {
                        skip,
                        ..Default::default()
                    },
                )
            })
            .collect();
        Ok(Self {
            src,
            clients,
            base: None,
            queue: VecDeque::new(),
            max_duration,
        })
    }

    fn process(&mut self, rec: Record, offset: usize) {
        let client = rec.client;
        let ts = rec.ts.saturating_sub(*self.base.get_or_insert(rec.ts));
        let c = self.clients.entry(client).or_default();
        let q = &mut self.queue;
        match rec.body {
            Body::TxStart => {
                c.skipping = c.skip.get(c.next).copied().unwrap_or(false);
                c.next += 1;
            }
            Body::TxEnd => c.skipping = false,
            Body::Ignore => {}
            Body::Session(frames) => {
                connect(q, c, client, ts);
                q.extend(frames.into_iter().map(|f| frame_msg(client, ts, offset, f)));
            }
            Body::Frame(f) => {
                if !c.skipping || f[0] == b'P' {
                    connect(q, c, client, ts);
                    q.push_back(frame_msg(client, ts, offset, f));
                }
            }
        }
    }
}

impl<R: Read + Seek> CaptureReader for PgrReader<R> {
    fn next(&mut self) -> ReadResult {
        loop {
            if let Some(msg) = self.queue.pop_front() {
                if msg.ts > self.max_duration {
                    return Err(ReadError::Eof);
                }
                return Ok(msg);
            }
            let offset = self.src.pos as usize;
            match eof_ok(read_record(&mut self.src)) {
                Ok(Some(rec)) => self.process(rec, offset),
                Ok(None) => return Err(ReadError::Eof),
                Err(e) => return Err(e.into()),
            }
        }
    }
}
