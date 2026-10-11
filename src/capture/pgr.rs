use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{self, Read, Seek};

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

struct Prepared {
    name: Vec<u8>,
    sql: bool,
    query: Vec<u8>,
    types: Vec<u32>,
}

enum Body {
    Session {
        gucs: Vec<(Vec<u8>, Vec<u8>)>,
        prepared: Vec<Prepared>,
    },
    Frame(Vec<u8>),
    TxStart,
    TxEnd {
        lsn: u64,
    },
    Lsn(u64),
}

struct Record {
    client: ClientId,
    ts: u64,
    body: Body,
}

fn str<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
    let n = r.u32()? as usize;
    r.vec(n)
}

fn types<R: Read>(r: &mut R) -> io::Result<Vec<u32>> {
    let n = r.u16()?;
    (0..n).map(|_| r.u32()).collect()
}

fn frame(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(payload.len() + 5);
    f.push(tag);
    f.extend_from_slice(&((payload.len() + 4) as u32).to_be_bytes());
    f.extend_from_slice(payload);
    f
}

fn put_cstr(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(s);
    out.push(0);
}

fn parse_frame(name: &[u8], query: &[u8], types: &[u32]) -> Vec<u8> {
    let mut p = Vec::new();
    put_cstr(&mut p, name);
    put_cstr(&mut p, query);
    p.extend_from_slice(&(types.len() as u16).to_be_bytes());
    for t in types {
        p.extend_from_slice(&t.to_be_bytes());
    }
    frame(b'P', &p)
}

fn query_frame(query: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    put_cstr(&mut p, query);
    frame(b'Q', &p)
}

fn quote(s: &[u8]) -> Vec<u8> {
    let mut o = vec![b'\''];
    for &b in s {
        if b == b'\'' {
            o.push(b'\'');
        }
        o.push(b);
    }
    o.push(b'\'');
    o
}

fn set_config_frame(name: &[u8], value: &[u8]) -> Vec<u8> {
    let mut q = b"SELECT set_config(".to_vec();
    q.extend_from_slice(&quote(name));
    q.push(b',');
    q.extend_from_slice(&quote(value));
    q.extend_from_slice(b",false)");
    query_frame(&q)
}

fn read_record<R: Read>(r: &mut R) -> io::Result<Option<Record>> {
    match read_inner(r) {
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
        other => other,
    }
}

fn read_inner<R: Read>(r: &mut R) -> io::Result<Option<Record>> {
    let mut first = [0u8; 1];
    if r.read(&mut first)? == 0 {
        return Ok(None);
    }
    let client = r.u32()?;
    let ts = r.u64()?;
    let body = match first[0] {
        SESSION_INFO => {
            let n = r.u32()?;
            let mut gucs = Vec::new();
            for _ in 0..n {
                let name = str(r)?;
                let val = str(r)?;
                r.u8()?;
                gucs.push((name, val));
            }
            let n = r.u32()?;
            let mut prepared = Vec::new();
            for _ in 0..n {
                let name = str(r)?;
                let sql = r.u8()? != 0;
                let query = str(r)?;
                let types = types(r)?;
                prepared.push(Prepared {
                    name,
                    sql,
                    query,
                    types,
                });
            }
            Body::Session { gucs, prepared }
        }
        PARSE => {
            let name = str(r)?;
            let query = str(r)?;
            let types = types(r)?;
            Body::Frame(parse_frame(&name, &query, &types))
        }
        QUERY => Body::Frame(query_frame(&str(r)?)),
        BIND => {
            let portal = str(r)?;
            let stmt = str(r)?;
            let nrf = r.u16()?;
            let mut rf = Vec::new();
            for _ in 0..nrf {
                rf.push(r.u16()?);
            }
            let np = r.u16()?;
            let mut p = Vec::new();
            put_cstr(&mut p, &portal);
            put_cstr(&mut p, &stmt);
            p.extend_from_slice(&0u16.to_be_bytes());
            p.extend_from_slice(&np.to_be_bytes());
            for _ in 0..np {
                r.u32()?;
                let len = r.u32()?;
                if len == u32::MAX {
                    p.extend_from_slice(&(-1i32).to_be_bytes());
                } else {
                    let v = r.vec(len as usize)?;
                    p.extend_from_slice(&(len as i32).to_be_bytes());
                    p.extend_from_slice(&v);
                }
            }
            p.extend_from_slice(&nrf.to_be_bytes());
            for f in rf {
                p.extend_from_slice(&f.to_be_bytes());
            }
            Body::Frame(frame(b'B', &p))
        }
        EXECUTE => {
            let portal = str(r)?;
            let max = (r.u64()? as i64).clamp(0, i32::MAX as i64) as i32;
            let mut p = Vec::new();
            put_cstr(&mut p, &portal);
            p.extend_from_slice(&max.to_be_bytes());
            Body::Frame(frame(b'E', &p))
        }
        SYNC => Body::Frame(frame(b'S', &[])),
        TX_START => Body::TxStart,
        LSN => Body::Lsn(r.u64()?),
        TX_END => {
            r.u8()?;
            r.u32()?;
            Body::TxEnd { lsn: r.u64()? }
        }
        _ => return Err(invalid("unknown record type")),
    };
    Ok(Some(Record { client, ts, body }))
}

pub struct PgrReader<R: Read + Seek> {
    r: R,
    sync: u64,
    ends: HashMap<ClientId, Vec<Option<u64>>>,
    state: HashMap<ClientId, (usize, bool)>,
    seen: HashSet<ClientId>,
    base: Option<u64>,
    queue: VecDeque<CaptureMessage>,
    ts_offset: u64,
    max_duration: u64,
}

impl<R: Read + Seek> PgrReader<R> {
    pub fn new(mut r: R, ts_offset: u64, max_duration: u64) -> anyhow::Result<Self> {
        let mut sync = None;
        let mut ends: HashMap<ClientId, Vec<Option<u64>>> = HashMap::new();
        while let Some(rec) = read_record(&mut r)? {
            match rec.body {
                Body::TxStart => ends.entry(rec.client).or_default().push(None),
                Body::TxEnd { lsn } => {
                    if let Some(last) = ends.get_mut(&rec.client).and_then(|v| v.last_mut()) {
                        *last = Some(lsn);
                    }
                }
                Body::Lsn(l) => {
                    sync.get_or_insert(l);
                }
                _ => {}
            }
        }
        let sync = sync.ok_or_else(|| anyhow!("no sync point"))?;
        r.rewind()?;
        Ok(Self {
            r,
            sync,
            ends,
            state: HashMap::new(),
            seen: HashSet::new(),
            base: None,
            queue: VecDeque::new(),
            ts_offset,
            max_duration,
        })
    }

    pub fn lsn(&self) -> u64 {
        self.sync
    }

    fn emit(
        &mut self,
        client: ClientId,
        ts: u64,
        offset: usize,
        frames: impl IntoIterator<Item = Vec<u8>>,
    ) {
        if self.seen.insert(client) {
            self.queue.push_back(CaptureMessage {
                client,
                ts,
                event: CaptureEvent::Connect,
            });
        }
        for frame in frames {
            let tag = frame[0];
            self.queue.push_back(CaptureMessage {
                client,
                ts,
                event: CaptureEvent::PqFrame { tag, offset, frame },
            });
        }
    }

    fn process(&mut self, rec: Record, offset: usize) {
        let base = *self.base.get_or_insert(rec.ts);
        let ts = rec.ts.saturating_sub(base);
        let client = rec.client;
        let st = self.state.entry(client).or_default();
        match rec.body {
            Body::TxStart => {
                st.1 = self
                    .ends
                    .get(&client)
                    .and_then(|v| v.get(st.0))
                    .copied()
                    .flatten()
                    .is_some_and(|l| l <= self.sync);
                st.0 += 1;
            }
            Body::TxEnd { .. } => st.1 = false,
            Body::Lsn(_) => {}
            Body::Session { gucs, prepared } => {
                let frames: Vec<Vec<u8>> = gucs
                    .into_iter()
                    .map(|(n, v)| set_config_frame(&n, &v))
                    .chain(prepared.into_iter().map(|p| {
                        if p.sql {
                            query_frame(&p.query)
                        } else {
                            parse_frame(&p.name, &p.query, &p.types)
                        }
                    }))
                    .collect();
                self.emit(client, ts, offset, frames);
            }
            Body::Frame(f) => {
                if !st.1 || f[0] == b'P' {
                    self.emit(client, ts, offset, [f]);
                }
            }
        }
    }
}

impl<R: Read + Seek> CaptureReader for PgrReader<R> {
    fn next(&mut self) -> ReadResult {
        loop {
            if let Some(msg) = self.queue.pop_front() {
                if msg.ts < self.ts_offset {
                    continue;
                }
                let ts = msg.ts - self.ts_offset;
                if ts > self.max_duration {
                    return Err(ReadError::Eof);
                }
                return Ok(CaptureMessage { ts, ..msg });
            }
            let offset = self.r.stream_position()? as usize;
            match read_record(&mut self.r) {
                Ok(Some(rec)) => self.process(rec, offset),
                Ok(None) => return Err(ReadError::Eof),
                Err(e) => return Err(e.into()),
            }
        }
    }
}
