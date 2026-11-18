use std::{
    fs::File,
    io::{self, Read},
};

use crate::readers::zstd::{ZReader, open_zstd};

const REC_GUC_SET: u8 = 1;
const REC_GUC_RESET: u8 = 2;
const REC_PREP_PUT: u8 = 3;
const REC_PREP_DROP: u8 = 4;
const REC_TABLE_BEGIN: u8 = 5;
const REC_TABLE_CHUNK: u8 = 6;
const REC_TABLE_END: u8 = 7;
const REC_TABLE_DROP: u8 = 8;

pub enum SessionRecord {
    GucSet {
        name: String,
        value: String,
    },
    GucReset {
        name: String,
    },
    PrepPut {
        name: String,
        from_sql: bool,
        query: String,
        param_types: Vec<u32>,
    },
    PrepDrop {
        name: String,
    },
    TableBegin {
        name: String,
        columns: String,
        post: String,
    },
    TableChunk(Vec<u8>),
    TableEnd,
    TableDrop {
        name: String,
    },
}

pub type CopyRows = Vec<Vec<Option<Vec<u8>>>>;

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

struct Cur<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Cur<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, p: 0 }
    }

    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        let end = self
            .p
            .checked_add(n)
            .filter(|&e| e <= self.b.len())
            .ok_or_else(|| invalid("short record"))?;
        let s = &self.b[self.p..end];
        self.p = end;
        Ok(s)
    }

    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> io::Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn str(&mut self) -> io::Result<String> {
        let n = self.u32()? as usize;
        Ok(String::from_utf8_lossy(self.take(n)?).into_owned())
    }

    fn be_i16(&mut self) -> io::Result<i16> {
        Ok(i16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn be_i32(&mut self) -> io::Result<i32> {
        Ok(i32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
}

pub struct SessionReader {
    buf: ZReader,
}

impl SessionReader {
    pub fn new(file: File) -> io::Result<Self> {
        Ok(Self {
            buf: open_zstd(file)?,
        })
    }

    fn read_body(&mut self) -> io::Result<Vec<u8>> {
        let mut l = [0u8; 4];
        self.buf.read_exact(&mut l)?;
        let mut v = vec![0u8; u32::from_le_bytes(l) as usize];
        self.buf.read_exact(&mut v)?;
        Ok(v)
    }

    pub fn next(&mut self) -> io::Result<Option<SessionRecord>> {
        let mut t = [0u8; 1];
        if self.buf.read(&mut t)? == 0 {
            return Ok(None);
        }
        let body = match self.read_body() {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        };
        parse_record(t[0], &body).map(Some)
    }
}

fn parse_record(t: u8, body: &[u8]) -> io::Result<SessionRecord> {
    let mut c = Cur::new(body);
    Ok(match t {
        REC_GUC_SET => SessionRecord::GucSet {
            name: c.str()?,
            value: c.str()?,
        },
        REC_GUC_RESET => SessionRecord::GucReset { name: c.str()? },
        REC_PREP_PUT => {
            let name = c.str()?;
            let from_sql = c.u8()? != 0;
            let query = c.str()?;
            let n = c.u16()?;
            let mut param_types = Vec::with_capacity(n as usize);
            for _ in 0..n {
                param_types.push(c.u32()?);
            }
            SessionRecord::PrepPut {
                name,
                from_sql,
                query,
                param_types,
            }
        }
        REC_PREP_DROP => SessionRecord::PrepDrop { name: c.str()? },
        REC_TABLE_BEGIN => SessionRecord::TableBegin {
            name: c.str()?,
            columns: c.str()?,
            post: c.str()?,
        },
        REC_TABLE_CHUNK => SessionRecord::TableChunk(body.to_vec()),
        REC_TABLE_END => SessionRecord::TableEnd,
        REC_TABLE_DROP => SessionRecord::TableDrop { name: c.str()? },
        _ => return Err(invalid("unknown session record")),
    })
}

pub fn parse_copy(data: &[u8]) -> io::Result<CopyRows> {
    let mut rows = Vec::new();
    if data.is_empty() {
        return Ok(rows);
    }
    let mut c = Cur::new(data);
    c.take(11)?;
    c.take(4)?;
    let ext = c.be_i32()?;
    c.take(ext as usize)?;
    loop {
        let n = c.be_i16()?;
        if n == -1 {
            break;
        }
        let mut row = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let l = c.be_i32()?;
            if l == -1 {
                row.push(None);
            } else {
                row.push(Some(c.take(l as usize)?.to_vec()));
            }
        }
        rows.push(row);
    }
    Ok(rows)
}
