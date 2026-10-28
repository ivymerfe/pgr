use std::{
    fs::File,
    io::{self, BufReader, Read},
};

pub type ClientId = u32;

const MSG_LSN: u8 = 1;
const MSG_CONNECT: u8 = 2;
const MSG_DISCONNECT: u8 = 3;
const MSG_SIMPLE_QUERY: u8 = 4;
const MSG_PARSE: u8 = 5;
const MSG_BIND: u8 = 6;
const MSG_EXECUTE: u8 = 7;
const MSG_SYNC: u8 = 8;
const MSG_TX_END: u8 = 9;
const MSG_CLOSE: u8 = 10;

pub struct BindParam {
    pub type_oid: u32,
    pub value: Option<Vec<u8>>,
}

pub enum ClientEvent {
    Lsn {
        lsn: u64,
    },
    Connect {
        session_id: String,
    },
    Disconnect,
    SimpleQuery {
        text: String,
    },
    Parse {
        name: String,
        query: String,
        param_types: Vec<u32>,
    },
    Bind {
        portal: String,
        statement: String,
        result_formats: Vec<u16>,
        params: Vec<BindParam>,
    },
    Execute {
        portal: String,
        max_rows: i64,
    },
    Sync,
    TxEnd {
        committed: bool,
        xid: u32,
        lsn: u64,
    },
    Close {
        kind: u8,
        name: String,
    },
}

pub struct CaptureMessage {
    pub id: ClientId,
    pub ts: u64,
    pub event: ClientEvent,
}

pub struct CaptureReader {
    buf: BufReader<File>,
    pub lsn: u64,
    pub start_ts: u64,
}

impl CaptureReader {
    pub fn new(file: File) -> io::Result<Self> {
        let mut r = Self {
            buf: BufReader::new(file),
            lsn: 0,
            start_ts: 0,
        };
        match r.read_event()? {
            Some(CaptureMessage {
                ts,
                event: ClientEvent::Lsn { lsn },
                ..
            }) => {
                r.lsn = lsn;
                r.start_ts = ts;
                Ok(r)
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "capture must start with lsn",
            )),
        }
    }

    fn raw(&mut self, n: usize) -> io::Result<Vec<u8>> {
        let mut v = vec![0u8; n];
        self.buf.read_exact(&mut v)?;
        Ok(v)
    }

    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.raw(1)?[0])
    }

    fn u16(&mut self) -> io::Result<u16> {
        Ok(u16::from_le_bytes(self.raw(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_le_bytes(self.raw(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_le_bytes(self.raw(8)?.try_into().unwrap()))
    }

    fn bytes(&mut self) -> io::Result<Vec<u8>> {
        let n = self.u32()? as usize;
        self.raw(n)
    }

    fn string(&mut self) -> io::Result<String> {
        Ok(String::from_utf8_lossy(&self.bytes()?).into_owned())
    }

    pub fn read_event(&mut self) -> io::Result<Option<CaptureMessage>> {
        let mut t = [0u8; 1];
        if self.buf.read(&mut t)? == 0 {
            return Ok(None);
        }
        match self.read_body(t[0]) {
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
            r => r.map(Some),
        }
    }

    fn read_body(&mut self, t: u8) -> io::Result<CaptureMessage> {
        let id = self.u32()?;
        let ts = self.u64()?;
        let event = match t {
            MSG_LSN => ClientEvent::Lsn { lsn: self.u64()? },
            MSG_CONNECT => ClientEvent::Connect {
                session_id: self.string()?,
            },
            MSG_DISCONNECT => ClientEvent::Disconnect,
            MSG_SIMPLE_QUERY => ClientEvent::SimpleQuery {
                text: self.string()?,
            },
            MSG_PARSE => {
                let name = self.string()?;
                let query = self.string()?;
                let n = self.u16()?;
                let mut param_types = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    param_types.push(self.u32()?);
                }
                ClientEvent::Parse {
                    name,
                    query,
                    param_types,
                }
            }
            MSG_BIND => {
                let portal = self.string()?;
                let statement = self.string()?;
                let nrf = self.u16()?;
                let mut result_formats = Vec::with_capacity(nrf as usize);
                for _ in 0..nrf {
                    result_formats.push(self.u16()?);
                }
                let np = self.u16()?;
                let mut params = Vec::with_capacity(np as usize);
                for _ in 0..np {
                    let type_oid = self.u32()?;
                    let len = self.u32()?;
                    let value = if len == u32::MAX {
                        None
                    } else {
                        Some(self.raw(len as usize)?)
                    };
                    params.push(BindParam { type_oid, value });
                }
                ClientEvent::Bind {
                    portal,
                    statement,
                    result_formats,
                    params,
                }
            }
            MSG_EXECUTE => ClientEvent::Execute {
                portal: self.string()?,
                max_rows: self.u64()? as i64,
            },
            MSG_SYNC => ClientEvent::Sync,
            MSG_TX_END => ClientEvent::TxEnd {
                committed: self.u8()? != 0,
                xid: self.u32()?,
                lsn: self.u64()?,
            },
            MSG_CLOSE => ClientEvent::Close {
                kind: self.u8()?,
                name: self.string()?,
            },
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unknown message type",
                ));
            }
        };
        Ok(CaptureMessage { id, ts, event })
    }
}
