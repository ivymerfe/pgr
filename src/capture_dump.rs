use std::{
    fs::File,
    io::{self, BufWriter, Write},
};

use crate::capture::{CaptureReader, ClientEvent};

fn ts(w: &mut impl Write, ts: u64, base: u64) -> io::Result<()> {
    let d = ts as i64 - base as i64;
    let a = d.unsigned_abs();
    if d < 0 {
        w.write_all(b"-")?;
    }
    write!(w, "{}.{:06}", a / 1_000_000, a % 1_000_000)
}

fn text(w: &mut impl Write, s: &[u8]) -> io::Result<()> {
    w.write_all(b",\"")?;
    let mut start = 0;
    let s = String::from_utf8_lossy(s);
    let b = s.as_bytes();
    for i in 0..b.len() {
        if b[i] == b'"' {
            w.write_all(&b[start..=i])?;
            start = i;
        }
    }
    w.write_all(&b[start..])?;
    w.write_all(b"\"")
}

fn head(w: &mut impl Write, t: u64, base: u64, id: u32, name: &str) -> io::Result<()> {
    ts(w, t, base)?;
    write!(w, ",{},{}", id, name)
}

fn list<T: std::fmt::Display>(w: &mut impl Write, v: &[T]) -> io::Result<()> {
    w.write_all(b",\"")?;
    for (i, x) in v.iter().enumerate() {
        if i > 0 {
            w.write_all(b" ")?;
        }
        write!(w, "{}", x)?;
    }
    w.write_all(b"\"")
}

pub fn dump(mut reader: CaptureReader, output: File) -> anyhow::Result<()> {
    let mut w = BufWriter::new(output);
    let base = reader.start_ts;
    w.write_all(b"timestamp,client_id,message,fields\n")?;
    head(&mut w, base, base, 0, "lsn")?;
    write!(w, ",{}\n", reader.lsn)?;

    while let Some(m) = reader.read_event()? {
        match m.event {
            ClientEvent::Lsn { lsn } => {
                head(&mut w, m.ts, base, m.id, "lsn")?;
                write!(w, ",{}", lsn)?;
            }
            ClientEvent::Connect { session_id } => {
                head(&mut w, m.ts, base, m.id, "connect")?;
                text(&mut w, session_id.as_bytes())?;
            }
            ClientEvent::Disconnect => {
                head(&mut w, m.ts, base, m.id, "disconnect")?;
            }
            ClientEvent::SimpleQuery { text: q } => {
                head(&mut w, m.ts, base, m.id, "simple_query")?;
                text(&mut w, q.as_bytes())?;
            }
            ClientEvent::Parse {
                name,
                query,
                param_types,
            } => {
                head(&mut w, m.ts, base, m.id, "parse")?;
                text(&mut w, name.as_bytes())?;
                text(&mut w, query.as_bytes())?;
                list(&mut w, &param_types)?;
            }
            ClientEvent::Bind {
                portal,
                statement,
                result_formats,
                params,
            } => {
                head(&mut w, m.ts, base, m.id, "bind")?;
                text(&mut w, portal.as_bytes())?;
                text(&mut w, statement.as_bytes())?;
                list(&mut w, &result_formats)?;
                for p in params {
                    write!(w, ",{}", p.type_oid)?;
                    match p.value {
                        Some(v) => text(&mut w, &v)?,
                        None => w.write_all(b",NULL")?,
                    }
                }
            }
            ClientEvent::Execute { portal, max_rows } => {
                head(&mut w, m.ts, base, m.id, "execute")?;
                text(&mut w, portal.as_bytes())?;
                write!(w, ",{}", max_rows)?;
            }
            ClientEvent::Sync => {
                head(&mut w, m.ts, base, m.id, "sync")?;
            }
            ClientEvent::TxEnd {
                committed,
                xid,
                lsn,
            } => {
                head(&mut w, m.ts, base, m.id, "tx_end")?;
                text(&mut w, if committed { b"commit" } else { b"abort" })?;
                write!(w, ",{},{}", xid, lsn)?;
            }
            ClientEvent::Close { kind, name } => {
                head(&mut w, m.ts, base, m.id, "close")?;
                write!(w, ",{}", kind)?;
                text(&mut w, name.as_bytes())?;
            }
        }
        w.write_all(b"\n")?;
    }

    w.flush()?;
    Ok(())
}
