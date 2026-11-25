use std::{
    fs::File,
    io::{self, BufWriter, Write},
};

use crate::readers::{
    capture::*,
    session::{SessionReader, SessionRecord, parse_copy},
    timings::TimingReader,
    trace::TraceReader,
};

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

pub fn dump_capture(mut reader: CaptureReader, output: File) -> anyhow::Result<()> {
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

fn msg_name(t: u8) -> &'static str {
    match t {
        MSG_LSN => "lsn",
        MSG_CONNECT => "connect",
        MSG_DISCONNECT => "disconnect",
        MSG_SIMPLE_QUERY => "simple_query",
        MSG_PARSE => "parse",
        MSG_BIND => "bind",
        MSG_EXECUTE => "execute",
        MSG_CLOSE => "close",
        MSG_SYNC => "sync",
        _ => "unknown",
    }
}

pub fn dump_trace(mut reader: TraceReader, output: File) -> anyhow::Result<()> {
    let mut w = BufWriter::new(output);
    w.write_all(b"client_id,frame_index,duration_us,event\n")?;
    loop {
        let d = match reader.next() {
            Ok(d) => d,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        };
        writeln!(
            w,
            "{},{},{},{}",
            d.id, d.frame_index, d.duration_us, d.event_type as char
        )?;
    }
    w.flush()?;
    Ok(())
}

pub fn dump_timings(mut reader: TimingReader, output: File) -> anyhow::Result<()> {
    let mut w = BufWriter::new(output);
    w.write_all(b"timestamp,client_id,message\n")?;
    while let Some(d) = reader.next()? {
        writeln!(w, "{},{},{}", d.ts, d.id, msg_name(d.event_type))?;
    }
    w.flush()?;
    Ok(())
}

fn field(w: &mut impl Write, v: &Option<Vec<u8>>) -> io::Result<()> {
    match v {
        None => w.write_all(b"NULL"),
        Some(b) => match std::str::from_utf8(b) {
            Ok(s) if !s.is_empty() && !s.chars().any(|c| c.is_control()) => {
                write!(w, "{:?}", s)
            }
            _ => {
                w.write_all(b"0x")?;
                for x in b {
                    write!(w, "{:02x}", x)?;
                }
                Ok(())
            }
        },
    }
}

pub fn dump_session(mut reader: SessionReader, output: File) -> anyhow::Result<()> {
    let mut w = BufWriter::new(output);
    let mut table: Option<(String, String, String, Vec<u8>)> = None;
    while let Some(r) = reader.next()? {
        match r {
            SessionRecord::GucSet { name, value } => {
                writeln!(w, "guc {} = {:?}", name, value)?;
            }
            SessionRecord::GucReset { name } => {
                writeln!(w, "guc-reset {}", name)?;
            }
            SessionRecord::PrepPut {
                name,
                from_sql,
                query,
                param_types,
            } => {
                writeln!(
                    w,
                    "prepared {:?} from_sql={} types={:?} query={:?}",
                    name, from_sql, param_types, query
                )?;
            }
            SessionRecord::PrepDrop { name } => {
                writeln!(w, "prepared-drop {:?}", name)?;
            }
            SessionRecord::TableBegin {
                name,
                columns,
                post,
            } => {
                table = Some((name, columns, post, Vec::new()));
            }
            SessionRecord::TableChunk(c) => {
                if let Some(t) = table.as_mut() {
                    t.3.extend_from_slice(&c);
                }
            }
            SessionRecord::TableEnd => {
                if let Some((name, columns, post, data)) = table.take() {
                    let rows = parse_copy(&data)?;
                    writeln!(w, "table {}", name)?;
                    writeln!(w, "  columns: {}", columns)?;
                    writeln!(w, "  post: {}", post)?;
                    writeln!(w, "  rows: {} bytes: {}", rows.len(), data.len())?;
                    for row in &rows {
                        w.write_all(b"  ")?;
                        for (i, v) in row.iter().enumerate() {
                            if i > 0 {
                                w.write_all(b" | ")?;
                            }
                            field(&mut w, v)?;
                        }
                        w.write_all(b"\n")?;
                    }
                }
            }
            SessionRecord::TableDrop { name } => {
                writeln!(w, "table-drop {}", name)?;
            }
        }
    }
    w.flush()?;
    Ok(())
}
