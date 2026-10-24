use std::{
    collections::VecDeque,
    fs::{self, File},
    hash::{Hash, Hasher},
    io::{self, BufWriter, ErrorKind, Write},
    path::PathBuf,
};

use ahash::{AHashMap, AHasher};
use anyhow::anyhow;
use tracing::{error, info, warn};

use crate::{
    capture::{BindParam, CaptureMessage, CaptureReader, ClientEvent, ClientId},
    trace_reader::{TraceData, TraceReader},
};

pub const NO_PARAMS: usize = u64::MAX as usize;

pub struct TraceRow {
    pub query_offset: usize,
    pub params_offset: usize,
    pub ts_secs: f32,
    pub client_id: u32,
    pub duration_ms: f32,
    pub event_type: u8,
}

pub struct StorageWriter {
    query_writer: BufWriter<File>,
    params_writer: BufWriter<File>,
    trace_writer: BufWriter<File>,
    query_offset: u64,
    params_offset: u64,
    query_map: AHashMap<u64, u64>,
    chunk_secs: f32,
    chunks: Vec<(f32, u64)>,
    trace_row_count: u64,
    folder: PathBuf,
}

fn hash_text(text: &str) -> u64 {
    let mut h = AHasher::default();
    text.hash(&mut h);
    h.finish()
}

impl StorageWriter {
    pub fn new(folder: &PathBuf, chunk_secs: f32) -> io::Result<Self> {
        fs::create_dir_all(folder)?;
        let query_writer = BufWriter::new(File::create(folder.join("queries"))?);
        let params_writer = BufWriter::new(File::create(folder.join("params"))?);
        let trace_writer = BufWriter::new(File::create(folder.join("traces"))?);
        Ok(Self {
            query_writer,
            params_writer,
            trace_writer,
            query_offset: 0,
            params_offset: 0,
            query_map: AHashMap::new(),
            chunk_secs,
            chunks: Vec::new(),
            trace_row_count: 0,
            folder: folder.clone(),
        })
    }

    pub fn map_query(&mut self, text: &str, parameter_types: &[u32]) -> io::Result<usize> {
        let key = hash_text(text);
        if let Some(&offset) = self.query_map.get(&key) {
            return Ok(offset as usize);
        }
        let offset = self.query_offset;
        let text_bytes = text.as_bytes();

        self.query_writer
            .write_all(&(text_bytes.len() as u32).to_le_bytes())?;
        self.query_writer.write_all(text_bytes)?;
        self.query_writer
            .write_all(&(parameter_types.len() as u16).to_le_bytes())?;
        for oid in parameter_types {
            self.query_writer.write_all(&oid.to_le_bytes())?;
        }
        self.query_offset += 4 + text_bytes.len() as u64 + 2 + (parameter_types.len() as u64) * 4;
        self.query_map.insert(key, offset);
        Ok(offset as usize)
    }

    pub fn write_params(
        &mut self,
        query_offset: usize,
        parameters: &[BindParam],
        result_formats: &[u16],
    ) -> io::Result<usize> {
        let offset = self.params_offset;

        self.params_writer
            .write_all(&(query_offset as u64).to_le_bytes())?;

        self.params_writer
            .write_all(&(parameters.len() as u16).to_le_bytes())?;
        for param in parameters {
            self.params_writer
                .write_all(&param.type_oid.to_le_bytes())?;
        }
        self.params_writer
            .write_all(&(parameters.len() as u16).to_le_bytes())?;
        let mut size: u64 = 8 + 2 + (parameters.len() as u64) * 2 + 2;
        for param in parameters {
            match &param.value {
                Some(bytes) => {
                    self.params_writer
                        .write_all(&(bytes.len() as u32).to_le_bytes())?;
                    self.params_writer.write_all(&bytes)?;
                    size += 4 + bytes.len() as u64;
                }
                None => {
                    self.params_writer.write_all(&u32::MAX.to_le_bytes())?;
                    size += 4;
                }
            }
        }
        self.params_writer
            .write_all(&(result_formats.len() as u16).to_le_bytes())?;
        for code in result_formats {
            self.params_writer.write_all(&code.to_le_bytes())?;
        }
        size += 2 + (result_formats.len() as u64) * 2;

        self.params_offset += size;
        Ok(offset as usize)
    }

    pub fn write_trace(&mut self, row: &TraceRow) -> io::Result<()> {
        let w = &mut self.trace_writer;
        w.write_all(&(row.query_offset as u64).to_le_bytes())?;
        w.write_all(&(row.params_offset as u64).to_le_bytes())?;
        w.write_all(&row.ts_secs.to_le_bytes())?;
        w.write_all(&row.client_id.to_le_bytes())?;
        w.write_all(&row.duration_ms.to_le_bytes())?;
        w.write_all(&[row.event_type])?;

        let idx = (row.ts_secs / self.chunk_secs) as usize;
        if idx >= self.chunks.len() {
            self.chunks.resize(idx + 1, (0.0, self.trace_row_count));
        }
        self.chunks[idx].0 = self.chunks[idx].0.max(row.duration_ms);
        self.trace_row_count += 1;

        Ok(())
    }

    pub fn finish(mut self) -> io::Result<()> {
        self.query_writer.flush()?;
        self.params_writer.flush()?;
        self.trace_writer.flush()?;

        let mut chunk_writer = BufWriter::new(File::create(self.folder.join("chunks"))?);
        chunk_writer.write_all(&self.chunk_secs.to_le_bytes())?;
        chunk_writer.write_all(&self.trace_row_count.to_le_bytes())?;
        for (dur, start_row) in &self.chunks {
            chunk_writer.write_all(&dur.to_le_bytes())?;
            chunk_writer.write_all(&start_row.to_le_bytes())?;
        }
        chunk_writer.flush()?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct QueryInfo {
    index: u32,
    offset: usize,
    params_offset: usize,
    ts: u64,
}

struct AnalyzeClient {
    id: ClientId,
    frame_index: u32,
    queries: VecDeque<QueryInfo>,
    statements: AHashMap<String, usize>,
    portals: AHashMap<String, (usize, usize)>,
}

impl AnalyzeClient {
    pub fn new(id: ClientId) -> Self {
        Self {
            id,
            frame_index: 0,
            queries: VecDeque::new(),
            statements: AHashMap::new(),
            portals: AHashMap::new(),
        }
    }

    pub fn on_trace(&mut self, data: &TraceData, writer: &mut StorageWriter) -> anyhow::Result<()> {
        while let Some(info) = self.queries.front() {
            if info.index < data.frame_index {
                self.queries.pop_front();
                continue;
            }
            if info.index > data.frame_index {
                break;
            }
            let row = TraceRow {
                client_id: self.id,
                query_offset: info.offset,
                params_offset: info.params_offset,
                ts_secs: (info.ts as f32) / 1e6,
                event_type: data.event_type,
                duration_ms: (data.duration_us as f32) / 1e3,
            };
            writer.write_trace(&row)?;
            return Ok(());
        }
        warn!("[{}] no query info for frame={}", self.id, data.frame_index);
        Ok(())
    }

    pub fn on_capture(
        &mut self,
        msg: &CaptureMessage,
        writer: &mut StorageWriter,
    ) -> anyhow::Result<()> {
        match &msg.event {
            ClientEvent::SimpleQuery { text } => {
                self.frame_index += 1;
                let query_offset = writer.map_query(&text, &[])?;
                let info = QueryInfo {
                    index: self.frame_index,
                    offset: query_offset,
                    params_offset: NO_PARAMS,
                    ts: msg.ts,
                };
                self.queries.push_back(info);
            }
            ClientEvent::Parse {
                name,
                query,
                param_types,
            } => {
                self.frame_index += 1;
                let query_offset = writer.map_query(&query, &param_types)?;
                self.statements.insert(name.to_string(), query_offset);
                let info = QueryInfo {
                    index: self.frame_index,
                    offset: query_offset,
                    params_offset: NO_PARAMS,
                    ts: msg.ts,
                };
                self.queries.push_back(info);
            }
            ClientEvent::Bind {
                portal,
                statement,
                params,
                result_formats,
            } => {
                self.frame_index += 1;
                match self.statements.get(statement).copied() {
                    Some(query_offset) => {
                        let params_offset =
                            writer.write_params(query_offset, &params, &result_formats)?;
                        self.portals
                            .insert(portal.to_string(), (query_offset, params_offset));
                        let info = QueryInfo {
                            index: self.frame_index,
                            offset: query_offset,
                            params_offset,
                            ts: msg.ts,
                        };
                        self.queries.push_back(info);
                    }
                    None => {
                        error!("[{}] Bind to unknown statement \"{}\"", self.id, statement);
                    }
                }
            }
            ClientEvent::Execute { portal, .. } => {
                self.frame_index += 1;
                match self.portals.get(portal) {
                    Some((query_offset, params_offset)) => {
                        let info = QueryInfo {
                            index: self.frame_index,
                            offset: *query_offset,
                            params_offset: *params_offset,
                            ts: msg.ts,
                        };
                        self.queries.push_back(info);
                    }
                    None => {
                        error!("[{}] Execute on unknown portal \"{}\"", self.id, portal);
                    }
                }
            }
            _ => (),
        }
        Ok(())
    }
}

pub fn analyze(
    mut capture_reader: CaptureReader,
    mut trace_reader: TraceReader,
    mut writer: StorageWriter,
) -> anyhow::Result<()> {
    let mut clients = AHashMap::<ClientId, AnalyzeClient>::new();

    let (mut traces_total, mut traces_processed) = (0, 0);
    let mut capture_eof = false;
    loop {
        let trace = match trace_reader.next() {
            Ok(data) => data,
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
            Err(e) => {
                return Err(anyhow!("Failed to read trace: {e}"));
            }
        };
        let client = clients
            .entry(trace.id)
            .or_insert_with(|| AnalyzeClient::new(trace.id));
        if client.frame_index >= trace.frame_index {
            client.on_trace(&trace, &mut writer)?;
            traces_processed += 1;
        } else {
            while !capture_eof {
                match capture_reader.read_event() {
                    Ok(Some(msg)) => {
                        let client = clients
                            .entry(msg.id)
                            .or_insert_with(|| AnalyzeClient::new(msg.id));
                        client.on_capture(&msg, &mut writer)?;
                        if client.id == trace.id && client.frame_index >= trace.frame_index {
                            client.on_trace(&trace, &mut writer)?;
                            traces_processed += 1;
                            break;
                        }
                    }
                    Ok(None) => {
                        info!(
                            "Finished reading capture on trace id={} index={}",
                            trace.id, trace.frame_index
                        );
                        capture_eof = true;
                    }
                    Err(e) => {
                        return Err(anyhow!("Failed to read capture: {e}"));
                    }
                }
            }
        }
        traces_total += 1;
    }
    info!("Processed {}/{}", traces_processed, traces_total);
    writer.finish()?;
    Ok(())
}
