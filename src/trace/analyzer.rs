use std::{collections::VecDeque, io::ErrorKind};

use ahash::AHashMap;
use anyhow::anyhow;
use tracing::{error, info, warn};

use crate::{
    capture::reader::{CaptureEvent, CaptureMessage, CaptureReader, ClientId, ReadError},
    proto::c2s::{PgMsg, PgMsgParser},
    trace::{
        reader::{TraceData, TraceReader},
        writer::{NO_PARAMS, StorageWriter, TraceRow},
    },
};

#[derive(Clone, Copy)]
struct QueryInfo {
    index: u32,
    offset: usize,
    params_offset: usize,
    ts: u64,
}

struct AnalyzeClient {
    id: ClientId,
    parser: PgMsgParser,
    frame_index: u32,
    queries: VecDeque<QueryInfo>,
    statements: AHashMap<String, usize>,
    portals: AHashMap<String, (usize, usize)>,
}

impl AnalyzeClient {
    pub fn new(id: ClientId) -> Self {
        Self {
            id,
            parser: PgMsgParser::new(),
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
        data: &CaptureMessage,
        writer: &mut StorageWriter,
    ) -> anyhow::Result<()> {
        if let CaptureEvent::PqFrame { frame, .. } = &data.event {
            let msg = match self.parser.parse(frame) {
                Ok(msg) => msg,
                Err(e) => {
                    return Err(anyhow!("[{}] failed to parse message: {}", self.id, e));
                }
            };
            match msg {
                PgMsg::Query(text) => {
                    self.frame_index += 1;
                    let query_offset = writer.map_query(text, &[])?;
                    let info = QueryInfo {
                        index: self.frame_index,
                        offset: query_offset,
                        params_offset: NO_PARAMS,
                        ts: data.ts,
                    };
                    self.queries.push_back(info);
                }
                PgMsg::Parse {
                    name,
                    query,
                    parameter_type_oids,
                } => {
                    self.frame_index += 1;
                    let query_offset = writer.map_query(query, parameter_type_oids)?;
                    self.statements.insert(name.to_string(), query_offset);
                    let info = QueryInfo {
                        index: self.frame_index,
                        offset: query_offset,
                        params_offset: NO_PARAMS,
                        ts: data.ts,
                    };
                    self.queries.push_back(info);
                }
                PgMsg::Bind {
                    portal,
                    statement,
                    parameter_format_codes,
                    parameters_src,
                    parameters,
                    result_format_codes,
                } => {
                    self.frame_index += 1;
                    match self.statements.get(statement).copied() {
                        Some(query_offset) => {
                            let params_offset = writer.write_params(
                                query_offset,
                                parameter_format_codes,
                                parameters_src,
                                parameters,
                                result_format_codes,
                            )?;
                            self.portals
                                .insert(portal.to_string(), (query_offset, params_offset));
                            let info = QueryInfo {
                                index: self.frame_index,
                                offset: query_offset,
                                params_offset,
                                ts: data.ts,
                            };
                            self.queries.push_back(info);
                        }
                        None => {
                            error!("[{}] Bind to unknown statement \"{}\"", self.id, statement);
                        }
                    }
                }
                PgMsg::Execute { portal, .. } => {
                    self.frame_index += 1;
                    match self.portals.get(portal) {
                        Some((query_offset, params_offset)) => {
                            let info = QueryInfo {
                                index: self.frame_index,
                                offset: *query_offset,
                                params_offset: *params_offset,
                                ts: data.ts,
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
        }
        Ok(())
    }
}

pub fn analyze(
    mut capture_reader: Box<dyn CaptureReader>,
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
                match capture_reader.next() {
                    Ok(msg) => {
                        let client = clients
                            .entry(msg.client)
                            .or_insert_with(|| AnalyzeClient::new(msg.client));
                        client.on_capture(&msg, &mut writer)?;
                        if client.id == trace.id && client.frame_index >= trace.frame_index {
                            client.on_trace(&trace, &mut writer)?;
                            traces_processed += 1;
                            break;
                        }
                    }
                    Err(ReadError::Eof) => {
                        info!(
                            "Finished reading capture on trace id={} index={}",
                            trace.id, trace.frame_index
                        );
                        capture_eof = true;
                    }
                    Err(ReadError::Error(e)) => {
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
