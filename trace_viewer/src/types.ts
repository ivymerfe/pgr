export interface TraceRow {
  query_offset: number;
  params_offset: number;
  ts_secs: number;
  client_id: number;
  duration_ms: number;
  event_type: number;
}

export interface QueryEntry {
  text: string;
  oids: number[];
}

export interface ParamsEntry {
  queryOffset: number;
  paramFormatCodes: number[];
  params: (Uint8Array | null)[];
  resultFormatCodes: number[];
}

export interface ChunkData {
  chunkSeconds: number;
  durations: Float32Array;
  startRows: Float64Array;
}
