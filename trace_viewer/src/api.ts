import type { TraceRow, QueryEntry, ParamsEntry, ChunkData } from "./types";

export const TRACE_ROW_SIZE = 8 + 8 + 4 + 4 + 4 + 1;
export const NO_PARAMS = Number(0xffffffffffffffffn);

export const queryCache = new Map<number, QueryEntry>();
export const queryPending = new Set<number>();
export const paramsCache = new Map<number, ParamsEntry>();

export function clearApiCaches() {
  queryCache.clear();
  queryPending.clear();
  paramsCache.clear();
}

export function parseChunks(buf: ArrayBuffer): ChunkData {
  const view = new DataView(buf);
  const chunkSeconds = view.getFloat32(0, true);
  const totalRows = Number(view.getBigUint64(4, true));
  const numChunks = (buf.byteLength - 12) / 12;
  const durations = new Float32Array(numChunks);
  const startRows = new Float64Array(numChunks);
  for (let i = 0; i < numChunks; i++) {
    const o = 12 + i * 12;
    durations[i] = view.getFloat32(o, true);
    startRows[i] = Number(view.getBigUint64(o + 4, true));
  }
  void totalRows;
  return { chunkSeconds, durations, startRows };
}

export async function fetchChunks(baseUrl: string): Promise<ChunkData> {
  const cleanUrl = cleanBaseUrl(baseUrl);
  const res = await fetch(`${cleanUrl}/chunks`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const buf = await res.arrayBuffer();
  return parseChunks(buf);
}

export async function fetchTracesRange(
  baseUrl: string,
  fromChunk: number,
  toChunk: number,
): Promise<TraceRow[]> {
  const cleanUrl = cleanBaseUrl(baseUrl);
  const res = await fetch(
    `${cleanUrl}/traces?from_chunk=${fromChunk}&to_chunk=${toChunk}`,
  );
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const buf = await res.arrayBuffer();
  return parseTraces(buf);
}

export function parseTraces(buf: ArrayBuffer): TraceRow[] {
  const view = new DataView(buf);
  const count = buf.byteLength / TRACE_ROW_SIZE;
  const out: TraceRow[] = new Array(count);
  for (let i = 0; i < count; i++) {
    const o = i * TRACE_ROW_SIZE;
    out[i] = {
      query_offset: Number(view.getBigUint64(o + 0, true)),
      params_offset: Number(view.getBigUint64(o + 8, true)),
      ts_secs: view.getFloat32(o + 16, true),
      client_id: view.getUint32(o + 20, true),
      duration_ms: view.getFloat32(o + 24, true),
      event_type: view.getUint8(o + 28),
    };
  }
  return out;
}

export function encodeOffsets(offsets: number[]): ArrayBuffer {
  const buf = new ArrayBuffer(offsets.length * 8);
  const view = new DataView(buf);
  offsets.forEach((o, i) => view.setBigUint64(i * 8, BigInt(o), true));
  return buf;
}

export function parseQueries(
  buf: ArrayBuffer,
  offsets: number[],
): Map<number, QueryEntry> {
  const view = new DataView(buf);
  const out = new Map<number, QueryEntry>();
  let pos = 0;
  for (const offset of offsets) {
    const textLen = view.getUint32(pos, true);
    pos += 4;
    const textBytes = new Uint8Array(buf, pos, textLen);
    const text = new TextDecoder().decode(textBytes);
    pos += textLen;
    const oidCount = view.getUint16(pos, true);
    pos += 2;
    const oids: number[] = new Array(oidCount);
    for (let i = 0; i < oidCount; i++) {
      oids[i] = view.getUint32(pos, true);
      pos += 4;
    }
    out.set(offset, { text, oids });
  }
  return out;
}

export function parseParams(
  buf: ArrayBuffer,
  offsets: number[],
): Map<number, ParamsEntry> {
  const view = new DataView(buf);
  const out = new Map<number, ParamsEntry>();
  let pos = 0;
  for (const offset of offsets) {
    const queryOffset = Number(view.getBigUint64(pos, true));
    pos += 8;
    const fmtCount = view.getUint16(pos, true);
    pos += 2;
    const paramFormatCodes = new Array<number>(fmtCount);
    for (let i = 0; i < fmtCount; i++) {
      paramFormatCodes[i] = view.getInt16(pos, true);
      pos += 2;
    }
    const paramCount = view.getUint16(pos, true);
    pos += 2;
    const params = new Array<Uint8Array | null>(paramCount);
    for (let i = 0; i < paramCount; i++) {
      const len = view.getUint32(pos, true);
      pos += 4;
      if (len === 0xffffffff) {
        params[i] = null;
      } else {
        const bytes = new Uint8Array(buf, pos, len);
        params[i] = bytes.slice();
        pos += len;
      }
    }
    const resultFmtCount = view.getUint16(pos, true);
    pos += 2;
    const resultFormatCodes = new Array<number>(resultFmtCount);
    for (let i = 0; i < resultFmtCount; i++) {
      resultFormatCodes[i] = view.getInt16(pos, true);
      pos += 2;
    }
    out.set(offset, {
      queryOffset,
      paramFormatCodes,
      params,
      resultFormatCodes,
    });
  }
  return out;
}

function cleanBaseUrl(url: string): string {
  let trimmed = url.trim();
  if (!trimmed.startsWith("http://") && !trimmed.startsWith("https://")) {
    trimmed = "http://" + trimmed;
  }
  return trimmed.replace(/\/+$/, "");
}

export async function fetchTraces(baseUrl: string): Promise<TraceRow[]> {
  const cleanUrl = cleanBaseUrl(baseUrl);
  const res = await fetch(`${cleanUrl}/traces`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const buf = await res.arrayBuffer();
  return parseTraces(buf);
}

export async function fetchQueries(
  baseUrl: string,
  offsets: number[],
  onLoaded: () => void,
): Promise<void> {
  const missing = offsets.filter(
    (o) => !queryCache.has(o) && !queryPending.has(o),
  );
  if (missing.length === 0) return;
  missing.forEach((o) => queryPending.add(o));

  const cleanUrl = cleanBaseUrl(baseUrl);
  try {
    const res = await fetch(`${cleanUrl}/queries`, {
      method: "POST",
      body: encodeOffsets(missing),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const buf = await res.arrayBuffer();
    const parsed = parseQueries(buf, missing);
    for (const [k, v] of parsed) queryCache.set(k, v);
  } catch (err) {
    console.error("Failed to fetch queries:", err);
  } finally {
    missing.forEach((o) => queryPending.delete(o));
    onLoaded();
  }
}

export async function fetchParams(
  baseUrl: string,
  offset: number,
): Promise<ParamsEntry | undefined> {
  if (paramsCache.has(offset)) return paramsCache.get(offset);

  const cleanUrl = cleanBaseUrl(baseUrl);
  const res = await fetch(`${cleanUrl}/params`, {
    method: "POST",
    body: encodeOffsets([offset]),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const buf = await res.arrayBuffer();
  const parsed = parseParams(buf, [offset]);
  const entry = parsed.get(offset);
  if (entry) paramsCache.set(offset, entry);
  return entry;
}

export function bytesToDisplay(bytes: Uint8Array | null): string {
  if (bytes === null) return "NULL";
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return (
      "0x" +
      Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("")
    );
  }
}

export function escapeHtml(s: string): string {
  const d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}
