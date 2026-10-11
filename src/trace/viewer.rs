use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use memmap2::Mmap;
use std::{fs::File, io, net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::net::TcpListener;
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;

struct AppState {
    queries: Mmap,
    params: Mmap,
    traces: Mmap,
    chunks: Mmap,
}

const TRACE_ROW_SIZE: usize = 8 + 8 + 4 + 4 + 4 + 1;
const CHUNK_HEADER_SIZE: usize = 4 + 8;
const CHUNK_ENTRY_SIZE: usize = 4 + 8;

fn chunk_row_range(chunks: &Mmap, from_chunk: usize, to_chunk: usize) -> (usize, usize) {
    let total_rows = u64::from_le_bytes(chunks[4..12].try_into().unwrap()) as usize;
    let num_chunks = (chunks.len() - CHUNK_HEADER_SIZE) / CHUNK_ENTRY_SIZE;
    if num_chunks == 0 {
        return (0, 0);
    }
    let entry_start_row = |i: usize| -> usize {
        let base = CHUNK_HEADER_SIZE + i * CHUNK_ENTRY_SIZE;
        u64::from_le_bytes(chunks[base + 4..base + 12].try_into().unwrap()) as usize
    };
    let from_chunk = from_chunk.min(num_chunks - 1);
    let to_chunk = to_chunk.min(num_chunks - 1);
    let start_row = entry_start_row(from_chunk);
    let end_row = if to_chunk + 1 < num_chunks {
        entry_start_row(to_chunk + 1)
    } else {
        total_rows
    };
    (start_row, end_row)
}

async fn get_chunks(State(state): State<Arc<AppState>>) -> Response {
    (
        [(header::CONTENT_TYPE, "application/octet-stream")],
        state.chunks.to_vec(),
    )
        .into_response()
}

#[derive(serde::Deserialize)]
struct TracesQuery {
    from_chunk: usize,
    to_chunk: usize,
}

async fn get_traces(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(q): axum::extract::Query<TracesQuery>,
) -> Response {
    let (start_row, end_row) = chunk_row_range(&state.chunks, q.from_chunk, q.to_chunk);
    let start = start_row * TRACE_ROW_SIZE;
    let end = (end_row * TRACE_ROW_SIZE).min(state.traces.len());
    if start >= end || start > state.traces.len() {
        return (
            [(header::CONTENT_TYPE, "application/octet-stream")],
            Vec::<u8>::new(),
        )
            .into_response();
    }
    (
        [(header::CONTENT_TYPE, "application/octet-stream")],
        state.traces[start..end].to_vec(),
    )
        .into_response()
}

fn parse_offsets(body: &[u8]) -> io::Result<Vec<usize>> {
    if body.len() % 8 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "body length not a multiple of 8",
        ));
    }
    Ok(body
        .chunks_exact(8)
        .map(|c| u64::from_le_bytes(c.try_into().unwrap()) as usize)
        .collect())
}

fn read_queries(queries: &Mmap, offsets: &[usize]) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    for &offset in offsets {
        let buf = &queries[offset..];
        if buf.len() < 4 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated query text len",
            ));
        }
        let text_len = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
        let after_text = 4 + text_len;
        if buf.len() < after_text + 2 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated oid count",
            ));
        }
        let oid_count =
            u16::from_le_bytes(buf[after_text..after_text + 2].try_into().unwrap()) as usize;
        let total = after_text + 2 + oid_count * 4;
        if buf.len() < total {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated oids",
            ));
        }
        out.extend_from_slice(&buf[..total]);
    }
    Ok(out)
}

fn read_params(params: &Mmap, offsets: &[usize]) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    for &offset in offsets {
        let buf = &params[offset..];
        let mut idx = 0usize;

        if buf.len() < idx + 8 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated params query_offset",
            ));
        }
        idx += 8;

        if buf.len() < idx + 2 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated fmt code count",
            ));
        }
        let fmt_count = u16::from_le_bytes(buf[idx..idx + 2].try_into().unwrap()) as usize;
        idx += 2 + fmt_count * 2;

        if buf.len() < idx + 2 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated param count",
            ));
        }
        let param_count = u16::from_le_bytes(buf[idx..idx + 2].try_into().unwrap()) as usize;
        idx += 2;

        for _ in 0..param_count {
            if buf.len() < idx + 4 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated param len",
                ));
            }
            let len = u32::from_le_bytes(buf[idx..idx + 4].try_into().unwrap());
            idx += 4;
            if len != u32::MAX {
                idx += len as usize;
            }
        }

        if buf.len() < idx + 2 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated result fmt count",
            ));
        }
        let result_fmt_count = u16::from_le_bytes(buf[idx..idx + 2].try_into().unwrap()) as usize;
        idx += 2 + result_fmt_count * 2;

        if buf.len() < idx {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated params entry",
            ));
        }
        out.extend_from_slice(&buf[..idx]);
    }
    Ok(out)
}

async fn post_queries(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    let offsets = match parse_offsets(&body) {
        Ok(o) => o,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    match read_queries(&state.queries, &offsets) {
        Ok(data) => ([(header::CONTENT_TYPE, "application/octet-stream")], data).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn post_params(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    let offsets = match parse_offsets(&body) {
        Ok(o) => o,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    match read_params(&state.params, &offsets) {
        Ok(data) => ([(header::CONTENT_TYPE, "application/octet-stream")], data).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

pub async fn serve(folder: &PathBuf, addr: SocketAddr) -> io::Result<()> {
    let queries = unsafe { Mmap::map(&File::open(folder.join("queries"))?)? };
    let params = unsafe { Mmap::map(&File::open(folder.join("params"))?)? };
    let traces = unsafe { Mmap::map(&File::open(folder.join("traces"))?)? };
    let chunks = unsafe { Mmap::map(&File::open(folder.join("chunks"))?)? };

    let state = Arc::new(AppState {
        queries,
        params,
        traces,
        chunks,
    });

    let app = Router::new()
        .route("/chunks", get(get_chunks))
        .route("/traces", get(get_traces))
        .route("/queries", post(post_queries))
        .route("/params", post(post_params))
        .layer(CompressionLayer::new())
        .layer(CorsLayer::permissive())
        .with_state(state);

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
}
