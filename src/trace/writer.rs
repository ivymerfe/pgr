use std::{
    fs::{self, File},
    hash::{Hash, Hasher},
    io::{self, BufWriter, Write},
    path::PathBuf,
};

use ahash::{AHashMap, AHasher};

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
        parameter_format_codes: &[i16],
        parameters_src: &[u8],
        parameters: &[Option<(usize, usize)>],
        result_format_codes: &[i16],
    ) -> io::Result<usize> {
        let offset = self.params_offset;

        self.params_writer
            .write_all(&(query_offset as u64).to_le_bytes())?;

        self.params_writer
            .write_all(&(parameter_format_codes.len() as u16).to_le_bytes())?;
        for code in parameter_format_codes {
            self.params_writer.write_all(&code.to_le_bytes())?;
        }
        self.params_writer
            .write_all(&(parameters.len() as u16).to_le_bytes())?;
        let mut size: u64 = 8 + 2 + (parameter_format_codes.len() as u64) * 2 + 2;
        for param in parameters {
            match param {
                Some((off, len)) => {
                    let bytes = &parameters_src[*off..*off + *len];
                    self.params_writer
                        .write_all(&(bytes.len() as u32).to_le_bytes())?;
                    self.params_writer.write_all(bytes)?;
                    size += 4 + bytes.len() as u64;
                }
                None => {
                    self.params_writer.write_all(&u32::MAX.to_le_bytes())?;
                    size += 4;
                }
            }
        }
        self.params_writer
            .write_all(&(result_format_codes.len() as u16).to_le_bytes())?;
        for code in result_format_codes {
            self.params_writer.write_all(&code.to_le_bytes())?;
        }
        size += 2 + (result_format_codes.len() as u64) * 2;

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
