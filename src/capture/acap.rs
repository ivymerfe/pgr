use crate::{
    capture::reader::{CaptureData, CaptureReader, ReadError, ReadResult},
    utils::counting_writer::CountingWriter,
};
use std::{
    fs::{self, File},
    io::{self, BufReader, Read, Write},
    net::SocketAddr,
    path::PathBuf,
};
use zstd::{Decoder, Encoder, zstd_safe::CParameter};

pub struct AcapWriter {
    folder: PathBuf,
    chunk_max_size: u64,
    chunk_idx: u32,
    compression_level: i32,
    worker_count: u8,
    map_file: File,
    chunk_writer: Encoder<'static, CountingWriter<File>>,
}

impl AcapWriter {
    pub fn new(
        folder: PathBuf,
        chunk_max_size: u64,
        compression_level: i32,
        worker_count: u8,
    ) -> anyhow::Result<Self> {
        fs::create_dir_all(&folder)?;
        let map_file = File::create(folder.join("map"))?;
        let chunk_writer = Self::open_chunk(&folder, 0, compression_level, worker_count)?;
        Ok(Self {
            folder,
            chunk_max_size,
            chunk_idx: 0,
            compression_level,
            worker_count,
            map_file,
            chunk_writer,
        })
    }

    fn open_chunk(
        folder: &PathBuf,
        idx: u32,
        compression_level: i32,
        worker_count: u8,
    ) -> anyhow::Result<Encoder<'static, CountingWriter<File>>> {
        let file = File::create(folder.join(format!("{idx}.zst")))?;
        let mut encoder = Encoder::new(CountingWriter::new(file), compression_level)?;
        encoder.set_parameter(CParameter::NbWorkers(worker_count as u32))?;
        Ok(encoder)
    }

    fn roll_chunk(&mut self) -> anyhow::Result<()> {
        let next = Self::open_chunk(
            &self.folder,
            self.chunk_idx + 1,
            self.compression_level,
            self.worker_count,
        )?;
        std::mem::replace(&mut self.chunk_writer, next).finish()?;
        self.chunk_idx += 1;
        Ok(())
    }

    pub fn write_addr(&mut self, addr: &SocketAddr) -> io::Result<()> {
        writeln!(self.map_file, "{}", addr)
    }

    pub fn write(&mut self, id: u32, ts: u32, data: &[u8]) -> anyhow::Result<()> {
        if self.chunk_writer.get_ref().count >= self.chunk_max_size {
            self.roll_chunk()?;
        }
        let len = data.len() as u32;
        let w = &mut self.chunk_writer;
        w.write_all(&id.to_le_bytes())?;
        w.write_all(&ts.to_le_bytes())?;
        w.write_all(&len.to_le_bytes())?;
        if len > 0 {
            w.write_all(data)?;
        }
        Ok(())
    }

    pub fn finish(self) -> anyhow::Result<()> {
        self.chunk_writer.finish()?;
        Ok(())
    }
}

fn open_chunk_reader(folder: &PathBuf, idx: u32) -> io::Result<Option<Box<dyn Read + Send>>> {
    let plain = folder.join(idx.to_string());
    if plain.exists() {
        return Ok(Some(Box::new(BufReader::new(File::open(plain)?))));
    }
    let zst = folder.join(format!("{idx}.zst"));
    if zst.exists() {
        return Ok(Some(Box::new(Decoder::new(File::open(zst)?)?)));
    }
    Ok(None)
}

pub struct AcapReader {
    folder: PathBuf,
    ts_offset: u64,
    max_duration: u64,
    chunk_idx: u32,
    chunk_reader: Box<dyn Read + Send>,
    buffer: Vec<u8>,
    acc_delta: u64,
    curr_delta: u64,
    first_chunk_ts: u64,
}

impl AcapReader {
    pub fn new(folder: &PathBuf, ts_offset: u64, max_duration: u64) -> anyhow::Result<Self> {
        let chunk_reader = open_chunk_reader(&folder, 0)?
            .ok_or_else(|| anyhow::anyhow!("no chunk 0 in {}", folder.display()))?;
        Ok(Self {
            folder: folder.clone(),
            ts_offset,
            max_duration,
            chunk_idx: 0,
            chunk_reader,
            buffer: Vec::new(),
            acc_delta: 0,
            curr_delta: 0,
            first_chunk_ts: 0,
        })
    }

    fn map_ts(&mut self, ts: u64) -> u64 {
        if self.first_chunk_ts == 0 {
            self.first_chunk_ts = ts;
        }
        self.curr_delta = ts.saturating_sub(self.first_chunk_ts);
        self.acc_delta + self.curr_delta
    }
}

impl CaptureReader for AcapReader {
    fn next(&mut self) -> ReadResult<'_> {
        loop {
            let mut id_buf = [0u8; 4];
            match self.chunk_reader.read_exact(&mut id_buf) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    match open_chunk_reader(&self.folder, self.chunk_idx + 1)? {
                        Some(next) => {
                            self.chunk_reader = next;
                            self.chunk_idx += 1;
                            self.acc_delta += self.curr_delta;
                            self.first_chunk_ts = 0;
                            self.curr_delta = 0;
                            continue;
                        }
                        None => return Err(ReadError::Eof),
                    }
                }
                Err(e) => return Err(ReadError::Error(e.to_string())),
            }
            let id = u32::from_le_bytes(id_buf);

            let mut ts_buf = [0u8; 4];
            self.chunk_reader.read_exact(&mut ts_buf)?;
            let ts = u32::from_le_bytes(ts_buf) as u64;

            let mut len_buf = [0u8; 4];
            self.chunk_reader.read_exact(&mut len_buf)?;
            let payload_len = u32::from_le_bytes(len_buf) as usize;

            self.buffer.resize(payload_len, 0);
            if payload_len > 0 {
                self.chunk_reader.read_exact(&mut self.buffer)?;
            }
            let ts_abs = self.map_ts(ts);
            if ts_abs < self.ts_offset {
                continue;
            }
            let ts_relative = ts_abs - self.ts_offset;
            if ts_relative > self.max_duration {
                return Err(ReadError::Eof);
            }
            return Ok(CaptureData {
                id,
                ts: ts_relative,
                connect: self.buffer.is_empty(),
                buf: &self.buffer,
            });
        }
    }
}
