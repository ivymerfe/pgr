use crate::{
    capture::{
        frame_buffer::FrameBuffer,
        reader::{CaptureReader, ReadData, ReadError, ReadResult},
    },
    utils::counting_writer::CountingWriter,
};
use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, BufRead, BufReader, Read, Write},
    net::SocketAddr,
    path::PathBuf,
};
use zstd::{Decoder, Encoder, zstd_safe::CParameter};

pub struct AcapMap {
    file: File,
    addrs: Vec<SocketAddr>,
    ids: HashMap<SocketAddr, u32>,
}

impl AcapMap {
    pub fn new(file: File) -> anyhow::Result<Self> {
        let mut reader = BufReader::new(file);
        let mut addrs = Vec::new();
        let mut ids = HashMap::new();
        let mut buf = String::with_capacity(128);
        while reader.read_line(&mut buf)? > 0 {
            let line = buf.trim_end();
            if !line.is_empty() {
                let addr: SocketAddr = line.parse()?;
                let id = addrs.len() as u32;
                addrs.push(addr);
                ids.insert(addr, id);
            }
            buf.clear();
        }
        Ok(Self {
            file: reader.into_inner(),
            addrs,
            ids,
        })
    }

    pub fn get_id(&mut self, addr: SocketAddr) -> u32 {
        *self.ids.entry(addr).or_insert_with(|| {
            let id = self.addrs.len() as u32;
            self.addrs.push(addr);
            let _ = writeln!(self.file, "{}", addr);
            id
        })
    }

    pub fn get_addr(&self, id: u32) -> Option<&SocketAddr> {
        self.addrs.get(id as usize)
    }
}

pub struct AcapWriter {
    folder: PathBuf,
    chunk_max_size: u64,
    chunk_idx: u32,
    compression_level: i32,
    worker_count: u8,
    map: AcapMap,
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
        let map = AcapMap::new(
            File::options()
                .create(true)
                .read(true)
                .append(true)
                .open(folder.join("map"))?,
        )?;
        let chunk_writer = Self::open_chunk(&folder, 0, compression_level, worker_count)?;
        Ok(Self {
            folder,
            chunk_max_size,
            chunk_idx: 0,
            compression_level,
            worker_count,
            map,
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

    pub fn write(&mut self, addr: &SocketAddr, ts: u32, data: &[u8]) -> anyhow::Result<()> {
        if self.chunk_writer.get_ref().count >= self.chunk_max_size {
            self.roll_chunk()?;
        }
        let id = self.map.get_id(addr.clone());
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
    map: AcapMap,
    ts_offset: u64,
    max_duration: u64,
    chunk_idx: u32,
    chunk_reader: Box<dyn Read + Send>,
    payload_buf: Vec<u8>,
    buffers: HashMap<SocketAddr, FrameBuffer>,
    acc_delta: u64,
    curr_delta: u64,
    first_chunk_ts: u64,
}

impl AcapReader {
    pub fn new(folder: &PathBuf, ts_offset: u64, max_duration: u64) -> anyhow::Result<Self> {
        let map = AcapMap::new(File::open(folder.join("map"))?)?;
        let chunk_reader = open_chunk_reader(&folder, 0)?
            .ok_or_else(|| anyhow::anyhow!("no chunk 0 in {}", folder.display()))?;
        Ok(Self {
            folder: folder.clone(),
            map,
            ts_offset,
            max_duration,
            chunk_idx: 0,
            chunk_reader,
            payload_buf: Vec::new(),
            buffers: HashMap::new(),
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

    fn try_next(&mut self) -> Result<(u32, u64), io::Error> {
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
                        None => return Err(e),
                    }
                }
                Err(e) => return Err(e),
            }
            let id = u32::from_le_bytes(id_buf);

            let mut ts_buf = [0u8; 4];
            self.chunk_reader.read_exact(&mut ts_buf)?;
            let ts = u32::from_le_bytes(ts_buf) as u64;

            let mut len_buf = [0u8; 4];
            self.chunk_reader.read_exact(&mut len_buf)?;
            let payload_len = u32::from_le_bytes(len_buf) as usize;

            self.payload_buf.resize(payload_len, 0);
            if payload_len > 0 {
                self.chunk_reader.read_exact(&mut self.payload_buf)?;
            }
            return Ok((id, self.map_ts(ts)));
        }
    }
}

impl CaptureReader for AcapReader {
    fn get_buffer(&mut self, addr: SocketAddr) -> Option<&mut FrameBuffer> {
        self.buffers.get_mut(&addr)
    }

    fn next(&mut self) -> ReadResult<'_> {
        let (id, ts_abs) = match self.try_next() {
            Ok((id, ts)) => (id, ts),
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Err(ReadError::Eof),
            Err(e) => return Err(e.into()),
        };
        if ts_abs < self.ts_offset {
            return Err(ReadError::Continue);
        }
        let ts_relative = ts_abs - self.ts_offset;
        if ts_relative > self.max_duration {
            return Err(ReadError::Eof);
        }
        if let Some(addr) = self.map.get_addr(id) {
            let fb = self.buffers.entry(*addr).or_default();
            if self.payload_buf.is_empty() {
                fb.mark_connection_start();
            } else {
                fb.extend(&self.payload_buf);
            }
            return Ok(ReadData {
                addr: addr.clone(),
                ts: ts_relative,
                buf: fb,
            });
        }
        Err(ReadError::Error(format!("Unknown id: {}", id)))
    }
}
