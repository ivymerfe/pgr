use crate::capture::{
    ebpf::WireEvent,
    frame_buffer::FrameBuffer,
    reader::{CaptureReader, ReadData, ReadError, ReadResult},
};
use std::{
    collections::HashMap,
    fs::File,
    io::{self, BufReader, Read, Seek, SeekFrom, Take, Write},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};
use zstd::{Decoder, Encoder, zstd_safe::CParameter};

pub struct ZcapWriter<'a> {
    encoder: Encoder<'a, File>,
    addr_ids: HashMap<SocketAddr, u32>,
    addrs_by_id: Vec<SocketAddr>,
}

impl<'a> ZcapWriter<'a> {
    pub fn new(out_file: File) -> Result<Self, io::Error> {
        let mut encoder = Encoder::new(out_file, 3)?;
        encoder.set_parameter(CParameter::NbWorkers(4))?;
        Ok(Self {
            encoder,
            addr_ids: HashMap::new(),
            addrs_by_id: Vec::new(),
        })
    }

    pub fn write_event(&mut self, event: WireEvent) -> io::Result<()> {
        let id = if let Some(&id) = self.addr_ids.get(&event.addr) {
            id
        } else {
            let id = self.addrs_by_id.len() as u32;
            self.addr_ids.insert(event.addr, id);
            self.addrs_by_id.push(event.addr);
            id
        };
        write_wire_event(&mut self.encoder, id, &event)
    }

    pub fn finish(self) -> io::Result<()> {
        let mut file = self.encoder.finish()?;

        let mut map_bytes = Vec::new();
        for addr in &self.addrs_by_id {
            serialize_addr(&mut map_bytes, addr)?;
        }
        let map_len = map_bytes.len() as u32;

        file.write_all(&map_bytes)?;
        file.write_all(&map_len.to_le_bytes())?;
        file.flush()?;

        Ok(())
    }
}

fn write_wire_event<W: Write>(w: &mut W, id: u32, ev: &WireEvent) -> io::Result<()> {
    w.write_all(&id.to_le_bytes())?;
    w.write_all(&ev.ts.to_le_bytes())?;
    let data = &ev.data;
    let len = data.len() as u32;
    w.write_all(&len.to_le_bytes())?;
    if len > 0 {
        w.write_all(&ev.data)?;
    }
    Ok(())
}

pub struct ZcapReader<'a> {
    decoder: Decoder<'a, BufReader<Take<File>>>,
    addrs: Vec<SocketAddr>,
    payload_buf: Vec<u8>,
    buffers: HashMap<SocketAddr, FrameBuffer>,
    first_ts: u64
}

impl<'a> ZcapReader<'a> {
    pub fn new(mut file: File) -> io::Result<Self> {
        let file_len = file.seek(SeekFrom::End(0))?;
        if file_len < 4 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "File too small"));
        }
        file.seek(SeekFrom::End(-4))?;
        let mut len_bytes = [0u8; 4];
        file.read_exact(&mut len_bytes)?;
        let map_len = u32::from_le_bytes(len_bytes) as u64;

        if file_len < 4 + map_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid zcap header/map length",
            ));
        }
        let map_start = file_len - 4 - map_len;
        file.seek(SeekFrom::Start(map_start))?;
        let mut map_buf = vec![0u8; map_len as usize];
        file.read_exact(&mut map_buf)?;

        let addrs = deserialize_map(&map_buf)?;

        file.seek(SeekFrom::Start(0))?;
        let decoder = Decoder::new(file.take(map_start))?;
        Ok(Self {
            decoder,
            addrs,
            payload_buf: Vec::new(),
            buffers: HashMap::new(),
            first_ts: 0
        })
    }

    fn try_next(&mut self) -> Result<(u32, u64), io::Error> {
        let mut id_buf = [0u8; 4];
        self.decoder.read_exact(&mut id_buf)?;
        let id = u32::from_le_bytes(id_buf);

        let mut ts_buf = [0u8; 4];
        self.decoder.read_exact(&mut ts_buf)?;
        let ts = u32::from_le_bytes(ts_buf) as u64;

        let mut len_buf = [0u8; 4];
        self.decoder.read_exact(&mut len_buf)?;
        let payload_len = u32::from_le_bytes(len_buf) as usize;

        self.payload_buf.resize(payload_len, 0);
        if payload_len > 0 {
            self.decoder.read_exact(&mut self.payload_buf)?;
        }
        if self.first_ts == 0 {
            self.first_ts = ts;
        }
        Ok((id, ts.saturating_sub(self.first_ts)))
    }
}

impl<'a> CaptureReader for ZcapReader<'a> {
    fn get_buffer(&mut self, addr: SocketAddr) -> Option<&mut FrameBuffer> {
        self.buffers.get_mut(&addr)
    }

    fn next(&mut self) -> ReadResult<'_> {
        let (id, ts) = match self.try_next() {
            Ok((id, ts)) => (id, ts),
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Err(ReadError::Eof),
            Err(e) => return Err(e.into()),
        };
        if let Some(addr) = self.addrs.get(id as usize) {
            let fb = self.buffers.entry(*addr).or_default();
            if self.payload_buf.len() == 0 {
                fb.mark_connection_start();
            } else {
                fb.extend(&self.payload_buf);
            }
            return Ok(ReadData {
                addr: addr.clone(),
                ts,
                buf: fb,
            });
        }
        Err(ReadError::Error(format!("Unknown id: {}", id)))
    }
}

fn serialize_addr<W: Write>(w: &mut W, addr: &SocketAddr) -> io::Result<()> {
    match addr {
        SocketAddr::V4(v4) => {
            w.write_all(&[4u8])?;
            w.write_all(&v4.ip().octets())?;
            w.write_all(&v4.port().to_le_bytes())?;
        }
        SocketAddr::V6(v6) => {
            w.write_all(&[6u8])?;
            w.write_all(&v6.ip().octets())?;
            w.write_all(&v6.port().to_le_bytes())?;
        }
    }
    Ok(())
}

fn deserialize_map(mut data: &[u8]) -> io::Result<Vec<SocketAddr>> {
    let mut addrs = Vec::new();
    while !data.is_empty() {
        let mut kind = [0u8; 1];
        data.read_exact(&mut kind)?;
        match kind[0] {
            4 => {
                let mut ip = [0u8; 4];
                data.read_exact(&mut ip)?;
                let mut port = [0u8; 2];
                data.read_exact(&mut port)?;
                let port = u16::from_le_bytes(port);
                addrs.push(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port)));
            }
            6 => {
                let mut ip = [0u8; 16];
                data.read_exact(&mut ip)?;
                let mut port = [0u8; 2];
                data.read_exact(&mut port)?;
                let port = u16::from_le_bytes(port);
                addrs.push(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(ip),
                    port,
                    0,
                    0,
                )));
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid IP version flag in address map",
                ));
            }
        }
    }
    Ok(addrs)
}
