use std::{
    fs::File,
    io::{self, BufReader, BufWriter},
    time::{Duration, Instant},
};

use zstd::{Encoder, zstd_safe::CParameter};

pub fn compress(input: File, output: File, level: i32, worker_count: u8) -> io::Result<Duration> {
    let start_time = Instant::now();

    let mut reader = BufReader::new(input);
    let writer = BufWriter::new(output);
    let mut encoder = Encoder::new(writer, level)?;
    encoder.set_parameter(CParameter::NbWorkers(worker_count as u32))?;
    io::copy(&mut reader, &mut encoder)?;
    encoder.finish()?;
    Ok(start_time.elapsed())
}
