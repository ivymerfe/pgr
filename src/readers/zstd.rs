use std::{
    fs::File,
    io::{self, BufReader},
};

use zstd::Decoder;

pub type ZReader = BufReader<Decoder<'static, BufReader<File>>>;

pub fn open_zstd(file: File) -> io::Result<ZReader> {
    Ok(BufReader::new(Decoder::new(file)?))
}
