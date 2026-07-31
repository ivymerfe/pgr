use core::fmt;
use std::error::Error;
use std::fmt::Write;
use std::fmt::{Display, Formatter};
use std::net::SocketAddr;

use crate::parser::c2s::parse_pg_message;
use crate::parser::pq_stream::FrameInfo;

#[derive(Debug)]
pub enum CompareError {
    FmtError(fmt::Error),
    MismatchedFrames {
        addr1: SocketAddr,
        info1: FrameInfo,
        content1: String,
        addr2: SocketAddr,
        info2: FrameInfo,
        content2: String,
    },
}

fn escape_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .flat_map(|&b| std::ascii::escape_default(b))
        .map(char::from)
        .collect()
}

fn get_frame_content(info: &FrameInfo, frame: &[u8]) -> Result<String, fmt::Error> {
    let mut content = String::with_capacity(1024);
    match parse_pg_message(info.tag, frame) {
        Ok(msg) => {
            write!(content, "{}", msg)?;
        }
        Err(e) => {
            write!(content, "({}):{} -> {}", e, info.tag, escape_bytes(frame))?;
        }
    }
    return Ok(content);
}

impl CompareError {
    pub fn new_frame_error(
        addr1: SocketAddr,
        info1: &FrameInfo,
        frame1: &[u8],
        addr2: SocketAddr,
        info2: &FrameInfo,
        frame2: &[u8],
    ) -> Self {
        let content1 = match get_frame_content(info1, frame1) {
            Ok(c) => c,
            Err(e) => return CompareError::FmtError(e),
        };
        let content2 = match get_frame_content(info2, frame2) {
            Ok(c) => c,
            Err(e) => return CompareError::FmtError(e),
        };
        CompareError::MismatchedFrames {
            addr1,
            info1: info1.clone(),
            content1,
            addr2,
            info2: info2.clone(),
            content2,
        }
    }
}

impl Display for CompareError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            CompareError::FmtError(e) => {
                write!(f, "Failed to format: {e}")
            }
            CompareError::MismatchedFrames {
                addr1,
                info1,
                content1,
                addr2,
                info2,
                content2,
            } => {
                write!(
                    f,
                    "Compare failed: Frame contents do not match\n\
                     {} at {}:{} <-> {} at {}:{}\n\
                      First frame:\n\
                      {}\n\
                      Second frame:\n\
                      {}
                    ",
                    addr1,
                    info1.stream_start,
                    info1.stream_end,
                    addr2,
                    info2.stream_start,
                    info2.stream_end,
                    content1,
                    content2
                )
            }
        }
    }
}

impl Error for CompareError {}
