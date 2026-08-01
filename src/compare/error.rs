use core::fmt;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::net::SocketAddr;

use crate::parser::c2s_display::TagFrame;
use crate::parser::pq_stream::FrameInfo;

#[derive(Debug)]
pub enum CompareError {
    MismatchedFrames {
        addr1: SocketAddr,
        info1: FrameInfo,
        content1: String,
        addr2: SocketAddr,
        info2: FrameInfo,
        content2: String,
    },
}

pub fn format_frame_mismatch(
    addr1: SocketAddr,
    info1: &FrameInfo,
    frame1: &[u8],
    addr2: SocketAddr,
    info2: &FrameInfo,
    frame2: &[u8],
) -> CompareError {
    CompareError::MismatchedFrames {
        addr1,
        info1: info1.clone(),
        content1: format!("{}", TagFrame(info1.tag, frame1)),
        addr2,
        info2: info2.clone(),
        content2: format!("{}", TagFrame(info2.tag, frame2)),
    }
}

impl Display for CompareError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
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
