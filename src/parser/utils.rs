use core::fmt;
use std::fmt::Write;

pub fn write_escaped_bytes<W: Write>(w: &mut W, bytes: &[u8]) -> fmt::Result {
    for &b in bytes {
        for c in std::ascii::escape_default(b) {
            w.write_char(c as char)?;
        }
    }
    Ok(())
}
