use std::fmt::{self, Write};

pub fn write_i16_slice<W: Write>(w: &mut W, codes: &[i16]) -> fmt::Result {
    w.write_char('[')?;
    for (i, c) in codes.iter().enumerate() {
        if i > 0 {
            w.write_char(';')?;
        }
        write!(w, "{}", c)?;
    }
    w.write_char(']')
}

pub struct DisplayBytes<'a>(pub &'a [u8]);

impl<'a> fmt::Display for DisplayBytes<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf = [0u8; 4];
        for &b in self.0 {
            let mut len = 0;
            for c in std::ascii::escape_default(b) {
                buf[len] = c;
                len += 1;
            }
            let s = unsafe { std::str::from_utf8_unchecked(&buf[..len]) };
            f.write_str(s)?;
        }
        Ok(())
    }
}
