#[derive(Debug)]
pub enum PgC2S<'a> {
    SSLRequest,
    GSSENCRequest,
    StartupMessage {
        version: u32,
        parameters: RawParams<'a>,
    },
    CancelRequest {
        process_id: u32,
        secret_key: u32,
    },
    Bind {
        portal: &'a str,
        statement: &'a str,
        parameter_format_codes: Codes<'a>,
        parameters: Values<'a>,
        result_format_codes: Codes<'a>,
    },
    Close {
        target_type: u8,
        name: &'a str,
    },
    Describe {
        target_type: u8,
        name: &'a str,
    },
    Execute {
        portal: &'a str,
        max_rows: i32,
    },
    Flush,
    FunctionCall {
        object_id: u32,
        argument_format_codes: Codes<'a>,
        arguments: Values<'a>,
        result_format_code: i16,
    },
    Parse {
        name: &'a str,
        query: &'a str,
        parameter_type_oids: Oids<'a>,
    },
    PasswordMessage(&'a str),
    Query(&'a str),
    Sync,
    Terminate,
    CopyData(&'a [u8]),
    CopyDone,
    CopyFail(&'a str),
    Unknown {
        tag: u8,
        payload: &'a [u8],
    },
}

pub fn parse_pg_message<'a>(tag: u8, payload: &'a [u8]) -> Result<PgC2S<'a>, &'static str> {
    if tag == 0 {
        if payload.len() < 4 {
            return Err("Truncated startup header");
        }
        let code_or_ver = read_u32(&payload[..4]);
        let major = code_or_ver >> 16;

        return match code_or_ver {
            80877102 => {
                if payload.len() < 12 {
                    return Err("Incomplete CancelRequest");
                }
                Ok(PgC2S::CancelRequest {
                    process_id: read_u32(&payload[4..8]),
                    secret_key: read_u32(&payload[8..12]),
                })
            }
            80877103 => Ok(PgC2S::SSLRequest),
            80877104 => Ok(PgC2S::GSSENCRequest),
            _ if major == 3 => Ok(PgC2S::StartupMessage {
                version: code_or_ver,
                parameters: RawParams(&payload[4..]),
            }),
            _ => Err("Unknown headerless protocol version"),
        };
    }

    let msg = match tag {
        b'Q' => {
            let (query, _) = read_c_string(payload)?;
            PgC2S::Query(query)
        }
        b'P' => {
            let mut idx = 0;
            let (name, len) = read_c_string(payload)?;
            idx += len;
            let (query, len) = read_c_string(&payload[idx..])?;
            idx += len;
            let parameter_type_oids = Oids::parse(payload, &mut idx)?;
            PgC2S::Parse {
                name,
                query,
                parameter_type_oids,
            }
        }
        b'B' => {
            let mut idx = 0;
            let (portal, len) = read_c_string(payload)?;
            idx += len;
            let (statement, len) = read_c_string(&payload[idx..])?;
            idx += len;
            let parameter_format_codes = Codes::parse(payload, &mut idx)?;
            let parameters = Values::parse(payload, &mut idx)?;
            let result_format_codes = Codes::parse(payload, &mut idx)?;
            PgC2S::Bind {
                portal,
                statement,
                parameter_format_codes,
                parameters,
                result_format_codes,
            }
        }
        b'E' => {
            let (portal, len) = read_c_string(payload)?;
            if len + 4 > payload.len() {
                return Err("Truncated Execute: missing max_rows");
            }
            let max_rows = read_i32(&payload[len..len + 4]);
            PgC2S::Execute { portal, max_rows }
        }
        b'F' => {
            let mut idx = 0;
            if payload.len() < 4 {
                return Err("Truncated FunctionCall: missing object id");
            }
            let object_id = read_u32(&payload[0..4]);
            idx += 4;
            let argument_format_codes = Codes::parse(payload, &mut idx)?;
            let arguments = Values::parse(payload, &mut idx)?;
            if idx + 2 > payload.len() {
                return Err("Truncated FunctionCall: missing result format code");
            }
            let result_format_code = read_i16(&payload[idx..idx + 2]);
            PgC2S::FunctionCall {
                object_id,
                argument_format_codes,
                arguments,
                result_format_code,
            }
        }
        b'D' => {
            if payload.is_empty() {
                return Err("Truncated Describe: missing target_type");
            }
            let target_type = payload[0];
            let (name, _) = read_c_string(&payload[1..])?;
            PgC2S::Describe { target_type, name }
        }
        b'C' => {
            if payload.is_empty() {
                return Err("Truncated Close: missing target_type");
            }
            let target_type = payload[0];
            let (name, _) = read_c_string(&payload[1..])?;
            PgC2S::Close { target_type, name }
        }
        b'S' => PgC2S::Sync,
        b'H' => PgC2S::Flush,
        b'X' => PgC2S::Terminate,
        b'd' => PgC2S::CopyData(payload),
        b'c' => PgC2S::CopyDone,
        b'f' => {
            let (msg, _) = read_c_string(payload)?;
            PgC2S::CopyFail(msg)
        }
        b'p' => {
            let (pass, _) = read_c_string(payload)?;
            PgC2S::PasswordMessage(pass)
        }
        _ => PgC2S::Unknown { tag, payload },
    };

    Ok(msg)
}

fn read_u32(b: &[u8]) -> u32 {
    return u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
}

fn read_i32(b: &[u8]) -> i32 {
    return i32::from_be_bytes([b[0], b[1], b[2], b[3]]);
}

fn read_u16(b: &[u8]) -> u16 {
    return u16::from_be_bytes([b[0], b[1]]);
}

fn read_i16(b: &[u8]) -> i16 {
    return i16::from_be_bytes([b[0], b[1]]);
}

#[inline]
fn read_c_string(buf: &[u8]) -> Result<(&str, usize), &'static str> {
    let null_pos = buf
        .iter()
        .position(|&b| b == 0)
        .ok_or("Missing null terminator")?;
    let s = std::str::from_utf8(&buf[..null_pos]).map_err(|_| "Invalid UTF-8 in C string")?;
    Ok((s, null_pos + 1))
}

#[derive(Debug, Clone, Copy)]
pub struct RawParams<'a>(&'a [u8]);

impl<'a> RawParams<'a> {
    pub fn iter(&self) -> RawParamsIter<'a> {
        RawParamsIter(self.0)
    }
}

pub struct RawParamsIter<'a>(&'a [u8]);

impl<'a> Iterator for RawParamsIter<'a> {
    type Item = (&'a str, &'a str);
    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() {
            return None;
        }
        let (k, len) = read_c_string(self.0).ok()?;
        if k.is_empty() {
            return None;
        }
        self.0 = &self.0[len..];
        let (v, len) = read_c_string(self.0).ok()?;
        self.0 = &self.0[len..];
        Some((k, v))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Codes<'a>(&'a [u8]);

impl<'a> Codes<'a> {
    fn parse(payload: &'a [u8], idx: &mut usize) -> Result<Self, &'static str> {
        if *idx + 2 > payload.len() {
            return Err("Truncated: missing element count");
        }
        let count = read_u16(&payload[*idx..*idx + 2]) as usize;
        *idx += 2;
        let total = count * 2;
        if *idx + total > payload.len() {
            return Err("Truncated: elements out of bounds");
        }
        let slice = &payload[*idx..*idx + total];
        *idx += total;
        Ok(Codes(slice))
    }

    pub fn iter(&self) -> impl Iterator<Item = i16> + 'a {
        let s = self.0;
        (0..s.len() / 2).map(move |i| read_i16(&s[i * 2..i * 2 + 2]))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Oids<'a>(&'a [u8]);

impl<'a> Oids<'a> {
    fn parse(payload: &'a [u8], idx: &mut usize) -> Result<Self, &'static str> {
        if *idx + 2 > payload.len() {
            return Err("Truncated: missing element count");
        }
        let count = read_u16(&payload[*idx..*idx + 2]) as usize;
        *idx += 2;
        let total = count * 4;
        if *idx + total > payload.len() {
            return Err("Truncated: elements out of bounds");
        }
        let slice = &payload[*idx..*idx + total];
        *idx += total;
        Ok(Oids(slice))
    }

    pub fn iter(&self) -> impl Iterator<Item = u32> + 'a {
        let s = self.0;
        (0..s.len() / 4).map(move |i| read_u32(&s[i * 4..i * 4 + 4]))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Values<'a>(&'a [u8]);

impl<'a> Values<'a> {
    fn parse(payload: &'a [u8], idx: &mut usize) -> Result<Self, &'static str> {
        if *idx + 2 > payload.len() {
            return Err("Truncated: missing value count");
        }
        let count = read_u16(&payload[*idx..*idx + 2]) as usize;
        let start = *idx;
        *idx += 2;

        for _ in 0..count {
            if *idx + 4 > payload.len() {
                return Err("Truncated: missing value length");
            }
            let len = read_i32(&payload[*idx..*idx + 4]);
            *idx += 4;
            if len < -1 {
                return Err("Invalid value length");
            } else if len >= 0 {
                let ulen = len as usize;
                if *idx + ulen > payload.len() {
                    return Err("Truncated: value out of bounds");
                }
                *idx += ulen;
            }
        }
        Ok(Values(&payload[start..*idx]))
    }

    pub fn iter(&self) -> ValuesIter<'a> {
        let count = read_u16(&self.0[0..2]) as usize;
        ValuesIter {
            buf: &self.0[2..],
            remaining: count,
        }
    }
}

pub struct ValuesIter<'a> {
    buf: &'a [u8],
    remaining: usize,
}

impl<'a> Iterator for ValuesIter<'a> {
    type Item = Option<&'a [u8]>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        let len = read_i32(&self.buf[0..4]);
        self.buf = &self.buf[4..];
        if len == -1 {
            Some(None)
        } else {
            let ulen = len as usize;
            let (v, rest) = self.buf.split_at(ulen);
            self.buf = rest;
            Some(Some(v))
        }
    }
}
