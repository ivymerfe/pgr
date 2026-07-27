use std::collections::HashMap;
use std::fmt;

#[derive(Debug)]
pub enum PgC2S<'a> {
    SSLRequest,
    StartupMessage {
        version: u32,
        parameters: HashMap<&'a str, &'a str>,
    },
    CancelRequest {
        process_id: u32,
        secret_key: u32,
    },
    Bind {
        portal: &'a str,
        statement: &'a str,
        parameter_format_codes: Vec<i16>,
        parameters: Vec<Option<&'a [u8]>>,
        result_format_codes: Vec<i16>,
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
    FunctionCall,
    Parse {
        name: &'a str,
        query: &'a str,
        parameter_type_oids: Vec<u32>,
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

#[inline]
fn read_c_string<'a>(buf: &'a [u8]) -> Result<(&'a str, usize), &'static str> {
    let mut null_pos = 0;
    for i in 0..buf.len() {
        if buf[i] == 0 {
            null_pos = i;
            break;
        }
    }
    let s = unsafe { std::str::from_utf8_unchecked(&buf[..null_pos]) };
    Ok((s, null_pos + 1))
}

pub fn parse_pg_message<'a>(tag: u8, payload: &'a [u8]) -> Result<PgC2S<'a>, &'static str> {
    if tag == 0 {
        if payload.len() < 4 {
            return Err("Truncated startup header");
        }

        let code_or_ver = u32::from_be_bytes(payload[..4].try_into().unwrap());
        return match code_or_ver {
            80877103 => Ok(PgC2S::SSLRequest),
            80877102 => {
                if payload.len() < 12 {
                    return Err("Incomplete CancelRequest");
                }
                Ok(PgC2S::CancelRequest {
                    process_id: u32::from_be_bytes(payload[4..8].try_into().unwrap()),
                    secret_key: u32::from_be_bytes(payload[8..12].try_into().unwrap()),
                })
            }
            196608 => {
                let mut params = HashMap::new();
                let mut idx = 4;
                while idx < payload.len().saturating_sub(1) {
                    let (k, len) = read_c_string(&payload[idx..])?;
                    idx += len;
                    if k.is_empty() {
                        break;
                    }
                    let (v, len) = read_c_string(&payload[idx..])?;
                    idx += len;
                    params.insert(k, v);
                }
                Ok(PgC2S::StartupMessage {
                    version: code_or_ver,
                    parameters: params,
                })
            }
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

            let iter = read_u16_prefixed(payload, &mut idx, 4, |chunk| {
                u32::from_be_bytes(chunk.try_into().unwrap())
            })?;

            PgC2S::Parse {
                name,
                query,
                parameter_type_oids: iter.collect(),
            }
        }
        b'B' => {
            let mut idx = 0;
            let (portal, len) = read_c_string(payload)?;
            idx += len;

            let (statement, len) = read_c_string(&payload[idx..])?;
            idx += len;

            let fmt_iter = read_u16_prefixed(payload, &mut idx, 2, |chunk| {
                i16::from_be_bytes(chunk.try_into().unwrap())
            })?;

            // 2. Parameters parsing
            if idx + 2 > payload.len() {
                return Err("Truncated Bind: missing parameter count");
            }
            let param_count =
                u16::from_be_bytes(payload[idx..idx + 2].try_into().unwrap()) as usize;
            idx += 2;

            let mut params = Vec::with_capacity(param_count);

            for _ in 0..param_count {
                if idx + 4 > payload.len() {
                    return Err("Truncated Bind: missing parameter length");
                }
                let len = i32::from_be_bytes(payload[idx..idx + 4].try_into().unwrap());
                idx += 4;

                if len == -1 {
                    params.push(None);
                } else if len < -1 {
                    return Err("Invalid parameter length");
                } else {
                    let ulen = len as usize;
                    if idx + ulen > payload.len() {
                        return Err("Truncated Bind: parameter value out of bounds");
                    }
                    params.push(Some(&payload[idx..idx + ulen]));
                    idx += ulen;
                }
            }

            let res_iter = read_u16_prefixed(payload, &mut idx, 2, |chunk| {
                i16::from_be_bytes(chunk.try_into().unwrap())
            })?;

            PgC2S::Bind {
                portal,
                statement,
                parameter_format_codes: fmt_iter.collect(),
                parameters: params,
                result_format_codes: res_iter.collect(),
            }
        }
        b'E' => {
            let (portal, len) = read_c_string(payload)?;
            if len + 4 > payload.len() {
                return Err("Truncated Execute: missing max_rows");
            }
            let max_rows = i32::from_be_bytes(payload[len..len + 4].try_into().unwrap());
            PgC2S::Execute { portal, max_rows }
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

impl<'a> fmt::Display for PgC2S<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PgC2S::SSLRequest => write!(f, "SSLRequest"),
            PgC2S::StartupMessage {
                version,
                parameters,
            } => {
                write!(
                    f,
                    "StartupMessage(version: {}, params: {:?})",
                    version, parameters
                )
            }
            PgC2S::CancelRequest {
                process_id,
                secret_key,
            } => {
                write!(
                    f,
                    "CancelRequest(pid: {}, secret_key: {})",
                    process_id, secret_key
                )
            }
            PgC2S::Bind {
                portal,
                statement,
                parameter_format_codes,
                parameters,
                result_format_codes,
            } => {
                write!(
                    f,
                    "Bind(portal: '{}', statement: '{}', param_formats: {}, params_cnt: {}, result_formats: {})",
                    portal,
                    statement,
                    parameter_format_codes.len(),
                    parameters.len(),
                    result_format_codes.len()
                )
            }
            PgC2S::Close { target_type, name } => {
                write!(
                    f,
                    "Close(target_type: {}, name: '{}')",
                    *target_type as char, name
                )
            }
            PgC2S::Describe { target_type, name } => {
                write!(
                    f,
                    "Describe(target_type: {}, name: '{}')",
                    *target_type as char, name
                )
            }
            PgC2S::Execute { portal, max_rows } => {
                write!(f, "Execute(portal: '{}', max_rows: {})", portal, max_rows)
            }
            PgC2S::Flush => write!(f, "Flush"),
            PgC2S::FunctionCall => write!(f, "FunctionCall"),
            PgC2S::Parse {
                name,
                query,
                parameter_type_oids,
            } => {
                write!(
                    f,
                    "Parse(name: '{}', query: '{}', param_oids: {:?})",
                    name, query, parameter_type_oids
                )
            }
            PgC2S::PasswordMessage(p) => write!(f, "PasswordMessage('{p}')"), // Sanitized for logging
            PgC2S::Query(query) => write!(f, "Query('{}')", query),
            PgC2S::Sync => write!(f, "Sync"),
            PgC2S::Terminate => write!(f, "Terminate"),
            PgC2S::CopyData(bytes) => write!(f, "CopyData({} bytes)", bytes.len()),
            PgC2S::CopyDone => write!(f, "CopyDone"),
            PgC2S::CopyFail(msg) => write!(f, "CopyFail('{}')", msg),
            PgC2S::Unknown { tag, payload } => {
                write!(f, "Unknown(tag: {}, len: {})", *tag as char, payload.len())
            }
        }
    }
}

pub struct U16PrefixedIter<'a, T, F> {
    slice: &'a [u8],
    remaining: usize,
    elem_size: usize,
    decode: F,
    _phantom: std::marker::PhantomData<T>,
}

impl<'a, T, F> Iterator for U16PrefixedIter<'a, T, F>
where
    F: Fn(&'a [u8]) -> T,
{
    type Item = T;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 || self.slice.len() < self.elem_size {
            return None;
        }
        let (chunk, rest) = self.slice.split_at(self.elem_size);
        self.slice = rest;
        self.remaining -= 1;
        Some((self.decode)(chunk))
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<'a, T, F> ExactSizeIterator for U16PrefixedIter<'a, T, F> where F: Fn(&'a [u8]) -> T {}

pub fn read_u16_prefixed<'a, T, F>(
    payload: &'a [u8],
    idx: &mut usize,
    elem_size: usize,
    decode: F,
) -> Result<U16PrefixedIter<'a, T, F>, &'static str>
where
    F: Fn(&'a [u8]) -> T,
{
    if *idx + 2 > payload.len() {
        return Err("Truncated: missing element count");
    }
    let count = u16::from_be_bytes(payload[*idx..*idx + 2].try_into().unwrap()) as usize;
    *idx += 2;

    let total_bytes = count * elem_size;
    if *idx + total_bytes > payload.len() {
        return Err("Truncated: elements out of bounds");
    }

    let subslice = &payload[*idx..*idx + total_bytes];
    *idx += total_bytes;

    Ok(U16PrefixedIter {
        slice: subslice,
        remaining: count,
        elem_size,
        decode,
        _phantom: std::marker::PhantomData,
    })
}
