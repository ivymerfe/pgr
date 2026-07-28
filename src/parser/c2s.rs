use std::collections::HashMap;

#[derive(Debug)]
pub enum PgC2S<'a> {
    SSLRequest,
    GSSENCRequest,
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
    FunctionCall {
        object_id: u32,
        argument_format_codes: Vec<i16>,
        arguments: Vec<Option<&'a [u8]>>,
        result_format_code: i16,
    },
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
    let null_pos = buf
        .iter()
        .position(|&b| b == 0)
        .ok_or("Missing null terminator")?;
    let s = std::str::from_utf8(&buf[..null_pos]).map_err(|_| "Invalid UTF-8 in C string")?;
    Ok((s, null_pos + 1))
}

pub fn parse_pg_message<'a>(tag: u8, payload: &'a [u8]) -> Result<PgC2S<'a>, &'static str> {
    if tag == 0 {
        if payload.len() < 4 {
            return Err("Truncated startup header");
        }

        let code_or_ver = u32::from_be_bytes(payload[..4].try_into().unwrap());
        let major = code_or_ver >> 16;
        // let minor = code_or_ver & 0xFFFF;

        return match code_or_ver {
            80877102 => {
                if payload.len() < 12 {
                    return Err("Incomplete CancelRequest");
                }
                Ok(PgC2S::CancelRequest {
                    process_id: u32::from_be_bytes(payload[4..8].try_into().unwrap()),
                    secret_key: u32::from_be_bytes(payload[8..12].try_into().unwrap()),
                })
            }
            80877103 => Ok(PgC2S::SSLRequest),
            80877104 => Ok(PgC2S::GSSENCRequest),
            _ if major == 3 => {
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
            let parameter_type_oids = read_u16_prefixed_u32(payload, &mut idx)?;
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

            let parameter_format_codes = read_u16_prefixed_i16(payload, &mut idx)?;
            let parameters = read_sized_values(payload, &mut idx)?;
            let result_format_codes = read_u16_prefixed_i16(payload, &mut idx)?;

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
            let max_rows = i32::from_be_bytes(payload[len..len + 4].try_into().unwrap());
            PgC2S::Execute { portal, max_rows }
        }
        b'F' => {
            let mut idx = 0;
            if payload.len() < 4 {
                return Err("Truncated FunctionCall: missing object id");
            }
            let object_id = u32::from_be_bytes(payload[0..4].try_into().unwrap());
            idx += 4;

            let argument_format_codes = read_u16_prefixed_i16(payload, &mut idx)?;
            let arguments = read_sized_values(payload, &mut idx)?;

            if idx + 2 > payload.len() {
                return Err("Truncated FunctionCall: missing result format code");
            }
            let result_format_code = i16::from_be_bytes(payload[idx..idx + 2].try_into().unwrap());

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

fn read_u16_prefixed_i16(payload: &[u8], idx: &mut usize) -> Result<Vec<i16>, &'static str> {
    if *idx + 2 > payload.len() {
        return Err("Truncated: missing element count");
    }
    let count = u16::from_be_bytes(payload[*idx..*idx + 2].try_into().unwrap()) as usize;
    *idx += 2;

    let total = count * 2;
    if *idx + total > payload.len() {
        return Err("Truncated: elements out of bounds");
    }

    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off = *idx + i * 2;
        out.push(i16::from_be_bytes(
            payload[off..off + 2].try_into().unwrap(),
        ));
    }
    *idx += total;
    Ok(out)
}

fn read_u16_prefixed_u32(payload: &[u8], idx: &mut usize) -> Result<Vec<u32>, &'static str> {
    if *idx + 2 > payload.len() {
        return Err("Truncated: missing element count");
    }
    let count = u16::from_be_bytes(payload[*idx..*idx + 2].try_into().unwrap()) as usize;
    *idx += 2;

    let total = count * 4;
    if *idx + total > payload.len() {
        return Err("Truncated: elements out of bounds");
    }

    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off = *idx + i * 4;
        out.push(u32::from_be_bytes(
            payload[off..off + 4].try_into().unwrap(),
        ));
    }
    *idx += total;
    Ok(out)
}

fn read_sized_values<'a>(
    payload: &'a [u8],
    idx: &mut usize,
) -> Result<Vec<Option<&'a [u8]>>, &'static str> {
    if *idx + 2 > payload.len() {
        return Err("Truncated: missing value count");
    }
    let count = u16::from_be_bytes(payload[*idx..*idx + 2].try_into().unwrap()) as usize;
    *idx += 2;

    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        if *idx + 4 > payload.len() {
            return Err("Truncated: missing value length");
        }
        let len = i32::from_be_bytes(payload[*idx..*idx + 4].try_into().unwrap());
        *idx += 4;

        if len == -1 {
            out.push(None);
        } else if len < -1 {
            return Err("Invalid value length");
        } else {
            let ulen = len as usize;
            if *idx + ulen > payload.len() {
                return Err("Truncated: value out of bounds");
            }
            out.push(Some(&payload[*idx..*idx + ulen]));
            *idx += ulen;
        }
    }
    Ok(out)
}
