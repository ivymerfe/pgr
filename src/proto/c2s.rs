use std::fmt::{self, Write};

use crate::{
    utils::format::{DisplayBytes, write_i16_slice},
    utils::parse::{read_c_string, read_i16, read_i32, read_u16, read_u32},
};

#[derive(Debug)]
pub enum PgMsg<'a> {
    SSLRequest,
    GSSENCRequest,
    StartupMessage {
        version: u32,
        parameters_src: &'a [u8],
        params: &'a [(usize, usize, usize, usize)],
    },
    CancelRequest {
        process_id: u32,
        secret_key: u32,
    },
    Bind {
        portal: &'a str,
        statement: &'a str,
        parameter_format_codes: &'a [i16],
        parameters_src: &'a [u8],
        parameters: &'a [Option<(usize, usize)>],
        result_format_codes: &'a [i16],
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
        argument_format_codes: &'a [i16],
        arguments_src: &'a [u8],
        arguments: &'a [Option<(usize, usize)>],
        result_format_code: i16,
    },
    Parse {
        name: &'a str,
        query: &'a str,
        parameter_type_oids: &'a [u32],
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

impl<'a> PgMsg<'a> {
    pub fn bind_param(&self, idx: usize) -> Option<&'a [u8]> {
        match self {
            PgMsg::Bind {
                parameters_src,
                parameters,
                ..
            } => parameters[idx].map(|(off, len)| &parameters_src[off..off + len]),
            _ => None,
        }
    }

    pub fn startup_param(&self, i: usize) -> Option<(&'a str, &'a str)> {
        match self {
            PgMsg::StartupMessage {
                parameters_src,
                params,
                ..
            } => {
                let (ko, kl, vo, vl) = params[i];
                let k = std::str::from_utf8(&parameters_src[ko..ko + kl]).ok()?;
                let v = std::str::from_utf8(&parameters_src[vo..vo + vl]).ok()?;
                Some((k, v))
            }
            _ => None,
        }
    }
}

impl<'a> fmt::Display for PgMsg<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PgMsg::SSLRequest => write!(f, "SSLRequest"),
            PgMsg::GSSENCRequest => write!(f, "GSSENCRequest"),
            PgMsg::StartupMessage {
                version, params, ..
            } => {
                write!(f, "StartupMessage,{},", version)?;
                for i in 0..params.len() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    if let Some((k, v)) = self.startup_param(i) {
                        write!(f, "{}:{}", k, v)?;
                    }
                }
                Ok(())
            }
            PgMsg::CancelRequest {
                process_id,
                secret_key,
            } => {
                write!(f, "CancelRequest,{},{}", process_id, secret_key)
            }
            PgMsg::Bind {
                portal,
                statement,
                parameter_format_codes,
                parameters,
                result_format_codes,
                ..
            } => {
                write!(f, "Bind,\"{}\",\"{}\",", portal, statement)?;
                write_i16_slice(f, parameter_format_codes)?;
                f.write_char(',')?;
                f.write_char('[')?;
                for i in 0..parameters.len() {
                    if i > 0 {
                        f.write_char(';')?;
                    }
                    match self.bind_param(i) {
                        Some(param) => write!(f, "\"{}\"", DisplayBytes(param))?,
                        None => write!(f, "None")?,
                    }
                }
                f.write_char(']')?;
                f.write_char(',')?;
                write_i16_slice(f, result_format_codes)
            }
            PgMsg::Close { target_type, name } => {
                write!(f, "Close,{},\"{}\"", *target_type as char, name)
            }
            PgMsg::Describe { target_type, name } => {
                write!(f, "Describe,{},\"{}\"", *target_type as char, name)
            }
            PgMsg::Execute { portal, max_rows } => {
                write!(f, "Execute,\"{}\",{}", portal, max_rows)
            }
            PgMsg::Flush => write!(f, "Flush"),
            PgMsg::FunctionCall {
                object_id,
                argument_format_codes,
                arguments,
                arguments_src,
                result_format_code,
            } => {
                write!(f, "FunctionCall,{},", object_id)?;
                write_i16_slice(f, argument_format_codes)?;
                f.write_char(',')?;
                f.write_char('[')?;
                for (i, v) in arguments.iter().enumerate() {
                    if i > 0 {
                        f.write_char(';')?;
                    }
                    match v {
                        Some((off, len)) => {
                            write!(f, "\"{}\"", DisplayBytes(&arguments_src[*off..*off + *len]))?
                        }
                        None => write!(f, "None")?,
                    }
                }
                f.write_char(']')?;
                write!(f, ",{}", result_format_code)
            }
            PgMsg::Parse {
                name,
                query,
                parameter_type_oids,
            } => {
                write!(f, "Parse,\"{}\",\"{}\",[", name, query)?;
                for (i, oid) in parameter_type_oids.iter().enumerate() {
                    if i > 0 {
                        f.write_char(';')?;
                    }
                    write!(f, "{}", oid)?;
                }
                f.write_char(']')?;
                Ok(())
            }
            PgMsg::PasswordMessage(p) => write!(f, "PasswordMessage,\"{p}\""),
            PgMsg::Query(query) => write!(f, "Query,\"{}\"", query),
            PgMsg::Sync => write!(f, "Sync"),
            PgMsg::Terminate => write!(f, "Terminate"),
            PgMsg::CopyData(bytes) => write!(f, "CopyData,{}", bytes.len()),
            PgMsg::CopyDone => write!(f, "CopyDone"),
            PgMsg::CopyFail(msg) => write!(f, "CopyFail,\"{}\"", msg),
            PgMsg::Unknown { tag, payload } => {
                write!(f, "Unknown,{},{}", *tag as char, DisplayBytes(payload))
            }
        }
    }
}

#[derive(Default)]
pub struct PgMsgParser {
    pub parameter_format_codes: Vec<i16>,
    pub parameters: Vec<Option<(usize, usize)>>, // (offset, len) into payload
    pub result_format_codes: Vec<i16>,
    pub argument_format_codes: Vec<i16>,
    pub arguments: Vec<Option<(usize, usize)>>,
    pub parameter_type_oids: Vec<u32>,
    pub startup_params: Vec<(usize, usize, usize, usize)>, // k_off,k_len,v_off,v_len
}

impl PgMsgParser {
    pub fn new() -> Self {
        Self::default()
    }

    fn clear(&mut self) {
        self.parameter_format_codes.clear();
        self.parameters.clear();
        self.result_format_codes.clear();
        self.argument_format_codes.clear();
        self.arguments.clear();
        self.parameter_type_oids.clear();
        self.startup_params.clear();
    }

    fn read_codes(payload: &[u8], idx: &mut usize, out: &mut Vec<i16>) -> Result<(), &'static str> {
        if *idx + 2 > payload.len() {
            return Err("Truncated: missing element count");
        }
        let count = read_u16(&payload[*idx..*idx + 2]) as usize;
        *idx += 2;
        let total = count * 2;
        if *idx + total > payload.len() {
            return Err("Truncated: elements out of bounds");
        }
        out.reserve(count);
        for i in 0..count {
            let off = *idx + i * 2;
            out.push(read_i16(&payload[off..off + 2]));
        }
        *idx += total;
        Ok(())
    }

    fn read_oids(payload: &[u8], idx: &mut usize, out: &mut Vec<u32>) -> Result<(), &'static str> {
        if *idx + 2 > payload.len() {
            return Err("Truncated: missing element count");
        }
        let count = read_u16(&payload[*idx..*idx + 2]) as usize;
        *idx += 2;
        let total = count * 4;
        if *idx + total > payload.len() {
            return Err("Truncated: elements out of bounds");
        }
        out.reserve(count);
        for i in 0..count {
            let off = *idx + i * 4;
            out.push(read_u32(&payload[off..off + 4]));
        }
        *idx += total;
        Ok(())
    }

    fn read_values(
        payload: &[u8],
        idx: &mut usize,
        out: &mut Vec<Option<(usize, usize)>>,
    ) -> Result<(), &'static str> {
        if *idx + 2 > payload.len() {
            return Err("Truncated: missing value count");
        }
        let count = read_u16(&payload[*idx..*idx + 2]) as usize;
        *idx += 2;
        out.reserve(count);
        for _ in 0..count {
            if *idx + 4 > payload.len() {
                return Err("Truncated: missing value length");
            }
            let len = read_i32(&payload[*idx..*idx + 4]);
            *idx += 4;
            if len < -1 {
                return Err("Invalid value length");
            } else if len == -1 {
                out.push(None);
            } else {
                let ulen = len as usize;
                if *idx + ulen > payload.len() {
                    return Err("Truncated: value out of bounds");
                }
                out.push(Some((*idx, ulen)));
                *idx += ulen;
            }
        }
        Ok(())
    }

    fn read_startup_params(
        payload: &[u8],
        out: &mut Vec<(usize, usize, usize, usize)>,
    ) -> Result<(), &'static str> {
        let mut off = 0;
        loop {
            if off >= payload.len() {
                break;
            }
            let (k, klen) = read_c_string(&payload[off..])?;
            if k.is_empty() {
                break;
            }
            let k_off = off;
            off += klen;
            let (_v, vlen) = read_c_string(&payload[off..])?;
            let v_off = off;
            off += vlen;
            out.push((k_off, klen - 1, v_off, vlen - 1));
        }
        Ok(())
    }

    pub fn parse<'a>(&'a mut self, payload: &'a [u8]) -> Result<PgMsg<'a>, &'static str> {
        self.clear();

        if payload.len() < 4 {
            return Err("Truncated frame");
        }
        let tag = payload[0];
        if tag == 0 {
            if payload.len() < 8 {
                return Err("Truncated startup header");
            }
            let body = &payload[4..];
            let code_or_ver = read_u32(&body[..4]);
            let major = code_or_ver >> 16;

            return match code_or_ver {
                80877102 => {
                    if body.len() < 12 {
                        return Err("Incomplete CancelRequest");
                    }
                    Ok(PgMsg::CancelRequest {
                        process_id: read_u32(&body[4..8]),
                        secret_key: read_u32(&body[8..12]),
                    })
                }
                80877103 => Ok(PgMsg::SSLRequest),
                80877104 => Ok(PgMsg::GSSENCRequest),
                _ if major == 3 => {
                    let params_src = &body[4..];
                    Self::read_startup_params(params_src, &mut self.startup_params)?;
                    Ok(PgMsg::StartupMessage {
                        version: code_or_ver,
                        parameters_src: params_src,
                        params: &self.startup_params,
                    })
                }
                _ => Err("Unknown headerless protocol version"),
            };
        }

        if payload.len() < 5 {
            return Err("Truncated frame");
        }
        let body = &payload[5..];

        let msg = match tag {
            b'Q' => {
                let (query, _) = read_c_string(body)?;
                PgMsg::Query(query)
            }
            b'P' => {
                let mut idx = 0;
                let (name, len) = read_c_string(body)?;
                idx += len;
                let (query, len) = read_c_string(&body[idx..])?;
                idx += len;
                Self::read_oids(body, &mut idx, &mut self.parameter_type_oids)?;
                PgMsg::Parse {
                    name,
                    query,
                    parameter_type_oids: &self.parameter_type_oids,
                }
            }
            b'B' => {
                let mut idx = 0;
                let (portal, len) = read_c_string(body)?;
                idx += len;
                let (statement, len) = read_c_string(&body[idx..])?;
                idx += len;
                Self::read_codes(body, &mut idx, &mut self.parameter_format_codes)?;
                Self::read_values(body, &mut idx, &mut self.parameters)?;
                Self::read_codes(body, &mut idx, &mut self.result_format_codes)?;
                PgMsg::Bind {
                    portal,
                    statement,
                    parameter_format_codes: &self.parameter_format_codes,
                    parameters_src: body,
                    parameters: &self.parameters,
                    result_format_codes: &self.result_format_codes,
                }
            }
            b'E' => {
                let (portal, len) = read_c_string(body)?;
                if len + 4 > body.len() {
                    return Err("Truncated Execute: missing max_rows");
                }
                let max_rows = read_i32(&body[len..len + 4]);
                PgMsg::Execute { portal, max_rows }
            }
            b'F' => {
                let mut idx = 0;
                if body.len() < 4 {
                    return Err("Truncated FunctionCall: missing object id");
                }
                let object_id = read_u32(&body[0..4]);
                idx += 4;
                Self::read_codes(body, &mut idx, &mut self.argument_format_codes)?;
                Self::read_values(body, &mut idx, &mut self.arguments)?;
                if idx + 2 > body.len() {
                    return Err("Truncated FunctionCall: missing result format code");
                }
                let result_format_code = read_i16(&body[idx..idx + 2]);
                PgMsg::FunctionCall {
                    object_id,
                    argument_format_codes: &self.argument_format_codes,
                    arguments_src: body,
                    arguments: &self.arguments,
                    result_format_code,
                }
            }
            b'D' => {
                if body.is_empty() {
                    return Err("Truncated Describe: missing target_type");
                }
                let target_type = body[0];
                let (name, _) = read_c_string(&body[1..])?;
                PgMsg::Describe { target_type, name }
            }
            b'C' => {
                if body.is_empty() {
                    return Err("Truncated Close: missing target_type");
                }
                let target_type = body[0];
                let (name, _) = read_c_string(&body[1..])?;
                PgMsg::Close { target_type, name }
            }
            b'S' => PgMsg::Sync,
            b'H' => PgMsg::Flush,
            b'X' => PgMsg::Terminate,
            b'd' => PgMsg::CopyData(body),
            b'c' => PgMsg::CopyDone,
            b'f' => {
                let (msg, _) = read_c_string(body)?;
                PgMsg::CopyFail(msg)
            }
            b'p' => {
                let (pass, _) = read_c_string(body)?;
                PgMsg::PasswordMessage(pass)
            }
            _ => PgMsg::Unknown { tag, payload: body },
        };

        Ok(msg)
    }
}
