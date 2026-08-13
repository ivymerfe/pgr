use crate::proto::parse::{
    Codes, Oids, RawParams, Values, read_c_string, read_i16, read_i32, read_u32,
};

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

impl<'a> PgC2S<'a> {
    pub fn parse(tag: u8, payload: &[u8]) -> Result<PgC2S<'_>, &'static str> {
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
}
