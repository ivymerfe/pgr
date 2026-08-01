use crate::parser::c2s::{Codes, PgC2S, Values};
use std::fmt::{self, Write};

impl<'a> fmt::Display for PgC2S<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PgC2S::SSLRequest => write!(f, "SSLRequest"),
            PgC2S::GSSENCRequest => write!(f, "GSSENCRequest"),
            PgC2S::StartupMessage {
                version,
                parameters,
            } => {
                write!(f, "StartupMessage(version: {}, params: {{", version)?;
                for (i, (k, v)) in parameters.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}: {}", k, v)?;
                }
                write!(f, "}})")
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
                    "Bind(portal: '{}', st: '{}', param_formats: [",
                    portal, statement
                )?;
                write_codes(f, parameter_format_codes)?;
                write!(f, "], params: [")?;
                write_values(f, parameters)?;
                write!(f, "], res_formats: [")?;
                write_codes(f, result_format_codes)?;
                write!(f, "])")
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
            PgC2S::FunctionCall {
                object_id,
                argument_format_codes,
                arguments,
                result_format_code,
            } => {
                write!(f, "FunctionCall(oid: {}, arg_formats: [", object_id)?;
                write_codes(f, argument_format_codes)?;
                write!(f, "], args: [")?;
                write_values(f, arguments)?;
                write!(f, "], res_format: {})", result_format_code)
            }
            PgC2S::Parse {
                name,
                query,
                parameter_type_oids,
            } => {
                write!(
                    f,
                    "Parse(name: '{}', query: '{}', param_oids: [",
                    name, query
                )?;
                for (i, oid) in parameter_type_oids.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", oid)?;
                }
                write!(f, "])")
            }
            PgC2S::PasswordMessage(p) => write!(f, "PasswordMessage('{p}')"),
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

fn write_codes(f: &mut fmt::Formatter<'_>, codes: &Codes<'_>) -> fmt::Result {
    for (i, c) in codes.iter().enumerate() {
        if i > 0 {
            write!(f, ", ")?;
        }
        write!(f, "{}", c)?;
    }
    Ok(())
}

fn write_escaped_bytes(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for &b in bytes {
        for c in std::ascii::escape_default(b) {
            f.write_char(c as char)?;
        }
    }
    Ok(())
}

fn write_values<'a>(f: &mut fmt::Formatter<'_>, vals: &Values<'_>) -> fmt::Result {
    for (i, v) in vals.iter().enumerate() {
        if i > 0 {
            write!(f, ", ")?;
        }
        match v {
            Some(b) => {
                write!(f, "'")?;
                write_escaped_bytes(f, b)?;
                write!(f, "'")?;
            }
            None => write!(f, "None")?,
        }
    }
    Ok(())
}
