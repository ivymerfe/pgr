use crate::parser::{
    c2s::{Codes, PgC2S, Values, parse_pg_message},
    utils,
};
use std::fmt::{self, Write};

pub struct TagFrame<'a>(pub u8, pub &'a [u8]);

impl<'a> fmt::Display for TagFrame<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match parse_pg_message(self.0, self.1) {
            Ok(msg) => {
                write!(f, "{}", msg)?;
            }
            Err(e) => {
                write!(f, "{},(\"{}\"),\"", self.0, e)?;
                utils::write_escaped_bytes(f, self.1)?;
                f.write_char('"')?;
            }
        }
        Ok(())
    }
}

impl<'a> fmt::Display for PgC2S<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PgC2S::SSLRequest => write!(f, "SSLRequest"),
            PgC2S::GSSENCRequest => write!(f, "GSSENCRequest"),
            PgC2S::StartupMessage {
                version,
                parameters,
            } => {
                write!(f, "StartupMessage,{},", version)?;
                for (i, (k, v)) in parameters.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "{}:{}", k, v)?;
                }
                Ok(())
            }
            PgC2S::CancelRequest {
                process_id,
                secret_key,
            } => {
                write!(f, "CancelRequest,{},{}", process_id, secret_key)
            }
            PgC2S::Bind {
                portal,
                statement,
                parameter_format_codes,
                parameters,
                result_format_codes,
            } => {
                write!(f, "Bind,\"{}\",\"{}\",", portal, statement)?;
                write_codes(f, parameter_format_codes)?;
                f.write_char(',')?;
                write_values(f, parameters)?;
                f.write_char(',')?;
                write_codes(f, result_format_codes)
            }
            PgC2S::Close { target_type, name } => {
                write!(f, "Close,{},\"{}\"", *target_type as char, name)
            }
            PgC2S::Describe { target_type, name } => {
                write!(f, "Describe,{},\"{}\"", *target_type as char, name)
            }
            PgC2S::Execute { portal, max_rows } => {
                write!(f, "Execute,\"{}\",{}", portal, max_rows)
            }
            PgC2S::Flush => write!(f, "Flush"),
            PgC2S::FunctionCall {
                object_id,
                argument_format_codes,
                arguments,
                result_format_code,
            } => {
                write!(f, "FunctionCall,{},", object_id)?;
                write_codes(f, argument_format_codes)?;
                f.write_char(',')?;
                write_values(f, arguments)?;
                write!(f, ",{}", result_format_code)
            }
            PgC2S::Parse {
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
            PgC2S::PasswordMessage(p) => write!(f, "PasswordMessage,\"{p}\""),
            PgC2S::Query(query) => write!(f, "Query,\"{}\"", query),
            PgC2S::Sync => write!(f, "Sync"),
            PgC2S::Terminate => write!(f, "Terminate"),
            PgC2S::CopyData(bytes) => write!(f, "CopyData,{}", bytes.len()),
            PgC2S::CopyDone => write!(f, "CopyDone"),
            PgC2S::CopyFail(msg) => write!(f, "CopyFail,\"{}\"", msg),
            PgC2S::Unknown { tag, payload } => {
                write!(f, "Unknown,{},", *tag as char)?;
                utils::write_escaped_bytes(f, *payload)
            }
        }
    }
}

pub fn write_codes<W: Write>(w: &mut W, codes: &Codes<'_>) -> fmt::Result {
    w.write_char('[')?;
    for (i, c) in codes.iter().enumerate() {
        if i > 0 {
            w.write_char(';')?;
        }
        write!(w, "{}", c)?;
    }
    w.write_char(']')
}

pub fn write_values<'a, W: Write>(w: &mut W, vals: &Values<'_>) -> fmt::Result {
    w.write_char('[')?;
    for (i, v) in vals.iter().enumerate() {
        if i > 0 {
            w.write_char(';')?;
        }
        match v {
            Some(b) => {
                w.write_char('"')?;
                utils::write_escaped_bytes(w, b)?;
                w.write_char('"')?;
            }
            None => write!(w, "None")?,
        }
    }
    w.write_char(']')
}
