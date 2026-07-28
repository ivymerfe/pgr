use crate::parser::c2s::PgC2S;
use std::fmt;

impl<'a> fmt::Display for PgC2S<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PgC2S::SSLRequest => write!(f, "SSLRequest"),
            PgC2S::GSSENCRequest => write!(f, "GSSENCRequest"),
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
                    "Bind(portal: '{}', statement: '{}', param_formats: {:?}, params: {:?}, result_formats: {:?})",
                    portal, statement, parameter_format_codes, parameters, result_format_codes
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
            PgC2S::FunctionCall {
                object_id,
                argument_format_codes,
                arguments,
                result_format_code,
            } => {
                write!(
                    f,
                    "FunctionCall(object_id: {}, argument_format_codes: {:?}, argument: {:?}, result_format_code: {})",
                    object_id, argument_format_codes, arguments, result_format_code
                )
            }
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
