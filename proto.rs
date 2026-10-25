#[allow(unused)]
pub const F_PROTO_VERSION: u32 = 196608;
pub const F_PASSWORD_MESSAGE: u8 = b'p';

pub const F_PARSE: u8 = b'P';
pub const F_BIND: u8 = b'B';
pub const F_DESCRIBE: u8 = b'D';
pub const F_EXECUTE: u8 = b'E';
pub const F_CLOSE: u8 = b'C';
pub const F_SYNC: u8 = b'S';
pub const F_QUERY: u8 = b'Q';
pub const F_TERMINATE: u8 = b'X';

pub const B_AUTH_REQUEST: u8 = b'R';
pub const B_PARAMETER_STATUS: u8 = b'S';
pub const B_BACKEND_KEY_DATA: u8 = b'K';

pub const B_PARSE_COMPLETE: u8 = b'1';
pub const B_BIND_COMPLETE: u8 = b'2';
pub const B_CLOSE_COMPLETE: u8 = b'3';
pub const B_COMMAND_COMPLETE: u8 = b'C';
pub const B_DATA_ROW: u8 = b'D';
pub const B_ERROR: u8 = b'E';
pub const B_EMPTY_QUERY: u8 = b'I';
pub const B_NOTICE: u8 = b'N';
pub const B_NOTIFICATION: u8 = b'A';
pub const B_NO_DATA: u8 = b'n';
pub const B_PORTAL_SUSPENDED: u8 = b's';
pub const B_PARAMETER_DESC: u8 = b't';
pub const B_ROW_DESC: u8 = b'T';
pub const B_READY_FOR_QUERY: u8 = b'Z';

pub enum BackendMessage<'a> {
    Authentication(Authentication),
    ParameterStatus { _name: String, _value: String },
    BackendKeyData { _pid: i32, _secret: i32 },
    ReadyForQuery,
    ErrorResponse(String),
    NoticeResponse,
    Other { _tag: u8, _frame: &'a [u8] },
}

pub enum Authentication {
    Ok,
    Cleartext,
    Md5 { salt: [u8; 4] },
    Unsupported(i32),
}

pub fn try_read_frame(buf: &[u8]) -> Option<(u8, usize)> {
    if buf.len() < 5 {
        return None;
    }
    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    let frame_len = 1 + len;
    if buf.len() < frame_len {
        return None;
    }
    Some((buf[0], frame_len))
}

pub fn parse_message(tag: u8, mut data: &[u8]) -> Result<BackendMessage<'_>, ()> {
    Ok(match tag {
        B_AUTH_REQUEST => {
            if data.len() < 4 {
                return Err(());
            }
            let code = i32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            data = &data[4..];
            match code {
                0 => BackendMessage::Authentication(Authentication::Ok),
                3 => BackendMessage::Authentication(Authentication::Cleartext),
                5 => {
                    if data.len() < 4 {
                        return Err(());
                    }
                    let mut salt = [0u8; 4];
                    salt.copy_from_slice(&data[..4]);
                    BackendMessage::Authentication(Authentication::Md5 { salt })
                }
                other => BackendMessage::Authentication(Authentication::Unsupported(other)),
            }
        }
        B_PARAMETER_STATUS => {
            let (name, rest) = read_cstr(data);
            let (value, _) = read_cstr(rest);
            BackendMessage::ParameterStatus {
                _name: name,
                _value: value,
            }
        }
        B_BACKEND_KEY_DATA => {
            if data.len() < 8 {
                return Err(());
            }
            let pid = i32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            let secret = i32::from_be_bytes([data[4], data[5], data[6], data[7]]);
            BackendMessage::BackendKeyData {
                _pid: pid,
                _secret: secret,
            }
        }
        B_READY_FOR_QUERY => BackendMessage::ReadyForQuery,
        B_ERROR => BackendMessage::ErrorResponse(read_cstr(data).0),
        B_NOTICE => BackendMessage::NoticeResponse,
        other => BackendMessage::Other {
            _tag: other,
            _frame: data,
        },
    })
}

pub const TERMINATE_MSG: [u8; 5] = [F_TERMINATE, 0, 0, 0, 4];

pub fn encode_startup(params: &[(&str, String)]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&F_PROTO_VERSION.to_be_bytes());
    for (k, v) in params {
        body.extend_from_slice(k.as_bytes());
        body.push(0);
        body.extend_from_slice(v.as_bytes());
        body.push(0);
    }
    body.push(0);

    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(4 + body.len() as i32).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

pub fn encode_password(pass: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(6 + pass.len());
    out.push(F_PASSWORD_MESSAGE);
    out.extend_from_slice(&(4 + pass.len() as i32 + 1).to_be_bytes());
    out.extend_from_slice(pass.as_bytes());
    out.push(0);
    out
}

pub fn hash_md5_password(user: &str, pass: &str, salt: &[u8; 4]) -> String {
    let inner = format!("{:x}", md5::compute(format!("{pass}{user}")));
    let mut buf = inner.into_bytes();
    buf.extend_from_slice(salt);
    format!("md5{:x}", md5::compute(&buf))
}

fn read_cstr(buf: &[u8]) -> (String, &[u8]) {
    let pos = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let s = String::from_utf8_lossy(&buf[..pos]).into_owned();
    let rest = if pos < buf.len() {
        &buf[pos + 1..]
    } else {
        &buf[pos..]
    };
    (s, rest)
}
