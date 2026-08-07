use crate::pg_client::error::PgClientError;

pub struct BackendFrame<'a> {
    pub tag: u8,
    pub data: &'a [u8],
}

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

pub fn parse_message(tag: u8, mut data: &[u8]) -> Result<BackendMessage<'_>, PgClientError> {
    Ok(match tag {
        b'R' => {
            if data.len() < 4 {
                return Err(PgClientError::MalformedMessage);
            }
            let code = i32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            data = &data[4..];
            match code {
                0 => BackendMessage::Authentication(Authentication::Ok),
                3 => BackendMessage::Authentication(Authentication::Cleartext),
                5 => {
                    if data.len() < 4 {
                        return Err(PgClientError::MalformedMessage);
                    }
                    let mut salt = [0u8; 4];
                    salt.copy_from_slice(&data[..4]);
                    BackendMessage::Authentication(Authentication::Md5 { salt })
                }
                other => BackendMessage::Authentication(Authentication::Unsupported(other)),
            }
        }
        b'S' => {
            let (name, rest) = read_cstr(data);
            let (value, _) = read_cstr(rest);
            BackendMessage::ParameterStatus {
                _name: name,
                _value: value,
            }
        }
        b'K' => {
            if data.len() < 8 {
                return Err(PgClientError::MalformedMessage);
            }
            let pid = i32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            let secret = i32::from_be_bytes([data[4], data[5], data[6], data[7]]);
            BackendMessage::BackendKeyData {
                _pid: pid,
                _secret: secret,
            }
        }
        b'Z' => BackendMessage::ReadyForQuery,
        b'E' => BackendMessage::ErrorResponse(read_cstr(data).0),
        b'N' => BackendMessage::NoticeResponse,
        other => BackendMessage::Other {
            _tag: other,
            _frame: data,
        },
    })
}

pub fn encode_startup(params: &[(String, String)]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&196608i32.to_be_bytes());
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
    out.push(b'p');
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
