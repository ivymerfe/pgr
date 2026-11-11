#[allow(unused)]
pub const F_PROTO_VERSION: u32 = 196608;
pub const F_PASSWORD_MESSAGE: u8 = b'p';

pub const F_PARSE: u8 = b'P';
pub const F_BIND: u8 = b'B';
pub const F_EXECUTE: u8 = b'E';
pub const F_CLOSE: u8 = b'C';
pub const F_SYNC: u8 = b'S';
pub const F_QUERY: u8 = b'Q';
pub const F_TERMINATE: u8 = b'X';

pub const B_AUTH_REQUEST: u8 = b'R';
pub const B_READY_FOR_QUERY: u8 = b'Z';

pub const TERMINATE_MSG: [u8; 5] = [F_TERMINATE, 0, 0, 0, 4];

#[derive(Debug, Default)]
pub struct ErrorFields {
    pub severity: Option<String>,
    pub code: Option<String>,
    pub message: Option<String>,
    pub detail: Option<String>,
    pub hint: Option<String>,
}

pub enum Authentication {
    Ok,
    Cleartext,
    Md5 { salt: [u8; 4] },
    Unsupported(i32),
}

pub enum BackendMessage {
    Authentication(Authentication),
    ReadyForQuery,
    ErrorResponse(ErrorFields),
    Other,
}

pub struct Frame(Vec<u8>);

impl Frame {
    pub fn new(tag: u8) -> Self {
        Self(vec![tag, 0, 0, 0, 0])
    }

    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }

    pub fn i16(&mut self, v: i16) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn i32(&mut self, v: i32) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn raw(&mut self, v: &[u8]) -> &mut Self {
        self.0.extend_from_slice(v);
        self
    }

    pub fn cstr(&mut self, s: &str) -> &mut Self {
        self.0.extend_from_slice(s.as_bytes());
        self.0.push(0);
        self
    }

    pub fn finish(mut self) -> Vec<u8> {
        let n = (self.0.len() - 1) as i32;
        self.0[1..5].copy_from_slice(&n.to_be_bytes());
        self.0
    }
}

pub fn parse_message(tag: u8, data: &[u8]) -> Result<BackendMessage, ()> {
    Ok(match tag {
        B_AUTH_REQUEST => {
            if data.len() < 4 {
                return Err(());
            }
            let code = i32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            match code {
                0 => BackendMessage::Authentication(Authentication::Ok),
                3 => BackendMessage::Authentication(Authentication::Cleartext),
                5 => {
                    let salt: [u8; 4] = data.get(4..8).ok_or(())?.try_into().unwrap();
                    BackendMessage::Authentication(Authentication::Md5 { salt })
                }
                other => BackendMessage::Authentication(Authentication::Unsupported(other)),
            }
        }
        B_ERROR => BackendMessage::ErrorResponse(parse_error_fields(data)),
        B_READY_FOR_QUERY => BackendMessage::ReadyForQuery,
        _ => BackendMessage::Other,
    })
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

pub fn parse_error_fields(mut data: &[u8]) -> ErrorFields {
    let mut fields = ErrorFields::default();
    while !data.is_empty() && data[0] != 0 {
        let field_type = data[0];
        let (val, rest) = read_cstr(&data[1..]);
        data = rest;
        match field_type {
            b'S' => fields.severity = Some(val),
            b'C' => fields.code = Some(val),
            b'M' => fields.message = Some(val),
            b'D' => fields.detail = Some(val),
            b'H' => fields.hint = Some(val),
            _ => {}
        }
    }
    fields
}

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

impl std::fmt::Display for ErrorFields {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts = Vec::new();
        if let Some(s) = &self.severity {
            parts.push(format!("severity={}", s));
        }
        if let Some(c) = &self.code {
            parts.push(format!("code={}", c));
        }
        if let Some(m) = &self.message {
            parts.push(format!("message={}", m));
        }
        if let Some(d) = &self.detail {
            parts.push(format!("detail={}", d));
        }
        if let Some(h) = &self.hint {
            parts.push(format!("hint={}", h));
        }
        write!(f, "{}", parts.join(", "))
    }
}
