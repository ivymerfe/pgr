use std::fmt;
use std::net::SocketAddr;

use bytes::{Buf, BufMut, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Clone, Default)]
pub struct ReplayConfig {
    pub user: String,
    pub password: Option<Vec<u8>>,
    pub dbname: String,
    pub application_name: String,
}
pub struct ReplayConnection {
    stream: TcpStream,
    read_buf: BytesMut,
    pub config: ReplayConfig,
    pub addr: SocketAddr,
}

impl ReplayConnection {
    pub async fn connect(
        addr: SocketAddr,
        config: ReplayConfig,
    ) -> Result<ReplayConnection, ReplayError> {
        let stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;
        let local_addr = stream.local_addr()?;

        let mut client = ReplayConnection {
            stream,
            read_buf: BytesMut::with_capacity(16384),
            addr: local_addr,
            config,
        };

        client.startup().await?;

        // let mut parameters = BTreeMap::new();
        loop {
            let msg = client.next_message().await?;
            match msg {
                BackendMessage::Authentication(auth) => client.handle_auth(auth).await?,
                BackendMessage::ParameterStatus { _name: _, _value: _ } => {
                    // parameters.insert(name, value);
                }
                BackendMessage::BackendKeyData { _pid: _, .. } => {
                    // process_id = pid;
                }
                BackendMessage::ReadyForQuery => break,
                BackendMessage::ErrorResponse(e) => return Err(ReplayError::ErrorResponse(e)),
                BackendMessage::NoticeResponse | BackendMessage::Other { .. } => {}
            }
        }
        Ok(client)
    }

    pub async fn next_message(&mut self) -> Result<BackendMessage, ReplayError> {
        loop {
            if let Some(msg) = try_parse(&mut self.read_buf) {
                return Ok(msg);
            }
            let mut chunk = [0u8; 4096];
            let n = self.stream.read(&mut chunk).await?;
            if n == 0 {
                return Err(ReplayError::ConnectionClosed);
            }
            self.read_buf.extend_from_slice(&chunk[..n]);
        }
    }

    pub async fn read_dont_care(&mut self) -> Result<usize, ReplayError> {
        let mut chunk = [0u8; 4096];
        let n = self.stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(ReplayError::ConnectionClosed);
        }
        Ok(n)
    }

    async fn startup(&mut self) -> Result<(), ReplayError> {
        let mut params = Vec::new();
        params.push((
            "application_name".to_string(),
            self.config.application_name.clone(),
        ));
        params.push(("user".to_string(), self.config.user.clone()));
        params.push(("database".to_string(), self.config.dbname.clone()));
        self.send_packet(&encode_startup(&params)).await?;
        Ok(())
    }

    async fn handle_auth(&mut self, auth: Authentication) -> Result<(), ReplayError> {
        match auth {
            Authentication::Ok => {}
            Authentication::Cleartext => {
                let pass = self
                    .config
                    .password
                    .as_ref()
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .unwrap_or_default();
                self.send_packet(&encode_password(&pass)).await?;
            }
            Authentication::Md5 { salt } => {
                let user = self.config.user.as_ref();
                let pass = self
                    .config
                    .password
                    .as_ref()
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .unwrap_or_default();
                let hashed = hash_md5_password(&user, &pass, &salt);
                self.send_packet(&encode_password(&hashed)).await?;
            }
            Authentication::Unsupported(code) => {
                return Err(ReplayError::UnsupportedAuth(code));
            }
        }
        Ok(())
    }

    pub async fn send_packet(&mut self, bytes: &[u8]) -> Result<(), std::io::Error> {
        self.stream.write_all(bytes).await
    }
}

pub enum ReplayError {
    ConnectionClosed,
    UnsupportedAuth(i32),
    ErrorResponse(String),
    IoError(std::io::Error),
}

impl fmt::Display for ReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReplayError::ConnectionClosed => write!(f, "connection closed"),
            ReplayError::UnsupportedAuth(code) => write!(f, "unsupperted auth method: {code}"),
            ReplayError::ErrorResponse(s) => write!(f, "server responded with error: {s}"),
            ReplayError::IoError(err) => write!(f, "I/O error: {err}"),
        }
    }
}

impl From<std::io::Error> for ReplayError {
    fn from(err: std::io::Error) -> Self {
        ReplayError::IoError(err)
    }
}

pub enum BackendMessage {
    Authentication(Authentication),
    ParameterStatus { _name: String, _value: String },
    BackendKeyData { _pid: i32, _secret: i32 },
    ReadyForQuery,
    ErrorResponse(String),
    NoticeResponse,
    Other { _tag: u8, _frame: BytesMut },
}

pub enum Authentication {
    Ok,
    Cleartext,
    Md5 { salt: [u8; 4] },
    Unsupported(i32),
}

fn read_cstr(buf: &mut BytesMut) -> String {
    let pos = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let s = String::from_utf8_lossy(&buf[..pos]).into_owned();
    if pos < buf.len() {
        buf.advance(pos + 1);
    } else {
        buf.advance(pos);
    }
    s
}

fn try_parse(src: &mut BytesMut) -> Option<BackendMessage> {
    if src.len() < 5 {
        return None;
    }
    let msg_type = src[0];
    let len = u32::from_be_bytes([src[1], src[2], src[3], src[4]]) as usize;
    if src.len() < 1 + len {
        return None;
    }

    let mut frame = src.split_to(1 + len);
    frame.advance(5);

    Some(match msg_type {
        b'R' => {
            let code = frame.get_i32();
            match code {
                0 => BackendMessage::Authentication(Authentication::Ok),
                3 => BackendMessage::Authentication(Authentication::Cleartext),
                5 => {
                    let mut salt = [0u8; 4];
                    frame.copy_to_slice(&mut salt);
                    BackendMessage::Authentication(Authentication::Md5 { salt })
                }
                other => BackendMessage::Authentication(Authentication::Unsupported(other)),
            }
        }
        b'S' => {
            let name = read_cstr(&mut frame);
            let value = read_cstr(&mut frame);
            BackendMessage::ParameterStatus { _name: name, _value: value }
        }
        b'K' => {
            let pid = frame.get_i32();
            let secret = frame.get_i32();
            BackendMessage::BackendKeyData { _pid: pid, _secret: secret }
        }
        b'Z' => BackendMessage::ReadyForQuery,
        b'E' => BackendMessage::ErrorResponse(read_cstr(&mut frame)),
        b'N' => BackendMessage::NoticeResponse,
        other => BackendMessage::Other { _tag: other, _frame: frame },
    })
}

fn encode_startup(params: &[(String, String)]) -> Vec<u8> {
    let mut body = BytesMut::new();
    body.put_i32(196608); // protocol 3.0
    for (k, v) in params {
        body.put_slice(k.as_bytes());
        body.put_u8(0);
        body.put_slice(v.as_bytes());
        body.put_u8(0);
    }
    body.put_u8(0);

    let mut out = BytesMut::new();
    out.put_i32(4 + body.len() as i32);
    out.put_slice(&body);
    out.to_vec()
}

fn encode_password(pass: &str) -> Vec<u8> {
    let mut out = BytesMut::new();
    out.put_u8(b'p');
    out.put_i32(4 + pass.len() as i32 + 1);
    out.put_slice(pass.as_bytes());
    out.put_u8(0);
    out.to_vec()
}

fn hash_md5_password(user: &str, pass: &str, salt: &[u8; 4]) -> String {
    let inner = format!("{:x}", md5::compute(format!("{pass}{user}")));
    let mut buf = inner.into_bytes();
    buf.extend_from_slice(salt);
    format!("md5{:x}", md5::compute(&buf))
}
