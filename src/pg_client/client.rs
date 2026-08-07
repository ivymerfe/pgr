use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use crate::pg_client::error::PgClientError;
use crate::pg_client::proto::{self, Authentication, BackendFrame, BackendMessage};

#[derive(Clone, Default)]
pub struct PgClientConfig {
    pub user: String,
    pub password: Option<Vec<u8>>,
    pub dbname: String,
    pub application_name: String,
}

pub struct PgClientReader {
    read_half: OwnedReadHalf,
    read_buf: Vec<u8>,
    parsed: usize,
}

impl PgClientReader {
    pub async fn next_frame(&mut self) -> Result<BackendFrame<'_>, PgClientError> {
        loop {
            if self.parsed > 0 {
                self.read_buf.drain(..self.parsed);
                self.parsed = 0;
            }
            if let Some((tag, frame_len)) = proto::try_read_frame(&self.read_buf) {
                self.parsed = frame_len;
                return Ok(BackendFrame {
                    tag,
                    data: &self.read_buf[5..frame_len],
                });
            }

            let mut chunk = [0u8; 4096];
            let n = self.read_half.read(&mut chunk).await?;
            if n == 0 {
                return Err(PgClientError::ConnectionClosed);
            }
            self.read_buf.extend_from_slice(&chunk[..n]);
        }
    }

    pub async fn next_message(&mut self) -> Result<BackendMessage<'_>, PgClientError> {
        let frame = self.next_frame().await?;
        proto::parse_message(frame.tag, frame.data)
    }
}

pub struct PgClientWriter {
    write_half: BufWriter<OwnedWriteHalf>,
}

impl PgClientWriter {
    pub async fn send(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.write_half.write_all(bytes).await
    }

    pub async fn flush(&mut self) -> std::io::Result<()> {
        self.write_half.flush().await
    }
}

pub struct PgClient {
    pub reader: PgClientReader,
    pub writer: PgClientWriter,
    pub config: PgClientConfig,
    pub addr: SocketAddr,
}

impl PgClient {
    pub async fn connect(
        addr: SocketAddr,
        config: PgClientConfig,
    ) -> Result<PgClient, PgClientError> {
        let stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;
        let local_addr = stream.local_addr()?;

        let (read_half, write_half) = stream.into_split();
        let mut client = PgClient {
            reader: PgClientReader {
                read_half,
                read_buf: Vec::with_capacity(65536),
                parsed: 0,
            },
            writer: PgClientWriter {
                write_half: BufWriter::with_capacity(65536, write_half),
            },
            addr: local_addr,
            config,
        };
        client.startup().await?;

        loop {
            let msg = client.reader.next_message().await?;
            match msg {
                BackendMessage::Authentication(auth) => client.handle_auth(auth).await?,
                BackendMessage::ParameterStatus { .. } => {}
                BackendMessage::BackendKeyData { .. } => {}
                BackendMessage::ReadyForQuery => break,
                BackendMessage::ErrorResponse(e) => return Err(PgClientError::ErrorResponse(e)),
                BackendMessage::NoticeResponse | BackendMessage::Other { .. } => {}
            }
        }
        Ok(client)
    }

    pub fn split(self) -> (PgClientReader, PgClientWriter) {
        (self.reader, self.writer)
    }

    async fn startup(&mut self) -> Result<(), PgClientError> {
        let mut params = Vec::new();
        params.push((
            "application_name".to_string(),
            self.config.application_name.clone(),
        ));
        params.push(("user".to_string(), self.config.user.clone()));
        params.push(("database".to_string(), self.config.dbname.clone()));
        self.writer.send(&proto::encode_startup(&params)).await?;
        self.writer.flush().await?;
        Ok(())
    }

    async fn handle_auth(&mut self, auth: Authentication) -> Result<(), PgClientError> {
        match auth {
            Authentication::Ok => {}
            Authentication::Cleartext => {
                let pass = self
                    .config
                    .password
                    .as_ref()
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .unwrap_or_default();
                self.writer.send(&proto::encode_password(&pass)).await?;
            }
            Authentication::Md5 { salt } => {
                let user = self.config.user.as_ref();
                let pass = self
                    .config
                    .password
                    .as_ref()
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .unwrap_or_default();
                let hashed = proto::hash_md5_password(user, &pass, &salt);
                self.writer.send(&proto::encode_password(&hashed)).await?;
            }
            Authentication::Unsupported(code) => {
                return Err(PgClientError::UnsupportedAuth(code));
            }
        }
        Ok(())
    }
}
