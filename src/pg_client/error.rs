use core::fmt;

pub enum PgClientError {
    ConnectionClosed,
    UnsupportedAuth(i32),
    ErrorResponse(String),
    MalformedMessage,
    IoError(std::io::Error),
}

impl fmt::Display for PgClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PgClientError::ConnectionClosed => write!(f, "connection closed"),
            PgClientError::UnsupportedAuth(code) => write!(f, "unsupperted auth method: {code}"),
            PgClientError::ErrorResponse(s) => write!(f, "server responded with error: {s}"),
            PgClientError::MalformedMessage => write!(f, "malformed message"),
            PgClientError::IoError(err) => write!(f, "I/O error: {err}"),
        }
    }
}

impl From<std::io::Error> for PgClientError {
    fn from(err: std::io::Error) -> Self {
        PgClientError::IoError(err)
    }
}
