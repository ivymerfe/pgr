use std::path::PathBuf;

pub struct ReplayState {
    host: String,
    port: u16,
    user: String,
    pass: Option<String>,
}

impl ReplayState {
    pub fn new(host: String, port: u16, user: String, pass: Option<String>) -> Self {
        Self {
            host,
            port,
            user,
            pass,
        }
    }

    pub fn replay(&mut self, input: PathBuf, cap_port: u16) {

    }
}
