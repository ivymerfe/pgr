pub const F_PROTO_VERSION: u32 = 196608;
pub const F_PASSWORD_MESSAGE: u8 = b'p';

pub const F_PARSE: u8 = b'P';
pub const F_BIND: u8 = b'B';
pub const F_DESCRIBE: u8 = b'D';
pub const F_EXECUTE: u8 = b'E';
pub const F_CLOSE: u8 = b'C';
pub const F_SYNC: u8 = b'S';
pub const F_QUERY: u8 = b'Q';

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
