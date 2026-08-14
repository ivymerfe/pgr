pub fn read_u32(b: &[u8]) -> u32 {
    return u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
}

pub fn read_i32(b: &[u8]) -> i32 {
    return i32::from_be_bytes([b[0], b[1], b[2], b[3]]);
}

pub fn read_u16(b: &[u8]) -> u16 {
    return u16::from_be_bytes([b[0], b[1]]);
}

pub fn read_i16(b: &[u8]) -> i16 {
    return i16::from_be_bytes([b[0], b[1]]);
}

pub fn read_c_string(buf: &[u8]) -> Result<(&str, usize), &'static str> {
    let null_pos = buf
        .iter()
        .position(|&b| b == 0)
        .ok_or("Missing null terminator")?;
    let s = std::str::from_utf8(&buf[..null_pos]).map_err(|_| "Invalid UTF-8 in C string")?;
    Ok((s, null_pos + 1))
}
