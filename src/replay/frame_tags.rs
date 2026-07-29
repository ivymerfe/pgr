pub fn should_replay_frame(tag: u8) -> bool {
    matches!(tag, b'Q' | b'P' | b'B' | b'D' | b'E' | b'F' | b'S' | b'X')
}
