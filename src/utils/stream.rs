pub struct Stream {
    data: Vec<u8>,
    compact_threshold: usize,
    data_offset: usize,
    read_offset: usize,
    committed_offset: usize,
}

impl Stream {
    pub fn new(compact_threshold: usize) -> Self {
        Self {
            data: Vec::with_capacity(compact_threshold),
            compact_threshold,
            data_offset: 0,
            read_offset: 0,
            committed_offset: 0,
        }
    }

    pub fn mark_read(&mut self, n: usize) {
        self.read_offset = (self.read_offset + n).min(self.data_offset + self.data.len());
        self.compact();
    }

    pub fn mark_read_all(&mut self) {
        self.read_offset = self.committed_offset;
        self.compact();
    }

    pub fn data(&self) -> &[u8] {
        &self.data[self.read_offset - self.data_offset..self.committed_offset - self.data_offset]
    }

    pub fn write(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
        self.committed_offset = self.data_offset + self.data.len();
    }

    // pub fn write_no_commit(&mut self, bytes: &[u8]) {
    //     self.data.extend_from_slice(bytes);
    // }

    // pub fn commit(&mut self, len: usize) {
    //     self.committed_offset =
    //         (self.committed_offset + len).min(self.data_offset + self.data.len());
    // }

    fn compact(&mut self) {
        let garbage_size = self.read_offset - self.data_offset;
        if garbage_size > self.compact_threshold {
            let remaining = self.data.len() - garbage_size;
            self.data.copy_within(garbage_size.., 0);
            self.data.truncate(remaining);
            self.data_offset = self.read_offset;
        }
    }
}
