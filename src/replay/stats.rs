use std::sync::atomic::{AtomicU64, Ordering};


pub struct ReplayStats {
    total_requests: AtomicU64,
    pps: AtomicU64
}

impl ReplayStats {
    pub fn new() -> Self {
        Self {total_requests: AtomicU64::new(0), pps: AtomicU64::new(0)}
    }

    pub fn count_packet(&self) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.pps.fetch_add(1, Ordering::Relaxed);
    }

    pub fn read_pps(&self) -> u64 {
        return self.pps.swap(0, Ordering::Relaxed);
    }
}