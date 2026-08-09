use std::sync::atomic::{AtomicU64, Ordering};

pub struct ReplayStats {
    total_req: AtomicU64,
    delta_req: AtomicU64,
    delta_recv: AtomicU64,
}

impl ReplayStats {
    pub fn new() -> Self {
        Self {
            total_req: AtomicU64::new(0),
            delta_req: AtomicU64::new(0),
            delta_recv: AtomicU64::new(0),
        }
    }

    pub fn log_send(&self) {
        self.total_req.fetch_add(1, Ordering::Relaxed);
        self.delta_req.fetch_add(1, Ordering::Relaxed);
    }

    pub fn log_recv(&self) {
        self.delta_recv.fetch_add(1, Ordering::Relaxed);
    }

    pub fn read_total_sent(&self) -> u64 {
        return self.total_req.load(Ordering::Relaxed);
    }

    pub fn read_delta_sent(&self) -> u64 {
        return self.delta_req.swap(0, Ordering::Relaxed);
    }

    pub fn read_delta_recv(&self) -> u64 {
        return self.delta_recv.swap(0, Ordering::Relaxed);
    }
}
