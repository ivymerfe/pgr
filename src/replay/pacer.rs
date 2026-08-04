use std::time::{Duration, Instant};

use crate::utils::timerfd::Delay;

#[derive(Clone)]
pub struct Pacer {
    start: Instant,
    origin: u64,
}

impl Pacer {
    pub fn start(origin: u64) -> Self {
        Self {
            start: Instant::now(),
            origin,
        }
    }

    pub fn time_to(&self, target: u64) -> i64 {
        let target_delta_us = (target.saturating_sub(self.origin)) as i64;
        let elapsed_us = self.start.elapsed().as_micros() as i64;
        target_delta_us - elapsed_us
    }

    pub async fn until(&self, target: u64) -> Result<(), std::io::Error> {
        let deadline = self.start + Duration::from_micros(target.saturating_sub(self.origin));
        if Instant::now() >= deadline {
            return Ok(());
        }
        Delay::new(deadline)?.await
    }
}
