use std::time::Duration;

use quanta::{Clock, Instant};

use crate::utils::timerfd::Timer;

#[derive(Clone)]
pub struct Pacer {
    clock: Clock,
    start: Instant,
    origin: u64,
}

impl Pacer {
    pub fn start(origin: u64) -> Self {
        let clock = Clock::new();
        let start = clock.now();
        Self {
            clock,
            start,
            origin,
        }
    }

    pub fn time_to(&self, target: u64) -> i64 {
        let target_delta_us = (target.saturating_sub(self.origin)) as i64;
        let elapsed_us = self.clock.now().duration_since(self.start).as_micros() as i64;
        target_delta_us - elapsed_us
    }

    pub async fn until(&self, target: u64, timer: &mut Timer) -> Result<(), std::io::Error> {
        let delta = self.start.elapsed();
        let target_delta = Duration::from_micros(target.saturating_sub(self.origin));
        if delta >= target_delta {
            return Ok(());
        }
        timer.sleep_for(target_delta - delta).await?;
        Ok(())
    }
}
