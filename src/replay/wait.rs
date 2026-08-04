use std::time::{Duration, Instant};

use crate::utils::timerfd::Delay;

#[derive(Clone)]
pub struct WaitInfo {
    start: Instant,
    pcap_ts: u64,
}

impl WaitInfo {
    pub fn start(pcap_ts: u64) -> Self {
        Self {
            start: Instant::now(),
            pcap_ts,
        }
    }

    pub fn time_to(&self, target: u64) -> i64 {
        let target_delta_us = target.saturating_sub(self.pcap_ts) as i64;
        let elapsed_us = self.start.elapsed().as_micros() as i64;
        target_delta_us - elapsed_us
    }

    pub async fn until(&mut self, target: u64) -> Result<(), std::io::Error> {
        let target_delta_us = target.saturating_sub(self.pcap_ts);
        let deadline = self.start + Duration::from_micros(target_delta_us);
        if Instant::now() >= deadline {
            return Ok(());
        }
        Delay::new(deadline)?.await
    }
}
