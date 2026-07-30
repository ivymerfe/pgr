use std::time::Duration;
use tokio::time::{Instant, sleep};
use tracing::warn;

#[derive(Clone, Debug)]
pub struct WaitInfo {
    start: Instant,
    pcap_ts: Option<u64>,
}

impl WaitInfo {
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
            pcap_ts: None,
        }
    }

    pub fn pcap_ts(&mut self, ts: u64) {
        if self.pcap_ts.is_none() {
            self.pcap_ts = Some(ts);
        }
    }

    pub async fn until(&self, target: u64) {
        let Some(file_start) = self.pcap_ts else {
            return;
        };
        let target_delta_us = target.saturating_sub(file_start);
        let elapsed_us = self.start.elapsed().as_micros() as u64;

        if target_delta_us > elapsed_us {
            let wait_us = target_delta_us - elapsed_us;

            sleep(Duration::from_micros(wait_us)).await;
        } else if elapsed_us - target_delta_us > 3000 {
            warn!(
                "Falling behind schedule by {}us",
                elapsed_us - target_delta_us
            );
        }
    }
}
