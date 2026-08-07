use std::io::{Error, Result};
use std::os::fd::{AsRawFd, RawFd};
use std::time::Duration;

use rustix::time::{Itimerspec, TimerfdClockId, TimerfdFlags, TimerfdTimerFlags, Timespec};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

fn to_timespec(d: Duration) -> Timespec {
    Timespec {
        tv_sec: d.as_secs().try_into().unwrap(),
        tv_nsec: d.subsec_nanos() as _,
    }
}

fn read_u64(fd: RawFd) -> Result<u64> {
    let mut buf = [0u8; 8];
    loop {
        let rv = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, 8) };
        if rv >= 0 {
            return Ok(u64::from_ne_bytes(buf));
        }
        let err = Error::last_os_error();
        if err.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return Err(err);
    }
}

pub struct Timer {
    fd: AsyncFd<rustix::fd::OwnedFd>,
}

impl Timer {
    pub fn new() -> Result<Self> {
        let fd = rustix::time::timerfd_create(
            TimerfdClockId::Monotonic,
            TimerfdFlags::NONBLOCK | TimerfdFlags::CLOEXEC,
        )?;
        let fd = AsyncFd::with_interest(fd, Interest::READABLE)?;
        Ok(Self { fd })
    }

    pub async fn sleep_for(&mut self, duration: Duration) -> Result<()> {
        if duration.is_zero() {
            return Ok(());
        }
        let spec = Itimerspec {
            it_value: to_timespec(duration),
            it_interval: Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
        };

        rustix::time::timerfd_settime(self.fd.get_ref(), TimerfdTimerFlags::empty(), &spec)?;

        loop {
            let mut guard = self.fd.readable().await?;
            match guard.try_io(|inner| read_u64(inner.as_raw_fd())) {
                Ok(res) => {
                    res?;
                    return Ok(());
                }
                Err(_would_block) => continue,
            }
        }
    }
}
