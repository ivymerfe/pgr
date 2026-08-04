use std::future::Future;
use std::io::{Error, Result};
use std::os::fd::{AsRawFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant};

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

pub struct Delay {
    fd: AsyncFd<rustix::fd::OwnedFd>,
    deadline: Instant,
    initialized: bool,
}

impl Delay {
    pub fn new(deadline: Instant) -> Result<Self> {
        let fd = rustix::time::timerfd_create(
            TimerfdClockId::Monotonic,
            TimerfdFlags::NONBLOCK | TimerfdFlags::CLOEXEC,
        )?;
        let fd = AsyncFd::with_interest(fd, Interest::READABLE)?;
        Ok(Delay {
            fd,
            deadline,
            initialized: false,
        })
    }
}

impl Future for Delay {
    type Output = Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.initialized {
            let now = Instant::now();
            let duration = if self.deadline > now {
                self.deadline - now
            } else {
                return Poll::Ready(Ok(()));
            };
            let spec = Itimerspec {
                it_value: to_timespec(duration),
                it_interval: Timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
            };
            rustix::time::timerfd_settime(self.fd.get_ref(), TimerfdTimerFlags::empty(), &spec)?;
            self.initialized = true;
        }

        loop {
            let mut guard = ready!(self.fd.poll_read_ready(cx))?;
            let fd = self.fd.as_raw_fd();
            match guard.try_io(|_| read_u64(fd)) {
                Ok(res) => {
                    res?;
                    return Poll::Ready(Ok(()));
                }
                Err(_would_block) => continue,
            }
        }
    }
}
