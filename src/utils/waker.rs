use std::{io, os::fd::RawFd};

pub struct Waker {
    fd: RawFd,
}

impl Waker {
    pub fn new() -> io::Result<Self> {
        let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd })
    }

    pub fn fd(&self) -> RawFd {
        self.fd
    }

    pub fn dup(&self) -> io::Result<Waker> {
        let fd = unsafe { libc::dup(self.fd) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd })
    }

    pub fn wake(&self) -> io::Result<()> {
        let val: u64 = 1;
        let ret = unsafe {
            libc::write(
                self.fd,
                &val as *const u64 as *const libc::c_void,
                std::mem::size_of::<u64>(),
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for Waker {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}
