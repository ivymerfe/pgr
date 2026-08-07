use std::path;
use std::str::FromStr;
use std::time::Duration;
use std::{fmt, path::PathBuf};

use anyhow::{Context, anyhow};

#[derive(Debug, Clone)]
pub struct CaptureDesc {
    pub path: PathBuf,
    pub port: u16,
    pub ts_offset: u64,
    pub max_duration: u64,
}

fn parse_micros(s: &str) -> anyhow::Result<u64> {
    let dur = humantime::parse_duration(s).context("invalid duration")?;
    Ok(dur.as_micros() as u64)
}

impl FromStr for CaptureDesc {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        let last_sep_idx = s.rfind(|c| c == '/' || c == '\\');
        let (prefix, mut rest) = match last_sep_idx {
            Some(idx) => (&s[..=idx], &s[idx + 1..]),
            None => ("", s),
        };
        let mut max_duration = u64::MAX;
        let mut ts_offset = 0u64;
        let mut port = 5432u16;

        if let Some((head, dur_str)) = rest.rsplit_once('+') {
            max_duration = parse_micros(dur_str)?;
            rest = head;
        }
        if let Some((head, offset_str)) = rest.rsplit_once('@') {
            ts_offset = parse_micros(offset_str)?;
            rest = head;
        }
        if let Some((head, port_str)) = rest.rsplit_once(':') {
            port = port_str.parse().context("invalid port")?;
            rest = head;
        }
        let full_path_str = format!("{prefix}{rest}");
        if full_path_str.is_empty() {
            return Err(anyhow!("empty path in capture descriptor"));
        }
        let path = path::absolute(PathBuf::from(full_path_str))?;

        Ok(CaptureDesc {
            path,
            port,
            ts_offset,
            max_duration,
        })
    }
}

impl fmt::Display for CaptureDesc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.path.display())?;
        if self.port != 5432 {
            write!(f, ":{}", self.port)?;
        }
        let has_offset = self.ts_offset != 0;
        let has_duration = self.max_duration != u64::MAX;
        if has_offset {
            write!(
                f,
                "(@{})",
                humantime::format_duration(Duration::from_micros(self.ts_offset))
            )?;
        }
        if has_duration {
            write!(
                f,
                "(+{})",
                humantime::format_duration(Duration::from_micros(self.max_duration))
            )?;
        }
        Ok(())
    }
}
