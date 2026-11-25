use anyhow::Context;
use clap::{Parser, Subcommand};

use std::env;
use std::fs::File;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Instant;

use time::{UtcOffset, macros::format_description};
use tracing::{error, info};
use tracing_subscriber::fmt::time::OffsetTime;

use crate::analyzer::StorageWriter;
use crate::client::ReplayConfig;
use crate::readers::capture::CaptureReader;
use crate::readers::session::SessionReader;
use crate::readers::timings::TimingReader;
use crate::readers::trace::TraceReader;

mod analyzer;
mod client;
mod compare;
mod dump;
mod manager;
mod proto;
mod readers;
mod utils;
mod viewer;
mod worker;

#[derive(Parser)]
#[command(author, version, about, long_about = None, arg_required_else_help = true, disable_help_flag = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Replay a capture against another database")]
    Replay {
        #[arg(value_parser = parse_absolute, help = "Capture")]
        input: PathBuf,

        #[arg(short, long, default_value = "127.0.0.1", help = "Target server host")]
        host: IpAddr,

        #[arg(short, long, default_value_t = 5432, help = "Target server port")]
        port: u16,

        #[arg(short, long, default_value = "postgres", help = "Database name")]
        dbname: String,

        #[arg(short, long, default_value_t = default_username(), help = "Database user")]
        user: String,

        #[arg(short = 'P', long, help = "Password")]
        pass: Option<String>,

        #[arg(
            short,
            long,
            default_value_t = 1.0,
            help = "Playback speed multiplier; shrinks client think time (2.0 = twice as fast)"
        )]
        speed: f64,

        #[arg(
            short,
            long,
            default_value_t = 3.0,
            help = "Network latency in ms subtracted from client think time"
        )]
        latency: f64,

        #[arg(short, long, default_value_t = 4, help = "Worker threads")]
        threads: usize,
    },
    #[command(about = "Dump a capture, trace, timing or session file to text")]
    Dump {
        #[arg(help = "Input file (.pr, .ptr, .ptm, .pgs)")]
        input: PathBuf,

        #[arg(short, long, value_parser = parse_absolute, help = "Output path")]
        output: Option<PathBuf>,
    },
    #[command(about = "Compare capture timings with replay timings")]
    Compare {
        #[arg(short, long, value_parser = parse_absolute, help = "Source capture")]
        capture: PathBuf,

        #[arg(short, long, value_parser = parse_absolute, help = "Replay timing file")]
        timing: PathBuf,
    },
    #[command(about = "Print WAL sync point of a capture")]
    Lsn {
        #[arg(value_parser = parse_absolute, help = "Capture file")]
        input: PathBuf,
    },
    #[command(about = "Print start timestamp of a capture")]
    Ts {
        #[arg(value_parser = parse_absolute, help = "Capture file")]
        input: PathBuf,
    },
    #[command(about = "Analyze trace")]
    Analyze {
        #[arg(short, long, help = "Capture file")]
        capture: PathBuf,

        #[arg(short, long, value_parser = parse_absolute, help = "Path to trace file or directory with trace files")]
        trace: PathBuf,

        #[arg(short, long, value_parser = parse_absolute, default_value = "analysis", help = "Output folder")]
        output: PathBuf,

        #[arg(long = "chunk", default_value_t = 0.05, help = "Seconds in one chunk")]
        chunk_secs: f32,

        #[arg(short, long, default_value = "127.0.0.1", help = "Viewer server addr")]
        addr: IpAddr,

        #[arg(short, long, default_value_t = 3232, help = "Viewer server port")]
        port: u16,
    },
    #[command(about = "View analysis")]
    View {
        #[arg(value_parser = parse_absolute, default_value = "analysis", help = "Path to analysis folder")]
        folder: PathBuf,

        #[arg(short, long, default_value = "127.0.0.1", help = "Viewer server addr")]
        addr: IpAddr,

        #[arg(short, long, default_value_t = 3232, help = "Viewer server port")]
        port: u16,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let local_offset = UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC);

    let format = format_description!("[hour]:[minute]:[second]");
    let timer = OffsetTime::new(local_offset, format);
    tracing_subscriber::fmt()
        .with_timer(timer)
        .with_target(false)
        .init();

    match run_command(cli) {
        Ok(()) => (),
        Err(e) => {
            error!("{}", e);
        }
    }

    Ok(())
}

fn run_command(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Commands::Replay {
            input,
            host,
            port,
            dbname,
            user,
            pass,
            speed,
            latency,
            threads,
        } => {
            let file = try_open(&input)?;
            let reader = CaptureReader::new(file)?;
            info!(
                "Replaying {} -> {host}:{port} dbname={dbname} user={user}",
                input.display()
            );
            let config = ReplayConfig {
                server: SocketAddr::new(host, port),
                user,
                password: pass,
                dbname,
                speed,
                latency,
                threads: threads.max(1),
            };
            manager::replay(config, reader)?;
        }
        Commands::Dump { input, output } => {
            let output = output.unwrap_or_else(|| {
                let mut name = input.file_name().unwrap_or_default().to_os_string();
                name.push(".csv");
                PathBuf::from(name)
            });
            let ext = input.extension().and_then(|e| e.to_str()).unwrap_or("");
            let file = try_open(&input)?;
            match ext {
                "pr" => {
                    let reader = CaptureReader::new(file)?;
                    let out = try_create(&output, "csv")?;
                    info!("Dumping {} -> {}", input.display(), output.display());
                    dump::dump_capture(reader, out)?;
                }
                "ptr" => {
                    let reader = TraceReader::new(file)?;
                    let out = try_create(&output, "csv")?;
                    info!("Dumping {} -> {}", input.display(), output.display());
                    dump::dump_trace(reader, out)?;
                }
                "ptm" => {
                    let reader = TimingReader::new(file)?;
                    let out = try_create(&output, "csv")?;
                    info!("Dumping {} -> {}", input.display(), output.display());
                    dump::dump_timings(reader, out)?;
                }
                "pgs" => {
                    let reader = SessionReader::new(file)?;
                    let out = try_create(&output, "txt")?;
                    info!("Dumping {} -> {}", input.display(), output.display());
                    dump::dump_session(reader, out)?;
                }
                _ => anyhow::bail!("Unknown file extension: '{}'", ext),
            }
            info!("Done");
        }
        Commands::Compare { capture, timing } => {
            let capture_reader = CaptureReader::new(try_open(&capture)?)?;
            let timing_reader = TimingReader::new(try_open(&timing)?)?;
            info!("Comparing {} <-> {}", capture.display(), timing.display());
            let start = Instant::now();
            compare::compare(capture_reader, timing_reader)?;
            info!("Done in {} ms", start.elapsed().as_millis());
        }
        Commands::Lsn { input } => {
            let file = try_open(&input)?;
            let reader = CaptureReader::new(file)?;
            print!("{:X}/{:08X}", reader.lsn >> 32, reader.lsn as u32);
        }
        Commands::Ts { input } => {
            let file = try_open(&input)?;
            let reader = CaptureReader::new(file)?;
            print!("{}", reader.start_ts)
        }
        Commands::Analyze {
            capture,
            trace,
            output,
            chunk_secs,
            addr,
            port,
        } => {
            let capture_file = try_open(&capture)?;
            let capture_reader = CaptureReader::new(capture_file)?;
            let trace_reader = TraceReader::new(File::open(&trace)?)?;
            let storage = StorageWriter::new(&output, chunk_secs)?;
            info!("Capture: {}", capture.display());
            info!("Trace: {}", trace.display());
            info!("Output dir: {}", output.display());
            let start = Instant::now();
            analyzer::analyze(capture_reader, trace_reader, storage)?;
            info!("Done in {:.3} ms", start.elapsed().as_millis());
            start_server(&output, addr, port)?;
        }
        Commands::View { folder, addr, port } => {
            start_server(&folder, addr, port)?;
        }
    }
    Ok(())
}

fn start_server(folder: &PathBuf, addr: IpAddr, port: u16) -> anyhow::Result<()> {
    info!("Serve: {}", folder.display());
    info!("At: http://{}:{}", addr, port);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(viewer::serve(folder, SocketAddr::new(addr, port)))?;
    Ok(())
}

fn parse_absolute(s: &str) -> Result<PathBuf, String> {
    std::path::absolute(s).map_err(|e| e.to_string())
}

fn default_username() -> String {
    env::var("USER")
        .or_else(|_| env::var("LOGNAME"))
        .unwrap_or_else(|_| String::from("postgres"))
}

pub fn try_open(path: &PathBuf) -> anyhow::Result<std::fs::File> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("Failed to open file: '{}'", path.display(),))?;
    Ok(file)
}

pub fn try_create(path: &PathBuf, ext: &str) -> anyhow::Result<std::fs::File> {
    let path = if path.extension().is_none() {
        &path.with_extension(ext)
    } else {
        path
    };
    let file = std::fs::File::create(&path)
        .with_context(|| format!("Failed to create file: '{}'", path.display(),))?;
    Ok(file)
}
