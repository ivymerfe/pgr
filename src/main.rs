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
use crate::capture::CaptureReader;
use crate::client::ReplayConfig;
use crate::manager::ReplayManager;
use crate::trace_reader::TraceReader;

mod analyzer;
mod capture;
mod capture_dump;
mod client;
mod r#loop;
mod manager;
mod proto;
mod trace_reader;
mod utils;
mod viewer;

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
    },
    #[command(about = "Dump a capture to CSV")]
    Dump {
        #[arg(help = "Capture")]
        input: PathBuf,

        #[arg(short, long, default_value = "capture.csv", value_parser = parse_absolute, help = "Output CSV path")]
        output: PathBuf,
    },
    #[command(about = "Compare two captures")]
    Compare {
        #[arg(short, long, value_parser = parse_absolute, help = "Source capture")]
        src: PathBuf,

        #[arg(short, long, value_parser = parse_absolute, help = "Replay capture")]
        replay: PathBuf,

        #[arg(long, help = "File to save differences to")]
        delta: Option<PathBuf>,
    },
    #[command(about = "Print WAL sync point of an extension capture")]
    Lsn {
        #[arg(value_parser = parse_absolute, help = "Extension capture file or directory")]
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
        } => {
            let file = try_open(&input)?;
            let reader = CaptureReader::new(file)?;
            info!(
                "Replaying {} -> {host}:{port} dbname={dbname} user={user}",
                input.display()
            );
            let config = ReplayConfig::new(host, port, dbname, user, pass);
            let mut mgr = ReplayManager::new();
            mgr.replay(config, reader)?;
        }
        Commands::Dump { input, output } => {
            let file = try_open(&input)?;
            let reader = CaptureReader::new(file)?;
            let output_file = try_create(&output, "csv")?;
            info!("Dumping {} -> {}", input.display(), output.display());
            capture_dump::dump(reader, output_file)?;
            info!("Done");
        }
        Commands::Compare { src, replay, delta } => {
            let src_file = try_open(&src)?;
            let replay_file = try_open(&replay)?;
            let src_reader = CaptureReader::new(src_file)?;
            let replay_reader = CaptureReader::new(replay_file)?;
            info!("Comparing {} <-> {}", src.display(), replay.display());
        }
        Commands::Lsn { input } => {
            let file = try_open(&input)?;
            let reader = CaptureReader::new(file)?;
            info!("LSN: {:X}/{:08X}", reader.lsn >> 32, reader.lsn as u32);
            info!("TS: {}", reader.start_ts)
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
            let trace_reader = TraceReader::new(File::open(&trace)?);
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
