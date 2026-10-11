use clap::{Parser, Subcommand};

use std::fs::File;
use std::io::BufWriter;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Instant;
use std::{env, fs};

use time::{UtcOffset, macros::format_description};
use tracing::{error, info};
use tracing_subscriber::fmt::time::OffsetTime;

use anyhow::{Context, anyhow, bail};

use crate::capture::pgr::sync_lsn;
use crate::capture::read_capture;
use crate::capture_desc::CaptureDesc;
use crate::replay::client::ReplayConfig;
use crate::replay::manager::ReplayManager;
use crate::trace::reader::TraceReader;
use crate::trace::writer::StorageWriter;
use crate::utils::files;

mod capture;
mod capture_desc;
mod compare;
mod dump;
mod proto;
mod replay;
mod trace;
mod utils;

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
        #[arg(help = "Capture: path[:port]@[offset][+duration]")]
        input: CaptureDesc,

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
        #[arg(help = "Capture: path[:port]@[offset][+duration]")]
        input: CaptureDesc,

        #[arg(short, long, default_value = "capture.csv", value_parser = parse_absolute, help = "Output CSV path")]
        output: PathBuf,
    },
    #[command(about = "Compare two captures")]
    Compare {
        #[arg(short, long, help = "Source capture: path[:port]@[offset][+duration]")]
        src: CaptureDesc,

        #[arg(short, long, help = "Replay capture: path[:port]@[offset][+duration]")]
        replay: CaptureDesc,

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
        capture: CaptureDesc,

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
            let reader = read_capture(&input)?;
            info!("Replaying {input} -> {host}:{port} dbname={dbname} user={user}");
            let config = ReplayConfig::new(host, port, dbname, user, pass);
            let mut mgr = ReplayManager::new();
            mgr.replay(config, reader)?;
        }
        Commands::Dump { input, output } => {
            let reader = read_capture(&input)?;
            let output_file = files::try_create(&output, "csv")?;
            info!("Dumping {input} -> {}", output.display());
            dump::dump(reader, output_file)?;
        }
        Commands::Compare { src, replay, delta } => {
            let src_reader = read_capture(&src)?;
            let replay_reader = read_capture(&replay)?;
            info!("Comparing {} <-> {}", src, replay);
            let mut delta_writer = None;
            if let Some(delta) = delta {
                let file = files::try_create(&delta, "csv")?;
                delta_writer = Some(BufWriter::new(file));
                info!("Deltas: {}", delta.display());
            }
            compare::compare(src_reader, replay_reader, delta_writer)?;
        }
        Commands::Lsn { input } => {
            let path = if input.is_dir() {
                latest_capture(&input)?
            } else {
                input
            };
            let lsn = sync_lsn(File::open(&path)?)?;
            info!("OK: {:X}/{:08X}", lsn >> 32, lsn as u32);
        }
        Commands::Analyze {
            capture,
            trace,
            output,
            chunk_secs,
            addr,
            port,
        } => {
            let capture_reader = read_capture(&capture)?;
            let trace_reader = TraceReader::new(find_trace(&trace)?);
            let storage = StorageWriter::new(&output, chunk_secs)?;
            info!("Capture: {capture}");
            info!("Trace: {}", trace.display());
            info!("Output dir: {}", output.display());
            let start = Instant::now();
            trace::analyzer::analyze(capture_reader, trace_reader, storage)?;
            info!("Done in {:.3} ms", start.elapsed().as_millis());
            start_server(&output, addr, port)?;
        }
        Commands::View { folder, addr, port } => {
            start_server(&folder, addr, port)?;
        }
    }
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

fn latest_capture(dir: &Path) -> anyhow::Result<PathBuf> {
    let mut best: Option<(u64, PathBuf)> = None;
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("pr") {
            continue;
        }
        let Some(ts) = path
            .file_stem()
            .and_then(|s| s.to_str())
            .and_then(|s| s.parse::<u64>().ok())
        else {
            continue;
        };
        if best.as_ref().map_or(true, |(b, _)| ts > *b) {
            best = Some((ts, path));
        }
    }
    best.map(|(_, p)| p)
        .ok_or_else(|| anyhow!("no .pr files in {}", dir.display()))
}

fn start_server(folder: &PathBuf, addr: IpAddr, port: u16) -> anyhow::Result<()> {
    info!("Serve: {}", folder.display());
    info!("At: http://{}:{}", addr, port);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(trace::viewer::serve(folder, SocketAddr::new(addr, port)))?;
    Ok(())
}

fn find_trace(path: &PathBuf) -> anyhow::Result<File> {
    if path.is_file() {
        let metadata = fs::metadata(path)
            .with_context(|| format!("Failed to read metadata: {}", path.display()))?;

        if metadata.len() == 0 {
            bail!("Trace file is empty: {}", path.display());
        }

        return File::open(path)
            .with_context(|| format!("Failed to open trace: {}", path.display()));
    }

    if path.is_dir() {
        let mut latest_file: Option<(PathBuf, std::time::SystemTime)> = None;

        for entry in
            fs::read_dir(path).with_context(|| format!("Failed to read dir: {}", path.display()))?
        {
            let entry = entry?;
            let entry_path = entry.path();

            if entry_path.is_file()
                && entry_path.extension().and_then(|ext| ext.to_str()) == Some("ptr")
            {
                let metadata = entry.metadata()?;
                if metadata.len() == 0 {
                    continue;
                }
                let modified = metadata
                    .modified()
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH);

                if latest_file
                    .as_ref()
                    .map_or(true, |(_, max_time)| modified > *max_time)
                {
                    latest_file = Some((entry_path, modified));
                }
            }
        }

        if let Some((latest_path, _)) = latest_file {
            info!("Found trace: {}", latest_path.display());
            return File::open(&latest_path)
                .with_context(|| format!("Failed to open trace: {}", latest_path.display()));
        } else {
            bail!("No non-empty .ptr files in {}", path.display());
        }
    }

    bail!("Does not exist: {}", path.display());
}
