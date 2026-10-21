use clap::{Parser, Subcommand};

use std::env;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Instant;

use time::{UtcOffset, macros::format_description};
use tracing::{error, info};
use tracing_subscriber::fmt::time::OffsetTime;

use anyhow::anyhow;

use crate::capture_desc::CaptureDesc;
use crate::pcap::reader::PcapReader;
use crate::pr::reader::{PgrReader, sync_lsn};
use crate::replay::client::ReplayConfig;
use crate::replay::manager::ReplayManager;
use crate::replay::source::CommandSource;
use crate::trace::reader::TraceReader;
use crate::trace::writer::StorageWriter;
use crate::utils::files;

mod capture_desc;
mod compare;
mod dump;
mod pcap;
mod pr;
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
        #[arg(help = "Capture: path[:port][+duration]")]
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
            let reader = open_capture(&input)?;
            info!("Replaying {input} -> {host}:{port} dbname={dbname} user={user}");
            let config = ReplayConfig::new(host, port, dbname, user, pass);
            let mut mgr = ReplayManager::new();
            mgr.replay(config, reader)?;
        }
        Commands::Dump { input, output } => {
            let reader = open_capture(&input)?;
            let output_file = files::try_create(&output, "csv")?;
            info!("Dumping {input} -> {}", output.display());
            dump::dump(reader, output_file)?;
        }
        Commands::Compare { src, replay, delta } => {
            let src_reader = open_capture(&src)?;
            let replay_reader = open_capture(&replay)?;
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
            let lsn = sync_lsn(File::open(&input)?)?;
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
            let capture_reader = open_capture(&capture)?;
            let trace_reader = TraceReader::new(File::open(&trace)?);
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

pub fn open_capture(desc: &CaptureDesc) -> anyhow::Result<Box<dyn CommandSource>> {
    let path = &desc.path;
    if !path.exists() {
        return Err(anyhow!("Capture file does not exist: {}", path.display()));
    }
    let ext = match path.extension() {
        Some(ext) => ext,
        None => {
            let abs_path = std::path::absolute(path)?;
            return Err(anyhow!(
                "Capture file has no extension: {}",
                abs_path.display()
            ));
        }
    };
    if ext == "pcap" || ext == "pcapng" {
        let file = files::try_open(path)?;
        let reader = PcapReader::new(file, desc.port, desc.max_duration)?;
        Ok(Box::new(reader))
    } else if ext == "pr" {
        let file = files::try_open(path)?;
        let reader = PgrReader::new(BufReader::new(file), desc.max_duration)?;
        Ok(Box::new(reader))
    } else {
        let abs_path = std::path::absolute(path)?;
        Err(anyhow!("Unknown file type: {}", abs_path.display()))
    }
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

fn parse_absolute(s: &str) -> Result<PathBuf, String> {
    std::path::absolute(s).map_err(|e| e.to_string())
}

fn default_username() -> String {
    env::var("USER")
        .or_else(|_| env::var("LOGNAME"))
        .unwrap_or_else(|_| String::from("postgres"))
}
