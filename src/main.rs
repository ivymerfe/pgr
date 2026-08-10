use anyhow::anyhow;
use bytesize::ByteSize;
use clap::{Parser, Subcommand};

use std::io::BufWriter;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;
use std::{env, fs};

use time::{UtcOffset, macros::format_description};
use tracing::{error, info};
use tracing_subscriber::fmt::time::OffsetTime;

use crate::capture::acap::AcapWriter;
use crate::capture::read_capture;
use crate::capture_desc::CaptureDesc;
use crate::compare::addr_map::AddrMapReader;
use crate::replay::addr_map::AddrMapWriter;
use crate::replay::client::ReplayConfig;
use crate::replay::latency::LatencyMap;
use crate::replay::manager::ReplayManager;
use crate::utils::files;

mod capture;
mod capture_desc;
mod compare;
mod dump;
mod parser;
mod proto;
mod replay;
mod utils;
mod zstd_test;

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

        #[arg(short,
            long,
            default_value = "replay.csv",
            value_parser = parse_absolute,
            help = "File to store address mapping (needed for compare)"
        )]
        addr_map: PathBuf,

        #[arg(short, long, value_parser = parse_absolute, help = "File to store latencies")]
        lat_map: Option<PathBuf>,

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

        #[arg(long, default_value_t = 2048, help = "io_uring ring size")]
        ring_size: u32,
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

        #[arg(
            short,
            long,
            default_value = "replay.csv",
            value_parser = parse_absolute,
            help = "Address mapping file produced by replay"
        )]
        addr_map: PathBuf,

        #[arg(long, help = "File to save differences to")]
        delta: Option<PathBuf>,
    },
    #[command(about = "Capture traffic")]
    Capture {
        #[arg(
            short,
            long,
            default_value = "zz_cap",
            value_parser = parse_absolute,
            help = "Folder to write the capture to"
        )]
        output: PathBuf,

        #[arg(short, long, default_value_t = false, help = "Force rewrite capture")]
        rewrite: bool,

        #[arg(short, long, default_value = "lo", help = "Network interface")]
        interface: String,

        #[arg(short, long, default_value_t = 5432, help = "Port to capture")]
        port: u16,

        #[arg(short, long, default_value = "1GiB", help = "Maximum chunk size")]
        max_chunk: ByteSize,

        #[arg(short, long, default_value_t = 3, help = "zstd compression level")]
        level: i32,

        #[arg(
            long,
            default_value_t = 4,
            help = "Number of compression worker threads"
        )]
        zw: u8,
    },
    #[command(about = "Compress a file with zstd")]
    Compress {
        #[arg(value_parser = parse_absolute, help = "Input file")]
        input: PathBuf,

        #[arg(short, long, value_parser = parse_absolute, help = "Output file")]
        output: PathBuf,

        #[arg(short, long, default_value_t = 3, help = "zstd compression level")]
        level: i32,

        #[arg(
            long,
            default_value_t = 4,
            help = "Number of compression worker threads"
        )]
        zw: u8,
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
            addr_map,
            lat_map,
            host,
            port,
            dbname,
            user,
            pass,
            ring_size,
        } => {
            let map_file = files::try_create(&addr_map, "csv")?;
            let reader = read_capture(&input)?;
            info!("Replaying {input} -> {host}:{port} dbname={dbname} user={user}");
            info!("Map: {}", addr_map.display());
            let map = AddrMapWriter::new(map_file);
            let lat_map = match lat_map {
                Some(lat_map_path) => {
                    Some(LatencyMap::new(files::try_create(&lat_map_path, "lat")?))
                }
                None => None,
            };
            let config = ReplayConfig::new(host, port, dbname, user, pass, ring_size);
            let mut mgr = ReplayManager::new();
            mgr.replay(config, reader, map, lat_map)?;
        }
        Commands::Dump { input, output } => {
            let reader = read_capture(&input)?;
            let output_file = files::try_create(&output, "csv")?;
            info!("Dumping {input} -> {}", output.display());
            dump::dump(reader, output_file)?;
        }
        Commands::Compare {
            src,
            replay,
            addr_map,
            delta,
        } => {
            let src_reader = read_capture(&src)?;
            let replay_reader = read_capture(&replay)?;
            let map_file = files::try_open(&addr_map)?;
            info!("Comparing {} <-> {}", src, replay);
            info!("Map: {}", addr_map.display());
            let mut map = AddrMapReader::new(map_file)?;
            let mut delta_writer = None;
            if let Some(delta) = delta {
                let file = files::try_create(&delta, "csv")?;
                delta_writer = Some(BufWriter::new(file));
                info!("Deltas: {}", delta.display());
            }
            compare::compare(&mut map, src_reader, replay_reader, delta_writer)?;
        }
        Commands::Capture {
            output,
            rewrite,
            interface,
            port,
            max_chunk,
            level,
            zw,
        } => {
            if output.exists() {
                if !output.is_dir() {
                    return Err(anyhow!("Not a directory: {}", output.display()));
                }
                if rewrite {
                    fs::remove_dir_all(&output)?;
                } else {
                    return Err(anyhow!("Output directory exists: {}", output.display()));
                }
            }
            fs::create_dir(&output)?;
            info!(
                "Capturing if={},port={} => {}",
                interface,
                port,
                output.display()
            );
            info!(
                "Max chunk size = {} Compression level = {}, zstd workers = {}",
                max_chunk, level, zw
            );
            let writer = AcapWriter::new(output, max_chunk.as_u64(), level, zw)?;
            capture::ebpf::run_capture(writer, &interface, port)?
        }
        Commands::Compress {
            input,
            output,
            level,
            zw,
        } => {
            let in_file = files::try_open(&input)?;
            let out_file = files::try_create(&output, "zst")?;
            info!("Compressing {} -> {}", input.display(), output.display());
            info!("Level = {level}, workers = {zw}");
            let dur = zstd_test::compress(in_file, out_file, level, zw)?;
            info!("Time taken: {}ms", dur.as_millis());
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
