use anyhow::anyhow;
use bytesize::ByteSize;
use clap::{Parser, Subcommand};

use std::io::BufWriter;
use std::net::IpAddr;
use std::path::PathBuf;
use std::{env, fs, path};

use time::{UtcOffset, macros::format_description};
use tracing::{error, info};
use tracing_subscriber::fmt::time::OffsetTime;

use crate::capture::acap::AcapWriter;
use crate::capture::read_capture;
use crate::compare::pair::PairMap;
use crate::replay::addr_map::AddrMap;
use crate::replay::client::ReplayManager;
use crate::utils::files;

mod capture;
mod compare;
mod dump;
mod parser;
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
        #[arg(help = "Path to the capture (acap folder or .pcap file)")]
        input: PathBuf,

        #[arg(
            short,
            long,
            default_value_t = 5432,
            help = "Port the capture was recorded on"
        )]
        cap_port: u16,

        #[arg(
            short,
            long,
            default_value = "replay.csv",
            help = "File to store address mapping (needed for compare)"
        )]
        addr_map: PathBuf,

        #[arg(short, long, default_value = "127.0.0.1", help = "Target server host")]
        host: String,

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
        #[arg(help = "Path to the capture")]
        input: PathBuf,

        #[arg(short, long, default_value = "capture.csv", help = "Output CSV path")]
        output: PathBuf,

        #[arg(
            short,
            long,
            default_value_t = 5432,
            help = "Port to parse traffic for"
        )]
        port: u16,
    },
    #[command(about = "Compare two captures")]
    Compare {
        #[arg(short, long, help = "Source capture")]
        src: PathBuf,

        #[arg(short, long, help = "Replay result capture")]
        replay: PathBuf,

        #[arg(
            short,
            long,
            default_value = "replay.csv",
            help = "Address mapping file produced by replay"
        )]
        addr_map: PathBuf,

        #[arg(long, help = "File to save differences to")]
        delta: Option<PathBuf>,

        #[arg(long, default_value_t = 5432, help = "Port in the source capture")]
        src_port: u16,

        #[arg(long, default_value_t = 5432, help = "Port in the replay capture")]
        replay_port: u16,
    },
    #[command(about = "Capture traffic")]
    Capture {
        #[arg(
            short,
            long,
            default_value = "zz_cap",
            help = "Folder to write the capture to"
        )]
        output: PathBuf,

        #[arg(short, long, default_value = "lo", help = "Network interface")]
        interface: String,

        #[arg(
            short,
            long,
            default_value = "::1",
            help = "Address to filter traffic by"
        )]
        addr: IpAddr,

        #[arg(short, long, default_value_t = 5432, help = "Port to capture")]
        port: u16,

        #[arg(
            short,
            long,
            default_value_t = 0,
            help = "Chunk number to start from (for appending)"
        )]
        chunk: u32,

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
        #[arg(help = "Input file")]
        input: PathBuf,

        #[arg(short, long, help = "Output file")]
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let local_offset = UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC);

    let format = format_description!("[hour]:[minute]:[second]");
    let timer = OffsetTime::new(local_offset, format);
    tracing_subscriber::fmt()
        .with_timer(timer)
        .with_target(false)
        .init();

    match run_command(cli).await {
        Ok(()) => (),
        Err(e) => {
            error!("{}", e.to_string());
        }
    }

    Ok(())
}

async fn run_command(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Commands::Replay {
            input,
            cap_port,
            addr_map,
            host,
            port,
            dbname,
            user,
            pass,
        } => {
            let (map_path, map_file) = files::try_create_a(addr_map, "csv").await?;
            let (input_path, reader) = read_capture(&input, cap_port)?;
            info!(
                "Replaying {}[port={cap_port}] at host={host} port={port} user={user}",
                input_path.display()
            );
            info!("Map: {}", map_path.display());
            let map = AddrMap::new(map_file);
            let mut mgr = ReplayManager::new(map, host, port, dbname, user, pass).await?;
            mgr.replay(reader).await?;
        }
        Commands::Dump {
            input,
            output,
            port,
        } => {
            let (input_path, reader) = read_capture(&input, port)?;
            let (output_path, output_file) = files::try_create(output, "csv")?;
            info!(
                "Dump {}[port={port}] -> {}",
                input_path.display(),
                output_path.display()
            );
            dump::dump(reader, output_file)?;
        }
        Commands::Compare {
            src,
            replay,
            addr_map,
            delta,
            src_port,
            replay_port,
        } => {
            let (src_path, src_reader) = read_capture(&src, src_port)?;
            let (replay_path, replay_reader) = read_capture(&replay, replay_port)?;
            let (map_path, map_file) = files::try_open(addr_map)?;
            info!(
                "Compare {}[{src_port}] <=> {}[{replay_port}]",
                src_path.display(),
                replay_path.display()
            );
            info!("Map: {}", map_path.display());
            let mut map = PairMap::new(map_file)?;
            let mut delta_writer = None;
            if let Some(delta) = delta {
                let (delta_path, file) = files::try_create(delta, "csv")?;
                delta_writer = Some(BufWriter::new(file));
                info!("Deltas: {}", delta_path.display());
            }
            compare::compare(&mut map, src_reader, replay_reader, delta_writer)?;
        }
        Commands::Capture {
            output,
            interface,
            addr,
            port,
            chunk,
            max_chunk,
            level,
            zw,
        } => {
            let out_path = path::absolute(output)?;
            if !out_path.exists() {
                fs::create_dir(&out_path)?;
            }
            if !out_path.is_dir() {
                return Err(anyhow!("Not a directory: {}", out_path.display()));
            }
            info!("Capturing into {}", out_path.display());
            info!(
                "Start chunk = {} Max chunk size = {} Compression level = {}, workers = {}",
                chunk, max_chunk, level, zw
            );
            let writer = AcapWriter::new(out_path, chunk, max_chunk.as_u64(), level, zw)?;
            capture::run_capture(writer, &interface, addr, port).await?
        }
        Commands::Compress {
            input,
            output,
            level,
            zw,
        } => {
            let (in_path, in_file) = files::try_open(input)?;
            let (out_path, out_file) = files::try_create(output, "zst")?;
            info!(
                "Compressing {} -> {}",
                in_path.display(),
                out_path.display()
            );
            info!("Level = {level}, workers = {zw}");
            let dur = zstd_test::compress(in_file, out_file, level, zw)?;
            info!("Time taken: {}ms", dur.as_millis());
        }
    }
    Ok(())
}

fn default_username() -> String {
    env::var("USER")
        .or_else(|_| env::var("LOGNAME"))
        .unwrap_or_else(|_| String::from("postgres"))
}
