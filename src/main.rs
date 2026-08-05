use anyhow::anyhow;
use bytesize::ByteSize;
use clap::{Parser, Subcommand};
use std::net::IpAddr;
use std::path::PathBuf;
use std::{env, fs, path};
use time::{UtcOffset, macros::format_description};
use tracing_subscriber::fmt::time::OffsetTime;

use tracing::{error, info};

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
    Replay {
        #[arg(required = true)]
        input: PathBuf,

        #[arg(short, long, default_value_t = 5432, value_parser = clap::value_parser!(u16).range(1..))]
        cap_port: u16,

        #[arg(short, long, default_value = "replay.csv")]
        addr_map: PathBuf,

        #[arg(short, long, default_value = "127.0.0.1")]
        host: String,

        #[arg(short, long, default_value_t = 5432, value_parser = clap::value_parser!(u16).range(1..))]
        port: u16,

        #[arg(short, long, default_value = "postgres")]
        dbname: String,

        #[arg(short, long, default_value_t = default_username())]
        user: String,

        #[arg(short = 'P', long)]
        pass: Option<String>,
    },
    Dump {
        #[arg(required = true)]
        input: PathBuf,

        #[arg()]
        output: Option<PathBuf>,

        #[arg(short, long, default_value_t = 5432, value_parser = clap::value_parser!(u16).range(1..))]
        cap_port: u16,
    },
    Compare {
        #[arg(required = true)]
        c1: PathBuf,

        #[arg(required = true)]
        c2: PathBuf,

        #[arg(short, long, default_value = "replay.csv")]
        addr_map: PathBuf,

        #[arg(short, long)]
        delta: Option<PathBuf>,

        #[arg(long = "p1", default_value_t = 5432, value_parser = clap::value_parser!(u16).range(1..))]
        port1: u16,

        #[arg(long = "p2", default_value_t = 5432, value_parser = clap::value_parser!(u16).range(1..))]
        port2: u16,
    },
    Capture {
        #[arg(short, long, default_value = "zz_cap")]
        output: PathBuf,

        #[arg(short, long, default_value = "lo")]
        iface: String,

        #[arg(short, long, default_value_t = 5432, value_parser = clap::value_parser!(u16).range(1..))]
        port: u16,

        #[arg(short, long, default_value_t = 0)]
        chunk: u32,

        #[arg(short, long, default_value = "64MB")]
        max_chunk: ByteSize,

        #[arg(short, long, default_value_t = 3, help = "Compression level")]
        level: i32,

        #[arg(long, default_value_t = 4, help = "Number of zstd workers")]
        zw: u8,
    },
    Compress {
        #[arg()]
        input: PathBuf,

        #[arg()]
        output: PathBuf,

        #[arg(short, long, default_value_t = 3, help = "Compression level")]
        level: i32,

        #[arg(long, default_value_t = 4, help = "Number of zstd workers")]
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
            cap_port,
        } => {
            let output = output.unwrap_or_else(|| input.with_added_extension("csv"));
            let (input_path, reader) = read_capture(&input, cap_port)?;
            let (output_path, output_file) = files::try_create(output, "csv")?;
            info!(
                "Dump {}[port={cap_port}] -> {}",
                input_path.display(),
                output_path.display()
            );
            dump::dump(reader, output_file)?;
        }
        Commands::Compare {
            c1,
            c2,
            addr_map,
            delta,
            port1,
            port2,
        } => {
            let (c1_path, c1_reader) = read_capture(&c1, port1)?;
            let (c2_path, c2_reader) = read_capture(&c2, port2)?;
            let (map_path, map_file) = files::try_open(addr_map)?;
            info!(
                "Compare {}[{port1}] <=> {}[{port2}]",
                c1_path.display(),
                c2_path.display()
            );
            info!("Map: {}", map_path.display());
            let mut map = PairMap::new(map_file)?;
            let mut delta_file = None;
            if let Some(delta) = delta {
                let (delta_path, file) = files::try_create(delta, "csv")?;
                delta_file = Some(file);
                info!("Deltas: {}", delta_path.display());
            }
            compare::compare(&mut map, c1_reader, c2_reader, delta_file)?;
        }
        Commands::Capture {
            output,
            iface,
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
            let dst_ip: IpAddr = "::1".parse()?;
            let writer = AcapWriter::new(out_path, chunk, max_chunk.as_u64(), level, zw)?;
            capture::run_capture(writer, &iface, dst_ip, port).await?
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
