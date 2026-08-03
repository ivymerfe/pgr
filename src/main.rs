use clap::{Parser, Subcommand};
use time::{UtcOffset, macros::format_description};
use tracing_subscriber::fmt::time::OffsetTime;
use std::env;
use std::path::PathBuf;
use std::error::Error;

use tracing::{error, info};

use crate::compare::pair::PairMap;
use crate::replay::addr_map::AddrMap;
use crate::replay::client::ReplayManager;

mod parser;
mod dump;
mod replay;
mod compare;
mod utils;

#[derive(Parser)]
#[command(author, version, about, long_about = None, arg_required_else_help = true, disable_help_flag = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Replay {
        #[arg(required=true)]
        input: PathBuf,

        #[arg(
            short, 
            long, 
            default_value_t = 5432, 
            value_parser = clap::value_parser!(u16).range(1..)
        )]
        cap_port: u16,

        #[arg(
            short, 
            long, 
            default_value = "replay.csv", 
        )]
        addr_map: PathBuf,

        #[arg(
            short,
            long, 
            default_value = "127.0.0.1",
        )]
        host: String,

        #[arg(
            short, 
            long, 
            default_value_t = 5432, 
            value_parser = clap::value_parser!(u16).range(1..)
        )]
        port: u16,

        #[arg(
            short,
            long, 
            default_value = "postgres",
        )]
        dbname: String,

        #[arg(
            short,
            long, 
            default_value_t = default_username(),
        )]
        user: String,

        #[arg(
            short = 'P',
            long, 
        )]
        pass: Option<String>,
    },
    Dump {
        #[arg(required=true)]
        input: PathBuf,

        #[arg()]
        output: Option<PathBuf>,

        #[arg(
            short, 
            long, 
            default_value_t = 5432, 
            value_parser = clap::value_parser!(u16).range(1..)
        )]
        cap_port: u16,
    },
    Compare {
        #[arg(required=true)]
        c1: PathBuf,

        #[arg(required=true)]
        c2: PathBuf,

        #[arg(
            short, 
            long, 
            default_value = "replay.csv", 
        )]
        addr_map: PathBuf,

        #[arg(
            short, 
            long, 
        )]
        delta: Option<PathBuf>,

        #[arg(
            long = "p1", 
            default_value_t = 5432, 
            value_parser = clap::value_parser!(u16).range(1..)
        )]
        port1: u16,

        #[arg(
            long = "p2", 
            default_value_t = 5432, 
            value_parser = clap::value_parser!(u16).range(1..)
        )]
        port2: u16
    }
}

#[tokio::main]
async fn main()-> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    let local_offset = UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC);

    let format = format_description!("[hour]:[minute]:[second]");
    let timer = OffsetTime::new(local_offset, format);
    tracing_subscriber::fmt().with_timer(timer).with_target(false).init();

    match run_command(cli).await {
        Ok(()) => (),
        Err(e) => {
            error!("{}", e.to_string());
        }
    }

    Ok(())
}

async fn run_command(cli: Cli) -> Result<(), Box<dyn Error>> {
    match cli.command {
        Commands::Replay { input, cap_port, addr_map, host, port, dbname, user, pass } => {
            let (map_path, map_file) = utils::try_create_a(addr_map, "csv").await?;
            let (input_path, input_file) = utils::try_open(input, "pcap")?;
            info!("Replaying {}[port={cap_port}] at host={host} port={port} user={user}", input_path.display());
            info!("Map: {}", map_path.display());
            let map = AddrMap::new(map_file);
            let mut mgr = ReplayManager::new(map, host, port, dbname, user, pass).await?;
            mgr.replay(input_file, cap_port).await?;
        }
        Commands::Dump { input, output, cap_port } => {
            let output = output.unwrap_or_else(|| input.with_added_extension("csv"));
            let (input_path, input_file) = utils::try_open(input, "pcap")?;
            let (output_path, output_file) = utils::try_create(output, "csv")?;
            info!("Dump {}[port={cap_port}] -> {}", input_path.display(), output_path.display());
            dump::dump(input_file, output_file, cap_port)?;
        }
        Commands::Compare { c1, c2, addr_map, delta, port1, port2 } => {
            let (c1_path, c1_file) = utils::try_open(c1, "pcap")?;
            let (c2_path, c2_file) = utils::try_open(c2, "pcap")?;
            let (map_path, map_file) = utils::try_open(addr_map, "csv")?;
            info!("Compare {}[{port1}] <=> {}[{port2}]", c1_path.display(), c2_path.display());
            info!("Map: {}", map_path.display());
            let mut map = PairMap::new(map_file)?;
            let mut delta_file = None;
            if let Some(delta) = delta {
                let (delta_path, file) = utils::try_create(delta, "csv")?;
                delta_file = Some(file);
                info!("Deltas: {}", delta_path.display());
            }
            compare::compare(&mut map, c1_file, c2_file, port1, port2, delta_file)?;
        }
    }
    Ok(())
}

fn default_username() -> String {
    env::var("USER")
        .or_else(|_| env::var("LOGNAME"))
        .unwrap_or_else(|_| String::from("postgres"))
}
