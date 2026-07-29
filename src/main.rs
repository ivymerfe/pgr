use clap::{Parser, Subcommand};
use time::{UtcOffset, macros::format_description};
use tracing_subscriber::fmt::time::OffsetTime;
use std::env;
use std::path::{self, PathBuf};
use std::error::Error;

use tracing::{error, info};

use crate::compare::CompareState;
use crate::replay::ReplayState;

mod parser;
mod dump;
mod replay;
mod replay_client;
mod compare;

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

        #[arg(required=true)]
        translations: PathBuf,

        #[arg(
            long = "p2", 
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
    tracing_subscriber::fmt().with_timer(timer).init();

    match cli.command {
        Commands::Replay { input, cap_port, host, port, dbname, user, pass } => {
            let mut input_path = path::absolute(&input)?;
            if !input_path.exists() {
                input_path.set_extension("pcap");  
            }
            if !input_path.exists() {
                error!("Input path does not exist: {}", input_path.display());
                return Ok(());
            }
            info!("Replaying {}[port={cap_port}] at host={host} port={port} user={user}", input_path.display());
            let mut state = ReplayState::new(host, port, dbname, user, pass)?;
            state.replay(input_path, cap_port).await?;
        }
        Commands::Dump { input, output, cap_port } => {
            let mut input_path = path::absolute(&input)?;
            if !input_path.exists() {
                input_path.set_extension("pcap");  
            }
            let output_path = match output {
                Some(path) => path::absolute(&path)?,
                None => input_path.with_added_extension("dump")
            };
            if !input_path.exists() {
                error!("Input path does not exist: {}", input_path.display());
                return Ok(());
            }
            info!("Dump {}[port={cap_port}] -> {}", input_path.display(), output_path.display());
            dump::dump(&input_path, &output_path, cap_port)?;
        }
        Commands::Compare { c1, c2, translations, port1, port2 } => {
            let mut c1_path = path::absolute(&c1)?;
            if !c1_path.exists() {
                c1_path.set_extension("pcap");  
            }
            if !c1_path.exists() {
                error!("First capture file does not exist: {}", c1_path.display());
                return Ok(());
            }
            let mut c2_path = path::absolute(&c2)?;
            if !c2_path.exists() {
                c2_path.set_extension("pcap");  
            }
            if !c2_path.exists() {
                error!("Second capture file does not exist: {}", c2_path.display());
                return Ok(());
            }
            let t_path = path::absolute(&translations)?;
            if !t_path.exists() {
                error!("Translations file does not exist: {}", t_path.display());
                return Ok(());
            }
            info!("Compare {}[{port1}] <=> {}[{port2}] via {}",
                c1_path.display(), c2_path.display(), t_path.display());
            let mut state = CompareState::new();
            state.load_translation(&t_path)?;
            state.compare(c1, c2, port1, port2)?;
            println!("{state}");
        }
    }
    Ok(())
}

fn default_username() -> String {
    env::var("USER")
        .or_else(|_| env::var("LOGNAME"))
        .unwrap_or_else(|_| String::from("postgres"))
}
