use clap::{Parser, Subcommand};
use time::{UtcOffset, macros::format_description};
use tracing_subscriber::fmt::time::OffsetTime;
use std::path::{self, PathBuf};
use std::error::Error;

use tracing::{error, info};

mod parser;
mod replay;
mod dumper;

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

        // superuser
        #[arg(
            short,
            long, 
            default_value = "postgres",
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
}

#[tokio::main]
async fn main()-> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    let local_offset = UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC);

    let format = format_description!("[hour]:[minute]:[second]");
    let timer = OffsetTime::new(local_offset, format);
    tracing_subscriber::fmt().with_timer(timer).init();

    match cli.command {
        Commands::Replay { input, cap_port, host, port, user, pass } => {
            let mut input_path = path::absolute(&input)?;
            if !input_path.exists() {
                input_path.set_extension("pcap");  
            }
            if !input_path.exists() {
                error!("Input path does not exist: {}", input_path.display());
                return Ok(());
            }
            
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
            info!("Dumping {} -> {}", input_path.display(), output_path.display());
            dumper::dump(&input_path, &output_path, cap_port)?;
        }
    }
    Ok(())
}
