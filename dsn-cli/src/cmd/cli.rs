use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "dsn", about = "Distributed Software Network CLI")]
pub struct Cli {
    #[arg(long, global = true, env = "DSN_CONFIG")]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Config(ConfigArgs),
}

#[derive(Parser, Debug)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: ConfigCommands,
}

#[derive(Subcommand, Debug)]
pub enum ConfigCommands {
    Locate,
    Init {
        path: Option<PathBuf>,
    },
    Validate {
        path: Option<PathBuf>,
    },
    Fix {
        path: Option<PathBuf>,
    },
    Keygen {
        #[arg(short = 't', long = "type", default_value = "ed25519")]
        key_type: String,
        #[arg(long)]
        output: bool,
    },
    Show,
    Get {
        parameter: String,
    },
    Set {
        #[arg(long)]
        force: bool,
        parameter: String,
        value: String,
    },
    Del {
        #[arg(long)]
        force: bool,
        parameter: String,
    },
}
