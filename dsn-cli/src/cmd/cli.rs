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
    Transport(TransportArgs),
    Node(NodeArgs),
    Dht(DhtArgs),
}

#[derive(Parser, Debug)]
pub struct TransportArgs {
    #[command(subcommand)]
    pub command: TransportCommands,
}

#[derive(Subcommand, Debug)]
pub enum TransportCommands {
    Listen { transport: String },
    Connect { transport: String },
}

#[derive(Parser, Debug)]
pub struct NodeArgs {
    #[command(subcommand)]
    pub command: NodeCommands,
}

#[derive(Subcommand, Debug)]
pub enum NodeCommands {
    Up {
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    Down {
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    Status {
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    #[command(hide = true, name = "run")]
    Run {
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    Whitelist {
        #[arg(long)]
        state_dir: Option<PathBuf>,
        #[command(subcommand)]
        command: NodeAclCommands,
    },
    Blacklist {
        #[arg(long)]
        state_dir: Option<PathBuf>,
        #[command(subcommand)]
        command: NodeAclCommands,
    },
}

#[derive(Parser, Debug)]
pub struct NodeAclArgs {
    #[command(subcommand)]
    pub command: NodeAclCommands,
}

#[derive(Subcommand, Debug)]
pub enum NodeAclCommands {
    List,
    Add { node_id: String },
    Del { node_id: String },
}

#[derive(Parser, Debug)]
pub struct DhtArgs {
    #[command(subcommand)]
    pub command: DhtCommands,
}

#[derive(Subcommand, Debug)]
pub enum DhtCommands {
    Namespaces,
    Main {
        #[command(subcommand)]
        command: DhtMainCommands,
    },
    Ip4 {
        #[command(subcommand)]
        command: DhtIpCommands,
    },
    Ip6 {
        #[command(subcommand)]
        command: DhtIpCommands,
    },
    Name {
        #[command(subcommand)]
        command: DhtNameCommands,
    },
}

#[derive(Subcommand, Debug)]
pub enum DhtMainCommands {
    My,
}

#[derive(Subcommand, Debug)]
pub enum DhtIpCommands {
    On,
    Off,
    Status,
    Get { value: String },
}

#[derive(Subcommand, Debug)]
pub enum DhtNameCommands {
    Check {
        name: String,
    },
    Get {
        name: String,
    },
    Take {
        name: String,
    },
    Challenge {
        name: String,
        #[arg(long = "difficulty")]
        difficulty: Option<u8>,
    },
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
