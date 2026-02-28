use anyhow::Result;

use crate::cmd::cli::{Cli, Commands};

mod config;
mod transport;

pub async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Config(config_cmd) => config::handle(config_cmd.command, cli.config).await,
        Commands::Transport(transport_cmd) => transport::handle(transport_cmd.command).await,
    }
}
