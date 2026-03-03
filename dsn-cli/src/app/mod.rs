use anyhow::Result;

use crate::cmd::cli::{Cli, Commands};

mod config;
mod node;
mod transport;

pub async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Config(config_cmd) => config::handle(config_cmd.command, cli.config).await,
        Commands::Transport(transport_cmd) => {
            transport::handle(transport_cmd.command, cli.config).await
        }
        Commands::Node(node_cmd) => node::handle(node_cmd.command, cli.config).await,
    }
}
