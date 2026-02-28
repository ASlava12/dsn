use anyhow::Result;

use crate::cmd::cli::{Cli, Commands};

mod config;

pub async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Config(config_cmd) => config::handle(config_cmd.command, cli.config).await,
    }
}
