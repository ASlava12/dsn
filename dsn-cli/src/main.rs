mod app;
mod cfg;
mod cmd;
mod helpers;
mod observability;

use anyhow::Result;
use clap::Parser;
use cmd::cli::Cli;
use metrics::counter;

#[tokio::main]
async fn main() -> Result<()> {
    observability::init()?;

    let cli = Cli::parse();
    counter!("dsn_cli_invocations_total").increment(1);

    app::run(cli).await
}
