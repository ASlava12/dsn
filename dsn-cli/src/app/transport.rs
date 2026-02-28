use anyhow::{Context, Result};
use dsn_core::TransportEndpoint;
use std::str::FromStr;

use crate::cmd::cli::TransportCommands;

pub async fn handle(command: TransportCommands) -> Result<()> {
    match command {
        TransportCommands::Listen { transport } => {
            let endpoint = TransportEndpoint::from_str(&transport)
                .with_context(|| format!("invalid transport endpoint: {transport}"))?;
            println!("transport listen is not implemented yet: {endpoint:?}");
        }
        TransportCommands::Connect { transport } => {
            let endpoint = TransportEndpoint::from_str(&transport)
                .with_context(|| format!("invalid transport endpoint: {transport}"))?;
            println!("transport connect is not implemented yet: {endpoint:?}");
        }
    }

    Ok(())
}
