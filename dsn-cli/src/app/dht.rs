use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::cmd::cli::{DhtCommands, DhtIpCommands, DhtMainCommands, DhtNameCommands};

pub async fn handle(command: DhtCommands, explicit_config: Option<PathBuf>) -> Result<()> {
    let req = match command {
        DhtCommands::Namespaces => "namespaces".to_string(),
        DhtCommands::Main { command } => match command {
            DhtMainCommands::My => "main my".to_string(),
        },
        DhtCommands::Ip4 { command } => match command {
            DhtIpCommands::On => "ip4 on".to_string(),
            DhtIpCommands::Off => "ip4 off".to_string(),
            DhtIpCommands::Status => "ip4 status".to_string(),
            DhtIpCommands::Get { value } => format!("ip4 get {value}"),
        },
        DhtCommands::Ip6 { command } => match command {
            DhtIpCommands::On => "ip6 on".to_string(),
            DhtIpCommands::Off => "ip6 off".to_string(),
            DhtIpCommands::Status => "ip6 status".to_string(),
            DhtIpCommands::Get { value } => format!("ip6 get {value}"),
        },
        DhtCommands::Name { command } => match command {
            DhtNameCommands::Check { name } => format!("name check {name}"),
            DhtNameCommands::Get { name } => format!("name get {name}"),
            DhtNameCommands::Take { name } => format!("name take {name}"),
            DhtNameCommands::Challenge { name, difficulty } => {
                format!("name challenge {name} {}", difficulty.unwrap_or(8))
            }
        },
    };

    let response = query_control_socket(explicit_config.as_deref(), &req).await?;
    if let Some(err) = response.get("error").and_then(Value::as_str) {
        bail!(err.to_string());
    }

    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn query_control_socket(explicit_config: Option<&Path>, request: &str) -> Result<Value> {
    let sock = control_socket_path(explicit_config)?;
    let mut stream = UnixStream::connect(&sock)
        .await
        .with_context(|| format!("failed to connect control socket {}", sock.display()))?;
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(b"\n").await?;

    let mut line = String::new();
    let mut reader = BufReader::new(stream);
    reader.read_line(&mut line).await?;
    if line.trim().is_empty() {
        bail!("empty response from control socket");
    }

    Ok(serde_json::from_str(line.trim()).context("invalid response payload")?)
}

fn control_socket_path(explicit_config: Option<&Path>) -> Result<PathBuf> {
    let cfg_path = dsn_core::resolve_config_path(explicit_config)?;
    let base = cfg_path.parent().unwrap_or_else(|| Path::new("."));

    let cfg = if cfg_path.exists() {
        dsn_core::load_config(&cfg_path)?
    } else {
        dsn_core::DsnConfig::default_with_generated_identity()?
    };

    let state_dir = base.join(&cfg.node.state_dir);
    let sock = Path::new(&cfg.node.control_socket);
    Ok(if sock.is_absolute() {
        sock.to_path_buf()
    } else {
        state_dir.join(sock)
    })
}
