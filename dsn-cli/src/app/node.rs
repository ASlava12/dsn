use anyhow::{Context, Result, bail};
use dsn_core::{DsnConfig, NodeRuntime, RuntimeStats, load_config, resolve_config_path};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::fs;

use crate::cmd::cli::NodeCommands;

pub async fn handle(command: NodeCommands, explicit_config: Option<PathBuf>) -> Result<()> {
    match command {
        NodeCommands::Up => up(explicit_config).await,
        NodeCommands::Down => down(explicit_config).await,
        NodeCommands::Status => status(explicit_config).await,
        NodeCommands::Run { state_dir } => run_foreground(explicit_config, state_dir).await,
    }
}

async fn up(explicit_config: Option<PathBuf>) -> Result<()> {
    let state_dir = state_dir_for(explicit_config.as_deref())?;
    let pid_path = state_dir.join("node.pid");

    if let Some(pid) = read_pid(&pid_path).await?
        && process_alive(pid).await
    {
        println!("node is already running (pid={pid})");
        return Ok(());
    }

    fs::create_dir_all(&state_dir).await?;
    let exe = std::env::current_exe().context("failed to resolve current executable")?;
    let mut cmd = std::process::Command::new(exe);
    if let Some(path) = explicit_config.as_ref() {
        cmd.arg("--config").arg(path);
    }
    cmd.arg("node")
        .arg("run")
        .arg("--state-dir")
        .arg(&state_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let child = cmd.spawn().context("failed to spawn node runtime")?;
    println!("node started (pid={})", child.id());
    Ok(())
}

async fn down(explicit_config: Option<PathBuf>) -> Result<()> {
    let state_dir = state_dir_for(explicit_config.as_deref())?;
    let pid_path = state_dir.join("node.pid");
    let Some(pid) = read_pid(&pid_path).await? else {
        println!("node is not running");
        return Ok(());
    };

    if !process_alive(pid).await {
        let _ = fs::remove_file(&pid_path).await;
        println!("node is not running");
        return Ok(());
    }

    let status = std::process::Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()
        .context("failed to send SIGTERM")?;

    if !status.success() {
        bail!("failed to terminate node pid={pid}");
    }

    println!("node stopping (pid={pid})");
    Ok(())
}

async fn status(explicit_config: Option<PathBuf>) -> Result<()> {
    let state_dir = state_dir_for(explicit_config.as_deref())?;
    let pid_path = state_dir.join("node.pid");
    let stats_path = state_dir.join("status.json");

    let Some(pid) = read_pid(&pid_path).await? else {
        println!("down");
        return Ok(());
    };

    if !process_alive(pid).await {
        println!("down");
        return Ok(());
    }

    let details = read_status(&stats_path).await.unwrap_or_default();
    println!(
        "up pid={} sessions={} published={} last_tick_us={}",
        pid, details.active_sessions, details.published_identities, details.last_tick_us
    );
    Ok(())
}

async fn run_foreground(explicit_config: Option<PathBuf>, state_dir: PathBuf) -> Result<()> {
    fs::create_dir_all(&state_dir).await?;
    let pid_path = state_dir.join("node.pid");
    let stats_path = state_dir.join("status.json");

    let cfg = load_runtime_config(explicit_config.as_deref())?;
    let runtime = NodeRuntime::new(cfg);
    let handle = runtime.start();

    fs::write(&pid_path, std::process::id().to_string()).await?;

    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(2));
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let stats = handle.snapshot().await;
                let payload = serde_json::to_vec(&PersistedStatus::from_runtime(stats))?;
                fs::write(&stats_path, payload).await?;
            }
            _ = &mut shutdown => {
                break;
            }
        }
    }

    handle.stop().await;
    let _ = fs::remove_file(&pid_path).await;
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("signal handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn state_dir_for(explicit_config: Option<&Path>) -> Result<PathBuf> {
    let cfg_path = resolve_config_path(explicit_config)?;
    let base = cfg_path.parent().unwrap_or_else(|| Path::new("."));
    Ok(base.join("node-state"))
}

fn load_runtime_config(explicit_config: Option<&Path>) -> Result<DsnConfig> {
    let path = resolve_config_path(explicit_config)?;
    if !path.exists() {
        return DsnConfig::default_with_generated_identity();
    }
    load_config(&path)
}

async fn read_pid(path: &Path) -> Result<Option<u32>> {
    let Ok(raw) = fs::read_to_string(path).await else {
        return Ok(None);
    };
    let pid = raw.trim().parse::<u32>().context("invalid pid file")?;
    Ok(Some(pid))
}

async fn process_alive(pid: u32) -> bool {
    std::process::Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PersistedStatus {
    active_sessions: usize,
    published_identities: u64,
    last_tick_us: u64,
}

impl PersistedStatus {
    fn from_runtime(stats: RuntimeStats) -> Self {
        Self {
            active_sessions: stats.active_sessions,
            published_identities: stats.published_identities,
            last_tick_us: stats.last_tick_us,
        }
    }
}

async fn read_status(path: &Path) -> Result<PersistedStatus> {
    let raw = fs::read(path).await?;
    Ok(serde_json::from_slice(&raw)?)
}

#[cfg(test)]
mod tests {
    use super::state_dir_for;
    use anyhow::Result;
    use std::path::Path;

    #[test]
    fn state_dir_is_adjacent_to_config() -> Result<()> {
        let dir = state_dir_for(Some(Path::new("/tmp/dsn/config.toml")))?;
        assert_eq!(dir, Path::new("/tmp/dsn/node-state"));
        Ok(())
    }
}
