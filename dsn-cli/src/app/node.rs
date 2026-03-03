use anyhow::{Context, Result, bail};
use dsn_core::{DsnConfig, NodeRuntime, RuntimeStats, load_config, resolve_config_path};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::fs;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::Mutex;

use crate::cmd::cli::NodeCommands;

#[derive(Debug, Default)]
struct DhtCliState {
    ip4_enabled: bool,
    ip6_enabled: bool,
    names: HashMap<String, String>,
}

pub async fn handle(command: NodeCommands, explicit_config: Option<PathBuf>) -> Result<()> {
    match command {
        NodeCommands::Up { state_dir } => up(explicit_config, state_dir).await,
        NodeCommands::Down { state_dir } => down(explicit_config, state_dir).await,
        NodeCommands::Status { state_dir } => status(explicit_config, state_dir).await,
        NodeCommands::Run { state_dir } => run_foreground(explicit_config, state_dir).await,
    }
}

async fn up(explicit_config: Option<PathBuf>, state_dir: Option<PathBuf>) -> Result<()> {
    let state_dir = state_dir_for(explicit_config.as_deref(), state_dir.as_deref())?;
    let pid_path = state_dir.join("node.pid");

    if let Some(pid) = read_pid(&pid_path).await?
        && process_alive(pid).await
    {
        println!("node is already running (pid={pid})");
        return Ok(());
    }

    fs::create_dir_all(&state_dir).await.with_context(|| {
        format!(
            "failed to prepare state_dir {} (if this path is a file, choose directory path)",
            state_dir.display()
        )
    })?;
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

async fn down(explicit_config: Option<PathBuf>, state_dir: Option<PathBuf>) -> Result<()> {
    let state_dir = state_dir_for(explicit_config.as_deref(), state_dir.as_deref())?;
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

async fn status(explicit_config: Option<PathBuf>, state_dir: Option<PathBuf>) -> Result<()> {
    let state_dir = state_dir_for(explicit_config.as_deref(), state_dir.as_deref())?;
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

async fn run_foreground(
    explicit_config: Option<PathBuf>,
    state_dir: Option<PathBuf>,
) -> Result<()> {
    let state_dir = state_dir_for(explicit_config.as_deref(), state_dir.as_deref())?;
    fs::create_dir_all(&state_dir).await.with_context(|| {
        format!(
            "failed to prepare state_dir {} (if this path is a file, choose directory path)",
            state_dir.display()
        )
    })?;
    let pid_path = state_dir.join("node.pid");
    let stats_path = state_dir.join("status.json");

    let cfg = load_runtime_config(explicit_config.as_deref())?;
    let control_sock_path = control_socket_path(&cfg, &state_dir);
    let runtime = NodeRuntime::new(cfg.clone());
    let handle = runtime.start();
    let dht = handle.dht();
    let cli_state = std::sync::Arc::new(Mutex::new(DhtCliState::default()));

    if std::fs::metadata(&control_sock_path).is_ok() {
        let _ = std::fs::remove_file(&control_sock_path);
    }
    let control_task = tokio::spawn(run_control_socket_server(
        control_sock_path.clone(),
        dht,
        cfg.identity.id.clone(),
        cli_state,
    ));

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

    control_task.abort();
    handle.stop().await;
    let _ = fs::remove_file(&pid_path).await;
    let _ = fs::remove_file(&control_sock_path).await;
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

fn state_dir_for(
    explicit_config: Option<&Path>,
    override_state_dir: Option<&Path>,
) -> Result<PathBuf> {
    if let Some(path) = override_state_dir {
        return Ok(path.to_path_buf());
    }

    let cfg = load_runtime_config(explicit_config)?;
    let cfg_path = resolve_config_path(explicit_config)?;
    let base = cfg_path.parent().unwrap_or_else(|| Path::new("."));
    Ok(base.join(&cfg.node.state_dir))
}

fn control_socket_path(cfg: &DsnConfig, state_dir: &Path) -> PathBuf {
    let socket = Path::new(&cfg.node.control_socket);
    if socket.is_absolute() {
        socket.to_path_buf()
    } else {
        state_dir.join(socket)
    }
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
        let dir = state_dir_for(Some(Path::new("/tmp/dsn/config.toml")), None)?;
        assert_eq!(dir, Path::new("/tmp/dsn/node-state"));
        Ok(())
    }
}

async fn run_control_socket_server(
    sock_path: PathBuf,
    dht: std::sync::Arc<Mutex<dsn_core::DhtRuntime>>,
    my_id: String,
    cli_state: std::sync::Arc<Mutex<DhtCliState>>,
) -> Result<()> {
    let listener = UnixListener::bind(&sock_path)
        .with_context(|| format!("failed to bind control socket {}", sock_path.display()))?;

    loop {
        let (stream, _) = listener.accept().await?;
        let dht = dht.clone();
        let my_id = my_id.clone();
        let cli_state = cli_state.clone();
        tokio::spawn(async move {
            let (read_half, mut write_half) = stream.into_split();
            let mut reader = BufReader::new(read_half);
            let mut line = String::new();
            let response = match reader.read_line(&mut line).await {
                Ok(0) => serde_json::json!({"error":"empty request"}),
                Ok(_) => handle_dht_admin_request(line.trim(), dht, &my_id, cli_state).await,
                Err(e) => serde_json::json!({"error": format!("io error: {e}")}),
            };
            let _ = write_half
                .write_all(format!("{}\n", response).as_bytes())
                .await;
        });
    }
}

async fn handle_dht_admin_request(
    request: &str,
    dht: std::sync::Arc<Mutex<dsn_core::DhtRuntime>>,
    my_id: &str,
    cli_state: std::sync::Arc<Mutex<DhtCliState>>,
) -> serde_json::Value {
    let parts: Vec<&str> = request.split_whitespace().collect();
    if parts.is_empty() {
        return serde_json::json!({"error":"empty request"});
    }

    match parts.as_slice() {
        ["namespaces"] => {
            let guard = dht.lock().await;
            serde_json::json!({"namespaces": guard.namespaces()})
        }
        ["main", "my"] => {
            let guard = dht.lock().await;
            let value = guard.find_value("main", my_id.as_bytes());
            match value.and_then(|v| serde_json::from_slice::<serde_json::Value>(&v).ok()) {
                Some(pid) => serde_json::json!({"identity": pid}),
                None => serde_json::json!({"error":"identity not published yet"}),
            }
        }
        ["ip4", "on"] => {
            cli_state.lock().await.ip4_enabled = true;
            serde_json::json!({"ok":true,"ip4_enabled":true})
        }
        ["ip4", "off"] => {
            cli_state.lock().await.ip4_enabled = false;
            serde_json::json!({"ok":true,"ip4_enabled":false})
        }
        ["ip4", "status"] => serde_json::json!({"ip4_enabled":cli_state.lock().await.ip4_enabled}),
        ["ip4", "get", addr] => {
            let guard = dht.lock().await;
            let value = guard.find_value("ip4", addr.as_bytes());
            match value.and_then(|v| serde_json::from_slice::<serde_json::Value>(&v).ok()) {
                Some(pid) => serde_json::json!({"identity": pid}),
                None => serde_json::json!({"error":"not found"}),
            }
        }
        ["ip6", "on"] => {
            cli_state.lock().await.ip6_enabled = true;
            serde_json::json!({"ok":true,"ip6_enabled":true})
        }
        ["ip6", "off"] => {
            cli_state.lock().await.ip6_enabled = false;
            serde_json::json!({"ok":true,"ip6_enabled":false})
        }
        ["ip6", "status"] => serde_json::json!({"ip6_enabled":cli_state.lock().await.ip6_enabled}),
        ["ip6", "get", addr] => {
            let guard = dht.lock().await;
            let value = guard.find_value("ip6", addr.as_bytes());
            match value.and_then(|v| serde_json::from_slice::<serde_json::Value>(&v).ok()) {
                Some(pid) => serde_json::json!({"identity": pid}),
                None => serde_json::json!({"error":"not found"}),
            }
        }
        ["name", "check", name] => {
            let st = cli_state.lock().await;
            serde_json::json!({"available": !st.names.contains_key(*name)})
        }
        ["name", "get", name] => {
            let st = cli_state.lock().await;
            match st.names.get(*name) {
                Some(owner) => serde_json::json!({"name":name,"owner":owner}),
                None => serde_json::json!({"error":"not found"}),
            }
        }
        ["name", "take", name] => {
            let mut st = cli_state.lock().await;
            if st.names.contains_key(*name) {
                serde_json::json!({"error":"name is already taken"})
            } else {
                st.names.insert((*name).to_string(), my_id.to_string());
                serde_json::json!({"ok":true,"name":name,"owner":my_id})
            }
        }
        ["name", "challenge", name, difficulty] => {
            let diff = difficulty.parse::<u8>().unwrap_or(8);
            let mut nonce: u64 = 0;
            loop {
                let tag = blake3::hash(format!("dsn:name:{}:{}:{}", name, my_id, nonce).as_bytes());
                let mut lead: u8 = 0;
                for b in tag.as_bytes() {
                    if *b == 0 {
                        lead = lead.saturating_add(8);
                    } else {
                        lead = lead.saturating_add(b.leading_zeros() as u8);
                        break;
                    }
                }
                if lead >= diff {
                    break serde_json::json!({"name":name,"difficulty":diff,"nonce":nonce});
                }
                nonce = nonce.saturating_add(1);
                if nonce > 5_000_000 {
                    break serde_json::json!({"error":"challenge limit exceeded"});
                }
            }
        }
        _ => serde_json::json!({"error":"unknown command"}),
    }
}
