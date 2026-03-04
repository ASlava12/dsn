use anyhow::{Context, Result, bail};
use dsn_core::{DsnConfig, NodeRuntime, RuntimeStats, load_config, resolve_config_path};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::fs;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::Mutex;

use crate::cmd::cli::{NodeAclCommands, NodeCommands};

#[derive(Debug, Default)]
struct DhtCliState {
    ip4_enabled: bool,
    ip6_enabled: bool,
    whitelist: HashSet<String>,
    blacklist: HashSet<String>,
}

pub async fn handle(command: NodeCommands, explicit_config: Option<PathBuf>) -> Result<()> {
    match command {
        NodeCommands::Up { state_dir } => up(explicit_config, state_dir).await,
        NodeCommands::Down { state_dir } => down(explicit_config, state_dir).await,
        NodeCommands::Status { state_dir } => status(explicit_config, state_dir).await,
        NodeCommands::Run { state_dir } => run_foreground(explicit_config, state_dir).await,
        NodeCommands::Whitelist { state_dir, command } => {
            update_acl(explicit_config, state_dir, "whitelist", command).await
        }
        NodeCommands::Blacklist { state_dir, command } => {
            update_acl(explicit_config, state_dir, "blacklist", command).await
        }
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
    let cfg = load_runtime_config(explicit_config.as_deref())?;
    let socket = control_socket_path(&cfg, &state_dir);
    println!("node started (pid={})", child.id());
    println!("admin socket={}", socket.display());
    Ok(())
}

async fn down(explicit_config: Option<PathBuf>, state_dir: Option<PathBuf>) -> Result<()> {
    let state_dir = state_dir_for(explicit_config.as_deref(), state_dir.as_deref())?;
    let cfg = load_runtime_config(explicit_config.as_deref())?;
    let sock = control_socket_path(&cfg, &state_dir);

    if query_admin_socket(&sock, "shutdown").await.is_ok() {
        println!("node stopping via admin socket");
        return Ok(());
    }

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
    let cfg = load_runtime_config(explicit_config.as_deref())?;
    let sock = control_socket_path(&cfg, &state_dir);

    let response = match query_admin_socket(&sock, "status").await {
        Ok(v) => v,
        Err(_) => {
            println!("down");
            return Ok(());
        }
    };

    if let Some(err) = response.get("error").and_then(|v| v.as_str()) {
        println!("down ({err})");
        return Ok(());
    }

    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn update_acl(
    explicit_config: Option<PathBuf>,
    state_dir: Option<PathBuf>,
    which: &str,
    command: NodeAclCommands,
) -> Result<()> {
    let state_dir = state_dir_for(explicit_config.as_deref(), state_dir.as_deref())?;
    let cfg = load_runtime_config(explicit_config.as_deref())?;
    let sock = control_socket_path(&cfg, &state_dir);
    let request = match command {
        NodeAclCommands::List => format!("{which} list"),
        NodeAclCommands::Add { node_id } => format!("{which} add {node_id}"),
        NodeAclCommands::Del { node_id } => format!("{which} del {node_id}"),
    };

    let response = query_admin_socket(&sock, &request).await?;
    if let Some(err) = response.get("error").and_then(|v| v.as_str()) {
        bail!(err.to_string());
    }
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn query_admin_socket(sock: &Path, request: &str) -> Result<serde_json::Value> {
    let mut stream = tokio::net::UnixStream::connect(sock)
        .await
        .with_context(|| format!("failed to connect admin socket {}", sock.display()))?;
    stream.write_all(request.as_bytes()).await?;
    stream
        .write_all(
            b"
",
        )
        .await?;

    let mut line = String::new();
    let mut reader = BufReader::new(stream);
    reader.read_line(&mut line).await?;
    if line.trim().is_empty() {
        bail!("empty response from admin socket");
    }
    Ok(serde_json::from_str(line.trim())?)
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
    let runtime_state_path = state_dir.join("runtime.json");

    let cfg = load_runtime_config(explicit_config.as_deref())?;
    let control_sock_path = control_socket_path(&cfg, &state_dir);
    let name_registry_path = name_registry_path(explicit_config.as_deref())?;
    let runtime = NodeRuntime::new(cfg.clone());
    let handle = runtime.start();
    let dht = handle.dht();
    let cli_state = std::sync::Arc::new(Mutex::new(DhtCliState::default()));

    if std::fs::metadata(&control_sock_path).is_ok() {
        let _ = std::fs::remove_file(&control_sock_path);
    }
    let (admin_shutdown_tx, mut admin_shutdown_rx) = tokio::sync::watch::channel(false);
    let control_task = tokio::spawn(run_control_socket_server(
        control_sock_path.clone(),
        dht,
        cfg.identity.id.clone(),
        cli_state,
        name_registry_path,
        admin_shutdown_tx,
        handle.stats_arc(),
        std::process::id(),
    ));

    fs::write(&pid_path, std::process::id().to_string()).await?;
    let runtime_state = RuntimeStateFile {
        pid: std::process::id(),
        socket_path: control_sock_path.to_string_lossy().to_string(),
    };
    fs::write(&runtime_state_path, serde_json::to_vec(&runtime_state)?).await?;

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
            _ = admin_shutdown_rx.changed() => {
                if *admin_shutdown_rx.borrow() {
                    break;
                }
            }
        }
    }

    control_task.abort();
    handle.stop().await;
    let _ = fs::remove_file(&pid_path).await;
    let _ = fs::remove_file(&control_sock_path).await;
    let _ = fs::remove_file(&runtime_state_path).await;
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

fn name_registry_path(explicit_config: Option<&Path>) -> Result<PathBuf> {
    let cfg_path = resolve_config_path(explicit_config)?;
    let base = cfg_path.parent().unwrap_or_else(|| Path::new("."));
    Ok(base.join(".dsn-name-registry.json"))
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RuntimeStateFile {
    pid: u32,
    socket_path: String,
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

async fn load_name_registry(path: &Path) -> Result<HashMap<String, String>> {
    let Ok(raw) = fs::read(path).await else {
        return Ok(HashMap::new());
    };
    if raw.is_empty() {
        return Ok(HashMap::new());
    }
    Ok(serde_json::from_slice(&raw)?)
}

async fn save_name_registry(path: &Path, names: &HashMap<String, String>) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await?;
    }
    let payload = serde_json::to_vec(names)?;
    fs::write(path, payload).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{DhtCliState, handle_admin_request, state_dir_for};
    use anyhow::Result;
    use dsn_core::DhtRuntime;
    use dsn_core::RuntimeStats;
    use std::path::Path;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    async fn call_admin(
        request: &str,
        dht: Arc<Mutex<DhtRuntime>>,
        cli_state: Arc<Mutex<DhtCliState>>,
        registry_path: &Path,
    ) -> serde_json::Value {
        let (tx, _) = tokio::sync::watch::channel(false);
        handle_admin_request(
            request,
            dht,
            "node-a",
            cli_state,
            registry_path,
            tx,
            Arc::new(Mutex::new(RuntimeStats::default())),
            1,
        )
        .await
    }

    #[test]
    fn state_dir_is_adjacent_to_config() -> Result<()> {
        let dir = state_dir_for(Some(Path::new("/tmp/dsn/config.toml")), None)?;
        assert_eq!(dir, Path::new("/tmp/dsn/node-state"));
        Ok(())
    }

    #[tokio::test]
    async fn name_commands_are_backed_by_dht_runtime() {
        let registry_path = std::env::temp_dir().join(format!(
            "dsn-name-registry-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));

        let dht = Arc::new(Mutex::new(DhtRuntime::new([1; 32], true)));
        let cli_state = Arc::new(Mutex::new(DhtCliState::default()));

        let take = call_admin(
            "name take test",
            dht.clone(),
            cli_state.clone(),
            &registry_path,
        )
        .await;
        assert_eq!(take.get("ok").and_then(|v| v.as_bool()), Some(true));

        let get = call_admin(
            "name get test",
            dht.clone(),
            cli_state.clone(),
            &registry_path,
        )
        .await;
        assert_eq!(get.get("owner").and_then(|v| v.as_str()), Some("node-a"));

        let check = call_admin(
            "name check test",
            dht.clone(),
            cli_state.clone(),
            &registry_path,
        )
        .await;
        assert_eq!(
            check.get("available").and_then(|v| v.as_bool()),
            Some(false)
        );

        let dht_guard = dht.lock().await;
        assert_eq!(
            dht_guard.find_value("name", b"test").as_deref(),
            Some(b"node-a".as_slice())
        );

        let _ = tokio::fs::remove_file(&registry_path).await;
    }

    #[tokio::test]
    async fn admin_status_and_acl_commands_work() {
        let registry_path = std::env::temp_dir().join(format!(
            "dsn-admin-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));

        let dht = Arc::new(Mutex::new(DhtRuntime::new([2; 32], true)));
        let cli_state = Arc::new(Mutex::new(DhtCliState::default()));

        let status = call_admin("status", dht.clone(), cli_state.clone(), &registry_path).await;
        assert_eq!(status.get("pid").and_then(|v| v.as_u64()), Some(1));

        let add = call_admin(
            "whitelist add 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            dht.clone(),
            cli_state.clone(),
            &registry_path,
        )
        .await;
        assert_eq!(add.get("ok").and_then(|v| v.as_bool()), Some(true));

        let list = call_admin("whitelist list", dht, cli_state, &registry_path).await;
        assert_eq!(
            list.get("whitelist")
                .and_then(|v| v.as_array())
                .map(|a| a.len()),
            Some(1)
        );

        let _ = tokio::fs::remove_file(&registry_path).await;
    }

    #[tokio::test]
    async fn name_get_can_read_persisted_registry() {
        let registry_path = std::env::temp_dir().join(format!(
            "dsn-name-registry-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));

        let mut names = std::collections::HashMap::new();
        names.insert("shared".to_string(), "node-z".to_string());
        tokio::fs::write(
            &registry_path,
            serde_json::to_vec(&names).expect("serialize"),
        )
        .await
        .expect("write");

        let dht = Arc::new(Mutex::new(DhtRuntime::new([1; 32], true)));
        let cli_state = Arc::new(Mutex::new(DhtCliState::default()));

        let get = call_admin("name get shared", dht, cli_state, &registry_path).await;

        assert_eq!(get.get("owner").and_then(|v| v.as_str()), Some("node-z"));

        let _ = tokio::fs::remove_file(&registry_path).await;
    }
}

async fn run_control_socket_server(
    sock_path: PathBuf,
    dht: std::sync::Arc<Mutex<dsn_core::DhtRuntime>>,
    my_id: String,
    cli_state: std::sync::Arc<Mutex<DhtCliState>>,
    registry_path: PathBuf,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    stats: std::sync::Arc<Mutex<RuntimeStats>>,
    pid: u32,
) -> Result<()> {
    let listener = UnixListener::bind(&sock_path)
        .with_context(|| format!("failed to bind control socket {}", sock_path.display()))?;

    loop {
        let (stream, _) = listener.accept().await?;
        let dht = dht.clone();
        let my_id = my_id.clone();
        let cli_state = cli_state.clone();
        let registry_path = registry_path.clone();
        let shutdown_tx = shutdown_tx.clone();
        let stats = stats.clone();
        tokio::spawn(async move {
            let (read_half, mut write_half) = stream.into_split();
            let mut reader = BufReader::new(read_half);
            let mut line = String::new();
            let response = match reader.read_line(&mut line).await {
                Ok(0) => serde_json::json!({"error":"empty request"}),
                Ok(_) => {
                    handle_admin_request(
                        line.trim(),
                        dht,
                        &my_id,
                        cli_state,
                        &registry_path,
                        shutdown_tx,
                        stats,
                        pid,
                    )
                    .await
                }
                Err(e) => serde_json::json!({"error": format!("io error: {e}")}),
            };
            let _ = write_half
                .write_all(format!("{}\n", response).as_bytes())
                .await;
        });
    }
}

async fn handle_admin_request(
    request: &str,
    dht: std::sync::Arc<Mutex<dsn_core::DhtRuntime>>,
    my_id: &str,
    cli_state: std::sync::Arc<Mutex<DhtCliState>>,
    registry_path: &Path,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    stats: std::sync::Arc<Mutex<RuntimeStats>>,
    pid: u32,
) -> serde_json::Value {
    let parts: Vec<&str> = request.split_whitespace().collect();
    if parts.is_empty() {
        return serde_json::json!({"error":"empty request"});
    }

    match parts.as_slice() {
        ["status"] => {
            let snapshot = stats.lock().await.clone();
            serde_json::json!({
                "pid": pid,
                "active_sessions": snapshot.active_sessions,
                "published_identities": snapshot.published_identities,
                "last_tick_us": snapshot.last_tick_us,
                "listen_endpoints": snapshot.listen_endpoints,
                "bootstrap_peers": snapshot.bootstrap_peers
            })
        }
        ["shutdown"] => {
            let _ = shutdown_tx.send(true);
            serde_json::json!({"ok": true})
        }
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
            let dht_has_name = {
                let guard = dht.lock().await;
                guard.find_value("name", name.as_bytes()).is_some()
            };
            let registry = load_name_registry(registry_path).await.unwrap_or_default();
            let available = !dht_has_name && !registry.contains_key(*name);
            serde_json::json!({"available": available})
        }
        ["name", "get", name] => {
            let local_owner = {
                let guard = dht.lock().await;
                guard
                    .find_value("name", name.as_bytes())
                    .and_then(|v| String::from_utf8(v).ok())
            };

            if let Some(owner) = local_owner {
                return serde_json::json!({"name":name,"owner":owner});
            }

            let registry = load_name_registry(registry_path).await.unwrap_or_default();
            match registry.get(*name) {
                Some(owner) => serde_json::json!({"name":name,"owner":owner}),
                None => serde_json::json!({"error":"not found"}),
            }
        }
        ["name", "take", name] => {
            let mut guard = dht.lock().await;
            if guard.find_value("name", name.as_bytes()).is_some() {
                return serde_json::json!({"error":"name is already taken"});
            }

            let mut registry = load_name_registry(registry_path).await.unwrap_or_default();
            if registry.contains_key(*name) {
                return serde_json::json!({"error":"name is already taken"});
            }

            guard.store("name", name.as_bytes().to_vec(), my_id.as_bytes().to_vec());
            registry.insert((*name).to_string(), my_id.to_string());
            if let Err(err) = save_name_registry(registry_path, &registry).await {
                return serde_json::json!({"error": format!("failed to persist names: {err}")});
            }
            serde_json::json!({"ok":true,"name":name,"owner":my_id})
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

        ["whitelist", "list"] => {
            let mut out = cli_state
                .lock()
                .await
                .whitelist
                .iter()
                .cloned()
                .collect::<Vec<_>>();
            out.sort();
            serde_json::json!({"whitelist": out})
        }
        ["whitelist", "add", node_id] => {
            if node_id.len() != 64 || !node_id.chars().all(|c| c.is_ascii_hexdigit()) {
                return serde_json::json!({"error":"node_id must be 64 hex chars"});
            }
            cli_state
                .lock()
                .await
                .whitelist
                .insert((*node_id).to_string());
            serde_json::json!({"ok":true})
        }
        ["whitelist", "del", node_id] => {
            cli_state.lock().await.whitelist.remove(*node_id);
            serde_json::json!({"ok":true})
        }
        ["blacklist", "list"] => {
            let mut out = cli_state
                .lock()
                .await
                .blacklist
                .iter()
                .cloned()
                .collect::<Vec<_>>();
            out.sort();
            serde_json::json!({"blacklist": out})
        }
        ["blacklist", "add", node_id] => {
            if node_id.len() != 64 || !node_id.chars().all(|c| c.is_ascii_hexdigit()) {
                return serde_json::json!({"error":"node_id must be 64 hex chars"});
            }
            cli_state
                .lock()
                .await
                .blacklist
                .insert((*node_id).to_string());
            serde_json::json!({"ok":true})
        }
        ["blacklist", "del", node_id] => {
            cli_state.lock().await.blacklist.remove(*node_id);
            serde_json::json!({"ok":true})
        }
        _ => serde_json::json!({"error":"unknown command"}),
    }
}
