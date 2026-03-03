use crate::{
    DhtRuntime, DsnConfig, PUBLICATION_TTL_US, SessionPolicy, SessionState, TransportEndpoint,
    publish_public_identity,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, watch};
use tokio::task::JoinHandle;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuntimeStats {
    pub started_at_us: u64,
    pub last_tick_us: u64,
    pub listen_endpoints: usize,
    pub bootstrap_peers: usize,
    pub active_sessions: usize,
    pub published_identities: u64,
}

#[derive(Debug)]
pub struct NodeRuntime {
    cfg: DsnConfig,
    dht: Arc<Mutex<DhtRuntime>>,
    sessions: Arc<Mutex<HashMap<String, SessionState>>>,
    stats: Arc<Mutex<RuntimeStats>>,
}

pub struct NodeRuntimeHandle {
    shutdown_tx: watch::Sender<bool>,
    join_handles: Vec<JoinHandle<()>>,
    stats: Arc<Mutex<RuntimeStats>>,
    dht: Arc<Mutex<DhtRuntime>>,
}

impl NodeRuntime {
    pub fn new(cfg: DsnConfig) -> Self {
        let mut node_id = [0u8; 32];
        if let Some(bytes) = decode_hex_32(&cfg.identity.id) {
            node_id = bytes;
        }

        let now = now_us();
        Self {
            dht: Arc::new(Mutex::new(DhtRuntime::new(node_id, cfg.participate_in_dht))),
            cfg: cfg.clone(),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            stats: Arc::new(Mutex::new(RuntimeStats {
                started_at_us: now,
                last_tick_us: now,
                listen_endpoints: cfg.listen.len(),
                bootstrap_peers: cfg.bootstrap_peers.len(),
                active_sessions: 0,
                published_identities: 0,
            })),
        }
    }

    pub fn start(self) -> NodeRuntimeHandle {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut join_handles = Vec::new();
        let dht = self.dht.clone();

        join_handles.push(tokio::spawn(run_bootstrap_loop(
            self.cfg.bootstrap_peers.clone(),
            self.sessions.clone(),
            self.stats.clone(),
            shutdown_rx.clone(),
        )));

        join_handles.push(tokio::spawn(run_ping_loop(
            self.sessions.clone(),
            self.stats.clone(),
            shutdown_rx.clone(),
        )));

        join_handles.push(tokio::spawn(run_rekey_loop(
            self.sessions.clone(),
            self.stats.clone(),
            shutdown_rx.clone(),
        )));

        join_handles.push(tokio::spawn(run_dht_publication_loop(
            self.cfg.clone(),
            dht.clone(),
            self.stats.clone(),
            shutdown_rx,
        )));

        NodeRuntimeHandle {
            shutdown_tx,
            join_handles,
            stats: self.stats,
            dht,
        }
    }
}

impl NodeRuntimeHandle {
    pub async fn stop(mut self) {
        let _ = self.shutdown_tx.send(true);
        for j in self.join_handles.drain(..) {
            let _ = j.await;
        }
    }

    pub async fn snapshot(&self) -> RuntimeStats {
        self.stats.lock().await.clone()
    }

    pub fn dht(&self) -> Arc<Mutex<DhtRuntime>> {
        self.dht.clone()
    }
}

async fn run_bootstrap_loop(
    peers: Vec<TransportEndpoint>,
    sessions: Arc<Mutex<HashMap<String, SessionState>>>,
    stats: Arc<Mutex<RuntimeStats>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let mut guard = sessions.lock().await;
                for peer in &peers {
                    let key = endpoint_key(peer);
                    guard.entry(key).or_insert_with(|| SessionState::new(SessionPolicy::default(), 1, now_us()));
                }
                let mut st = stats.lock().await;
                st.last_tick_us = now_us();
                st.active_sessions = guard.len();
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }
}

async fn run_ping_loop(
    sessions: Arc<Mutex<HashMap<String, SessionState>>>,
    stats: Arc<Mutex<RuntimeStats>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    let mut request_id: u64 = 1;
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let now = now_us();
                let mut guard = sessions.lock().await;
                guard.retain(|_, session| {
                    let ping = session.track_ping(request_id, now);
                    request_id = request_id.saturating_add(1);
                    let pong = session.respond_pong(ping);
                    let _ = session.handle_pong(pong, now.saturating_add(100));
                    !session.is_timed_out(now)
                });
                let mut st = stats.lock().await;
                st.last_tick_us = now;
                st.active_sessions = guard.len();
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }
}

async fn run_rekey_loop(
    sessions: Arc<Mutex<HashMap<String, SessionState>>>,
    stats: Arc<Mutex<RuntimeStats>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    let mut request_id: u64 = 10_000;
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let now = now_us();
                let mut guard = sessions.lock().await;
                for session in guard.values_mut() {
                    if session.should_rekey(now) {
                        let req = session.build_session_change_request(request_id, session.active_key_id().saturating_add(1), now);
                        request_id = request_id.saturating_add(1);
                        let ack = session.accept_session_change_request(req);
                        let _ = session.handle_session_change_ack(ack, now.saturating_add(1));
                    }
                }
                stats.lock().await.last_tick_us = now;
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }
}

async fn run_dht_publication_loop(
    cfg: DsnConfig,
    dht: Arc<Mutex<DhtRuntime>>,
    stats: Arc<Mutex<RuntimeStats>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    let mut ip4_nonce = 0u32;
    let mut ip6_nonce = 0u128;
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let now = now_us();
                let mut dht_guard = dht.lock().await;
                dht_guard.expire_publications(now);
                let _ = publish_public_identity(&cfg, &mut dht_guard, &cfg.identity, ip4_nonce, ip6_nonce, now);
                ip4_nonce = ip4_nonce.saturating_add(1);
                ip6_nonce = ip6_nonce.saturating_add(1);
                let mut st = stats.lock().await;
                st.last_tick_us = now;
                st.published_identities = st.published_identities.saturating_add(1);
                if now.saturating_sub(st.started_at_us) > PUBLICATION_TTL_US {
                    st.started_at_us = now;
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }
}

fn endpoint_key(ep: &TransportEndpoint) -> String {
    format!(
        "{}://{}:{}{}",
        ep.scheme,
        ep.host,
        ep.port,
        ep.path.clone().unwrap_or_default()
    )
}

fn decode_hex_32(raw: &str) -> Option<[u8; 32]> {
    if raw.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let part = &raw[i * 2..i * 2 + 2];
        out[i] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(out)
}

fn now_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

#[cfg(test)]
mod tests {
    use super::NodeRuntime;
    use crate::DsnConfig;
    use anyhow::Result;
    use tokio::time::{Duration, sleep};

    #[tokio::test]
    async fn runtime_ticks_and_populates_sessions() -> Result<()> {
        let mut cfg = DsnConfig::default_with_generated_identity()?;
        cfg.bootstrap_peers = vec![
            "tcp://127.0.0.1:10001".parse()?,
            "tcp://127.0.0.1:10002".parse()?,
        ];

        let runtime = NodeRuntime::new(cfg);
        let handle = runtime.start();
        sleep(Duration::from_secs(6)).await;
        let stats = handle.snapshot().await;
        assert!(stats.active_sessions >= 2);
        handle.stop().await;
        Ok(())
    }
}
