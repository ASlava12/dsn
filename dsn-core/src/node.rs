use crate::config::AddressMode as ConfigAddressMode;
use crate::transport::AddressMode as HsAddressMode;
use crate::transport::{SessionStore, SessionStoreKind};
use crate::{
    ControlMessage, ControlMsgType, ControlPing, ControlPong, ControlSessionChangeAck,
    ControlSessionChangeRequest, CreateRouteRequest, DhtRuntime, DsnConfig, MuxConfig, PeerLinks,
    PeerLinksMode, PowChallenge, PowScope, REKEY_ACK_OK, REKEY_ACK_REJECTED, RekeyReason,
    RouteManager, RouteStorageKind, SessionPolicy, SessionState, TokenBucket, TransportEndpoint,
    publish_public_identity, transport_for_scheme, verify_pow,
};
use anyhow::{Result, anyhow};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, RwLock, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tracing::info;

use crate::{
    HANDSHAKE_V1_VERSION, HandshakeConfig, SessionKeys, build_client_hello, handle_client_hello,
    handle_server_hello, server_session_keys, verify_finished,
};

const DHT_NAMESPACE_MAIN: u32 = 0;
const DHT_FLAG_RESPONSE: u16 = 0x1;
const DHT_MSG_TYPE_MIN: u16 = ControlMsgType::FindNode as u16;
const DHT_MSG_TYPE_MAX: u16 = ControlMsgType::NodeContact as u16;
const NODE_CONTACT_FLAG_REQUEST: u16 = 0;
const NODE_CONTACT_FLAG_CHALLENGE: u16 = 1;
const NODE_CONTACT_FLAG_SOLUTION: u16 = 2;
const NODE_CONTACT_FLAG_RESPONSE: u16 = 3;
const NODE_CONTACT_CHALLENGE_TTL_US: u64 = 30_000_000;
const NODE_CONTACT_DIFFICULTY: u8 = 18;
const NET_MSG_CREATE_ROUTE_REQUEST: u16 = 0x0200;
const NET_MSG_CREATE_ROUTE_RESPONSE: u16 = 0x0201;
const NET_MSG_ROUTE_SEND_NODE: u16 = 0x0202;
const DATA_MSG_ROUTE_SEND_IP4: u16 = 0x0300;
const DATA_MSG_ROUTE_SEND_IP6: u16 = 0x0301;
const DHT_NAMESPACE_IP4: &str = "ip4";
const DHT_NAMESPACE_IP6: &str = "ip6";
const SESSION_STORE_FLUSH_INTERVAL_SECS: u64 = 10;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuntimeStats {
    pub started_at_us: u64,
    pub last_tick_us: u64,
    pub listen_endpoints: usize,
    pub bootstrap_peers: usize,
    pub active_sessions: usize,
    pub published_identities: u64,
    pub rekey_started: u64,
    pub rekey_completed: u64,
    pub rekey_by_bytes: u64,
    pub rekey_by_age: u64,
    pub route_forwarded: u64,
    pub route_delivered: u64,
    pub dropped_frames_total: u64,
    pub dropped_control_frames: u64,
    pub dropped_net_frames: u64,
    pub dropped_data_frames: u64,
    pub queue_depth_control: u64,
    pub queue_depth_net: u64,
    pub queue_depth_data: u64,
    pub rtt_last_us: u64,
    pub rtt_avg_us: u64,
    pub rtt_samples: u64,
}

struct ReplayWindow {
    max_seen: u64,
    bits: u128,
}

impl ReplayWindow {
    fn new() -> Self {
        Self {
            max_seen: 0,
            bits: 0,
        }
    }

    fn accept(&mut self, seq: u64) -> bool {
        if self.max_seen == 0 {
            self.max_seen = seq;
            self.bits = 1;
            return true;
        }
        if seq > self.max_seen {
            let shift = (seq - self.max_seen).min(128) as u32;
            self.bits = if shift >= 128 {
                1
            } else {
                (self.bits << shift) | 1
            };
            self.max_seen = seq;
            return true;
        }

        let delta = self.max_seen - seq;
        if delta >= 128 {
            return false;
        }
        let mask = 1u128 << delta;
        if self.bits & mask != 0 {
            return false;
        }
        self.bits |= mask;
        true
    }
}

struct PeerRuntime {
    links: Arc<PeerLinks>,
    session: Arc<Mutex<SessionState>>,
    keys: Arc<Mutex<SessionKeys>>,
    replay: Arc<Mutex<ReplayWindow>>,
    send_seq: AtomicU64,
    peer_verify_key: VerifyingKey,
    peer_node_id: [u8; 32],
    pending_rekey: Arc<Mutex<Option<PendingRekeyKeys>>>,
    stats: Arc<Mutex<RuntimeStats>>,
}

struct DhtRequestManager {
    pending_find_node: Mutex<HashMap<u64, oneshot::Sender<Vec<[u8; 32]>>>>,
    next_request_id: AtomicU64,
    rate_window_start_us: Mutex<u64>,
    rate_counter: Mutex<u32>,
    pending_node_contact_challenge: Mutex<HashMap<u64, oneshot::Sender<crate::NodeContact>>>,
    pending_node_contact_response: Mutex<HashMap<u64, oneshot::Sender<crate::NodeContact>>>,
}

impl DhtRequestManager {
    fn new() -> Self {
        Self {
            pending_find_node: Mutex::new(HashMap::new()),
            next_request_id: AtomicU64::new(1_000_000),
            rate_window_start_us: Mutex::new(0),
            rate_counter: Mutex::new(0),
            pending_node_contact_challenge: Mutex::new(HashMap::new()),
            pending_node_contact_response: Mutex::new(HashMap::new()),
        }
    }

    fn next_request_id(&self) -> u64 {
        self.next_request_id.fetch_add(1, Ordering::Relaxed)
    }

    async fn allow_send(&self, now_us: u64) -> bool {
        let mut ws = self.rate_window_start_us.lock().await;
        let mut cnt = self.rate_counter.lock().await;
        if now_us.saturating_sub(*ws) > 1_000_000 {
            *ws = now_us;
            *cnt = 0;
        }
        if *cnt >= 64 {
            return false;
        }
        *cnt += 1;
        true
    }
}

struct PendingRekeyKeys {
    request_id: u64,
    new_key_id: u32,
    keys: SessionKeys,
}

struct NodeContactChallengeState {
    peer_node_id: [u8; 32],
    request_id: u64,
    seed: [u8; 32],
    difficulty: u8,
    expires_at_us: u64,
    issued_key_id: u32,
    used: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct RouteCreateWire {
    session_id: [u8; 32],
    src_node_id: [u8; 32],
    dst_node_id: [u8; 32],
    next_hop_node_id: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct RouteCreateResponseWire {
    session_id: [u8; 32],
    status: u8,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct RouteSendNodeWire {
    session_id: [u8; 32],
    dst_node_id: [u8; 32],
    payload: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct RouteSendIpWire {
    session_id: [u8; 32],
    ip: String,
    payload: Vec<u8>,
}

struct TunRuntime {
    ingress_tx: mpsc::Sender<Vec<u8>>,
    ingress_rx: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
    egress_tx: mpsc::Sender<Vec<u8>>,
    egress_rx: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
}

pub struct NodeRuntime {
    cfg: DsnConfig,
    dht: Arc<Mutex<DhtRuntime>>,
    peers: Arc<RwLock<HashMap<String, Arc<PeerRuntime>>>>,
    stats: Arc<Mutex<RuntimeStats>>,
    signing: SigningKey,
    verifying: VerifyingKey,
    node_id: [u8; 32],
    peer_tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
    dht_requests: Arc<DhtRequestManager>,
    dht_inbound_bucket: Arc<Mutex<TokenBucket>>,
    node_contact_challenges: Arc<Mutex<HashMap<[u8; 32], NodeContactChallengeState>>>,
    node_contact_bucket: Arc<Mutex<TokenBucket>>,
    route_manager: Arc<Mutex<RouteManager>>,
    tun: Option<Arc<TunRuntime>>,
    session_store: Arc<dyn SessionStore>,
}

pub struct NodeRuntimeHandle {
    shutdown_tx: watch::Sender<bool>,
    join_handles: Vec<JoinHandle<()>>,
    stats: Arc<Mutex<RuntimeStats>>,
    dht: Arc<Mutex<DhtRuntime>>,
    peer_tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
    peers: Arc<RwLock<HashMap<String, Arc<PeerRuntime>>>>,
    dht_requests: Arc<DhtRequestManager>,
    node_id: [u8; 32],
    tun_ingress_tx: Option<mpsc::Sender<Vec<u8>>>,
    tun_egress_rx: Option<Arc<Mutex<mpsc::Receiver<Vec<u8>>>>>,
}

impl NodeRuntime {
    pub fn new(cfg: DsnConfig) -> Self {
        let node_id = decode_hex_32(&cfg.identity.id).unwrap_or([0; 32]);
        let signing = decode_signing_key(&cfg.identity.private_key).expect("valid private key");
        let verifying = signing.verifying_key();
        let now = now_us();
        let session_store = build_session_store(&cfg).expect("valid session store config");
        let tun = if cfg.tun_enabled {
            let (ingress_tx, ingress_rx) = mpsc::channel(256);
            let (egress_tx, egress_rx) = mpsc::channel(256);
            Some(Arc::new(TunRuntime {
                ingress_tx,
                ingress_rx: Arc::new(Mutex::new(ingress_rx)),
                egress_tx,
                egress_rx: Arc::new(Mutex::new(egress_rx)),
            }))
        } else {
            None
        };
        Self {
            dht: Arc::new(Mutex::new(DhtRuntime::new(node_id, cfg.participate_in_dht))),
            cfg: cfg.clone(),
            peers: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(Mutex::new(RuntimeStats {
                started_at_us: now,
                last_tick_us: now,
                listen_endpoints: cfg.listen.len(),
                bootstrap_peers: cfg.bootstrap_peers.len(),
                active_sessions: 0,
                published_identities: 0,
                rekey_started: 0,
                rekey_completed: 0,
                rekey_by_bytes: 0,
                rekey_by_age: 0,
                route_forwarded: 0,
                route_delivered: 0,
                dropped_frames_total: 0,
                dropped_control_frames: 0,
                dropped_net_frames: 0,
                dropped_data_frames: 0,
                queue_depth_control: 0,
                queue_depth_net: 0,
                queue_depth_data: 0,
                rtt_last_us: 0,
                rtt_avg_us: 0,
                rtt_samples: 0,
            })),
            signing,
            verifying,
            node_id,
            peer_tasks: Arc::new(Mutex::new(Vec::new())),
            dht_requests: Arc::new(DhtRequestManager::new()),
            dht_inbound_bucket: Arc::new(Mutex::new(TokenBucket::new(256, 128, now))),
            node_contact_challenges: Arc::new(Mutex::new(HashMap::new())),
            node_contact_bucket: Arc::new(Mutex::new(TokenBucket::new(32, 16, now))),
            route_manager: Arc::new(Mutex::new(init_route_manager(&cfg))),
            tun,
            session_store,
        }
    }

    pub fn start(self) -> NodeRuntimeHandle {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut join_handles = Vec::new();
        let shared = Arc::new(self);

        join_handles.push(tokio::spawn(run_listeners_loop(
            shared.clone(),
            shutdown_rx.clone(),
        )));
        join_handles.push(tokio::spawn(run_outbound_dial_loop(
            shared.clone(),
            shutdown_rx.clone(),
        )));
        join_handles.push(tokio::spawn(run_ping_loop(
            shared.clone(),
            shutdown_rx.clone(),
        )));
        join_handles.push(tokio::spawn(run_rekey_loop(
            shared.clone(),
            shutdown_rx.clone(),
        )));
        join_handles.push(tokio::spawn(run_dht_publication_loop(
            shared.cfg.clone(),
            shared.dht.clone(),
            shared.stats.clone(),
            shutdown_rx.clone(),
        )));
        if shared.cfg.tun_enabled {
            join_handles.push(tokio::spawn(run_tun_loop(
                shared.clone(),
                shutdown_rx.clone(),
            )));
        }
        join_handles.push(tokio::spawn(run_session_store_flush_loop(
            shared.clone(),
            shutdown_rx,
        )));

        NodeRuntimeHandle {
            shutdown_tx,
            join_handles,
            stats: shared.stats.clone(),
            dht: shared.dht.clone(),
            peer_tasks: shared.peer_tasks.clone(),
            peers: shared.peers.clone(),
            dht_requests: shared.dht_requests.clone(),
            node_id: shared.node_id,
            tun_ingress_tx: shared.tun.as_ref().map(|t| t.ingress_tx.clone()),
            tun_egress_rx: shared.tun.as_ref().map(|t| t.egress_rx.clone()),
        }
    }
}

impl NodeRuntimeHandle {
    pub async fn stop(mut self) {
        let _ = self.shutdown_tx.send(true);
        for t in self.peer_tasks.lock().await.drain(..) {
            t.abort();
        }
        for j in self.join_handles.drain(..) {
            let _ = j.await;
        }
    }

    pub async fn snapshot(&self) -> RuntimeStats {
        self.stats.lock().await.clone()
    }

    pub fn stats_arc(&self) -> Arc<Mutex<RuntimeStats>> {
        self.stats.clone()
    }

    pub fn dht(&self) -> Arc<Mutex<DhtRuntime>> {
        self.dht.clone()
    }

    pub async fn dht_find_node(&self, target_id: [u8; 32], max: usize) -> Result<Vec<[u8; 32]>> {
        let peers = self.peers.read().await;
        let Some(peer) = peers.values().next().cloned() else {
            return Err(anyhow!("no active peers for dht query"));
        };
        drop(peers);

        for _ in 0..=2 {
            let now = now_us();
            if !self.dht_requests.allow_send(now).await {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }

            let request_id = self.dht_requests.next_request_id();
            let (tx, rx) = oneshot::channel();
            self.dht_requests
                .pending_find_node
                .lock()
                .await
                .insert(request_id, tx);

            let msg = ControlMessage::FindNode(crate::FindNode {
                request_id,
                flags: 0,
                error_code: 0,
                namespace_id: DHT_NAMESPACE_MAIN,
                target_node_id: target_id,
            });

            if send_control(peer.clone(), msg).await.is_err() {
                let _ = self
                    .dht_requests
                    .pending_find_node
                    .lock()
                    .await
                    .remove(&request_id);
                continue;
            }

            if let Ok(Ok(nodes)) = tokio::time::timeout(Duration::from_millis(800), rx).await {
                return Ok(nodes.into_iter().take(max).collect());
            }

            let _ = self
                .dht_requests
                .pending_find_node
                .lock()
                .await
                .remove(&request_id);
        }

        Err(anyhow!("dht FIND_NODE timeout after retries"))
    }

    pub async fn node_contact_request(&self, target_node_id: [u8; 32]) -> Result<Vec<u8>> {
        let challenge = self.node_contact_get_challenge(target_node_id).await?;
        let difficulty = challenge.error_code as u8;
        let expires_at_us = parse_u64_payload(&challenge.payload)?;
        let solution_nonce = solve_node_contact_pow(
            self.node_id,
            challenge.node_id_contact,
            challenge.request_id,
            challenge.nonce,
            difficulty,
            expires_at_us,
        )
        .ok_or_else(|| anyhow!("unable to solve NODE_CONTACT pow before deadline"))?;
        self.node_contact_submit_solution(target_node_id, challenge, solution_nonce)
            .await
    }

    pub async fn node_contact_get_challenge(
        &self,
        target_node_id: [u8; 32],
    ) -> Result<crate::NodeContact> {
        let peers = self.peers.read().await;
        let Some(peer) = peers.values().next().cloned() else {
            return Err(anyhow!("no active peers for NODE_CONTACT"));
        };
        drop(peers);

        let request_id = self.dht_requests.next_request_id();
        let (challenge_tx, challenge_rx) = oneshot::channel();
        self.dht_requests
            .pending_node_contact_challenge
            .lock()
            .await
            .insert(request_id, challenge_tx);

        let request = ControlMessage::NodeContact(crate::NodeContact {
            request_id,
            flags: NODE_CONTACT_FLAG_REQUEST,
            error_code: 0,
            node_id_contact: target_node_id,
            nonce: [0u8; 32],
            payload: Vec::new(),
        });
        send_control(peer.clone(), request).await?;

        let challenge = tokio::time::timeout(Duration::from_millis(1200), challenge_rx)
            .await
            .map_err(|_| anyhow!("NODE_CONTACT challenge timeout"))??;
        if challenge.flags != NODE_CONTACT_FLAG_CHALLENGE {
            return Err(anyhow!("expected NODE_CONTACT challenge"));
        }
        Ok(challenge)
    }

    pub async fn node_contact_submit_solution(
        &self,
        target_node_id: [u8; 32],
        challenge: crate::NodeContact,
        solution_nonce: u64,
    ) -> Result<Vec<u8>> {
        let peers = self.peers.read().await;
        let Some(peer) = peers.values().next().cloned() else {
            return Err(anyhow!("no active peers for NODE_CONTACT"));
        };
        drop(peers);

        let (resp_tx, resp_rx) = oneshot::channel();
        self.dht_requests
            .pending_node_contact_response
            .lock()
            .await
            .insert(challenge.request_id, resp_tx);
        let solve = ControlMessage::NodeContact(crate::NodeContact {
            request_id: challenge.request_id,
            flags: NODE_CONTACT_FLAG_SOLUTION,
            error_code: 0,
            node_id_contact: target_node_id,
            nonce: challenge.nonce,
            payload: solution_nonce.to_be_bytes().to_vec(),
        });
        send_control(peer, solve).await?;

        let response = tokio::time::timeout(Duration::from_millis(1200), resp_rx)
            .await
            .map_err(|_| anyhow!("NODE_CONTACT response timeout"))??;
        if response.flags != NODE_CONTACT_FLAG_RESPONSE {
            return Err(anyhow!("NODE_CONTACT denied or invalid response"));
        }
        Ok(response.payload)
    }

    pub async fn send_tun_packet(&self, packet: Vec<u8>) -> Result<()> {
        let Some(tx) = &self.tun_ingress_tx else {
            return Err(anyhow!("tun is not enabled"));
        };
        tx.send(packet)
            .await
            .map_err(|_| anyhow!("tun ingress closed"))
    }

    pub async fn recv_tun_packet(&self, timeout: Duration) -> Result<Vec<u8>> {
        let Some(rx) = &self.tun_egress_rx else {
            return Err(anyhow!("tun is not enabled"));
        };
        let mut guard = rx.lock().await;
        let maybe = tokio::time::timeout(timeout, guard.recv())
            .await
            .map_err(|_| anyhow!("tun egress timeout"))?;
        maybe.ok_or_else(|| anyhow!("tun egress closed"))
    }

    pub async fn create_route_via_first_peer(
        &self,
        session_id: [u8; 32],
        dst_node_id: [u8; 32],
        next_hop_node_id: [u8; 32],
    ) -> Result<()> {
        let peers = self.peers.read().await;
        let Some(peer) = peers.values().next().cloned() else {
            return Err(anyhow!("no active peers for route create"));
        };
        drop(peers);

        let wire = RouteCreateWire {
            session_id,
            src_node_id: self.node_id,
            dst_node_id,
            next_hop_node_id,
        };
        send_net(
            peer,
            NET_MSG_CREATE_ROUTE_REQUEST,
            serde_json::to_vec(&wire)?,
        )
        .await
    }

    pub async fn route_send_node_via_first_peer(
        &self,
        session_id: [u8; 32],
        dst_node_id: [u8; 32],
        payload: Vec<u8>,
    ) -> Result<()> {
        let peers = self.peers.read().await;
        let Some(peer) = peers.values().next().cloned() else {
            return Err(anyhow!("no active peers for route send"));
        };
        drop(peers);

        let wire = RouteSendNodeWire {
            session_id,
            dst_node_id,
            payload,
        };
        send_net(peer, NET_MSG_ROUTE_SEND_NODE, serde_json::to_vec(&wire)?).await
    }
}

async fn run_listeners_loop(runtime: Arc<NodeRuntime>, mut shutdown: watch::Receiver<bool>) {
    let mut tasks = Vec::new();
    for endpoint in runtime.cfg.listen.clone() {
        let rt = runtime.clone();
        let mut srx = shutdown.clone();
        tasks.push(tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = srx.changed() => {
                        if *srx.borrow() { break; }
                    }
                    accepted = accept_once(&rt, &endpoint) => {
                        if let Ok(peer) = accepted {
                            let key = format!("inbound-{}", now_us());
                            rt.peers.write().await.insert(key.clone(), peer.clone());
                            let task = tokio::spawn(run_peer_read_loop(rt.clone(), peer, key));
                            rt.peer_tasks.lock().await.push(task);
                            rt.stats.lock().await.active_sessions = rt.peers.read().await.len();
                        }
                    }
                }
            }
        }));
    }
    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            break;
        }
    }
    for t in tasks {
        t.abort();
    }
}

async fn accept_once(
    runtime: &Arc<NodeRuntime>,
    endpoint: &TransportEndpoint,
) -> Result<Arc<PeerRuntime>> {
    let transport = transport_for_scheme(endpoint.scheme)?;
    let conn = transport.listen(endpoint).await?;
    let stream = match conn {
        crate::Connection::Stream(s) => s,
        crate::Connection::Datagram(_) => {
            return Err(anyhow!("datagram listener unsupported in node mux"));
        }
    };
    handshake_and_build_peer(runtime.clone(), stream, false).await
}

async fn run_outbound_dial_loop(runtime: Arc<NodeRuntime>, mut shutdown: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(Duration::from_secs(2));
    loop {
        tokio::select! {
            _ = interval.tick() => {
                for endpoint in &runtime.cfg.bootstrap_peers {
                    let key = endpoint_key(endpoint);
                    if runtime.peers.read().await.contains_key(&key) {
                        continue;
                    }
                    let transport = match transport_for_scheme(endpoint.scheme) {
                        Ok(t) => t,
                        Err(_) => continue,
                    };
                    let conn = match transport.connect(endpoint).await {
                        Ok(c) => c,
                        Err(_) => continue,
                    };
                    let stream = match conn {
                        crate::Connection::Stream(s) => s,
                        crate::Connection::Datagram(_) => continue,
                    };
                    if let Ok(peer) = handshake_and_build_peer(runtime.clone(), stream, true).await {
                        runtime.peers.write().await.insert(key.clone(), peer.clone());
                        let task = tokio::spawn(run_peer_read_loop(runtime.clone(), peer, key));
                        runtime.peer_tasks.lock().await.push(task);
                        runtime.stats.lock().await.active_sessions = runtime.peers.read().await.len();
                    }
                }
                runtime.stats.lock().await.last_tick_us = now_us();
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }
}

async fn handshake_and_build_peer(
    runtime: Arc<NodeRuntime>,
    mut stream: crate::BoxedStreamConn,
    outbound: bool,
) -> Result<Arc<PeerRuntime>> {
    let keys;
    let peer_verify_key;
    let peer_node_id;
    if outbound {
        let cfg = handshake_config(&runtime);
        let (client_state, hello) = build_client_hello(&runtime.signing, cfg)?;
        stream.write_all(&runtime.verifying.to_bytes()).await?;
        write_client_hello(&mut stream, &hello).await?;

        let mut remote_vk = [0u8; 32];
        stream.read_exact(&mut remote_vk).await?;
        let server_vk =
            VerifyingKey::from_bytes(&remote_vk).map_err(|_| anyhow!("invalid server key"))?;
        let server_hello = read_server_hello(&mut stream).await?;
        let (session_keys, finished) =
            handle_server_hello(client_state, &server_hello, &server_vk)?;
        write_finished(&mut stream, &finished).await?;
        keys = session_keys;
        peer_verify_key = server_vk;
        peer_node_id = server_hello.config.node_id;
    } else {
        let mut remote_vk = [0u8; 32];
        stream.read_exact(&mut remote_vk).await?;
        let client_vk =
            VerifyingKey::from_bytes(&remote_vk).map_err(|_| anyhow!("invalid client key"))?;
        let client_hello = read_client_hello(&mut stream).await?;
        let (server_state, server_hello) = handle_client_hello(
            &client_hello,
            &client_vk,
            &runtime.signing,
            handshake_config(&runtime),
        )?;
        stream.write_all(&runtime.verifying.to_bytes()).await?;
        write_server_hello(&mut stream, &server_hello).await?;
        let finished = read_finished(&mut stream).await?;
        verify_finished(&server_state, &finished)?;
        keys = server_session_keys(&server_state);
        peer_verify_key = client_vk;
        peer_node_id = client_hello.config.node_id;
    }

    let links = Arc::new(PeerLinks::single_mux(stream, MuxConfig::default()));
    let initial_session = restored_or_new_session_state(&runtime, peer_node_id, now_us());
    let peer = Arc::new(PeerRuntime {
        links: links.clone(),
        session: Arc::new(Mutex::new(initial_session)),
        keys: Arc::new(Mutex::new(keys)),
        replay: Arc::new(Mutex::new(ReplayWindow::new())),
        send_seq: AtomicU64::new(1),
        peer_verify_key,
        peer_node_id,
        pending_rekey: Arc::new(Mutex::new(None)),
        stats: runtime.stats.clone(),
    });
    Ok(peer)
}

async fn note_drop(peer: &PeerRuntime, class: crate::FrameClass) {
    let mut st = peer.stats.lock().await;
    st.dropped_frames_total = st.dropped_frames_total.saturating_add(1);
    match class {
        crate::FrameClass::Control => {
            st.dropped_control_frames = st.dropped_control_frames.saturating_add(1)
        }
        crate::FrameClass::Net => st.dropped_net_frames = st.dropped_net_frames.saturating_add(1),
        crate::FrameClass::Data => {
            st.dropped_data_frames = st.dropped_data_frames.saturating_add(1)
        }
    }
}

async fn run_peer_read_loop(runtime: Arc<NodeRuntime>, peer: Arc<PeerRuntime>, peer_key: String) {
    while let Ok(frame) = peer.links.recv().await {
        let aad = build_aad(frame.class as u8, frame.msg_type, frame.flags);
        let enc = match decode_encrypted_payload(&frame.payload) {
            Ok(v) => v,
            Err(_) => {
                note_drop(&peer, frame.class).await;
                continue;
            }
        };

        let now = now_us();
        {
            let sess = peer.session.lock().await;
            if !sess.can_accept_key_id(enc.key_id, now) {
                note_drop(&peer, frame.class).await;
                continue;
            }
        }
        if !peer.replay.lock().await.accept(enc.seq) {
            note_drop(&peer, frame.class).await;
            continue;
        }
        let keys = { peer.keys.lock().await.clone() };
        let plain = match crate::decrypt_frame(&keys, &enc, &aad) {
            Ok(v) => v,
            Err(_) => {
                note_drop(&peer, frame.class).await;
                continue;
            }
        };

        if frame.class == crate::FrameClass::Control
            && let Ok(msg) = ControlMessage::decode(&plain)
        {
            handle_control_message(runtime.clone(), peer.clone(), msg).await;
        } else if frame.class == crate::FrameClass::Net {
            handle_net_message(runtime.clone(), peer.clone(), frame.msg_type, &plain).await;
        } else if frame.class == crate::FrameClass::Data {
            handle_data_message(runtime.clone(), peer.clone(), frame.msg_type, &plain).await;
        }
    }

    runtime.peers.write().await.remove(&peer_key);
    let _ = runtime.session_store.delete(peer.peer_node_id);
    runtime.stats.lock().await.active_sessions = runtime.peers.read().await.len();
}

async fn handle_control_message(
    runtime: Arc<NodeRuntime>,
    peer: Arc<PeerRuntime>,
    msg: ControlMessage,
) {
    match msg {
        ControlMessage::Ping(p) => {
            let pong = ControlMessage::Pong(ControlPong {
                request_id: p.request_id,
                responder_node_id: runtime.node_id,
            });
            let _ = send_control(peer, pong).await;
        }
        ControlMessage::Pong(p) => {
            let mut sess = peer.session.lock().await;
            if let Ok(rtt_us) = sess.handle_pong(
                crate::Pong {
                    request_id: p.request_id,
                },
                now_us(),
            ) {
                let mut st = runtime.stats.lock().await;
                st.rtt_last_us = rtt_us;
                st.rtt_samples = st.rtt_samples.saturating_add(1);
                if st.rtt_samples == 1 {
                    st.rtt_avg_us = rtt_us;
                } else {
                    st.rtt_avg_us = ((st.rtt_avg_us as u128 * (st.rtt_samples - 1) as u128)
                        .saturating_add(rtt_us as u128)
                        / st.rtt_samples as u128) as u64;
                }
            }
        }
        ControlMessage::SessionChangeRequest(req) => {
            handle_rekey_request(runtime, peer, req).await;
        }
        ControlMessage::SessionChangeAck(ack) => {
            handle_rekey_ack(runtime, peer, ack).await;
        }
        ControlMessage::FindNode(msg) => {
            if runtime
                .dht_inbound_bucket
                .lock()
                .await
                .try_consume(now_us(), 1)
                .is_err()
            {
                note_drop(&peer, crate::FrameClass::Control).await;
                return;
            }
            handle_dht_find_node(runtime, peer, msg).await;
        }
        ControlMessage::FindValue(msg) => {
            if runtime
                .dht_inbound_bucket
                .lock()
                .await
                .try_consume(now_us(), 1)
                .is_err()
            {
                note_drop(&peer, crate::FrameClass::Control).await;
                return;
            }
            handle_dht_find_value(runtime, peer, msg).await;
        }
        ControlMessage::Store(msg) => {
            if runtime
                .dht_inbound_bucket
                .lock()
                .await
                .try_consume(now_us(), 1)
                .is_err()
            {
                note_drop(&peer, crate::FrameClass::Control).await;
                return;
            }
            handle_dht_store(runtime, peer, msg).await;
        }
        ControlMessage::Delete(msg) => {
            if runtime
                .dht_inbound_bucket
                .lock()
                .await
                .try_consume(now_us(), 1)
                .is_err()
            {
                note_drop(&peer, crate::FrameClass::Control).await;
                return;
            }
            handle_dht_delete(runtime, peer, msg).await;
        }
        ControlMessage::NodeContact(msg) => {
            handle_dht_node_contact(runtime, peer, msg).await;
        }
    }
}

async fn handle_dht_find_node(
    runtime: Arc<NodeRuntime>,
    peer: Arc<PeerRuntime>,
    msg: crate::FindNode,
) {
    runtime.dht.lock().await.add_known_node(peer.peer_node_id);

    if msg.flags & DHT_FLAG_RESPONSE != 0 {
        if let Some(tx) = runtime
            .dht_requests
            .pending_find_node
            .lock()
            .await
            .remove(&msg.request_id)
        {
            let _ = tx.send(vec![msg.target_node_id]);
        }
        return;
    }

    let nearest = runtime.dht.lock().await.find_node(msg.target_node_id, 1);
    let response_id = nearest.first().copied().unwrap_or([0u8; 32]);
    let response = ControlMessage::FindNode(crate::FindNode {
        request_id: msg.request_id,
        flags: DHT_FLAG_RESPONSE,
        error_code: 0,
        namespace_id: msg.namespace_id,
        target_node_id: response_id,
    });
    let _ = send_control(peer, response).await;
}

async fn handle_dht_find_value(
    runtime: Arc<NodeRuntime>,
    peer: Arc<PeerRuntime>,
    msg: crate::FindValue,
) {
    runtime.dht.lock().await.add_known_node(peer.peer_node_id);
    if msg.flags & DHT_FLAG_RESPONSE == 0 {
        let value = runtime
            .dht
            .lock()
            .await
            .find_value("main", &msg.key)
            .unwrap_or_default();
        let response = ControlMessage::Store(crate::Store {
            request_id: msg.request_id,
            namespace_id: msg.namespace_id,
            flags: DHT_FLAG_RESPONSE,
            error_code: 0,
            key: msg.key,
            value,
            signature: Vec::new(),
        });
        let _ = send_control(peer, response).await;
    }
}

async fn handle_dht_store(runtime: Arc<NodeRuntime>, peer: Arc<PeerRuntime>, msg: crate::Store) {
    runtime.dht.lock().await.add_known_node(peer.peer_node_id);
    if msg.flags & DHT_FLAG_RESPONSE == 0 {
        runtime.dht.lock().await.store("main", msg.key, msg.value);
        let ack = ControlMessage::Store(crate::Store {
            request_id: msg.request_id,
            namespace_id: msg.namespace_id,
            flags: DHT_FLAG_RESPONSE,
            error_code: 0,
            key: Vec::new(),
            value: Vec::new(),
            signature: Vec::new(),
        });
        let _ = send_control(peer, ack).await;
    }
}

async fn handle_dht_delete(runtime: Arc<NodeRuntime>, peer: Arc<PeerRuntime>, msg: crate::Delete) {
    runtime.dht.lock().await.add_known_node(peer.peer_node_id);
    if msg.flags & DHT_FLAG_RESPONSE == 0 {
        let _ = runtime.dht.lock().await.delete("main", &msg.key);
        let ack = ControlMessage::Delete(crate::Delete {
            request_id: msg.request_id,
            namespace_id: msg.namespace_id,
            flags: DHT_FLAG_RESPONSE,
            error_code: 0,
            key: Vec::new(),
            value: Vec::new(),
            signature: Vec::new(),
        });
        let _ = send_control(peer, ack).await;
    }
}

async fn handle_dht_node_contact(
    runtime: Arc<NodeRuntime>,
    peer: Arc<PeerRuntime>,
    msg: crate::NodeContact,
) {
    if msg.flags == NODE_CONTACT_FLAG_CHALLENGE {
        if let Some(tx) = runtime
            .dht_requests
            .pending_node_contact_challenge
            .lock()
            .await
            .remove(&msg.request_id)
        {
            let _ = tx.send(msg);
        }
        return;
    }
    if msg.flags == NODE_CONTACT_FLAG_RESPONSE {
        if let Some(tx) = runtime
            .dht_requests
            .pending_node_contact_response
            .lock()
            .await
            .remove(&msg.request_id)
        {
            let _ = tx.send(msg);
        }
        return;
    }

    if msg.flags == NODE_CONTACT_FLAG_REQUEST {
        let now = now_us();
        if runtime
            .node_contact_bucket
            .lock()
            .await
            .try_consume(now, 1)
            .is_err()
        {
            return;
        }
        let mut seed_hasher = blake3::Hasher::new();
        seed_hasher.update(b"dsn-node-contact-challenge-v1");
        seed_hasher.update(&runtime.node_id);
        seed_hasher.update(&msg.request_id.to_be_bytes());
        seed_hasher.update(&now.to_be_bytes());
        let seed = *seed_hasher.finalize().as_bytes();
        let expires_at_us = now.saturating_add(NODE_CONTACT_CHALLENGE_TTL_US);
        let issued_key_id = peer.session.lock().await.active_key_id();

        runtime.node_contact_challenges.lock().await.insert(
            seed,
            NodeContactChallengeState {
                peer_node_id: peer.peer_node_id,
                request_id: msg.request_id,
                seed,
                difficulty: NODE_CONTACT_DIFFICULTY,
                expires_at_us,
                issued_key_id,
                used: false,
            },
        );

        let challenge = ControlMessage::NodeContact(crate::NodeContact {
            request_id: msg.request_id,
            flags: NODE_CONTACT_FLAG_CHALLENGE,
            error_code: NODE_CONTACT_DIFFICULTY as u16,
            node_id_contact: runtime.node_id,
            nonce: seed,
            payload: expires_at_us.to_be_bytes().to_vec(),
        });
        // best effort send back to requester: first connected peer
        let _ = send_control(peer, challenge).await;
        return;
    }

    if msg.flags == NODE_CONTACT_FLAG_SOLUTION {
        let Some(solution_nonce) = parse_u64_payload(&msg.payload).ok() else {
            return;
        };
        let now = now_us();
        let mut challenges = runtime.node_contact_challenges.lock().await;
        let Some(state) = challenges.get_mut(&msg.nonce) else {
            return;
        };
        if state.used || state.request_id != msg.request_id || now > state.expires_at_us {
            return;
        }
        if state.issued_key_id != peer.session.lock().await.active_key_id()
            || state.peer_node_id != peer.peer_node_id
        {
            return;
        }
        let challenge = PowChallenge {
            scope: PowScope::NodeContact,
            peer_id: state.peer_node_id,
            request_id: state.request_id,
            target_id: runtime.node_id,
            challenge_seed: state.seed,
            nonce: solution_nonce,
            difficulty: state.difficulty,
        };
        if verify_pow(challenge).is_err() {
            return;
        }
        state.used = true;

        let endpoint = runtime
            .cfg
            .listen
            .first()
            .map(endpoint_key)
            .unwrap_or_default();
        let mut payload = Vec::new();
        payload.extend_from_slice(&(endpoint.len() as u16).to_be_bytes());
        payload.extend_from_slice(endpoint.as_bytes());
        payload.extend_from_slice(&runtime.verifying.to_bytes());
        let response = ControlMessage::NodeContact(crate::NodeContact {
            request_id: msg.request_id,
            flags: NODE_CONTACT_FLAG_RESPONSE,
            error_code: 0,
            node_id_contact: runtime.node_id,
            nonce: msg.nonce,
            payload,
        });
        let _ = send_control(peer, response).await;
        return;
    }

    runtime.dht.lock().await.add_known_node(msg.node_id_contact);
}

async fn handle_rekey_request(
    runtime: Arc<NodeRuntime>,
    peer: Arc<PeerRuntime>,
    req: ControlSessionChangeRequest,
) {
    let mut status = REKEY_ACK_OK;
    if req.requester_node_id != runtime.node_id {
        let sig_payload = rekey_signature_payload(req.request_id, req.new_key_id, &req.kem_payload);
        let parsed_sig = ed25519_dalek::Signature::from_slice(&req.sign);
        if parsed_sig
            .ok()
            .and_then(|sig| peer.peer_verify_key.verify(&sig_payload, &sig).ok())
            .is_none()
        {
            status = REKEY_ACK_REJECTED;
        }
    } else {
        status = REKEY_ACK_REJECTED;
    }

    if status == REKEY_ACK_OK {
        let current = { peer.keys.lock().await.clone() };
        let new_keys = derive_rekey_keys(
            &current,
            req.new_key_id,
            req.request_id,
            &req.kem_payload,
            req.requester_node_id,
            runtime.node_id,
        );
        {
            let mut keys_guard = peer.keys.lock().await;
            *keys_guard = new_keys;
        }
        let mut session = peer.session.lock().await;
        session.switch_to_remote_key(req.new_key_id, now_us());
    }

    let ack = ControlMessage::SessionChangeAck(ControlSessionChangeAck {
        request_id: req.request_id,
        key_id: req.new_key_id,
        status,
    });
    let _ = send_control(peer, ack).await;
}

async fn handle_rekey_ack(
    runtime: Arc<NodeRuntime>,
    peer: Arc<PeerRuntime>,
    ack: ControlSessionChangeAck,
) {
    if ack.status != REKEY_ACK_OK {
        return;
    }

    let pending = { peer.pending_rekey.lock().await.take() };
    let Some(pending) = pending else {
        return;
    };
    if pending.request_id != ack.request_id || pending.new_key_id != ack.key_id {
        return;
    }

    {
        let mut session = peer.session.lock().await;
        let _ = session.handle_session_change_ack(
            crate::SessionChangeAck {
                request_id: ack.request_id,
                accepted_key_id: ack.key_id,
            },
            now_us(),
        );
    }
    {
        let mut keys = peer.keys.lock().await;
        *keys = pending.keys;
    }
    let mut stats = runtime.stats.lock().await;
    stats.rekey_completed = stats.rekey_completed.saturating_add(1);
}

async fn send_control(peer: Arc<PeerRuntime>, msg: ControlMessage) -> Result<()> {
    let frame_msg_type = control_frame_msg_type(&msg);
    let payload = msg.encode();
    let seq = peer.send_seq.fetch_add(1, Ordering::Relaxed);
    let key_id = peer.session.lock().await.active_key_id();
    let aad = build_aad(crate::FrameClass::Control as u8, frame_msg_type, 0);
    let keys = { peer.keys.lock().await.clone() };
    let enc = crate::encrypt_frame(&keys, key_id, seq, &payload, &aad)?;
    let framed_payload = encode_encrypted_payload(&enc);
    {
        let mut st = peer.stats.lock().await;
        st.queue_depth_control = st.queue_depth_control.saturating_add(1);
    }
    let send_res = peer
        .links
        .send_control(frame_msg_type, 0, framed_payload)
        .await
        .map_err(|e| anyhow!("send control failed: {e}"));
    {
        let mut st = peer.stats.lock().await;
        st.queue_depth_control = st.queue_depth_control.saturating_sub(1);
        if send_res.is_err() {
            st.dropped_frames_total = st.dropped_frames_total.saturating_add(1);
            st.dropped_control_frames = st.dropped_control_frames.saturating_add(1);
        }
    }
    send_res?;
    peer.session.lock().await.on_bytes_sent(payload.len());
    Ok(())
}

async fn send_net(peer: Arc<PeerRuntime>, msg_type: u16, payload: Vec<u8>) -> Result<()> {
    let seq = peer.send_seq.fetch_add(1, Ordering::Relaxed);
    let key_id = peer.session.lock().await.active_key_id();
    let aad = build_aad(crate::FrameClass::Net as u8, msg_type, 0);
    let keys = { peer.keys.lock().await.clone() };
    let enc = crate::encrypt_frame(&keys, key_id, seq, &payload, &aad)?;
    let framed_payload = encode_encrypted_payload(&enc);
    {
        let mut st = peer.stats.lock().await;
        st.queue_depth_net = st.queue_depth_net.saturating_add(1);
    }
    let send_res = peer
        .links
        .send_net(msg_type, 0, framed_payload)
        .await
        .map_err(|e| anyhow!("send net failed: {e}"));
    {
        let mut st = peer.stats.lock().await;
        st.queue_depth_net = st.queue_depth_net.saturating_sub(1);
        if send_res.is_err() {
            st.dropped_frames_total = st.dropped_frames_total.saturating_add(1);
            st.dropped_net_frames = st.dropped_net_frames.saturating_add(1);
        }
    }
    send_res?;
    peer.session.lock().await.on_bytes_sent(payload.len());
    Ok(())
}

async fn send_data(peer: Arc<PeerRuntime>, msg_type: u16, payload: Vec<u8>) -> Result<()> {
    let seq = peer.send_seq.fetch_add(1, Ordering::Relaxed);
    let key_id = peer.session.lock().await.active_key_id();
    let aad = build_aad(crate::FrameClass::Data as u8, msg_type, 0);
    let keys = { peer.keys.lock().await.clone() };
    let enc = crate::encrypt_frame(&keys, key_id, seq, &payload, &aad)?;
    let framed_payload = encode_encrypted_payload(&enc);
    {
        let mut st = peer.stats.lock().await;
        st.queue_depth_data = st.queue_depth_data.saturating_add(1);
    }
    let accepted_res = peer
        .links
        .send_data(msg_type, 0, framed_payload)
        .await
        .map_err(|e| anyhow!("send data failed: {e}"));
    let mut dropped_backpressure = false;
    let accepted = match accepted_res {
        Ok(v) => v,
        Err(e) => {
            let mut st = peer.stats.lock().await;
            st.queue_depth_data = st.queue_depth_data.saturating_sub(1);
            st.dropped_frames_total = st.dropped_frames_total.saturating_add(1);
            st.dropped_data_frames = st.dropped_data_frames.saturating_add(1);
            return Err(e);
        }
    };
    {
        let mut st = peer.stats.lock().await;
        st.queue_depth_data = st.queue_depth_data.saturating_sub(1);
        if !accepted {
            dropped_backpressure = true;
            st.dropped_frames_total = st.dropped_frames_total.saturating_add(1);
            st.dropped_data_frames = st.dropped_data_frames.saturating_add(1);
        }
    }
    if dropped_backpressure {
        return Err(anyhow!("data queue backpressure"));
    }
    peer.session.lock().await.on_bytes_sent(payload.len());
    Ok(())
}

async fn handle_net_message(
    runtime: Arc<NodeRuntime>,
    peer: Arc<PeerRuntime>,
    msg_type: u16,
    payload: &[u8],
) {
    match msg_type {
        NET_MSG_CREATE_ROUTE_REQUEST => {
            let Ok(req) = serde_json::from_slice::<RouteCreateWire>(payload) else {
                return;
            };
            let now = now_us();
            let create_req = CreateRouteRequest {
                session_id: req.session_id,
                dst_node_id: req.dst_node_id,
                src_node_id: req.src_node_id,
                ingress_transport: format!("peer:{}", hex32(peer.peer_node_id)),
                egress_transport: format!("peer:{}", hex32(req.next_hop_node_id)),
                namespace: None,
            };
            let status = runtime
                .route_manager
                .lock()
                .await
                .create_route(create_req, now)
                .map(|_| 0u8)
                .unwrap_or(1u8);
            let resp = RouteCreateResponseWire {
                session_id: req.session_id,
                status,
            };
            let _ = send_net(
                peer,
                NET_MSG_CREATE_ROUTE_RESPONSE,
                serde_json::to_vec(&resp).unwrap_or_default(),
            )
            .await;
        }
        NET_MSG_CREATE_ROUTE_RESPONSE => {
            let _ = serde_json::from_slice::<RouteCreateResponseWire>(payload);
        }
        NET_MSG_ROUTE_SEND_NODE => {
            let Ok(msg) = serde_json::from_slice::<RouteSendNodeWire>(payload) else {
                return;
            };
            if msg.dst_node_id == runtime.node_id {
                let mut st = runtime.stats.lock().await;
                st.route_delivered = st.route_delivered.saturating_add(1);
                return;
            }
            let now = now_us();
            let route = runtime
                .route_manager
                .lock()
                .await
                .use_route(msg.session_id, now)
                .ok()
                .flatten();
            let Some(route) = route else {
                return;
            };
            let next = parse_peer_node_id_from_transport(&route.egress_transport);
            let Some(next_hop_id) = next else {
                return;
            };
            let next_peer = find_peer_by_node_id(&runtime, next_hop_id).await;
            let Some(next_peer) = next_peer else {
                return;
            };
            let _ = send_net(next_peer, NET_MSG_ROUTE_SEND_NODE, payload.to_vec()).await;
            let mut st = runtime.stats.lock().await;
            st.route_forwarded = st.route_forwarded.saturating_add(1);
        }
        _ => {}
    }
}

async fn handle_data_message(
    runtime: Arc<NodeRuntime>,
    _peer: Arc<PeerRuntime>,
    msg_type: u16,
    payload: &[u8],
) {
    match msg_type {
        DATA_MSG_ROUTE_SEND_IP4 | DATA_MSG_ROUTE_SEND_IP6 => {
            let Ok(msg) = serde_json::from_slice::<RouteSendIpWire>(payload) else {
                return;
            };

            if is_local_tun_ip(&runtime.cfg, msg_type, &msg.ip) {
                if let Some(tun) = &runtime.tun {
                    let _ = tun.egress_tx.send(msg.payload).await;
                    let mut st = runtime.stats.lock().await;
                    st.route_delivered = st.route_delivered.saturating_add(1);
                }
                return;
            }

            let now = now_us();
            let route = runtime
                .route_manager
                .lock()
                .await
                .use_route(msg.session_id, now)
                .ok()
                .flatten();
            let Some(route) = route else {
                return;
            };
            let next = parse_peer_node_id_from_transport(&route.egress_transport);
            let Some(next_hop_id) = next else {
                return;
            };
            let Some(next_peer) = find_peer_by_node_id(&runtime, next_hop_id).await else {
                return;
            };
            let _ = send_data(next_peer, msg_type, payload.to_vec()).await;
            let mut st = runtime.stats.lock().await;
            st.route_forwarded = st.route_forwarded.saturating_add(1);
        }
        _ => {}
    }
}

async fn run_tun_loop(runtime: Arc<NodeRuntime>, mut shutdown: watch::Receiver<bool>) {
    let Some(tun) = runtime.tun.clone() else {
        return;
    };

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
            packet = async {
                let mut rx = tun.ingress_rx.lock().await;
                rx.recv().await
            } => {
                let Some(packet) = packet else { continue; };
                let Some((msg_type, namespace, ip)) = parse_overlay_packet_destination(&packet) else {
                    continue;
                };
                let now = now_us();
                let target_node_id = {
                    let dht = runtime.dht.lock().await;
                    dht.find_value_at(namespace, ip.as_bytes(), now)
                };
                let Some(target_node_id) = target_node_id else {
                    continue;
                };
                if target_node_id.len() != 32 {
                    continue;
                }
                let mut dst = [0u8; 32];
                dst.copy_from_slice(&target_node_id);
                let Some(peer) = find_peer_by_node_id(&runtime, dst).await else {
                    continue;
                };
                let msg = RouteSendIpWire {
                    session_id: [0u8; 32],
                    ip,
                    payload: packet,
                };
                let Ok(bytes) = serde_json::to_vec(&msg) else {
                    continue;
                };
                let _ = send_data(peer, msg_type, bytes).await;
            }
        }
    }
}

async fn run_session_store_flush_loop(
    runtime: Arc<NodeRuntime>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval =
        tokio::time::interval(Duration::from_secs(SESSION_STORE_FLUSH_INTERVAL_SECS));
    loop {
        tokio::select! {
            _ = interval.tick() => {
                flush_sessions_to_store(runtime.clone()).await;
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    flush_sessions_to_store(runtime.clone()).await;
                    break;
                }
            }
        }
    }
}

async fn flush_sessions_to_store(runtime: Arc<NodeRuntime>) {
    let peers = runtime
        .peers
        .read()
        .await
        .values()
        .cloned()
        .collect::<Vec<_>>();

    for peer in peers {
        let snapshot = {
            let sess = peer.session.lock().await;
            sess.snapshot(peer.peer_node_id)
        };
        let _ = runtime.session_store.save(&snapshot);
    }
}

async fn run_ping_loop(runtime: Arc<NodeRuntime>, mut shutdown: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    let mut request_id: u64 = 1;
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let peers = runtime.peers.read().await.iter().map(|(k,v)| (k.clone(), v.clone())).collect::<Vec<_>>();
                let mut timed_out_keys = Vec::new();
                for (peer_key, peer) in peers {
                    let now = now_us();
                    {
                        let mut session = peer.session.lock().await;
                        if session.is_timed_out(now) {
                            timed_out_keys.push(peer_key);
                            continue;
                        }
                        session.track_ping(request_id, now);
                    }
                    let ping = ControlMessage::Ping(ControlPing { request_id, sender_node_id: runtime.node_id });
                    if send_control(peer, ping).await.is_err() {
                        timed_out_keys.push(peer_key);
                        continue;
                    }
                    request_id = request_id.saturating_add(1);
                }
                if !timed_out_keys.is_empty() {
                    let mut guard = runtime.peers.write().await;
                    for key in timed_out_keys {
                        if let Some(peer) = guard.remove(&key) {
                            let _ = runtime.session_store.delete(peer.peer_node_id);
                        }
                    }
                    runtime.stats.lock().await.active_sessions = guard.len();
                }
                runtime.stats.lock().await.last_tick_us = now_us();
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }
}

async fn run_rekey_loop(runtime: Arc<NodeRuntime>, mut shutdown: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    let mut request_id: u64 = 10_000;
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let now = now_us();
                let peers = runtime.peers.read().await.values().cloned().collect::<Vec<_>>();
                for peer in peers {
                    let rekey_plan = {
                        let mut session = peer.session.lock().await;
                        if let Some(reason) = session.rekey_reason(now) {
                            let next_key_id = session.active_key_id().saturating_add(1);
                            let req = session.build_session_change_request(request_id, next_key_id, now);
                            Some((reason, req))
                        } else {
                            None
                        }
                    };

                    if let Some((reason, req)) = rekey_plan {
                        let kem_payload = build_rekey_kem_payload(request_id, now);
                        let sign_payload = rekey_signature_payload(req.request_id, req.next_key_id, &kem_payload);
                        let sign = runtime.signing.sign(&sign_payload).to_bytes().to_vec();
                        let current_keys = { peer.keys.lock().await.clone() };
                        let derived = derive_rekey_keys(
                            &current_keys,
                            req.next_key_id,
                            req.request_id,
                            &kem_payload,
                            runtime.node_id,
                            runtime.node_id,
                        );
                        *peer.pending_rekey.lock().await = Some(PendingRekeyKeys {
                            request_id: req.request_id,
                            new_key_id: req.next_key_id,
                            keys: derived,
                        });
                        let control_req = ControlMessage::SessionChangeRequest(ControlSessionChangeRequest {
                            request_id: req.request_id,
                            new_key_id: req.next_key_id,
                            requester_node_id: runtime.node_id,
                            kem_payload,
                            sign,
                        });
                        let _ = send_control(peer.clone(), control_req).await;
                        let mut stats = runtime.stats.lock().await;
                        stats.rekey_started = stats.rekey_started.saturating_add(1);
                        match reason {
                            RekeyReason::Bytes => stats.rekey_by_bytes = stats.rekey_by_bytes.saturating_add(1),
                            RekeyReason::Age => stats.rekey_by_age = stats.rekey_by_age.saturating_add(1),
                        }
                        info!(request_id=req.request_id, next_key_id=req.next_key_id, ?reason, "session rekey started");
                        request_id = request_id.saturating_add(1);
                    }
                }
                runtime.stats.lock().await.last_tick_us = now;
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
    let node_id = decode_hex_32(&cfg.identity.id).unwrap_or([0u8; 32]);
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let now = now_us();
                let mut dht_guard = dht.lock().await;
                dht_guard.expire_publications(now);
                let _ = publish_public_identity(&cfg, &mut dht_guard, &cfg.identity, ip4_nonce, ip6_nonce, now);
                if cfg.tun_enabled {
                    if cfg.tun_use_ip4 && let Some(ip4) = &cfg.tun_ip4 {
                        dht_guard.store_publication(DHT_NAMESPACE_IP4, ip4.as_bytes().to_vec(), node_id.to_vec(), now);
                    }
                    if cfg.tun_use_ip6 && let Some(ip6) = &cfg.tun_ip6 {
                        dht_guard.store_publication(DHT_NAMESPACE_IP6, ip6.as_bytes().to_vec(), node_id.to_vec(), now);
                    }
                }
                ip4_nonce = ip4_nonce.saturating_add(1);
                ip6_nonce = ip6_nonce.saturating_add(1);
                let mut st = stats.lock().await;
                st.last_tick_us = now;
                st.published_identities = st.published_identities.saturating_add(1);
                if now.saturating_sub(st.started_at_us) > crate::PUBLICATION_TTL_US {
                    st.started_at_us = now;
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }
}

fn build_session_store(cfg: &DsnConfig) -> Result<Arc<dyn SessionStore>> {
    let kind = match cfg.node.session_store.as_str() {
        "memory" => SessionStoreKind::Memory,
        "file" => {
            let dir = std::path::Path::new(&cfg.node.state_dir).join(&cfg.node.session_store_path);
            SessionStoreKind::File { dir }
        }
        "redis" => {
            SessionStoreKind::Redis {
                uri: cfg.node.session_store_redis_url.clone().ok_or_else(|| {
                    anyhow!("missing node.session_store_redis_url for store=redis")
                })?,
                prefix: cfg.node.session_store_redis_prefix.clone(),
            }
        }
        other => return Err(anyhow!("unsupported session_store kind: {other}")),
    };

    Ok(Arc::from(kind.build()?))
}

fn restored_or_new_session_state(
    runtime: &NodeRuntime,
    peer_node_id: [u8; 32],
    now_us: u64,
) -> SessionState {
    let persisted = runtime.session_store.load(peer_node_id).ok().flatten();
    match persisted {
        Some(p) if p.version == 1 => {
            SessionState::from_persisted(default_session_policy(), p, now_us)
        }
        _ => SessionState::new(default_session_policy(), 1, now_us),
    }
}

fn handshake_config(runtime: &NodeRuntime) -> HandshakeConfig {
    HandshakeConfig {
        protocol_version: HANDSHAKE_V1_VERSION,
        mux_mode: PeerLinksMode::SingleMux,
        address_mode: match runtime.cfg.address_mode {
            ConfigAddressMode::PublicOnly => HsAddressMode::PublicOnly,
            ConfigAddressMode::GrayOnly => HsAddressMode::GrayOnly,
            ConfigAddressMode::All => HsAddressMode::All,
        },
        pow_difficulty: 0,
        node_id: runtime.node_id,
    }
}

fn encode_encrypted_payload(frame: &crate::EncryptedFrame) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + frame.ciphertext.len());
    out.extend_from_slice(&frame.key_id.to_be_bytes());
    out.extend_from_slice(&frame.seq.to_be_bytes());
    out.extend_from_slice(&(frame.ciphertext.len() as u32).to_be_bytes());
    out.extend_from_slice(&frame.ciphertext);
    out
}

fn decode_encrypted_payload(raw: &[u8]) -> Result<crate::EncryptedFrame> {
    if raw.len() < 16 {
        return Err(anyhow!("short encrypted payload"));
    }
    let key_id = u32::from_be_bytes(raw[0..4].try_into()?);
    let seq = u64::from_be_bytes(raw[4..12].try_into()?);
    let len = u32::from_be_bytes(raw[12..16].try_into()?) as usize;
    if raw.len() != 16 + len {
        return Err(anyhow!("encrypted payload length mismatch"));
    }
    Ok(crate::EncryptedFrame {
        key_id,
        seq,
        ciphertext: raw[16..].to_vec(),
    })
}

fn build_aad(class: u8, msg_type: u16, flags: u16) -> Vec<u8> {
    let mut aad = Vec::with_capacity(5);
    aad.push(class);
    aad.extend_from_slice(&msg_type.to_be_bytes());
    aad.extend_from_slice(&flags.to_be_bytes());
    aad
}

fn control_frame_msg_type(msg: &ControlMessage) -> u16 {
    let msg_type = match msg {
        ControlMessage::Ping(_) => ControlMsgType::Ping as u16,
        ControlMessage::Pong(_) => ControlMsgType::Pong as u16,
        ControlMessage::FindNode(_) => ControlMsgType::FindNode as u16,
        ControlMessage::FindValue(_) => ControlMsgType::FindValue as u16,
        ControlMessage::Store(_) => ControlMsgType::Store as u16,
        ControlMessage::Delete(_) => ControlMsgType::Delete as u16,
        ControlMessage::NodeContact(_) => ControlMsgType::NodeContact as u16,
        ControlMessage::SessionChangeRequest(_) => ControlMsgType::SessionChangeRequest as u16,
        ControlMessage::SessionChangeAck(_) => ControlMsgType::SessionChangeAck as u16,
    };
    debug_assert!(
        !(DHT_MSG_TYPE_MIN..=DHT_MSG_TYPE_MAX).contains(&msg_type)
            || matches!(
                msg,
                ControlMessage::FindNode(_)
                    | ControlMessage::FindValue(_)
                    | ControlMessage::Store(_)
                    | ControlMessage::Delete(_)
                    | ControlMessage::NodeContact(_)
            )
    );
    msg_type
}

fn build_rekey_kem_payload(request_id: u64, now: u64) -> Vec<u8> {
    let mut h = blake3::Hasher::new();
    h.update(b"dsn-rekey-kem-v1");
    h.update(&request_id.to_be_bytes());
    h.update(&now.to_be_bytes());
    h.finalize().as_bytes().to_vec()
}

fn rekey_signature_payload(request_id: u64, new_key_id: u32, kem_payload: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(64 + kem_payload.len());
    payload.extend_from_slice(b"dsn-session-change-request-v1");
    payload.extend_from_slice(&request_id.to_be_bytes());
    payload.extend_from_slice(&new_key_id.to_be_bytes());
    payload.extend_from_slice(kem_payload);
    payload
}

fn derive_rekey_keys(
    current: &SessionKeys,
    new_key_id: u32,
    request_id: u64,
    kem_payload: &[u8],
    requester_node_id: [u8; 32],
    local_node_id: [u8; 32],
) -> SessionKeys {
    let mut h = blake3::Hasher::new();
    h.update(b"dsn-rekey-derive-v1");
    h.update(&current.send_key);
    h.update(&current.recv_key);
    h.update(&new_key_id.to_be_bytes());
    h.update(&request_id.to_be_bytes());
    h.update(&requester_node_id);
    h.update(kem_payload);
    let seed = *h.finalize().as_bytes();

    let mut a2b_h = blake3::Hasher::new();
    a2b_h.update(b"dsn-rekey-a2b");
    a2b_h.update(&seed);
    let mut b2a_h = blake3::Hasher::new();
    b2a_h.update(b"dsn-rekey-b2a");
    b2a_h.update(&seed);
    let a2b = *a2b_h.finalize().as_bytes();
    let b2a = *b2a_h.finalize().as_bytes();

    if local_node_id == requester_node_id {
        SessionKeys {
            send_key: a2b,
            recv_key: b2a,
        }
    } else {
        SessionKeys {
            send_key: b2a,
            recv_key: a2b,
        }
    }
}

fn parse_u64_payload(payload: &[u8]) -> Result<u64> {
    if payload.len() < 8 {
        return Err(anyhow!("payload too short for u64"));
    }
    Ok(u64::from_be_bytes(payload[0..8].try_into()?))
}

fn solve_node_contact_pow(
    peer_id: [u8; 32],
    target_id: [u8; 32],
    request_id: u64,
    challenge_seed: [u8; 32],
    difficulty: u8,
    expires_at_us: u64,
) -> Option<u64> {
    for nonce in 0..5_000_000u64 {
        if now_us() > expires_at_us {
            return None;
        }
        let challenge = PowChallenge {
            scope: PowScope::NodeContact,
            peer_id,
            request_id,
            target_id,
            challenge_seed,
            nonce,
            difficulty,
        };
        if verify_pow(challenge).is_ok() {
            return Some(nonce);
        }
    }
    None
}

fn decode_signing_key(raw: &str) -> Result<SigningKey> {
    let bytes = if Path::new(raw).exists() {
        std::fs::read(raw)?
    } else {
        base64::engine::general_purpose::STANDARD.decode(raw)?
    };
    let sk = match bytes.len() {
        32 => SigningKey::from_bytes(&bytes.try_into().map_err(|_| anyhow!("invalid sk len"))?),
        64 => SigningKey::from_keypair_bytes(
            &bytes.try_into().map_err(|_| anyhow!("invalid sk len"))?,
        )
        .map_err(|e| anyhow!("invalid keypair: {e}"))?,
        _ => return Err(anyhow!("invalid signing key length")),
    };
    Ok(sk)
}

async fn write_client_hello(
    w: &mut crate::BoxedStreamConn,
    hello: &crate::ClientHello,
) -> Result<()> {
    write_hs_cfg(w, &hello.config).await?;
    write_vec_u16(w, &hello.kem_public_key).await?;
    write_vec_u16(w, &hello.signature).await
}

async fn read_client_hello(r: &mut crate::BoxedStreamConn) -> Result<crate::ClientHello> {
    Ok(crate::ClientHello {
        config: read_hs_cfg(r).await?,
        kem_public_key: read_vec_u16(r).await?,
        signature: read_vec_u16(r).await?,
    })
}

async fn write_server_hello(
    w: &mut crate::BoxedStreamConn,
    hello: &crate::ServerHello,
) -> Result<()> {
    write_hs_cfg(w, &hello.config).await?;
    write_vec_u16(w, &hello.kem_ciphertext).await?;
    write_vec_u16(w, &hello.signature).await
}

async fn read_server_hello(r: &mut crate::BoxedStreamConn) -> Result<crate::ServerHello> {
    Ok(crate::ServerHello {
        config: read_hs_cfg(r).await?,
        kem_ciphertext: read_vec_u16(r).await?,
        signature: read_vec_u16(r).await?,
    })
}

async fn write_finished(w: &mut crate::BoxedStreamConn, f: &crate::Finished) -> Result<()> {
    w.write_all(&f.verify_tag).await?;
    w.flush().await?;
    Ok(())
}

async fn read_finished(r: &mut crate::BoxedStreamConn) -> Result<crate::Finished> {
    let mut tag = [0u8; 32];
    r.read_exact(&mut tag).await?;
    Ok(crate::Finished { verify_tag: tag })
}

async fn write_hs_cfg(w: &mut crate::BoxedStreamConn, cfg: &HandshakeConfig) -> Result<()> {
    w.write_u8(cfg.protocol_version).await?;
    w.write_u8(match cfg.mux_mode {
        PeerLinksMode::SingleMux => 0,
        PeerLinksMode::MultiConn => 1,
    })
    .await?;
    w.write_u8(match cfg.address_mode {
        HsAddressMode::PublicOnly => 0,
        HsAddressMode::GrayOnly => 1,
        HsAddressMode::All => 2,
    })
    .await?;
    w.write_u8(cfg.pow_difficulty).await?;
    w.write_all(&cfg.node_id).await?;
    Ok(())
}

async fn read_hs_cfg(r: &mut crate::BoxedStreamConn) -> Result<HandshakeConfig> {
    let protocol_version = r.read_u8().await?;
    let mux_mode = match r.read_u8().await? {
        0 => PeerLinksMode::SingleMux,
        1 => PeerLinksMode::MultiConn,
        _ => return Err(anyhow!("invalid mux mode")),
    };
    let address_mode = match r.read_u8().await? {
        0 => HsAddressMode::PublicOnly,
        1 => HsAddressMode::GrayOnly,
        2 => HsAddressMode::All,
        _ => return Err(anyhow!("invalid address mode")),
    };
    let pow_difficulty = r.read_u8().await?;
    let mut node_id = [0u8; 32];
    r.read_exact(&mut node_id).await?;
    Ok(HandshakeConfig {
        protocol_version,
        mux_mode,
        address_mode,
        pow_difficulty,
        node_id,
    })
}

async fn write_vec_u16(w: &mut crate::BoxedStreamConn, v: &[u8]) -> Result<()> {
    if v.len() > u16::MAX as usize {
        return Err(anyhow!("vector too long"));
    }
    w.write_u16(v.len() as u16).await?;
    w.write_all(v).await?;
    Ok(())
}

async fn read_vec_u16(r: &mut crate::BoxedStreamConn) -> Result<Vec<u8>> {
    let len = r.read_u16().await? as usize;
    let mut out = vec![0u8; len];
    r.read_exact(&mut out).await?;
    Ok(out)
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

fn hex32(id: [u8; 32]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect::<String>()
}

fn parse_overlay_packet_destination(packet: &[u8]) -> Option<(u16, &'static str, String)> {
    if packet.is_empty() {
        return None;
    }
    let version = packet[0] >> 4;
    if version == 4 && packet.len() >= 20 {
        let ip = std::net::Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        return Some((DATA_MSG_ROUTE_SEND_IP4, DHT_NAMESPACE_IP4, ip.to_string()));
    }
    if version == 6 && packet.len() >= 40 {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&packet[24..40]);
        let ip = std::net::Ipv6Addr::from(octets);
        return Some((DATA_MSG_ROUTE_SEND_IP6, DHT_NAMESPACE_IP6, ip.to_string()));
    }
    None
}

fn is_local_tun_ip(cfg: &DsnConfig, msg_type: u16, ip: &str) -> bool {
    match msg_type {
        DATA_MSG_ROUTE_SEND_IP4 => {
            cfg.tun_enabled && cfg.tun_use_ip4 && cfg.tun_ip4.as_deref() == Some(ip)
        }
        DATA_MSG_ROUTE_SEND_IP6 => {
            cfg.tun_enabled && cfg.tun_use_ip6 && cfg.tun_ip6.as_deref() == Some(ip)
        }
        _ => false,
    }
}

fn parse_peer_node_id_from_transport(raw: &str) -> Option<[u8; 32]> {
    let hex = raw.strip_prefix("peer:")?;
    decode_hex_32(hex)
}

async fn find_peer_by_node_id(
    runtime: &NodeRuntime,
    node_id: [u8; 32],
) -> Option<Arc<PeerRuntime>> {
    runtime
        .peers
        .read()
        .await
        .values()
        .find(|p| p.peer_node_id == node_id)
        .cloned()
}

fn init_route_manager(cfg: &DsnConfig) -> RouteManager {
    let mut manager = RouteManager::new(RouteStorageKind::Memory).expect("route manager memory");
    for id in &cfg.route_whitelist_node_ids {
        if let Some(parsed) = decode_hex_32(id) {
            manager.acl_mut().whitelist_add(None, parsed);
        }
    }
    for id in &cfg.route_blacklist_node_ids {
        if let Some(parsed) = decode_hex_32(id) {
            manager.acl_mut().blacklist_add(None, parsed);
        }
    }
    manager
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

#[cfg(not(test))]
fn default_session_policy() -> SessionPolicy {
    SessionPolicy::default()
}

#[cfg(test)]
fn default_session_policy() -> SessionPolicy {
    SessionPolicy {
        session_timeout_us: 6_000_000,
        ..SessionPolicy::default()
    }
}

#[cfg(test)]
mod tests {
    use super::{NodeRuntime, parse_u64_payload, solve_node_contact_pow};
    use crate::DsnConfig;
    use anyhow::Result;
    use tokio::time::{Duration, sleep};

    #[tokio::test]
    async fn two_nodes_exchange_ping_over_control() -> Result<()> {
        let mut cfg_a = DsnConfig::default_with_generated_identity()?;
        let mut cfg_b = DsnConfig::default_with_generated_identity()?;

        cfg_a.listen = vec!["tcp://127.0.0.1:19081".parse()?];
        cfg_b.listen = vec!["tcp://127.0.0.1:19082".parse()?];
        cfg_a.bootstrap_peers = vec!["tcp://127.0.0.1:19082".parse()?];
        cfg_b.bootstrap_peers = vec!["tcp://127.0.0.1:19081".parse()?];

        let node_a = NodeRuntime::new(cfg_a).start();
        let node_b = NodeRuntime::new(cfg_b).start();

        sleep(Duration::from_secs(8)).await;

        let stats_a = node_a.snapshot().await;
        let stats_b = node_b.snapshot().await;
        assert!(stats_a.active_sessions >= 1);
        assert!(stats_b.active_sessions >= 1);

        node_a.stop().await;
        node_b.stop().await;
        Ok(())
    }

    #[tokio::test]
    async fn find_node_request_goes_over_network_with_retries_timeouts_manager() -> Result<()> {
        let mut cfg_a = DsnConfig::default_with_generated_identity()?;
        let mut cfg_b = DsnConfig::default_with_generated_identity()?;

        cfg_a.listen = vec!["tcp://127.0.0.1:19281".parse()?];
        cfg_b.listen = vec!["tcp://127.0.0.1:19282".parse()?];
        cfg_a.bootstrap_peers = vec!["tcp://127.0.0.1:19282".parse()?];
        cfg_b.bootstrap_peers = vec!["tcp://127.0.0.1:19281".parse()?];

        let target = [0x42; 32];

        let node_a = NodeRuntime::new(cfg_a).start();
        let node_b = NodeRuntime::new(cfg_b).start();

        {
            let dht_b = node_b.dht();
            let mut dht = dht_b.lock().await;
            dht.add_known_node(target);
        }

        sleep(Duration::from_secs(8)).await;

        let got = node_a.dht_find_node(target, 1).await?;
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], target);

        node_a.stop().await;
        node_b.stop().await;
        Ok(())
    }

    #[tokio::test]
    async fn node_contact_requires_valid_pow_and_rejects_replay() -> Result<()> {
        let mut cfg_a = DsnConfig::default_with_generated_identity()?;
        let mut cfg_b = DsnConfig::default_with_generated_identity()?;

        cfg_a.listen = vec!["tcp://127.0.0.1:19381".parse()?];
        cfg_b.listen = vec!["tcp://127.0.0.1:19382".parse()?];
        cfg_a.bootstrap_peers = vec!["tcp://127.0.0.1:19382".parse()?];
        cfg_b.bootstrap_peers = vec!["tcp://127.0.0.1:19381".parse()?];

        let node_a = NodeRuntime::new(cfg_a).start();
        let node_b = NodeRuntime::new(cfg_b).start();
        sleep(Duration::from_secs(8)).await;

        let target = [7u8; 32];
        let challenge = node_a.node_contact_get_challenge(target).await?;

        let invalid = node_a
            .node_contact_submit_solution(target, challenge.clone(), 0)
            .await;
        assert!(invalid.is_err(), "invalid pow must be rejected");

        let difficulty = challenge.error_code as u8;
        let expires_at = parse_u64_payload(&challenge.payload)?;
        let nonce = solve_node_contact_pow(
            node_a.node_id,
            challenge.node_id_contact,
            challenge.request_id,
            challenge.nonce,
            difficulty,
            expires_at,
        )
        .expect("pow must solve");

        let ok = node_a
            .node_contact_submit_solution(target, challenge.clone(), nonce)
            .await?;
        assert!(!ok.is_empty());

        let replay = node_a
            .node_contact_submit_solution(target, challenge, nonce)
            .await;
        assert!(replay.is_err(), "replay of old solution must fail");

        node_a.stop().await;
        node_b.stop().await;
        Ok(())
    }

    #[tokio::test]
    async fn route_send_node_goes_via_one_relay_and_updates_ttl_cache() -> Result<()> {
        let mut cfg_a = DsnConfig::default_with_generated_identity()?;
        let mut cfg_b = DsnConfig::default_with_generated_identity()?;
        let mut cfg_c = DsnConfig::default_with_generated_identity()?;

        cfg_a.listen = vec!["tcp://127.0.0.1:19481".parse()?];
        cfg_b.listen = vec!["tcp://127.0.0.1:19482".parse()?];
        cfg_c.listen = vec!["tcp://127.0.0.1:19483".parse()?];
        cfg_a.bootstrap_peers = vec!["tcp://127.0.0.1:19482".parse()?];
        cfg_b.bootstrap_peers = vec![
            "tcp://127.0.0.1:19481".parse()?,
            "tcp://127.0.0.1:19483".parse()?,
        ];
        cfg_c.bootstrap_peers = vec!["tcp://127.0.0.1:19482".parse()?];

        let node_a = NodeRuntime::new(cfg_a).start();
        let node_b = NodeRuntime::new(cfg_b).start();
        let node_c = NodeRuntime::new(cfg_c).start();

        sleep(Duration::from_secs(10)).await;

        let c_id = {
            let dht = node_c.dht();
            dht.lock().await.node_id
        };
        let session_id = [0xAB; 32];
        node_a
            .create_route_via_first_peer(session_id, c_id, c_id)
            .await?;

        sleep(Duration::from_secs(1)).await;
        node_a
            .route_send_node_via_first_peer(session_id, c_id, b"hello-route".to_vec())
            .await?;

        sleep(Duration::from_secs(2)).await;

        let stats_b = node_b.snapshot().await;
        let stats_c = node_c.snapshot().await;
        assert!(stats_b.route_forwarded >= 1, "relay must forward");
        assert!(stats_c.route_delivered >= 1, "destination must receive");

        node_a.stop().await;
        node_b.stop().await;
        node_c.stop().await;
        Ok(())
    }

    #[test]
    fn file_session_store_restores_session_state_into_runtime() -> Result<()> {
        let mut cfg = DsnConfig::default_with_generated_identity()?;
        cfg.node.session_store = "file".to_string();
        cfg.node.state_dir = std::env::temp_dir()
            .join(format!("dsn-node-store-{}", std::process::id()))
            .to_string_lossy()
            .to_string();
        cfg.node.session_store_path = "sessions-runtime".to_string();

        let peer_id = [0xAA; 32];
        {
            let rt = NodeRuntime::new(cfg.clone());
            rt.session_store
                .save(&crate::transport::PersistedPeerSession {
                    version: 1,
                    peer_node_id: peer_id,
                    active_key_id: 77,
                    bytes_on_active_key: 1234,
                    active_key_since_us: 111,
                    last_pong_us: 222,
                })?;
        }

        let rt2 = NodeRuntime::new(cfg.clone());
        let restored = super::restored_or_new_session_state(&rt2, peer_id, 333);
        assert_eq!(restored.active_key_id(), 77);

        let path = std::path::Path::new(&cfg.node.state_dir);
        let _ = std::fs::remove_dir_all(path);
        Ok(())
    }

    #[test]
    fn redis_session_store_restores_session_state_when_redis_available() -> Result<()> {
        let Some(redis_url) = std::env::var("DSN_TEST_REDIS_URL").ok() else {
            return Ok(());
        };

        let mut cfg = DsnConfig::default_with_generated_identity()?;
        cfg.node.session_store = "redis".to_string();
        cfg.node.session_store_redis_url = Some(redis_url);
        cfg.node.session_store_redis_prefix = format!("dsn:test:{}", std::process::id());

        let peer_id = [0xBB; 32];
        let rt = NodeRuntime::new(cfg.clone());
        rt.session_store
            .save(&crate::transport::PersistedPeerSession {
                version: 1,
                peer_node_id: peer_id,
                active_key_id: 55,
                bytes_on_active_key: 5,
                active_key_since_us: 10,
                last_pong_us: 20,
            })?;

        let rt2 = NodeRuntime::new(cfg);
        let restored = super::restored_or_new_session_state(&rt2, peer_id, 40);
        assert_eq!(restored.active_key_id(), 55);
        Ok(())
    }

    fn ipv4_packet(dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut pkt = vec![0u8; 20 + payload.len()];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 17;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&dst);
        pkt[20..].copy_from_slice(payload);
        pkt
    }

    #[tokio::test]
    async fn tun_mode_routes_packet_between_two_nodes_via_dht_ip4_map() -> Result<()> {
        let mut cfg_a = DsnConfig::default_with_generated_identity()?;
        let mut cfg_b = DsnConfig::default_with_generated_identity()?;

        cfg_a.listen = vec!["tcp://127.0.0.1:19581".parse()?];
        cfg_b.listen = vec!["tcp://127.0.0.1:19582".parse()?];
        cfg_a.bootstrap_peers = vec!["tcp://127.0.0.1:19582".parse()?];
        cfg_b.bootstrap_peers = vec!["tcp://127.0.0.1:19581".parse()?];

        cfg_a.address_mode = crate::config::AddressMode::All;
        cfg_b.address_mode = crate::config::AddressMode::All;
        cfg_a.tun_enabled = true;
        cfg_a.tun_use_ip4 = true;
        cfg_a.tun_ip4 = Some("10.9.0.1".to_string());
        cfg_b.tun_enabled = true;
        cfg_b.tun_use_ip4 = true;
        cfg_b.tun_ip4 = Some("10.9.0.2".to_string());

        let node_a = NodeRuntime::new(cfg_a).start();
        let node_b = NodeRuntime::new(cfg_b).start();

        sleep(Duration::from_secs(8)).await;

        {
            let dht = node_a.dht();
            dht.lock().await.store_publication(
                super::DHT_NAMESPACE_IP4,
                b"10.9.0.2".to_vec(),
                node_b.node_id.to_vec(),
                super::now_us(),
            );
        }

        let packet = ipv4_packet([10, 9, 0, 2], b"tun-e2e");
        node_a.send_tun_packet(packet.clone()).await?;

        let got = node_b.recv_tun_packet(Duration::from_secs(5)).await?;
        assert_eq!(got, packet);

        node_a.stop().await;
        node_b.stop().await;
        Ok(())
    }
}
