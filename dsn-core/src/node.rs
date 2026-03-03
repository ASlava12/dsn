use crate::config::AddressMode as ConfigAddressMode;
use crate::transport::AddressMode as HsAddressMode;
use crate::{
    CONTROL_PROTOCOL_V1, ControlMessage, ControlPing, ControlPong, DhtRuntime, DsnConfig,
    MuxConfig, PeerLinks, PeerLinksMode, SessionPolicy, SessionState, TransportEndpoint,
    publish_public_identity, transport_for_scheme,
};
use anyhow::{Result, anyhow};
use base64::Engine;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, RwLock, watch};
use tokio::task::JoinHandle;

use crate::{
    HANDSHAKE_V1_VERSION, HandshakeConfig, SessionKeys, build_client_hello, handle_client_hello,
    handle_server_hello, server_session_keys, verify_finished,
};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuntimeStats {
    pub started_at_us: u64,
    pub last_tick_us: u64,
    pub listen_endpoints: usize,
    pub bootstrap_peers: usize,
    pub active_sessions: usize,
    pub published_identities: u64,
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
    keys: SessionKeys,
    replay: Arc<Mutex<ReplayWindow>>,
    send_seq: AtomicU64,
}

pub struct NodeRuntime {
    cfg: DsnConfig,
    dht: Arc<Mutex<DhtRuntime>>,
    peers: Arc<RwLock<HashMap<String, Arc<PeerRuntime>>>>,
    stats: Arc<Mutex<RuntimeStats>>,
    signing: SigningKey,
    verifying: VerifyingKey,
    node_id: [u8; 32],
}

pub struct NodeRuntimeHandle {
    shutdown_tx: watch::Sender<bool>,
    join_handles: Vec<JoinHandle<()>>,
    stats: Arc<Mutex<RuntimeStats>>,
    dht: Arc<Mutex<DhtRuntime>>,
}

impl NodeRuntime {
    pub fn new(cfg: DsnConfig) -> Self {
        let node_id = decode_hex_32(&cfg.identity.id).unwrap_or([0; 32]);
        let signing = decode_signing_key(&cfg.identity.private_key).expect("valid private key");
        let verifying = signing.verifying_key();
        let now = now_us();
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
            })),
            signing,
            verifying,
            node_id,
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
            shutdown_rx,
        )));

        NodeRuntimeHandle {
            shutdown_tx,
            join_handles,
            stats: shared.stats.clone(),
            dht: shared.dht.clone(),
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
                            rt.peers.write().await.insert(key, peer.clone());
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
    handshake_and_spawn(runtime.clone(), stream, false).await
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
                    if let Ok(peer) = handshake_and_spawn(runtime.clone(), stream, true).await {
                        runtime.peers.write().await.insert(key, peer);
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

async fn handshake_and_spawn(
    runtime: Arc<NodeRuntime>,
    mut stream: crate::BoxedStreamConn,
    outbound: bool,
) -> Result<Arc<PeerRuntime>> {
    let keys;
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
    }

    let links = Arc::new(PeerLinks::single_mux(stream, MuxConfig::default()));
    let peer = Arc::new(PeerRuntime {
        links: links.clone(),
        session: Arc::new(Mutex::new(SessionState::new(
            SessionPolicy::default(),
            1,
            now_us(),
        ))),
        keys,
        replay: Arc::new(Mutex::new(ReplayWindow::new())),
        send_seq: AtomicU64::new(1),
    });
    tokio::spawn(run_peer_read_loop(runtime, peer.clone()));
    Ok(peer)
}

async fn run_peer_read_loop(runtime: Arc<NodeRuntime>, peer: Arc<PeerRuntime>) {
    while let Ok(frame) = peer.links.recv().await {
        let aad = build_aad(frame.class as u8, frame.msg_type, frame.flags);
        let enc = match decode_encrypted_payload(&frame.payload) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let now = now_us();
        let mut sess = peer.session.lock().await;
        if !sess.can_accept_key_id(enc.key_id, now) {
            continue;
        }
        if !peer.replay.lock().await.accept(enc.seq) {
            continue;
        }
        let plain = match crate::decrypt_frame(&peer.keys, &enc, &aad) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if frame.class == crate::FrameClass::Control
            && let Ok(msg) = ControlMessage::decode(&plain)
        {
            handle_control_message(runtime.clone(), peer.clone(), msg).await;
        }
        sess.on_bytes_sent(frame.payload.len());
    }
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
            let _ = sess.handle_pong(
                crate::Pong {
                    request_id: p.request_id,
                },
                now_us(),
            );
        }
        _ => {}
    }
}

async fn send_control(peer: Arc<PeerRuntime>, msg: ControlMessage) -> Result<()> {
    let payload = msg.encode();
    let seq = peer.send_seq.fetch_add(1, Ordering::Relaxed);
    let key_id = peer.session.lock().await.active_key_id();
    let aad = build_aad(
        crate::FrameClass::Control as u8,
        CONTROL_PROTOCOL_V1 as u16,
        0,
    );
    let enc = crate::encrypt_frame(&peer.keys, key_id, seq, &payload, &aad)?;
    let framed_payload = encode_encrypted_payload(&enc);
    peer.links
        .send_control(CONTROL_PROTOCOL_V1 as u16, 0, framed_payload)
        .await
        .map_err(|e| anyhow!("send control failed: {e}"))?;
    peer.session.lock().await.on_bytes_sent(payload.len());
    Ok(())
}

async fn run_ping_loop(runtime: Arc<NodeRuntime>, mut shutdown: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    let mut request_id: u64 = 1;
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let peers = runtime.peers.read().await.values().cloned().collect::<Vec<_>>();
                for peer in peers {
                    let now = now_us();
                    peer.session.lock().await.track_ping(request_id, now);
                    let ping = ControlMessage::Ping(ControlPing { request_id, sender_node_id: runtime.node_id });
                    let _ = send_control(peer, ping).await;
                    request_id = request_id.saturating_add(1);
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
                    let mut session = peer.session.lock().await;
                    if session.should_rekey(now) {
                        let next_key_id = session.active_key_id().saturating_add(1);
                        let req = session.build_session_change_request(request_id, next_key_id, now);
                        request_id = request_id.saturating_add(1);
                        let ack = session.accept_session_change_request(req);
                        let _ = session.handle_session_change_ack(ack, now.saturating_add(1));
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
}
