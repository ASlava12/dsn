use dsn_core::{
    AddressMode, DhtRuntime, DsnConfig, HandshakeConfig, PeerLinksMode, Ping, SessionPolicy,
    SessionState, build_client_hello, generate_identity, handle_client_hello, handle_server_hello,
    publish_public_identity, server_session_keys, verify_finished,
};
use ed25519_dalek::SigningKey;

fn id_byte(v: u8) -> [u8; 32] {
    [v; 32]
}

fn parse_id_hex_32(raw: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&raw[i * 2..i * 2 + 2], 16).expect("hex byte");
    }
    out
}

fn signing_key_from_b64(raw: &str) -> SigningKey {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw.as_bytes())
        .expect("base64 private key");
    SigningKey::from_keypair_bytes(
        bytes
            .as_slice()
            .try_into()
            .expect("ed25519 keypair bytes must be 64 bytes"),
    )
    .expect("signing key")
}

#[test]
fn bootstrap_handshake_ping_mesh_store_find_rekey_publish() {
    // 3-node in-process testbed
    let mut dht_a = DhtRuntime::new(id_byte(0x10), true);
    let mut dht_b = DhtRuntime::new(id_byte(0x20), true);
    let mut dht_c = DhtRuntime::new(id_byte(0x30), true);

    dht_a.add_known_node(dht_b.node_id);
    dht_a.add_known_node(dht_c.node_id);
    dht_b.add_known_node(dht_a.node_id);
    dht_b.add_known_node(dht_c.node_id);
    dht_c.add_known_node(dht_a.node_id);
    dht_c.add_known_node(dht_b.node_id);

    // bootstrap + nearest nodes
    let nearest = dht_a.find_node(id_byte(0x21), 2);
    assert_eq!(nearest.len(), 2);

    // handshake A <-> B
    let ida = generate_identity("ed25519").expect("id a");
    let idb = generate_identity("ed25519").expect("id b");
    let sign_a = signing_key_from_b64(&ida.private_key);
    let sign_b = signing_key_from_b64(&idb.private_key);

    let (client_state, ch) = build_client_hello(
        &sign_a,
        HandshakeConfig {
            protocol_version: 1,
            mux_mode: PeerLinksMode::SingleMux,
            address_mode: AddressMode::All,
            pow_difficulty: 8,
            node_id: parse_id_hex_32(&ida.id),
        },
    )
    .expect("client hello");

    let (server_state, sh) = handle_client_hello(
        &ch,
        &sign_a.verifying_key(),
        &sign_b,
        HandshakeConfig {
            protocol_version: 1,
            mux_mode: PeerLinksMode::SingleMux,
            address_mode: AddressMode::All,
            pow_difficulty: 8,
            node_id: parse_id_hex_32(&idb.id),
        },
    )
    .expect("server hello");

    let (client_keys, finished) = handle_server_hello(client_state, &sh, &sign_b.verifying_key())
        .expect("client handles server hello");
    verify_finished(&server_state, &finished).expect("finished verified");
    let server_keys = server_session_keys(&server_state);
    assert_eq!(client_keys.send_key, server_keys.recv_key);

    // ping mesh
    let mut ab = SessionState::new(SessionPolicy::default(), 1, 1_000);
    let ba = SessionState::new(SessionPolicy::default(), 1, 1_000);

    for req in 1..=5u64 {
        let ping = ab.track_ping(req, 2_000 + req * 100);
        let pong = ba.respond_pong(Ping {
            request_id: ping.request_id,
            ts_mono_us: ping.ts_mono_us,
        });
        let rtt = ab
            .handle_pong(pong, 2_050 + req * 100)
            .expect("pong tracked");
        assert!(rtt > 0);
    }
    assert_eq!(ab.rtt_ring_us().len(), 5);

    // store/find over namespace (simulated replication)
    let ns = "main";
    let key = b"k:hello".to_vec();
    let val = b"v:world".to_vec();
    dht_a.store(ns, key.clone(), val.clone());
    dht_b.store(ns, key.clone(), val.clone());
    dht_c.store(ns, key.clone(), val.clone());
    assert_eq!(dht_b.find_value(ns, &key), Some(val.clone()));

    // rekey with reduced threshold in test policy
    let mut rekey_state = SessionState::new(
        SessionPolicy {
            rekey_bytes_threshold: 256,
            rekey_age_threshold_us: u64::MAX,
            grace_window_us: 50,
            session_timeout_us: 300_000_000,
        },
        7,
        10,
    );
    rekey_state.on_bytes_sent(300);
    assert!(rekey_state.should_rekey(100));
    let req = rekey_state.build_session_change_request(42, 8, 100);
    let ack = rekey_state.accept_session_change_request(req);
    rekey_state
        .handle_session_change_ack(ack, 120)
        .expect("ack switches key");
    assert_eq!(rekey_state.active_key_id(), 8);

    // address publish into DHT
    let mut cfg = DsnConfig::default_with_generated_identity().expect("cfg");
    cfg.address_mode = dsn_core::config::AddressMode::All;
    cfg.identity = ida.clone();
    let published = publish_public_identity(&cfg, &mut dht_a, &ida, 1, 1, 5_000).expect("publish");
    assert_eq!(published.id, ida.id);
    assert!(dht_a.find_value_at("main", ida.id.as_bytes(), 5_000).is_some());
}
