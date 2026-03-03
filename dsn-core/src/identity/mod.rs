use anyhow::{Result, anyhow, bail};
use base64::Engine;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::config::{DsnConfig, IdentityConfig};
use crate::dht::DhtRuntime;

pub fn generate_identity(algo: &str) -> Result<IdentityConfig> {
    if algo != "ed25519" {
        bail!("unsupported key algorithm: {algo}");
    }

    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();

    let public_key = base64::engine::general_purpose::STANDARD.encode(verifying_key.as_bytes());
    let private_key =
        base64::engine::general_purpose::STANDARD.encode(signing_key.to_keypair_bytes().as_ref());

    let hash_output = blake3::hash(verifying_key.as_bytes());
    let id = hash_output
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    Ok(IdentityConfig {
        algo: algo.to_owned(),
        public_key,
        private_key,
        id,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicIdentity {
    pub algo: String,
    pub public_key: String,
    pub id: String,
    pub ip4_nonce: u32,
    pub ip6_nonce: u128,
    pub ip4: Option<Ipv4Addr>,
    pub ip6: Option<Ipv6Addr>,
    pub publication_date_us: u64,
}

pub fn allocate_ipv4(public_key: &[u8], nonce: u32) -> Ipv4Addr {
    let short = blake3::hash(public_key);
    let mut seed = [0u8; 8];
    seed[..4].copy_from_slice(&short.as_bytes()[..4]);
    seed[4..].copy_from_slice(&nonce.to_be_bytes());
    let hash = blake3::hash(&seed);
    Ipv4Addr::new(
        hash.as_bytes()[0],
        hash.as_bytes()[1],
        hash.as_bytes()[2],
        hash.as_bytes()[3],
    )
}

pub fn allocate_ipv6(public_key: &[u8], nonce: u128) -> Ipv6Addr {
    let short = blake3::hash(public_key);
    let mut seed = [0u8; 32];
    seed[..16].copy_from_slice(&short.as_bytes()[..16]);
    seed[16..].copy_from_slice(&nonce.to_be_bytes());
    let hash = blake3::hash(&seed);
    let mut out = [0u8; 16];
    out.copy_from_slice(&hash.as_bytes()[..16]);
    Ipv6Addr::from(out)
}

pub fn publish_public_identity(
    cfg: &DsnConfig,
    dht: &mut DhtRuntime,
    identity: &IdentityConfig,
    ip4_nonce: u32,
    ip6_nonce: u128,
    now_us: u64,
) -> Result<PublicIdentity> {
    let public_key_bytes = base64::engine::general_purpose::STANDARD
        .decode(identity.public_key.as_bytes())
        .map_err(|_| anyhow!("identity.public_key must be base64"))?;

    let ip4 = allocate_ipv4(&public_key_bytes, ip4_nonce);
    let ip6 = allocate_ipv6(&public_key_bytes, ip6_nonce);

    let ip4_allowed = cfg.is_allowed_ipv4(ip4);
    let ip6_allowed = cfg.is_allowed_ipv6(ip6);

    let resolved_ip4 = if ip4_allowed { Some(ip4) } else { None };
    let resolved_ip6 = if ip6_allowed { Some(ip6) } else { None };

    let pid = PublicIdentity {
        algo: identity.algo.clone(),
        public_key: identity.public_key.clone(),
        id: identity.id.clone(),
        ip4_nonce,
        ip6_nonce,
        ip4: resolved_ip4,
        ip6: resolved_ip6,
        publication_date_us: now_us,
    };

    dht.expire_publications(now_us);

    let payload = serde_json::to_vec(&pid)?;
    let self_id_key = identity.id.as_bytes().to_vec();

    if let Some(existing) = dht.find_value_at("main", &self_id_key, now_us)
        && !same_identity(&existing, &pid)
    {
        bail!("main namespace key already occupied by another identity");
    }

    dht.store_publication("main", self_id_key, payload.clone(), now_us);

    if let Some(ip4) = pid.ip4 {
        let key = ip4.to_string().into_bytes();
        if let Some(existing) = dht.find_value_at("ip4", &key, now_us)
            && !same_identity(&existing, &pid)
        {
            bail!("ip4 namespace key already occupied");
        }
        dht.store_publication("ip4", key, payload.clone(), now_us);
    }

    if let Some(ip6) = pid.ip6 {
        let key = ip6.to_string().into_bytes();
        if let Some(existing) = dht.find_value_at("ip6", &key, now_us)
            && !same_identity(&existing, &pid)
        {
            bail!("ip6 namespace key already occupied");
        }
        dht.store_publication("ip6", key, payload.clone(), now_us);
    }

    Ok(pid)
}

fn same_identity(raw: &[u8], id: &PublicIdentity) -> bool {
    serde_json::from_slice::<PublicIdentity>(raw)
        .map(|other| other.id == id.id)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::{
        PublicIdentity, allocate_ipv4, allocate_ipv6, generate_identity, publish_public_identity,
    };
    use crate::config::{AddressMode, DsnConfig};
    use crate::dht::{DhtRuntime, PUBLICATION_TTL_US};

    fn cfg(mode: AddressMode) -> DsnConfig {
        let mut cfg = DsnConfig::default_with_generated_identity().expect("cfg");
        cfg.address_mode = mode;
        cfg.ip4_include_net = vec![];
        cfg.ip4_exclude_net = vec![];
        cfg.ip6_include_net = vec![];
        cfg.ip6_exclude_net = vec![];
        cfg
    }

    #[test]
    fn ip_allocation_is_deterministic() {
        let pk = b"pk-sample";
        assert_eq!(allocate_ipv4(pk, 7), allocate_ipv4(pk, 7));
        assert_eq!(allocate_ipv6(pk, 9), allocate_ipv6(pk, 9));
    }

    #[test]
    fn publish_checks_occupancy_and_publication_ttl() {
        let id1 = generate_identity("ed25519").expect("id1");
        let id2 = generate_identity("ed25519").expect("id2");

        let mut dht = DhtRuntime::new([1; 32], true);
        let mut cfg1 = cfg(AddressMode::All);
        cfg1.identity = id1.clone();

        let first = publish_public_identity(&cfg1, &mut dht, &id1, 1, 1, 100).expect("publish #1");
        assert!(first.ip4.is_some() || first.ip6.is_some());

        let mut cfg2 = cfg(AddressMode::All);
        cfg2.identity = id2.clone();
        let _ = publish_public_identity(&cfg2, &mut dht, &id2, 1, 1, 101).expect("publish #2");

        dht.expire_publications(100 + PUBLICATION_TTL_US + 1);
        let key = id1.id.as_bytes();
        assert!(dht.find_value("main", key).is_none());
    }

    #[test]
    fn publish_respects_address_mode_filters() {
        let id = generate_identity("ed25519").expect("id");
        let mut dht = DhtRuntime::new([2; 32], true);
        let mut cfg = cfg(AddressMode::PublicOnly);
        cfg.identity = id.clone();

        let pubid = publish_public_identity(&cfg, &mut dht, &id, 0, 0, 1_000).expect("publish");

        if let Some(ip4) = pubid.ip4 {
            assert!(cfg.is_allowed_ipv4(ip4));
        }
        if let Some(ip6) = pubid.ip6 {
            assert!(cfg.is_allowed_ipv6(ip6));
        }

        let raw = dht
            .find_value_at("main", id.id.as_bytes(), 1_000)
            .expect("main record must exist");
        let parsed: PublicIdentity = serde_json::from_slice(&raw).expect("decode pid");
        assert_eq!(parsed.id, id.id);
    }
}
