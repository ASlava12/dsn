use std::collections::HashMap;

const NON_RELAY_CACHE_TTL_US: u64 = 5 * 60 * 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhtRecord {
    pub namespace: String,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DhtRuntime {
    pub node_id: [u8; 32],
    pub participate_in_dht: bool,
    stores: HashMap<String, HashMap<Vec<u8>, Vec<u8>>>,
    known_nodes: Vec<[u8; 32]>,
    non_relay_cache_until_us: HashMap<Vec<u8>, u64>,
}

impl DhtRuntime {
    pub fn new(node_id: [u8; 32], participate_in_dht: bool) -> Self {
        Self {
            node_id,
            participate_in_dht,
            stores: HashMap::new(),
            known_nodes: Vec::new(),
            non_relay_cache_until_us: HashMap::new(),
        }
    }

    pub fn add_known_node(&mut self, node_id: [u8; 32]) {
        if node_id != self.node_id && !self.known_nodes.iter().any(|id| id == &node_id) {
            self.known_nodes.push(node_id);
        }
    }

    pub fn store(&mut self, namespace: &str, key: Vec<u8>, value: Vec<u8>) {
        self.stores
            .entry(namespace.to_owned())
            .or_default()
            .insert(key, value);
    }

    pub fn find_value(&self, namespace: &str, key: &[u8]) -> Option<Vec<u8>> {
        self.stores
            .get(namespace)
            .and_then(|ns| ns.get(key).cloned())
    }

    pub fn delete(&mut self, namespace: &str, key: &[u8]) -> bool {
        self.stores
            .get_mut(namespace)
            .and_then(|ns| ns.remove(key))
            .is_some()
    }

    pub fn find_node(&self, target_id: [u8; 32], max: usize) -> Vec<[u8; 32]> {
        let mut nodes = self.known_nodes.clone();
        nodes.sort_by_key(|id| xor_distance_prefix(*id, target_id));
        nodes.truncate(max);
        nodes
    }

    pub fn should_relay(&mut self, request_fingerprint: Vec<u8>, now_us: u64) -> bool {
        self.gc_cache(now_us);
        self.non_relay_cache_until_us
            .insert(request_fingerprint, now_us + NON_RELAY_CACHE_TTL_US);
        self.participate_in_dht
    }

    pub fn has_cached_request(&mut self, request_fingerprint: &[u8], now_us: u64) -> bool {
        self.gc_cache(now_us);
        self.non_relay_cache_until_us
            .get(request_fingerprint)
            .is_some_and(|until| *until >= now_us)
    }

    fn gc_cache(&mut self, now_us: u64) {
        self.non_relay_cache_until_us
            .retain(|_, until| *until >= now_us);
    }
}

fn xor_distance_prefix(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::DhtRuntime;

    fn id(v: u8) -> [u8; 32] {
        [v; 32]
    }

    #[test]
    fn namespace_store_find_delete_works() {
        let mut dht = DhtRuntime::new(id(1), true);
        dht.store("main", b"node-a".to_vec(), b"value-a".to_vec());
        dht.store("ip4", b"1.2.3.4".to_vec(), b"value-ip".to_vec());

        assert_eq!(
            dht.find_value("main", b"node-a").as_deref(),
            Some(&b"value-a"[..])
        );
        assert_eq!(
            dht.find_value("ip4", b"1.2.3.4").as_deref(),
            Some(&b"value-ip"[..])
        );
        assert!(dht.delete("main", b"node-a"));
        assert!(dht.find_value("main", b"node-a").is_none());
    }

    #[test]
    fn find_node_returns_nearest_for_three_nodes() {
        let mut a = DhtRuntime::new(id(0x10), true);
        let b = id(0x11);
        let c = id(0x80);
        a.add_known_node(b);
        a.add_known_node(c);

        let nearest = a.find_node(id(0x12), 2);
        assert_eq!(nearest.len(), 2);
        assert_eq!(nearest[0], b);
        assert_eq!(nearest[1], c);
    }

    #[test]
    fn non_participant_does_not_relay_but_caches_five_minutes() {
        let mut dht = DhtRuntime::new(id(1), false);
        let fingerprint = b"find_node:req-1".to_vec();

        let should_relay = dht.should_relay(fingerprint.clone(), 1_000);
        assert!(!should_relay);
        assert!(dht.has_cached_request(&fingerprint, 1_000));
        assert!(dht.has_cached_request(&fingerprint, 1_000 + 4 * 60 * 1_000_000));
        assert!(!dht.has_cached_request(&fingerprint, 1_000 + 5 * 60 * 1_000_000 + 1));
    }
}
