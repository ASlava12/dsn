use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::{Context, Result, anyhow, bail};
use redis::Commands;
use serde::{Deserialize, Serialize};

pub const ROUTE_TTL_US: u64 = 60 * 60 * 1_000_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteEntry {
    pub session_id: [u8; 32],
    pub dst_node_id: [u8; 32],
    pub src_node_id: [u8; 32],
    pub ingress_transport: String,
    pub egress_transport: String,
    pub expires_at_us: u64,
}

#[derive(Debug, Clone)]
pub struct CreateRouteRequest {
    pub session_id: [u8; 32],
    pub dst_node_id: [u8; 32],
    pub src_node_id: [u8; 32],
    pub ingress_transport: String,
    pub egress_transport: String,
    pub namespace: Option<String>,
}

#[derive(Debug, Clone)]
pub enum RouteStorageKind {
    Memory,
    File { dir: PathBuf },
    Redis { url: String, prefix: String },
}

trait RouteStore: Send + Sync {
    fn put(&self, key: &str, entry: &RouteEntry) -> Result<()>;
    fn get(&self, key: &str) -> Result<Option<RouteEntry>>;
    fn delete(&self, key: &str) -> Result<()>;
}

struct MemoryRouteStore {
    entries: Mutex<HashMap<String, RouteEntry>>,
}

impl MemoryRouteStore {
    fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }
}

impl RouteStore for MemoryRouteStore {
    fn put(&self, key: &str, entry: &RouteEntry) -> Result<()> {
        self.entries
            .lock()
            .map_err(|_| anyhow!("memory route store poisoned"))?
            .insert(key.to_owned(), entry.clone());
        Ok(())
    }

    fn get(&self, key: &str) -> Result<Option<RouteEntry>> {
        Ok(self
            .entries
            .lock()
            .map_err(|_| anyhow!("memory route store poisoned"))?
            .get(key)
            .cloned())
    }

    fn delete(&self, key: &str) -> Result<()> {
        self.entries
            .lock()
            .map_err(|_| anyhow!("memory route store poisoned"))?
            .remove(key);
        Ok(())
    }
}

struct FileRouteStore {
    dir: PathBuf,
}

impl FileRouteStore {
    fn new(dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create route dir {}", dir.display()))?;
        Ok(Self { dir })
    }

    fn path_for_key(&self, key: &str) -> PathBuf {
        self.dir.join(format!("{key}.json"))
    }
}

impl RouteStore for FileRouteStore {
    fn put(&self, key: &str, entry: &RouteEntry) -> Result<()> {
        let path = self.path_for_key(key);
        let payload = serde_json::to_vec(entry)?;
        fs::write(&path, payload).with_context(|| format!("failed write route {}", path.display()))
    }

    fn get(&self, key: &str) -> Result<Option<RouteEntry>> {
        let path = self.path_for_key(key);
        if !path.exists() {
            return Ok(None);
        }
        let raw =
            fs::read(&path).with_context(|| format!("failed read route {}", path.display()))?;
        Ok(Some(serde_json::from_slice(&raw)?))
    }

    fn delete(&self, key: &str) -> Result<()> {
        let path = self.path_for_key(key);
        if path.exists() {
            let _ = fs::remove_file(path);
        }
        Ok(())
    }
}

struct RedisRouteStore {
    client: redis::Client,
    prefix: String,
}

impl RedisRouteStore {
    fn new(url: String, prefix: String) -> Result<Self> {
        let client = redis::Client::open(url).context("invalid redis url for route store")?;
        Ok(Self { client, prefix })
    }

    fn redis_key(&self, key: &str) -> String {
        format!("{}:{}", self.prefix, key)
    }
}

impl RouteStore for RedisRouteStore {
    fn put(&self, key: &str, entry: &RouteEntry) -> Result<()> {
        let mut conn = self
            .client
            .get_connection()
            .context("redis connection failed")?;
        let payload = serde_json::to_string(entry)?;
        let ttl_secs = ((entry.expires_at_us.saturating_sub(now_us_fallback())) / 1_000_000).max(1);
        let _: () = conn
            .set_ex(self.redis_key(key), payload, ttl_secs)
            .context("redis set_ex failed")?;
        Ok(())
    }

    fn get(&self, key: &str) -> Result<Option<RouteEntry>> {
        let mut conn = self
            .client
            .get_connection()
            .context("redis connection failed")?;
        let raw: Option<String> = conn.get(self.redis_key(key)).context("redis get failed")?;
        match raw {
            Some(v) => Ok(Some(serde_json::from_str(&v)?)),
            None => Ok(None),
        }
    }

    fn delete(&self, key: &str) -> Result<()> {
        let mut conn = self
            .client
            .get_connection()
            .context("redis connection failed")?;
        let _: () = conn.del(self.redis_key(key)).context("redis del failed")?;
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct RouteAcl {
    whitelist: HashMap<Option<String>, HashSet<[u8; 32]>>,
    blacklist: HashMap<Option<String>, HashSet<[u8; 32]>>,
}

impl RouteAcl {
    pub fn whitelist_add(&mut self, namespace: Option<String>, node_id: [u8; 32]) {
        self.whitelist.entry(namespace).or_default().insert(node_id);
    }

    pub fn blacklist_add(&mut self, namespace: Option<String>, node_id: [u8; 32]) {
        self.blacklist.entry(namespace).or_default().insert(node_id);
    }

    fn allowed(&self, namespace: &Option<String>, src: [u8; 32]) -> bool {
        if self
            .blacklist
            .get(namespace)
            .is_some_and(|set| set.contains(&src))
        {
            return false;
        }

        match self.whitelist.get(namespace) {
            Some(set) if !set.is_empty() => set.contains(&src),
            _ => true,
        }
    }
}

pub struct RouteManager {
    store: Box<dyn RouteStore>,
    acl: RouteAcl,
}

impl RouteManager {
    pub fn new(storage: RouteStorageKind) -> Result<Self> {
        let store: Box<dyn RouteStore> = match storage {
            RouteStorageKind::Memory => Box::new(MemoryRouteStore::new()),
            RouteStorageKind::File { dir } => Box::new(FileRouteStore::new(dir)?),
            RouteStorageKind::Redis { url, prefix } => Box::new(RedisRouteStore::new(url, prefix)?),
        };

        Ok(Self {
            store,
            acl: RouteAcl::default(),
        })
    }

    pub fn acl_mut(&mut self) -> &mut RouteAcl {
        &mut self.acl
    }

    pub fn create_route(&self, req: CreateRouteRequest, now_us: u64) -> Result<RouteEntry> {
        if !self.acl.allowed(&req.namespace, req.src_node_id) {
            bail!("route source denied by whitelist/blacklist");
        }

        let entry = RouteEntry {
            session_id: req.session_id,
            dst_node_id: req.dst_node_id,
            src_node_id: req.src_node_id,
            ingress_transport: req.ingress_transport,
            egress_transport: req.egress_transport,
            expires_at_us: now_us.saturating_add(ROUTE_TTL_US),
        };

        self.store.put(&route_key(req.session_id), &entry)?;
        Ok(entry)
    }

    pub fn get_route(&self, session_id: [u8; 32], now_us: u64) -> Result<Option<RouteEntry>> {
        let key = route_key(session_id);
        let Some(entry) = self.store.get(&key)? else {
            return Ok(None);
        };

        if now_us > entry.expires_at_us {
            self.store.delete(&key)?;
            return Ok(None);
        }

        Ok(Some(entry))
    }

    pub fn use_route(&self, session_id: [u8; 32], now_us: u64) -> Result<Option<RouteEntry>> {
        let key = route_key(session_id);
        let Some(mut entry) = self.get_route(session_id, now_us)? else {
            return Ok(None);
        };

        entry.expires_at_us = now_us.saturating_add(ROUTE_TTL_US);
        self.store.put(&key, &entry)?;
        Ok(Some(entry))
    }
}

fn route_key(session_id: [u8; 32]) -> String {
    session_id
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
}

fn now_us_fallback() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{CreateRouteRequest, ROUTE_TTL_US, RouteManager, RouteStorageKind};
    use std::fs;

    fn id(v: u8) -> [u8; 32] {
        [v; 32]
    }

    #[test]
    fn route_lives_one_hour_and_extends_on_use() {
        let manager = RouteManager::new(RouteStorageKind::Memory).expect("manager");
        let req = CreateRouteRequest {
            session_id: id(1),
            dst_node_id: id(2),
            src_node_id: id(3),
            ingress_transport: "tcp://in".to_owned(),
            egress_transport: "tcp://out".to_owned(),
            namespace: None,
        };

        let created = manager.create_route(req, 100).expect("create");
        assert_eq!(created.expires_at_us, 100 + ROUTE_TTL_US);

        let used = manager.use_route(id(1), 200).expect("use").expect("exists");
        assert_eq!(used.expires_at_us, 200 + ROUTE_TTL_US);

        let expired = manager
            .get_route(id(1), 200 + ROUTE_TTL_US + 1)
            .expect("get after ttl");
        assert!(expired.is_none());
    }

    #[test]
    fn whitelist_and_blacklist_are_applied() {
        let mut manager = RouteManager::new(RouteStorageKind::Memory).expect("manager");
        manager
            .acl_mut()
            .whitelist_add(Some("main".to_owned()), id(7));

        let denied = manager.create_route(
            CreateRouteRequest {
                session_id: id(1),
                dst_node_id: id(2),
                src_node_id: id(8),
                ingress_transport: "in".to_owned(),
                egress_transport: "out".to_owned(),
                namespace: Some("main".to_owned()),
            },
            0,
        );
        assert!(denied.is_err());

        manager
            .acl_mut()
            .blacklist_add(Some("main".to_owned()), id(7));
        let denied_black = manager.create_route(
            CreateRouteRequest {
                session_id: id(3),
                dst_node_id: id(2),
                src_node_id: id(7),
                ingress_transport: "in".to_owned(),
                egress_transport: "out".to_owned(),
                namespace: Some("main".to_owned()),
            },
            0,
        );
        assert!(denied_black.is_err());
    }

    #[test]
    fn file_store_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "dsn-route-test-{}-{}",
            std::process::id(),
            123456u64
        ));
        let manager =
            RouteManager::new(RouteStorageKind::File { dir: dir.clone() }).expect("manager");

        let _ = manager
            .create_route(
                CreateRouteRequest {
                    session_id: id(9),
                    dst_node_id: id(2),
                    src_node_id: id(3),
                    ingress_transport: "in".to_owned(),
                    egress_transport: "out".to_owned(),
                    namespace: None,
                },
                10,
            )
            .expect("create");

        let got = manager.get_route(id(9), 20).expect("get");
        assert!(got.is_some());

        let _ = fs::remove_dir_all(dir);
    }
}
