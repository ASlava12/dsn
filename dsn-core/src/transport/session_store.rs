use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::{Context, Result, anyhow, bail};
use redis::Commands;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistedPeerSession {
    pub peer_node_id: [u8; 32],
    pub active_key_id: u32,
    pub bytes_on_active_key: u64,
    pub active_key_since_us: u64,
    pub last_pong_us: u64,
}

pub trait SessionStore: Send + Sync {
    fn save(&self, session: &PersistedPeerSession) -> Result<()>;
    fn load(&self, peer_node_id: [u8; 32]) -> Result<Option<PersistedPeerSession>>;
    fn list(&self) -> Result<Vec<PersistedPeerSession>>;
    fn delete(&self, peer_node_id: [u8; 32]) -> Result<()>;
}

#[derive(Debug, Clone)]
pub enum SessionStoreKind {
    Memory,
    File { dir: PathBuf },
    Redis { uri: String, prefix: String },
}

impl SessionStoreKind {
    pub fn build(self) -> Result<Box<dyn SessionStore>> {
        match self {
            SessionStoreKind::Memory => Ok(Box::new(MemorySessionStore::new())),
            SessionStoreKind::File { dir } => Ok(Box::new(FileSessionStore::new(dir)?)),
            SessionStoreKind::Redis { uri, prefix } => {
                validate_redis_session_store_uri(&uri)?;
                Ok(Box::new(RedisSessionStore::new(uri, prefix)?))
            }
        }
    }
}

#[derive(Default)]
struct MemorySessionStore {
    sessions: Mutex<HashMap<[u8; 32], PersistedPeerSession>>,
}

impl MemorySessionStore {
    fn new() -> Self {
        Self::default()
    }
}

impl SessionStore for MemorySessionStore {
    fn save(&self, session: &PersistedPeerSession) -> Result<()> {
        self.sessions
            .lock()
            .map_err(|_| anyhow!("memory session store poisoned"))?
            .insert(session.peer_node_id, session.clone());
        Ok(())
    }

    fn load(&self, peer_node_id: [u8; 32]) -> Result<Option<PersistedPeerSession>> {
        Ok(self
            .sessions
            .lock()
            .map_err(|_| anyhow!("memory session store poisoned"))?
            .get(&peer_node_id)
            .cloned())
    }

    fn list(&self) -> Result<Vec<PersistedPeerSession>> {
        Ok(self
            .sessions
            .lock()
            .map_err(|_| anyhow!("memory session store poisoned"))?
            .values()
            .cloned()
            .collect())
    }

    fn delete(&self, peer_node_id: [u8; 32]) -> Result<()> {
        self.sessions
            .lock()
            .map_err(|_| anyhow!("memory session store poisoned"))?
            .remove(&peer_node_id);
        Ok(())
    }
}

struct FileSessionStore {
    dir: PathBuf,
}

impl FileSessionStore {
    fn new(dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create session dir {}", dir.display()))?;
        Ok(Self { dir })
    }

    fn path_for(&self, peer_node_id: [u8; 32]) -> PathBuf {
        self.dir.join(format!("{}.json", to_hex(peer_node_id)))
    }
}

impl SessionStore for FileSessionStore {
    fn save(&self, session: &PersistedPeerSession) -> Result<()> {
        let path = self.path_for(session.peer_node_id);
        let raw = serde_json::to_vec_pretty(session)?;
        fs::write(&path, raw).with_context(|| format!("failed write {}", path.display()))
    }

    fn load(&self, peer_node_id: [u8; 32]) -> Result<Option<PersistedPeerSession>> {
        let path = self.path_for(peer_node_id);
        if !path.exists() {
            return Ok(None);
        }
        let raw = fs::read(&path).with_context(|| format!("failed read {}", path.display()))?;
        Ok(Some(serde_json::from_slice(&raw)?))
    }

    fn list(&self) -> Result<Vec<PersistedPeerSession>> {
        let mut out = Vec::new();
        for entry in fs::read_dir(&self.dir)
            .with_context(|| format!("failed read_dir {}", self.dir.display()))?
        {
            let entry = entry?;
            if !entry.path().is_file() {
                continue;
            }
            let raw = fs::read(entry.path())?;
            out.push(serde_json::from_slice(&raw)?);
        }
        Ok(out)
    }

    fn delete(&self, peer_node_id: [u8; 32]) -> Result<()> {
        let path = self.path_for(peer_node_id);
        if path.exists() {
            let _ = fs::remove_file(path);
        }
        Ok(())
    }
}

struct RedisSessionStore {
    client: redis::Client,
    prefix: String,
}

impl RedisSessionStore {
    fn new(uri: String, prefix: String) -> Result<Self> {
        let client = redis::Client::open(uri).context("invalid redis URI")?;
        Ok(Self { client, prefix })
    }

    fn key(&self, peer_node_id: [u8; 32]) -> String {
        format!("{}:{}", self.prefix, to_hex(peer_node_id))
    }

    fn list_key(&self) -> String {
        format!("{}:__index__", self.prefix)
    }
}

impl SessionStore for RedisSessionStore {
    fn save(&self, session: &PersistedPeerSession) -> Result<()> {
        let mut conn = self
            .client
            .get_connection()
            .context("redis connection failed")?;
        let payload = serde_json::to_string(session)?;
        let key = self.key(session.peer_node_id);
        let _: () = conn.set(&key, payload).context("redis set failed")?;
        let _: () = conn
            .sadd(self.list_key(), key)
            .context("redis index update failed")?;
        Ok(())
    }

    fn load(&self, peer_node_id: [u8; 32]) -> Result<Option<PersistedPeerSession>> {
        let mut conn = self
            .client
            .get_connection()
            .context("redis connection failed")?;
        let raw: Option<String> = conn
            .get(self.key(peer_node_id))
            .context("redis get failed")?;
        match raw {
            Some(v) => Ok(Some(serde_json::from_str(&v)?)),
            None => Ok(None),
        }
    }

    fn list(&self) -> Result<Vec<PersistedPeerSession>> {
        let mut conn = self
            .client
            .get_connection()
            .context("redis connection failed")?;
        let keys: Vec<String> = conn
            .smembers(self.list_key())
            .context("redis smembers failed")?;
        let mut out = Vec::new();
        for key in keys {
            let raw: Option<String> = conn.get(&key)?;
            if let Some(raw) = raw {
                out.push(serde_json::from_str(&raw)?);
            }
        }
        Ok(out)
    }

    fn delete(&self, peer_node_id: [u8; 32]) -> Result<()> {
        let mut conn = self
            .client
            .get_connection()
            .context("redis connection failed")?;
        let key = self.key(peer_node_id);
        let _: () = conn.del(&key).context("redis del failed")?;
        let _: () = conn
            .srem(self.list_key(), key)
            .context("redis index cleanup failed")?;
        Ok(())
    }
}

pub fn validate_redis_session_store_uri(uri: &str) -> Result<()> {
    if uri.starts_with("redis+unix://") {
        let parsed = Url::parse(uri).with_context(|| format!("invalid redis URI: {uri}"))?;
        if parsed.scheme() != "redis+unix" {
            bail!("unsupported redis URI scheme");
        }
        if parsed.path().is_empty() || parsed.path() == "/" {
            bail!("redis+unix URI must include socket path");
        }
        return Ok(());
    }

    let parsed = Url::parse(uri).with_context(|| format!("invalid redis URI: {uri}"))?;
    match parsed.scheme() {
        "redis" | "rediss" => {}
        _ => bail!("unsupported redis URI scheme; expected redis/rediss/redis+unix"),
    }

    if parsed.host_str().is_none() {
        bail!("redis/rediss URI must include host");
    }

    Ok(())
}

fn to_hex(bytes: [u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{PersistedPeerSession, SessionStoreKind, validate_redis_session_store_uri};

    fn id(v: u8) -> [u8; 32] {
        [v; 32]
    }

    fn sample(peer: [u8; 32]) -> PersistedPeerSession {
        PersistedPeerSession {
            peer_node_id: peer,
            active_key_id: 7,
            bytes_on_active_key: 42,
            active_key_since_us: 100,
            last_pong_us: 120,
        }
    }

    #[test]
    fn file_store_restores_peer_state_across_restart() {
        let dir = std::env::temp_dir().join(format!(
            "dsn-session-store-{}-{}",
            std::process::id(),
            987654u64
        ));

        let store = SessionStoreKind::File { dir: dir.clone() }
            .build()
            .expect("store");
        let s1 = sample(id(1));
        store.save(&s1).expect("save");

        // Simulate restart: create a fresh store instance over same directory.
        let restarted = SessionStoreKind::File { dir: dir.clone() }
            .build()
            .expect("restart store");
        let restored = restarted.load(id(1)).expect("load").expect("exists");
        assert_eq!(restored, s1);

        let listed = restarted.list().expect("list");
        assert_eq!(listed.len(), 1);

        restarted.delete(id(1)).expect("delete");
        assert!(restarted.load(id(1)).expect("load after delete").is_none());

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn memory_store_roundtrip() {
        let store = SessionStoreKind::Memory.build().expect("memory store");
        let s = sample(id(9));

        store.save(&s).expect("save");
        assert_eq!(store.load(id(9)).expect("load"), Some(s.clone()));
        assert_eq!(store.list().expect("list").len(), 1);
        store.delete(id(9)).expect("delete");
        assert!(store.load(id(9)).expect("load after delete").is_none());
    }

    #[test]
    fn redis_uri_validation_accepts_expected_forms() {
        let ok = [
            "redis://localhost",
            "redis://user:pass@localhost:6379/0",
            "rediss://localhost:6380/1?tls=true",
            "redis+unix:///var/run/redis.sock",
        ];

        for uri in ok {
            validate_redis_session_store_uri(uri).expect(uri);
        }
    }

    #[test]
    fn redis_uri_validation_rejects_invalid_forms() {
        let bad = [
            "http://localhost:6379",
            "redis://",
            "redis+unix:///",
            "redis+unix://",
            "rediss://",
        ];

        for uri in bad {
            assert!(
                validate_redis_session_store_uri(uri).is_err(),
                "uri should fail: {uri}"
            );
        }
    }
}
