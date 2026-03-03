use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use configparser::ini::Ini;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use ipnet::{Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use crate::identity::generate_identity;
use crate::transport::{TransportEndpoint, TransportParam, TransportScheme};

pub mod format;
pub mod paths;
pub mod value;

use format::ConfigFormat;
use value::set_in_value;

const ENV_PREFIX: &str = "DSN";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AddressMode {
    #[default]
    PublicOnly,
    GrayOnly,
    All,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    #[serde(default = "default_state_dir")]
    pub state_dir: String,
    #[serde(default = "default_control_socket")]
    pub control_socket: String,
}

fn default_state_dir() -> String {
    "node-state".to_string()
}

fn default_control_socket() -> String {
    "control.sock".to_string()
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            state_dir: default_state_dir(),
            control_socket: default_control_socket(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsnConfig {
    #[serde(default)]
    pub participate_in_dht: bool,
    pub identity: IdentityConfig,

    #[serde(default)]
    pub bootstrap_peers: Vec<TransportEndpoint>,

    #[serde(default)]
    pub listen: Vec<TransportEndpoint>,

    #[serde(default)]
    pub address_mode: AddressMode,

    #[serde(default)]
    pub ip4_include_net: Vec<String>,

    #[serde(default)]
    pub ip4_exclude_net: Vec<String>,

    #[serde(default)]
    pub ip6_include_net: Vec<String>,

    #[serde(default)]
    pub ip6_exclude_net: Vec<String>,

    #[serde(default)]
    pub node: NodeConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityConfig {
    pub algo: String,
    pub public_key: String,
    pub private_key: String,
    pub id: String,
}

impl DsnConfig {
    pub fn default_with_generated_identity() -> Result<Self> {
        Ok(Self {
            participate_in_dht: false,
            identity: generate_identity("ed25519")?,
            bootstrap_peers: Vec::new(),
            listen: Vec::new(),
            address_mode: AddressMode::PublicOnly,
            ip4_include_net: Vec::new(),
            ip4_exclude_net: Vec::new(),
            ip6_include_net: Vec::new(),
            ip6_exclude_net: Vec::new(),
            node: NodeConfig::default(),
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.identity.algo != "ed25519" {
            bail!(
                "unsupported identity algorithm '{}', currently only ed25519 is supported",
                self.identity.algo
            );
        }

        if self.identity.id.len() != 64 {
            bail!("identity.id must contain 64 hex characters (256 bits)");
        }

        if !self.identity.id.chars().all(|ch| ch.is_ascii_hexdigit()) {
            bail!("identity.id must contain only hex characters");
        }

        let public_key_bytes = decode_key_field("public_key", &self.identity.public_key)?;
        let private_key_bytes = decode_key_field("private_key", &self.identity.private_key)?;

        let public_key = parse_public_key(&public_key_bytes)?;
        let signing_key = parse_private_key(&private_key_bytes)?;

        let expected_id = expected_identity_id(&self.identity.public_key)?;

        if self.identity.id.to_ascii_lowercase() != expected_id {
            bail!("identity.id does not match blake3(public_key)");
        }

        if signing_key.verifying_key() != public_key {
            bail!("public_key does not match private_key");
        }

        let probe = b"dsn-config-signature-check";
        let signature: Signature = signing_key.sign(probe);
        public_key
            .verify(probe, &signature)
            .context("failed to verify test signature")?;

        self.validate_transport_endpoints()?;
        self.validate_address_filters()?;
        self.validate_node_paths()?;

        Ok(())
    }

    pub fn is_allowed_ipv4(&self, addr: Ipv4Addr) -> bool {
        let include = parse_ipv4_nets(&self.ip4_include_net).ok();
        let exclude = parse_ipv4_nets(&self.ip4_exclude_net).ok();

        match (include, exclude) {
            (Some(include), Some(exclude)) => {
                is_allowed_ipv4(addr, self.address_mode, &include, &exclude)
            }
            _ => false,
        }
    }

    pub fn is_allowed_ipv6(&self, addr: Ipv6Addr) -> bool {
        let include = parse_ipv6_nets(&self.ip6_include_net).ok();
        let exclude = parse_ipv6_nets(&self.ip6_exclude_net).ok();

        match (include, exclude) {
            (Some(include), Some(exclude)) => {
                is_allowed_ipv6(addr, self.address_mode, &include, &exclude)
            }
            _ => false,
        }
    }

    fn validate_address_filters(&self) -> Result<()> {
        parse_ipv4_nets(&self.ip4_include_net)?;
        parse_ipv4_nets(&self.ip4_exclude_net)?;
        parse_ipv6_nets(&self.ip6_include_net)?;
        parse_ipv6_nets(&self.ip6_exclude_net)?;
        Ok(())
    }

    fn validate_node_paths(&self) -> Result<()> {
        if self.node.state_dir.trim().is_empty() {
            bail!("node.state_dir must not be empty");
        }
        if self.node.control_socket.trim().is_empty() {
            bail!("node.control_socket must not be empty");
        }
        Ok(())
    }

    pub fn is_allowed_ipv4(&self, addr: Ipv4Addr) -> bool {
        let include = parse_ipv4_nets(&self.ip4_include_net).ok();
        let exclude = parse_ipv4_nets(&self.ip4_exclude_net).ok();

        match (include, exclude) {
            (Some(include), Some(exclude)) => {
                is_allowed_ipv4(addr, self.address_mode, &include, &exclude)
            }
            _ => false,
        }
    }

    pub fn is_allowed_ipv6(&self, addr: Ipv6Addr) -> bool {
        let include = parse_ipv6_nets(&self.ip6_include_net).ok();
        let exclude = parse_ipv6_nets(&self.ip6_exclude_net).ok();

        match (include, exclude) {
            (Some(include), Some(exclude)) => {
                is_allowed_ipv6(addr, self.address_mode, &include, &exclude)
            }
            _ => false,
        }
    }

    fn validate_address_filters(&self) -> Result<()> {
        parse_ipv4_nets(&self.ip4_include_net)?;
        parse_ipv4_nets(&self.ip4_exclude_net)?;
        parse_ipv6_nets(&self.ip6_include_net)?;
        parse_ipv6_nets(&self.ip6_exclude_net)?;
        Ok(())
    }

    fn validate_transport_endpoints(&self) -> Result<()> {
        for (index, endpoint) in self.bootstrap_peers.iter().enumerate() {
            validate_transport_endpoint(endpoint)
                .with_context(|| format!("bootstrap_peers[{index}] is invalid"))?;
        }

        for (index, endpoint) in self.listen.iter().enumerate() {
            validate_transport_endpoint(endpoint)
                .with_context(|| format!("listen[{index}] is invalid"))?;
        }

        Ok(())
    }
}

fn validate_transport_endpoint(endpoint: &TransportEndpoint) -> Result<()> {
    if endpoint.scheme != TransportScheme::Unix && endpoint.port == 0 {
        bail!("port must be greater than 0");
    }

    let needs_tls_assets = matches!(
        endpoint.scheme,
        TransportScheme::Tls
            | TransportScheme::Wss
            | TransportScheme::Quic
            | TransportScheme::H2
            | TransportScheme::G2
    );

    if !needs_tls_assets {
        return Ok(());
    }

    for param in [
        TransportParam::Ca.as_str(),
        TransportParam::Cert.as_str(),
        TransportParam::Key.as_str(),
    ] {
        if let Some(path) = endpoint.params.get(param)
            && !Path::new(path).exists()
        {
            bail!("query param '{param}' points to missing path: {path}");
        }
    }

    Ok(())
}

fn parse_ipv4_nets(values: &[String]) -> Result<Vec<Ipv4Net>> {
    values
        .iter()
        .map(|raw| {
            raw.parse::<Ipv4Net>()
                .with_context(|| format!("invalid IPv4 CIDR '{raw}'"))
        })
        .collect()
}

fn parse_ipv6_nets(values: &[String]) -> Result<Vec<Ipv6Net>> {
    values
        .iter()
        .map(|raw| {
            raw.parse::<Ipv6Net>()
                .with_context(|| format!("invalid IPv6 CIDR '{raw}'"))
        })
        .collect()
}

fn is_allowed_ipv4(
    addr: Ipv4Addr,
    mode: AddressMode,
    include: &[Ipv4Net],
    exclude: &[Ipv4Net],
) -> bool {
    if is_hard_deny_ipv4(addr) {
        return false;
    }

    let in_gray = is_gray_ipv4(addr);
    let mode_allowed = match mode {
        AddressMode::PublicOnly => !in_gray,
        AddressMode::GrayOnly => in_gray,
        AddressMode::All => true,
    };

    if !mode_allowed {
        return false;
    }

    if !include.is_empty() && !include.iter().any(|n| n.contains(&addr)) {
        return false;
    }

    if exclude.iter().any(|n| n.contains(&addr)) {
        return false;
    }

    true
}

fn is_allowed_ipv6(
    addr: Ipv6Addr,
    mode: AddressMode,
    include: &[Ipv6Net],
    exclude: &[Ipv6Net],
) -> bool {
    if is_hard_deny_ipv6(addr) {
        return false;
    }

    let in_gray = is_gray_ipv6(addr);
    let mode_allowed = match mode {
        AddressMode::PublicOnly => is_ipv6_gua(addr),
        AddressMode::GrayOnly => in_gray,
        AddressMode::All => true,
    };

    if !mode_allowed {
        return false;
    }

    if !include.is_empty() && !include.iter().any(|n| n.contains(&addr)) {
        return false;
    }

    if exclude.iter().any(|n| n.contains(&addr)) {
        return false;
    }

    true
}

fn is_hard_deny_ipv4(addr: Ipv4Addr) -> bool {
    addr.is_loopback() || addr.is_unspecified() || addr.is_multicast() || addr.is_link_local()
}

fn is_hard_deny_ipv6(addr: Ipv6Addr) -> bool {
    addr.is_loopback()
        || addr.is_unspecified()
        || addr.is_multicast()
        || addr.is_unicast_link_local()
}

fn is_gray_ipv4(addr: Ipv4Addr) -> bool {
    addr.is_private()
        || Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 10)
            .expect("valid cgnat")
            .contains(&addr)
}

fn is_gray_ipv6(addr: Ipv6Addr) -> bool {
    Ipv6Net::new("fd00::".parse().expect("valid ula"), 8)
        .expect("valid ula net")
        .contains(&addr)
}

fn is_ipv6_gua(addr: Ipv6Addr) -> bool {
    Ipv6Net::new("2000::".parse().expect("valid gua"), 3)
        .expect("valid gua net")
        .contains(&addr)
}

pub fn init_config(path: &Path) -> Result<DsnConfig> {
    ConfigFormat::from_path(path)?;
    if path.exists() {
        bail!("config already exists: {}", path.display());
    }

    let cfg = DsnConfig::default_with_generated_identity()?;
    save_config(path, &cfg)?;
    Ok(cfg)
}

pub fn validate_config(path: &Path) -> Result<DsnConfig> {
    load_config(path)
}

pub fn fix_config(path: &Path) -> Result<bool> {
    let mut cfg = load_config_unvalidated(path)?;

    if cfg.validate().is_ok() {
        return Ok(false);
    }

    let expected_id = expected_identity_id(&cfg.identity.public_key)
        .context("unable to repair identity.id from public_key")?;

    if cfg.identity.id == expected_id {
        cfg.validate()
            .with_context(|| format!("invalid config {}", path.display()))?;
        return Ok(false);
    }

    cfg.identity.id = expected_id;
    cfg.validate().with_context(|| {
        format!(
            "config remains invalid after automatic fix {}",
            path.display()
        )
    })?;

    save_config(path, &cfg)
        .with_context(|| format!("failed to persist fixed config {}", path.display()))?;

    Ok(true)
}

pub fn regenerate_keys(path: &Path) -> Result<DsnConfig> {
    let mut cfg = load_config(path)?;
    cfg.identity = generate_identity("ed25519")?;
    cfg.validate()?;
    save_config(path, &cfg)?;
    Ok(cfg)
}

pub fn load_config(path: &Path) -> Result<DsnConfig> {
    let cfg = load_config_unvalidated(path)?;
    cfg.validate()
        .with_context(|| format!("invalid config {}", path.display()))?;

    Ok(cfg)
}

fn load_config_unvalidated(path: &Path) -> Result<DsnConfig> {
    let format = ConfigFormat::from_path(path)?;
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read config file {}", path.display()))?;

    let mut value = match format {
        ConfigFormat::Toml => {
            toml::from_str::<Value>(&content).context("failed to parse TOML config")?
        }
        ConfigFormat::Yaml => {
            serde_yaml::from_str::<Value>(&content).context("failed to parse YAML config")?
        }
        ConfigFormat::Json => {
            serde_json::from_str::<Value>(&content).context("failed to parse JSON config")?
        }
        ConfigFormat::Ini => parse_ini_to_value(&content)?,
    };

    apply_env_overrides(&mut value)?;

    serde_json::from_value(value).context("failed to deserialize config into dsn schema")
}

pub fn save_config(path: &Path, cfg: &DsnConfig) -> Result<()> {
    save_config_value(
        path,
        serde_json::to_value(cfg).context("failed to convert config to JSON value")?,
    )
}

pub fn save_config_value(path: &Path, value: Value) -> Result<()> {
    let format = ConfigFormat::from_path(path)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create parent directory {}", parent.display()))?;
    }

    let output = match format {
        ConfigFormat::Toml => {
            let parsed: toml::Value =
                serde_json::from_value(value).context("failed to build TOML value")?;
            toml::to_string_pretty(&parsed).context("failed to serialize TOML")?
        }
        ConfigFormat::Yaml => serde_yaml::to_string(&value).context("failed to serialize YAML")?,
        ConfigFormat::Json => {
            serde_json::to_string_pretty(&value).context("failed to serialize JSON")?
        }
        ConfigFormat::Ini => value_to_ini_string(&value)?,
    };

    fs::write(path, output).with_context(|| format!("failed to write config {}", path.display()))
}

fn decode_key_field(name: &str, value: &str) -> Result<Vec<u8>> {
    let as_path = PathBuf::from(value);
    if as_path.exists() {
        return fs::read(&as_path)
            .with_context(|| format!("failed to read {name} from {}", as_path.display()));
    }

    base64::engine::general_purpose::STANDARD
        .decode(value)
        .with_context(|| format!("{name} must be base64 or an existing file path"))
}

fn parse_public_key(raw: &[u8]) -> Result<VerifyingKey> {
    let bytes: [u8; 32] = raw
        .try_into()
        .map_err(|_| anyhow!("public_key must decode to 32 bytes for ed25519"))?;

    VerifyingKey::from_bytes(&bytes).context("public_key is not a valid ed25519 key")
}

fn parse_private_key(raw: &[u8]) -> Result<SigningKey> {
    match raw.len() {
        32 => {
            let bytes: [u8; 32] = raw
                .try_into()
                .map_err(|_| anyhow!("private_key must decode to 32 or 64 bytes for ed25519"))?;
            Ok(SigningKey::from_bytes(&bytes))
        }
        64 => {
            let bytes: [u8; 64] = raw
                .try_into()
                .map_err(|_| anyhow!("private_key must decode to 32 or 64 bytes for ed25519"))?;
            SigningKey::from_keypair_bytes(&bytes)
                .map_err(|err| anyhow!("private_key is not a valid ed25519 keypair: {err}"))
        }
        _ => bail!("private_key must decode to 32 or 64 bytes for ed25519"),
    }
}

fn expected_identity_id(public_key: &str) -> Result<String> {
    let public_key_bytes = decode_key_field("public_key", public_key)?;
    let public_key = parse_public_key(&public_key_bytes)?;

    Ok(blake3::hash(public_key.as_bytes())
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>())
}

fn parse_ini_to_value(content: &str) -> Result<Value> {
    let mut ini = Ini::new();
    let map = ini
        .read(content.to_owned())
        .map_err(|err| anyhow!("failed to parse INI config: {err}"))?;

    let mut root = serde_json::Map::new();

    for (section, values) in map {
        let target = if section.eq_ignore_ascii_case("default") || section.is_empty() {
            &mut root
        } else {
            root.entry(section)
                .or_insert_with(|| Value::Object(Default::default()))
                .as_object_mut()
                .ok_or_else(|| anyhow!("invalid INI section object"))?
        };

        for (key, value) in values {
            if let Some(raw) = value {
                target.insert(key, parse_scalar(&raw));
            }
        }
    }

    Ok(Value::Object(root))
}

fn value_to_ini_string(value: &Value) -> Result<String> {
    let mut out = String::new();
    let obj = value
        .as_object()
        .ok_or_else(|| anyhow!("top-level INI config must be an object"))?;

    for (key, val) in obj {
        if !val.is_object() {
            out.push_str(&format!("{key}={}\n", scalar_to_string(val)?));
        }
    }

    for (section, val) in obj {
        if let Some(section_obj) = val.as_object() {
            out.push_str(&format!("\n[{section}]\n"));
            for (key, inner) in section_obj {
                out.push_str(&format!("{key}={}\n", scalar_to_string(inner)?));
            }
        }
    }

    Ok(out)
}

fn scalar_to_string(value: &Value) -> Result<String> {
    match value {
        Value::String(v) => Ok(v.clone()),
        Value::Bool(v) => Ok(v.to_string()),
        Value::Number(v) => Ok(v.to_string()),
        _ => bail!("INI serializer supports only scalar values"),
    }
}

fn parse_scalar(raw: &str) -> Value {
    if let Ok(value) = raw.parse::<bool>() {
        return Value::Bool(value);
    }

    if let Ok(value) = raw.parse::<i64>() {
        return Value::Number(value.into());
    }

    if let Ok(value) = raw.parse::<f64>()
        && let Some(number) = serde_json::Number::from_f64(value)
    {
        return Value::Number(number);
    }

    Value::String(raw.to_owned())
}

fn apply_env_overrides(value: &mut Value) -> Result<()> {
    for (key, raw_value) in std::env::vars() {
        if !key.starts_with(&format!("{ENV_PREFIX}_")) {
            continue;
        }

        let key_path = key
            .trim_start_matches(&format!("{ENV_PREFIX}_"))
            .to_ascii_lowercase()
            .replace("__", ".");

        set_in_value(value, &key_path, parse_scalar(&raw_value))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{AddressMode, DsnConfig, fix_config, init_config, load_config};
    use crate::identity::generate_identity;
    use crate::transport::TransportEndpoint;
    use std::fs;
    use std::str::FromStr;

    #[test]
    fn init_config_does_not_overwrite_existing_file() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let base =
            std::env::temp_dir().join(format!("dsn-init-test-{}-{unique}", std::process::id()));
        let _ = fs::create_dir_all(&base);
        let path = base.join("config.toml");
        fs::write(&path, "[identity]\nid=\"old\"\n").expect("seed config");

        let err = init_config(&path).expect_err("init should fail when config exists");
        assert!(err.to_string().contains("config already exists"));

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn validate_checks_identity_binding() {
        let mut cfg = DsnConfig::default_with_generated_identity().expect("default config");
        cfg.validate().expect("generated config should validate");

        cfg.identity.id = "0".repeat(64);
        let err = cfg.validate().expect_err("tampered id should fail");
        assert!(err.to_string().contains("identity.id does not match"));
    }

    #[test]
    fn fix_config_repairs_identity_id() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let base =
            std::env::temp_dir().join(format!("dsn-fix-test-{}-{unique}", std::process::id()));
        fs::create_dir_all(&base).expect("create temp dir");
        let path = base.join("config.json");

        let mut cfg = DsnConfig::default_with_generated_identity().expect("default config");
        cfg.identity.id = "badid".to_owned();
        fs::write(
            &path,
            serde_json::to_string_pretty(&cfg).expect("serialize"),
        )
        .expect("write config");

        let fixed = fix_config(&path).expect("fix should succeed");
        assert!(fixed, "config should be modified");

        let loaded = load_config(&path).expect("fixed config should validate");
        assert_eq!(loaded.identity.id.len(), 64);

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn validate_checks_signature() {
        let mut cfg = DsnConfig::default_with_generated_identity().expect("default config");
        let other = generate_identity("ed25519").expect("other identity");
        cfg.identity.private_key = other.private_key;

        let err = cfg.validate().expect_err("mismatched keys must fail");
        assert!(
            err.to_string()
                .contains("public_key does not match private_key")
        );
    }

    #[test]
    fn validate_accepts_empty_transport_lists() {
        let cfg = DsnConfig::default_with_generated_identity().expect("default config");
        cfg.validate()
            .expect("empty bootstrap_peers/listen must stay valid");
    }

    #[test]
    fn validate_checks_tls_asset_paths_for_transport_lists() {
        let mut cfg = DsnConfig::default_with_generated_identity().expect("default config");
        cfg.listen = vec![
            TransportEndpoint::from_str(
                "wss://127.0.0.1:443/path?cert=/definitely/missing/cert.pem",
            )
            .expect("endpoint parse"),
        ];

        let err = cfg.validate().expect_err("missing cert path must fail");
        assert!(err.to_string().contains("listen[0] is invalid"));
    }

    #[test]
    fn address_filter_pipeline_ipv4_table() {
        let mut cfg = DsnConfig::default_with_generated_identity().expect("default config");
        cfg.address_mode = AddressMode::PublicOnly;
        cfg.ip4_include_net = vec!["1.0.0.0/8".to_owned()];
        cfg.ip4_exclude_net = vec!["1.2.3.0/24".to_owned()];

        let cases = [
            ("1.1.1.1", true),
            ("1.2.3.4", false),
            ("10.0.0.1", false),
            ("0.0.0.0", false),
            ("127.0.0.1", false),
        ];

        for (raw, expected) in cases {
            let ip = raw.parse().expect("ipv4 parse");
            assert_eq!(cfg.is_allowed_ipv4(ip), expected, "ip={raw}");
        }
    }

    #[test]
    fn public_only_ipv6_accepts_only_gua() {
        let mut cfg = DsnConfig::default_with_generated_identity().expect("default config");
        cfg.address_mode = AddressMode::PublicOnly;

        let cases = [
            ("2001:4860:4860::8888", true),
            ("fd12::1", false),
            ("fe80::1", false),
            ("::1", false),
            ("ff02::1", false),
        ];

        for (raw, expected) in cases {
            let ip = raw.parse().expect("ipv6 parse");
            assert_eq!(cfg.is_allowed_ipv6(ip), expected, "ip={raw}");
        }
    }

    #[test]
    fn yaml_listen_as_string_endpoints_deserializes() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let base =
            std::env::temp_dir().join(format!("dsn-yaml-endpoint-{}-{unique}", std::process::id()));
        fs::create_dir_all(&base).expect("create temp dir");
        let path = base.join("config.yaml");

        let id = generate_identity("ed25519").expect("identity");
        let raw = format!(
            "address_mode: public_only\nparticipate_in_dht: false\nidentity:\n  algo: {}\n  id: {}\n  private_key: {}\n  public_key: {}\nlisten:\n  - udp://127.0.0.2:9990\nbootstrap_peers: []\nip4_include_net: []\nip4_exclude_net: []\nip6_include_net: []\nip6_exclude_net: []\n",
            id.algo, id.id, id.private_key, id.public_key
        );
        fs::write(&path, raw).expect("write config");

        let cfg = load_config(&path).expect("yaml with string endpoints should load");
        assert_eq!(cfg.listen.len(), 1);
        assert_eq!(cfg.listen[0].scheme, crate::transport::TransportScheme::Udp);

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn validate_rejects_invalid_cidr_filters() {
        let mut cfg = DsnConfig::default_with_generated_identity().expect("default config");
        cfg.ip4_include_net = vec!["not-a-cidr".to_owned()];

        let err = cfg.validate().expect_err("invalid CIDR must fail");
        assert!(err.to_string().contains("invalid IPv4 CIDR"));
    }
}
