use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use configparser::ini::Ini;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

const ENV_PREFIX: &str = "DSN";
const DEFAULT_CONFIG_DIR: &str = ".dsn";
const DEFAULT_CONFIG_NAME: &str = "config.toml";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFormat {
    Toml,
    Yaml,
    Json,
    Ini,
}

impl ConfigFormat {
    pub fn from_path(path: &Path) -> Result<Self> {
        let ext = path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(str::to_ascii_lowercase)
            .ok_or_else(|| anyhow!("config path must have extension: toml/yaml/yml/json/ini"))?;

        match ext.as_str() {
            "toml" => Ok(Self::Toml),
            "yaml" | "yml" => Ok(Self::Yaml),
            "json" => Ok(Self::Json),
            "ini" => Ok(Self::Ini),
            _ => bail!("unsupported config format: {ext}"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsnConfig {
    #[serde(default)]
    pub participate_in_dht: bool,
    pub identity: IdentityConfig,
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
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.identity.algo != "ed25519" {
            bail!(
                "unsupported identity algorithm '{}', currently only ed25519 is supported",
                self.identity.algo
            );
        }

        validate_key_field("public_key", &self.identity.public_key)?;
        validate_key_field("private_key", &self.identity.private_key)?;

        if self.identity.id.len() != 256 {
            bail!("identity.id must contain 256 hex characters");
        }

        if !self.identity.id.chars().all(|ch| ch.is_ascii_hexdigit()) {
            bail!("identity.id must contain only hex characters");
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct LocatedConfig {
    pub path: PathBuf,
    pub exists: bool,
    pub will_use: bool,
}

pub fn locate_configs(explicit: Option<&Path>) -> Result<Vec<LocatedConfig>> {
    let mut ordered_candidates = Vec::<PathBuf>::new();

    if let Some(path) = explicit {
        ConfigFormat::from_path(path)?;
        ordered_candidates.push(path.to_path_buf());
    }

    let home = user_default_config_dir()?;
    let etc = PathBuf::from("/etc/dsn");

    for base in [&home, &etc] {
        for ext in ["toml", "yaml", "yml", "ini", "json"] {
            ordered_candidates.push(base.join(format!("config.{ext}")));
        }
    }

    let selected = ordered_candidates
        .iter()
        .find(|path| path.exists())
        .cloned();

    Ok(ordered_candidates
        .into_iter()
        .map(|path| {
            let exists = path.exists();
            let will_use = selected.as_ref() == Some(&path) || (selected.is_none() && exists);
            LocatedConfig {
                path,
                exists,
                will_use,
            }
        })
        .collect())
}

pub fn resolve_config_path(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        ConfigFormat::from_path(path)?;
        return Ok(path.to_path_buf());
    }

    let located = locate_configs(None)?;
    if let Some(current) = located.iter().find(|entry| entry.exists && entry.will_use) {
        return Ok(current.path.clone());
    }

    Ok(default_config_path())
}

pub fn init_config(path: &Path) -> Result<DsnConfig> {
    ConfigFormat::from_path(path)?;
    let cfg = DsnConfig::default_with_generated_identity()?;
    save_config(path, &cfg)?;
    Ok(cfg)
}

pub fn validate_config(path: &Path) -> Result<DsnConfig> {
    let cfg = load_config(path)?;
    cfg.validate()?;
    Ok(cfg)
}

pub fn regenerate_keys(path: &Path) -> Result<DsnConfig> {
    let mut cfg = load_config(path)?;
    cfg.identity = generate_identity("ed25519")?;
    cfg.validate()?;
    save_config(path, &cfg)?;
    Ok(cfg)
}

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

    let mut hash_output = [0_u8; 128];
    blake3::Hasher::new()
        .update(verifying_key.as_bytes())
        .finalize_xof()
        .fill(&mut hash_output);
    let id = hash_output
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

pub fn load_config(path: &Path) -> Result<DsnConfig> {
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

pub fn default_config_path() -> PathBuf {
    user_default_config_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(DEFAULT_CONFIG_NAME)
}

fn user_default_config_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("failed to determine home directory"))?;
    Ok(home.join(DEFAULT_CONFIG_DIR))
}

fn validate_key_field(name: &str, value: &str) -> Result<()> {
    let as_path = PathBuf::from(value);
    if as_path.exists() {
        return Ok(());
    }

    base64::engine::general_purpose::STANDARD
        .decode(value)
        .with_context(|| format!("{name} must be base64 or an existing file path"))?;

    Ok(())
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
                .unwrap()
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

    if let Ok(value) = raw.parse::<f64>() {
        if let Some(number) = serde_json::Number::from_f64(value) {
            return Value::Number(number);
        }
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

pub fn set_in_value(root: &mut Value, key_path: &str, value: Value) -> Result<()> {
    let parts: Vec<_> = key_path
        .split('.')
        .filter(|part| !part.is_empty())
        .collect();
    if parts.is_empty() {
        bail!("parameter path cannot be empty");
    }

    let mut current = root;
    for part in &parts[..parts.len() - 1] {
        if !current.is_object() {
            *current = Value::Object(Default::default());
        }
        current = current
            .as_object_mut()
            .expect("object enforced")
            .entry((*part).to_owned())
            .or_insert_with(|| Value::Object(Default::default()));
    }

    current
        .as_object_mut()
        .ok_or_else(|| anyhow!("target parameter path is not an object"))?
        .insert(parts[parts.len() - 1].to_owned(), value);

    Ok(())
}

pub fn remove_in_value(root: &mut Value, key_path: &str) -> Result<()> {
    let parts: Vec<_> = key_path
        .split('.')
        .filter(|part| !part.is_empty())
        .collect();
    if parts.is_empty() {
        bail!("parameter path cannot be empty");
    }

    let mut current = root;
    for part in &parts[..parts.len() - 1] {
        current = current
            .get_mut(*part)
            .ok_or_else(|| anyhow!("parameter '{key_path}' not found"))?;
    }

    current
        .as_object_mut()
        .ok_or_else(|| anyhow!("parameter '{key_path}' parent is not an object"))?
        .remove(parts[parts.len() - 1])
        .ok_or_else(|| anyhow!("parameter '{key_path}' not found"))?;

    Ok(())
}

pub fn get_from_value<'a>(root: &'a Value, key_path: &str) -> Result<&'a Value> {
    let parts: Vec<_> = key_path
        .split('.')
        .filter(|part| !part.is_empty())
        .collect();
    if parts.is_empty() {
        bail!("parameter path cannot be empty");
    }

    let mut current = root;
    for part in parts {
        current = current
            .get(part)
            .ok_or_else(|| anyhow!("parameter '{key_path}' not found"))?;
    }

    Ok(current)
}
