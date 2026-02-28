use anyhow::{Result, anyhow, bail};
use std::path::Path;

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
