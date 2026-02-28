use anyhow::{Result, anyhow};
use std::path::{Path, PathBuf};

use crate::format::ConfigFormat;

const DEFAULT_CONFIG_DIR: &str = ".dsn";
const DEFAULT_CONFIG_NAME: &str = "config.toml";

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

pub fn default_config_path() -> PathBuf {
    user_default_config_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(DEFAULT_CONFIG_NAME)
}

fn user_default_config_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("failed to determine home directory"))?;
    Ok(home.join(DEFAULT_CONFIG_DIR))
}
