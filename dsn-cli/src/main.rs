mod cfg;
mod cmd;
mod helpers;

use anyhow::{Context, Result};
use clap::Parser;
use cmd::cli::{Cli, Commands, ConfigCommands};
use dsn_core::{
    DsnConfig, generate_identity, get_from_value, init_config, load_config, locate_configs,
    remove_in_value, resolve_config_path, save_config_value, set_in_value, validate_config,
};
use metrics::counter;
use metrics_exporter_prometheus::PrometheusBuilder;
use serde_json::Value;
use std::path::{Path, PathBuf};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    init_observability()?;
    let cli = Cli::parse();
    counter!("dsn_cli_invocations_total").increment(1);
    run(cli).await
}

async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Config(config) => handle_config(config.command, cli.config).await,
    }
}

async fn handle_config(command: ConfigCommands, explicit_config: Option<PathBuf>) -> Result<()> {
    match command {
        ConfigCommands::Locate => {
            for entry in locate_configs(explicit_config.as_deref())? {
                let marker = if entry.will_use && entry.exists {
                    "use"
                } else {
                    "---"
                };
                let status = if entry.exists { "found" } else { "missing" };
                println!("[{marker}] {status}: {}", entry.path.display());
            }
        }
        ConfigCommands::Init { path } => {
            let target = pick_target_path(path.as_deref(), explicit_config.as_deref())?;
            let cfg = init_config(&target)?;
            info!(path = %target.display(), "config initialized");
            println!("Config initialized: {}", target.display());
            println!("identity.id={}", cfg.identity.id);
        }
        ConfigCommands::Validate { path } => {
            let target = pick_target_path(path.as_deref(), explicit_config.as_deref())?;
            validate_config(&target)?;
            println!("Config is valid: {}", target.display());
        }
        ConfigCommands::Keygen { key_type, output } => {
            let identity = generate_identity(&key_type)?;
            if output {
                println!("algo={}", identity.algo);
                println!("public_key={}", identity.public_key);
                println!("private_key={}", identity.private_key);
                println!("id={}", identity.id);
            } else {
                let target = resolve_config_path(explicit_config.as_deref())?;
                let mut cfg = if target.exists() {
                    load_config(&target)?
                } else {
                    DsnConfig::default_with_generated_identity()?
                };
                cfg.identity = identity;
                cfg.validate()?;
                dsn_core::save_config(&target, &cfg)?;
                println!("Keys regenerated and saved into {}", target.display());
            }
        }
        ConfigCommands::Show => {
            let target = resolve_config_path(explicit_config.as_deref())?;
            let cfg = load_config(&target)?;
            println!("{}", serde_json::to_string_pretty(&cfg)?);
        }
        ConfigCommands::Get { parameter } => {
            let target = resolve_config_path(explicit_config.as_deref())?;
            let value = serde_json::to_value(load_config(&target)?)?;
            let found = get_from_value(&value, &parameter)?;
            if found.is_string() {
                println!("{}", found.as_str().unwrap_or_default());
            } else {
                println!("{}", found);
            }
        }
        ConfigCommands::Set {
            force,
            parameter,
            value,
        } => {
            let target = resolve_config_path(explicit_config.as_deref())?;
            let mut raw = load_or_init_json(&target)?;
            set_in_value(&mut raw, &parameter, parse_cli_value(&value))?;
            persist_with_validation(&target, raw, force)?;
            println!("Parameter set: {parameter}");
        }
        ConfigCommands::Del { force, parameter } => {
            let target = resolve_config_path(explicit_config.as_deref())?;
            let mut raw = load_or_init_json(&target)?;
            remove_in_value(&mut raw, &parameter)?;
            persist_with_validation(&target, raw, force)?;
            println!("Parameter removed: {parameter}");
        }
    }

    Ok(())
}

fn pick_target_path(path: Option<&Path>, explicit: Option<&Path>) -> Result<PathBuf> {
    match (path, explicit) {
        (Some(path), _) => Ok(path.to_path_buf()),
        (None, Some(path)) => Ok(path.to_path_buf()),
        (None, None) => Ok(dsn_core::default_config_path()),
    }
}

fn load_or_init_json(path: &Path) -> Result<Value> {
    if path.exists() {
        return serde_json::to_value(load_config(path)?).context("failed to load existing config");
    }

    serde_json::to_value(DsnConfig::default_with_generated_identity()?)
        .context("failed to build default config")
}

fn persist_with_validation(path: &Path, raw: Value, force: bool) -> Result<()> {
    if !force {
        let cfg: DsnConfig = serde_json::from_value(raw.clone())
            .context("config shape is invalid after modification")?;
        cfg.validate()?;
    }

    save_config_value(path, raw)
}

fn parse_cli_value(value: &str) -> Value {
    serde_json::from_str::<Value>(value).unwrap_or_else(|_| Value::String(value.to_owned()))
}

fn init_observability() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let builder = PrometheusBuilder::new();
    let _handle = builder
        .install_recorder()
        .context("failed to initialize prometheus metrics recorder")?;

    Ok(())
}
