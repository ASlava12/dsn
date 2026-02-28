use anyhow::{Context, Result};
use metrics_exporter_prometheus::PrometheusBuilder;
use tracing_subscriber::EnvFilter;

pub fn init() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let builder = PrometheusBuilder::new();
    let _handle = builder
        .install_recorder()
        .context("failed to initialize prometheus metrics recorder")?;

    Ok(())
}
