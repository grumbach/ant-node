//! `ant-node-adversary` — large-testnet adversary node binary.
//!
//! **NOT FOR PRODUCTION.** Compiles only with `--features adversary`.
//! The release pipeline does not enable the `adversary` feature, so
//! this binary is excluded from shipped artifacts via the
//! `required-features` clause in `Cargo.toml`.
//!
//! Reuses the production `ant-node` CLI machinery (clap surface,
//! logging init, bootstrap discovery) — the only difference is one
//! early `crate::adversary::init_from_env()` call that picks up the
//! adversary mode from `ANT_ADVERSARY_MODE`. All bad behaviour is
//! triggered by `#[cfg(feature = "adversary")]` branches inside the
//! production code paths; this binary just turns the feature on.
//!
//! ## Environment
//!
//! - `ANT_ADVERSARY_MODE`: one of `lazy`, `chunk-deleter`, `silent`,
//!   `throwaway-key`, `bootstrap-shield`, `fake-storage`, `relay`, or
//!   `none` (acts identical to the honest binary).
//! - `ANT_ADVERSARY_GO_BAD_AT_UNIX_SEC`: bad behaviour activates at
//!   this wall-clock time. Defaults to 0 (immediately bad).
//! - `ANT_ADVERSARY_DELETE_AFTER_SEC`: lazy/chunk-deleter retention
//!   (default 600).
//! - `ANT_ADVERSARY_DELETE_EVERY_SEC`: chunk-deleter cadence
//!   (default 1800).
//! - `ANT_V12_EVENT_LOG`: where to write the structured event log
//!   (default `/var/log/ant-node-v12-events.jsonl`).

#![cfg(feature = "adversary")]
#![cfg_attr(not(feature = "logging"), allow(unused_variables))]

#[path = "../ant-node/cli.rs"]
mod cli;
#[path = "../ant-node/platform.rs"]
mod platform;

use ant_node::NodeBuilder;
use clap::Parser;
use cli::Cli;
#[cfg(feature = "logging")]
use cli::CliLogFormat;
#[cfg(feature = "logging")]
use tracing_subscriber::prelude::*;
#[cfg(feature = "logging")]
use tracing_subscriber::{fmt, EnvFilter, Layer};

#[cfg(feature = "logging")]
fn init_logging(
    cli: &Cli,
) -> color_eyre::Result<Option<tracing_appender::non_blocking::WorkerGuard>> {
    if !cli.enable_logging {
        return Ok(None);
    }
    let log_format = cli.log_format;
    let log_dir = cli.log_dir.clone();
    let log_max_files = cli.log_max_files;
    let log_level: String = cli.log_level.into();
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&log_level));
    let guard: Option<tracing_appender::non_blocking::WorkerGuard>;
    let layer: Box<dyn Layer<_> + Send + Sync> = match (log_format, log_dir) {
        (CliLogFormat::Text, None) => {
            guard = None;
            Box::new(fmt::layer())
        }
        (CliLogFormat::Json, None) => {
            guard = None;
            Box::new(fmt::layer().json().flatten_event(true))
        }
        (CliLogFormat::Text, Some(dir)) => {
            let file_appender = tracing_appender::rolling::Builder::new()
                .rotation(tracing_appender::rolling::Rotation::DAILY)
                .max_log_files(log_max_files)
                .filename_prefix("ant-node-adversary")
                .filename_suffix("log")
                .build(dir)?;
            let (non_blocking, g) = tracing_appender::non_blocking(file_appender);
            guard = Some(g);
            Box::new(fmt::layer().with_writer(non_blocking).with_ansi(false))
        }
        (CliLogFormat::Json, Some(dir)) => {
            let file_appender = tracing_appender::rolling::Builder::new()
                .rotation(tracing_appender::rolling::Rotation::DAILY)
                .max_log_files(log_max_files)
                .filename_prefix("ant-node-adversary")
                .filename_suffix("log")
                .build(dir)?;
            let (non_blocking, g) = tracing_appender::non_blocking(file_appender);
            guard = Some(g);
            Box::new(
                fmt::layer()
                    .json()
                    .flatten_event(true)
                    .with_writer(non_blocking)
                    .with_ansi(false),
            )
        }
    };
    tracing_subscriber::registry()
        .with(layer)
        .with(filter)
        .init();
    Ok(guard)
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    // Populate the adversary config from environment BEFORE the node
    // starts so every hook sees the active mode on first call.
    ant_node::adversary::init_from_env();
    let mode = ant_node::adversary::config()
        .map_or_else(|| "none".to_string(), |c| format!("{:?}", c.mode));
    eprintln!("ant-node-adversary: starting with mode={mode}");

    let cli = Cli::parse();

    #[cfg(feature = "logging")]
    let _logging_guard = init_logging(&cli)?;

    ant_node::logging::info!(
        version = env!("CARGO_PKG_VERSION"),
        adversary_mode = %mode,
        "ant-node-adversary starting"
    );

    let (config, bootstrap_source) = cli.into_config()?;
    let _ = bootstrap_source; // surface logged via the production binary path; same shape here.

    let mut node = NodeBuilder::new(config).build().await?;
    node.run().await?;
    Ok(())
}
