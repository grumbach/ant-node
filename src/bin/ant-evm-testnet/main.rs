//! `ant-evm-testnet` — standalone local-EVM host for the v12 testnet.
//!
//! **NOT FOR PRODUCTION.** Compiles only with `--features evm-host`.
//! Excluded from shipped artifacts via the `required-features` clause in
//! `Cargo.toml`.
//!
//! Stands up a single Anvil chain on one VM, deploys the ANT token +
//! payment vault contracts, writes the connection details (RPC URL,
//! contract addresses, funded wallet key) to a JSON file the deploy
//! scripts consume, and blocks until killed. Every ant-node + the
//! workload client point their `--evm-rpc-url` at this host so payment
//! verification runs against a local chain instead of Arbitrum mainnet.
//!
//! ## Binding for remote VMs
//!
//! Anvil binds to `localhost` by default, which is useless across VMs.
//! Set `ANVIL_IP_ADDR=0.0.0.0` so other droplets can reach it, and
//! `ANVIL_PORT=8545` for a stable port. Both are read by
//! `evmlib::testnet::start_node`. The JSON manifest reports the RPC URL
//! anvil bound to; the deploy script rewrites the host to the EVM VM's
//! reachable IP before handing it to the nodes (anvil reports the bind
//! address, which for `0.0.0.0` is not directly dialable).
//!
//! ## Usage
//!
//! ```text
//! ANVIL_IP_ADDR=0.0.0.0 ANVIL_PORT=8545 \
//!   ant-evm-testnet --out /var/lib/ant-evm/evm-info.json
//! ```

#![cfg(feature = "evm-host")]

use std::path::PathBuf;

use clap::Parser;
use serde::Serialize;

/// Connection details for the local EVM, consumed by the deploy scripts.
#[derive(Debug, Serialize)]
struct EvmInfo {
    /// RPC URL as anvil reports it (host taken from `ANVIL_IP_ADDR`).
    rpc_url: String,
    /// Deployed ANT token (ERC-20) contract address, `0x`-prefixed.
    payment_token_address: String,
    /// Deployed payment vault contract address, `0x`-prefixed.
    payment_vault_address: String,
    /// Pre-funded Anvil account #0 private key (`0x`-prefixed). Used by
    /// the workload client to pay for uploads; every node's
    /// `--rewards-address` can be any address since rewards aren't
    /// withdrawn during the run.
    funded_private_key: String,
    /// Anvil's default chain id (31337) — informational.
    chain_id: u64,
}

#[derive(Parser, Debug)]
#[command(name = "ant-evm-testnet")]
struct Cli {
    /// Where to write the EVM connection JSON. Also printed to stdout.
    #[arg(long)]
    out: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    let cli = Cli::parse();

    eprintln!(
        "ant-evm-testnet: starting Anvil (ANVIL_IP_ADDR={}, ANVIL_PORT={}) and deploying contracts…",
        std::env::var("ANVIL_IP_ADDR").unwrap_or_else(|_| "localhost".to_string()),
        std::env::var("ANVIL_PORT").unwrap_or_else(|_| "<random>".to_string()),
    );

    let testnet = evmlib::testnet::Testnet::new()
        .await
        .map_err(|e| color_eyre::eyre::eyre!("Failed to start Anvil testnet: {e}"))?;

    let network = testnet.to_network();
    let funded_private_key = testnet
        .default_wallet_private_key()
        .map_err(|e| color_eyre::eyre::eyre!("Failed to read funded wallet key: {e}"))?;

    let (rpc_url, payment_token_address, payment_vault_address) = match &network {
        evmlib::Network::Custom(custom) => (
            custom.rpc_url_http.to_string(),
            format!("{:?}", custom.payment_token_address),
            format!("{:?}", custom.payment_vault_address),
        ),
        other => {
            return Err(color_eyre::eyre::eyre!(
                "Anvil testnet returned non-Custom network: {other:?}"
            ))
        }
    };

    let info = EvmInfo {
        rpc_url,
        payment_token_address,
        payment_vault_address,
        funded_private_key,
        // Anvil's default chain id; evmlib does not expose it on the
        // Custom network, but anvil always uses 31337 unless overridden.
        chain_id: 31337,
    };

    let json = serde_json::to_string_pretty(&info)?;
    if let Some(ref path) = cli.out {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(path, &json).await?;
        eprintln!("ant-evm-testnet: wrote EVM info to {}", path.display());
    }
    // Always print to stdout so the deploy script can capture it even
    // without --out.
    println!("{json}");

    eprintln!(
        "ant-evm-testnet: chain live at {}; token={} vault={}. \
         Holding the chain open — press Ctrl+C (or stop the service) to tear down.",
        info.rpc_url, info.payment_token_address, info.payment_vault_address
    );

    // Hold the Testnet alive: dropping it stops Anvil. Block until the
    // process is asked to stop.
    tokio::signal::ctrl_c().await?;
    eprintln!("ant-evm-testnet: shutting down Anvil.");
    drop(testnet);
    Ok(())
}
