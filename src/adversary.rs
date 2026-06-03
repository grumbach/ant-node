//! Adversary mode hooks for large-testnet verification.
//!
//! **This module exists exclusively for the v12 large-testnet
//! verification harness. It is gated behind `cfg(feature = "adversary")`
//! and never compiled in production builds.** Default `cargo build` and
//! `cargo build --release` do not see it. The CI release pipeline runs
//! `cargo build --release --no-default-features --features logging`
//! which also does not see it.
//!
//! ## Why hooks instead of monkey-patching
//!
//! Several adversary behaviours (silent / throwaway-key / bootstrap-
//! shield / fake-storage / relay) cannot be implemented as an external
//! process — they need to alter what the node emits on the wire. Rather
//! than ship a fork of the binary per attack mode, we drop a small
//! number of `if AdversaryMode::current().<predicate>()` branches into
//! production code, all gated behind `cfg(feature = "adversary")` so
//! the production binary's call graph is provably unaffected.
//!
//! Two attack modes (lazy / chunk-deleter) do not need in-tree hooks at
//! all: an external thread deletes LMDB entries on a schedule.
//!
//! ## Modes
//!
//! See [`AdversaryMode`](crate::adversary::AdversaryMode) for the full
//! catalog. Selected at process start
//! via `ANT_ADVERSARY_MODE`; defaulting to `none` (which is identical to
//! a production build because every hook returns early when
//! `current() == None`).
//!
//! ## Activation timing
//!
//! `ANT_ADVERSARY_GO_BAD_AT_UNIX_SEC` defines when the bad behaviour
//! turns on. Until that timestamp every hook acts as if the mode were
//! `None`. This gives the test runner a 30-min control window for an
//! apples-to-apples honest-perf baseline.

use std::sync::OnceLock;
use std::time::{Duration, SystemTime};

/// One adversary behaviour. Selected at startup via `ANT_ADVERSARY_MODE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdversaryMode {
    /// Stores chunks initially, then deletes them after the
    /// `ANT_ADVERSARY_DELETE_AFTER_SEC` window. Keeps gossiping its
    /// commitment as if everything were fine. Target eviction path:
    /// audit `BytesHashMismatch` → trust drops.
    Lazy,
    /// Like lazy but every `ANT_ADVERSARY_DELETE_EVERY_SEC` deletes 50 %
    /// of stored chunks, gossiping a fresh commitment after each
    /// delete. Target eviction path: `MissingBytesForCommittedKey`
    /// (round-12 distinguished failure mode).
    ChunkDeleter,
    /// Joins network, accepts puts, NEVER gossips a commitment. Target
    /// eviction path: §3 + §6 → never credited as holder → no rewards
    /// (bootstrap-claim shield).
    Silent,
    /// Generates a side keypair, signs commitments with it but claims
    /// its real peer-id. Target eviction path: gate 2c (`peer_id` ↔
    /// pubkey binding) at gossip ingest → never appears in the
    /// auditor's `last_commitment_by_peer`.
    ThrowawayKey,
    /// Answers every audit with `AuditResponse::Bootstrapping` for its
    /// entire lifetime. Target eviction path: bootstrap-claim-abuse
    /// detector (existing pre-v12 code) flags after grace period.
    BootstrapShield,
    /// Always returns `PresenceEvidence::Present` for any key, but
    /// cannot pass commitment-bound audits. Target eviction path:
    /// quorum holder-credit predicate (§6) downgrades Present →
    /// Unresolved → no reward, then audit failure on actual
    /// challenge → trust drop.
    FakeStorage,
    /// Drops bytes; on audit challenge, fetches from neighbor and
    /// answers with valid path under original commitment. Documented
    /// v12 economic-not-cryptographic limit (§7 Path A'). Expected to
    /// PASS audits but not earn (bandwidth cost > storage cost).
    Relay,
}

impl AdversaryMode {
    fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "lazy" => Some(Self::Lazy),
            "chunk-deleter" | "chunk_deleter" => Some(Self::ChunkDeleter),
            "silent" => Some(Self::Silent),
            "throwaway-key" | "throwaway_key" => Some(Self::ThrowawayKey),
            "bootstrap-shield" | "bootstrap_shield" => Some(Self::BootstrapShield),
            "fake-storage" | "fake_storage" => Some(Self::FakeStorage),
            "relay" => Some(Self::Relay),
            _ => None,
        }
    }
}

/// Process-wide adversary config, populated once at startup.
#[derive(Debug, Clone, Copy)]
pub struct AdversaryConfig {
    /// The adversary behaviour selected at startup.
    pub mode: AdversaryMode,
    /// Unix-seconds: bad behaviour turns on at this wall-clock time.
    /// Before then, every hook acts as if `mode == None`.
    pub go_bad_at: u64,
    /// For lazy/chunk-deleter modes: how long to retain newly-stored
    /// chunks before the deleter task drops them.
    pub delete_after: Duration,
    /// For chunk-deleter mode: re-trigger cadence.
    pub delete_every: Duration,
}

static CONFIG: OnceLock<Option<AdversaryConfig>> = OnceLock::new();

/// Initialize from environment. Call once at startup of the
/// `ant-node-adversary` binary.
pub fn init_from_env() {
    let mode = std::env::var("ANT_ADVERSARY_MODE")
        .ok()
        .and_then(|s| AdversaryMode::parse(&s));
    let cfg = mode.map(|mode| AdversaryConfig {
        mode,
        go_bad_at: std::env::var("ANT_ADVERSARY_GO_BAD_AT_UNIX_SEC")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        delete_after: std::env::var("ANT_ADVERSARY_DELETE_AFTER_SEC")
            .ok()
            .and_then(|s| s.parse().ok())
            .map_or_else(|| Duration::from_secs(600), Duration::from_secs),
        delete_every: std::env::var("ANT_ADVERSARY_DELETE_EVERY_SEC")
            .ok()
            .and_then(|s| s.parse().ok())
            .map_or_else(|| Duration::from_secs(1800), Duration::from_secs),
    });
    let _ = CONFIG.set(cfg);
}

/// Snapshot the active adversary mode, or `None` if not yet active
/// (either no mode selected, or before `go_bad_at`).
#[must_use]
pub fn current() -> Option<AdversaryMode> {
    let cfg = CONFIG.get().and_then(|o| o.as_ref())?;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    if now < cfg.go_bad_at {
        return None;
    }
    Some(cfg.mode)
}

/// Snapshot the active config without the wall-clock gate (for the
/// background deleter task, which sleeps until `go_bad_at` itself).
#[must_use]
pub fn config() -> Option<AdversaryConfig> {
    CONFIG.get().and_then(|o| *o)
}

/// True iff the active mode is `Silent`.
#[must_use]
pub fn is_silent() -> bool {
    current() == Some(AdversaryMode::Silent)
}

/// True iff the active mode is `ThrowawayKey`.
#[must_use]
pub fn is_throwaway_key() -> bool {
    current() == Some(AdversaryMode::ThrowawayKey)
}

/// True iff the active mode is `BootstrapShield`.
#[must_use]
pub fn is_bootstrap_shield() -> bool {
    current() == Some(AdversaryMode::BootstrapShield)
}

/// True iff the active mode is `FakeStorage`.
#[must_use]
pub fn is_fake_storage() -> bool {
    current() == Some(AdversaryMode::FakeStorage)
}

/// True iff the active mode is `Relay`.
#[must_use]
pub fn is_relay() -> bool {
    current() == Some(AdversaryMode::Relay)
}

/// True iff the active mode is `Lazy` or `ChunkDeleter` (both delete
/// stored chunks but otherwise act normally).
#[must_use]
pub fn is_storage_deleter() -> bool {
    matches!(
        current(),
        Some(AdversaryMode::Lazy | AdversaryMode::ChunkDeleter)
    )
}
