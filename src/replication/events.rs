//! Structured v12 event log for large-testnet attribution.
//!
//! Behind `cfg(feature = "v12-event-log")`. Without the feature flag,
//! every event function compiles to an empty `#[inline]` no-op —
//! production release builds carry zero overhead from this module.
//!
//! When the feature is on, every v12 decision (gossip ingest, audit
//! issue/verdict, holder credit, trust event, peer removal) appends one
//! JSON-Lines record to `${ANT_V12_EVENT_LOG}` (defaults to
//! `/var/log/ant-node-v12-events.jsonl`). The collector script on the
//! monitoring droplet rsyncs these files; the analysis script parses
//! them to produce per-mechanism attribution tables. See the
//! large-testnet verification plan (kept outside this repo) for the
//! analysis pipeline.
//!
//! ## Design
//!
//! - **Unconditional call sites.** Every event helper exists in both
//!   build paths; with the feature off they are `#[inline]` empty
//!   functions and the compiler removes their arguments via DCE. Call
//!   sites in `audit.rs`, `mod.rs`, etc. don't need `#[cfg]` gates.
//! - **No locking on the hot path.** When the feature is on, the sink
//!   is a `LazyLock<Mutex<Option<File>>>`. Events are serialized into a
//!   `Vec<u8>` outside the lock; only the `write_all` syscall is
//!   inside.
//! - **Best-effort.** Write failures are swallowed — losing a few
//!   events at the end of a run is fine, crashing on disk-full is not.
//! - **No transitive deps.** Uses `serde_json` (already in workspace).

// These lints only fire once the module is reachable from real call sites
// (the v12 helpers are otherwise dead code and skipped). They are cosmetic
// / MSRV-config artifacts in this self-contained module with no behavioural
// meaning: the doc identifiers (`PeerId`, `XorName`, `PeerRemoved`) read
// fine unquoted, `LazyLock` is the intended sink primitive, and the
// `SystemTime` map/unwrap_or is clearer than `map_or` here.
#![allow(
    clippy::doc_markdown,
    clippy::incompatible_msrv,
    clippy::map_unwrap_or,
    clippy::too_long_first_doc_paragraph
)]

use crate::ant_protocol::XorName;
use saorsa_core::identity::PeerId;

/// Convenience: format a PeerId as its lowercase hex.
#[must_use]
pub fn peer_hex(p: &PeerId) -> String {
    hex::encode(p.as_bytes())
}

/// Convenience: format a 32-byte hash (pin, commitment hash) as lowercase hex.
#[must_use]
pub fn hex32(b: &[u8; 32]) -> String {
    hex::encode(b)
}

/// Convenience: format a XorName key as lowercase hex.
#[must_use]
pub fn key_hex(k: &XorName) -> String {
    hex::encode(k)
}

// ---------------------------------------------------------------------------
// Public event-recording API
//
// Every function below is `#[inline]` and empty when the feature is off.
// The compiler removes the argument-evaluation cost too (the helpers
// take `&str` etc., not owned strings).
// ---------------------------------------------------------------------------

/// Self-announce: emitted once at node startup so the analysis pipeline
/// can bind this node's `peer_hex` to its slot. The log file is named
/// `v12-events-<global_index>.jsonl`, so a single record carrying the
/// node's own `peer_hex` lets the analyzer map `peer_hex` to
/// `global_index` without the heuristics the older pipeline relied on.
/// `role` is
/// `honest` or the adversary mode string; `version` is the binary
/// version for sanity-checking the fleet ran one build.
#[inline]
pub fn node_started(peer: &str, role: &str, version: &str) {
    #[cfg(feature = "v12-event-log")]
    inner::record(&inner::V12Event::NodeStarted {
        peer,
        role,
        version,
    });
    let _ = (peer, role, version);
}

/// Inbound gossip carrying a commitment: did we accept it?
///
/// `reason` is one of: `rt_gate`, `peer_id_mismatch`, `pubkey_bind_mismatch`,
/// `sig_verify_rate_limited`, `sig_invalid`, `cache_evict`, `accepted`.
#[inline]
pub fn gossip_ingest(source: &str, accept: bool, reason: &str, cache_size: usize) {
    #[cfg(feature = "v12-event-log")]
    inner::record(&inner::V12Event::GossipIngest {
        source,
        accept,
        reason,
        cache_size,
    });
    // Suppress unused-variable warnings without the feature.
    let _ = (source, accept, reason, cache_size);
}

/// Outbound audit challenge issued.
///
/// `pin` is `None` for legacy unpinned challenges.
#[inline]
pub fn audit_issued(
    challenged_peer: &str,
    challenge_id: u64,
    keys: usize,
    pin: Option<&str>,
    commitment_capable: bool,
) {
    #[cfg(feature = "v12-event-log")]
    inner::record(&inner::V12Event::AuditIssued {
        challenged_peer,
        challenge_id,
        keys,
        pin,
        commitment_capable,
    });
    let _ = (challenged_peer, challenge_id, keys, pin, commitment_capable);
}

/// Verdict on an audit response (or timeout).
///
/// `outcome`: `passed_commitment_bound` / `passed_legacy` /
/// `bootstrap_claim` / `failed` / `idle_rotation` /
/// `idle_capable_no_commitment` / `timeout` / `malformed`.
///
/// `gate`: For `failed`, the verifier gate that fired
/// (`structural`, `pin`, `signature`, `bytes_hash`, `path`,
/// `leaf_index`, `digest`, `peer_id_bind`, `missing_bytes`,
/// `key_not_in_commitment`).
#[inline]
pub fn audit_outcome(challenged_peer: &str, challenge_id: u64, outcome: &str, gate: Option<&str>) {
    #[cfg(feature = "v12-event-log")]
    inner::record(&inner::V12Event::AuditOutcome {
        challenged_peer,
        challenge_id,
        outcome,
        gate,
    });
    let _ = (challenged_peer, challenge_id, outcome, gate);
}

/// `recent_provers` accepted a successful audit.
#[inline]
pub fn holder_credit_recorded(peer: &str, key: &str, pin: &str) {
    #[cfg(feature = "v12-event-log")]
    inner::record(&inner::V12Event::HolderCreditRecorded { peer, key, pin });
    let _ = (peer, key, pin);
}

/// `recent_provers` invalidated entries.
///
/// `reason`: `unknown_commitment_hash` / `peer_removed` / `ttl_sweep`.
#[inline]
pub fn holder_credit_dropped(
    peer: Option<&str>,
    pin: Option<&str>,
    reason: &str,
    entries_dropped: usize,
) {
    #[cfg(feature = "v12-event-log")]
    inner::record(&inner::V12Event::HolderCreditDropped {
        peer,
        pin,
        reason,
        entries_dropped,
    });
    let _ = (peer, pin, reason, entries_dropped);
}

/// Underlying saorsa-core trust event fired.
///
/// `kind`: `application_success` / `application_failure`.
/// `reason`: free-form (e.g. `audit_digest_mismatch`, `audit_timeout`,
/// `commitment_bound_passed`, `bootstrap_claim_abuse`).
#[inline]
pub fn trust_event(peer: &str, kind: &str, weight: f64, reason: &str) {
    #[cfg(feature = "v12-event-log")]
    inner::record(&inner::V12Event::TrustEvent {
        peer,
        kind,
        weight,
        reason,
    });
    let _ = (peer, kind, weight, reason);
}

/// Routing-table eviction observed (from PeerRemoved DHT event).
#[inline]
pub fn peer_removed(peer: &str) {
    #[cfg(feature = "v12-event-log")]
    inner::record(&inner::V12Event::PeerRemoved { peer });
    let _ = peer;
}

/// Quorum decision for a specific key.
#[inline]
pub fn quorum_decision(
    key: &str,
    outcome: &str,
    present_credited: usize,
    present_uncredited: usize,
    absent: usize,
    unresolved: usize,
) {
    #[cfg(feature = "v12-event-log")]
    inner::record(&inner::V12Event::QuorumDecision {
        key,
        outcome,
        present_credited,
        present_uncredited,
        absent,
        unresolved,
    });
    let _ = (
        key,
        outcome,
        present_credited,
        present_uncredited,
        absent,
        unresolved,
    );
}

/// Local commitment rotated (responder side).
#[inline]
pub fn commitment_rotated(new_pin: &str, key_count: u32, retained_slots: usize) {
    #[cfg(feature = "v12-event-log")]
    inner::record(&inner::V12Event::CommitmentRotated {
        new_pin,
        key_count,
        retained_slots,
    });
    let _ = (new_pin, key_count, retained_slots);
}

// ---------------------------------------------------------------------------
// Inner: only compiled with the feature on.
// ---------------------------------------------------------------------------

#[cfg(feature = "v12-event-log")]
mod inner {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::{LazyLock, Mutex};
    use std::time::SystemTime;

    use serde::Serialize;

    const DEFAULT_PATH: &str = "/var/log/ant-node-v12-events.jsonl";

    static SINK: LazyLock<Mutex<Option<std::fs::File>>> = LazyLock::new(|| {
        let path = std::env::var("ANT_V12_EVENT_LOG")
            .map_or_else(|_| PathBuf::from(DEFAULT_PATH), PathBuf::from);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| {
                eprintln!(
                    "v12-event-log: could not open {}: {} — events will be dropped",
                    path.display(),
                    e
                );
            })
            .ok();
        Mutex::new(file)
    });

    #[derive(Debug, Serialize)]
    #[serde(tag = "event")]
    pub(super) enum V12Event<'a> {
        #[serde(rename = "node_started")]
        NodeStarted {
            peer: &'a str,
            role: &'a str,
            version: &'a str,
        },
        #[serde(rename = "gossip_ingest")]
        GossipIngest {
            source: &'a str,
            accept: bool,
            reason: &'a str,
            cache_size: usize,
        },
        #[serde(rename = "audit_issued")]
        AuditIssued {
            challenged_peer: &'a str,
            challenge_id: u64,
            keys: usize,
            pin: Option<&'a str>,
            commitment_capable: bool,
        },
        #[serde(rename = "audit_outcome")]
        AuditOutcome {
            challenged_peer: &'a str,
            challenge_id: u64,
            outcome: &'a str,
            gate: Option<&'a str>,
        },
        #[serde(rename = "holder_credit_recorded")]
        HolderCreditRecorded {
            peer: &'a str,
            key: &'a str,
            pin: &'a str,
        },
        #[serde(rename = "holder_credit_dropped")]
        HolderCreditDropped {
            peer: Option<&'a str>,
            pin: Option<&'a str>,
            reason: &'a str,
            entries_dropped: usize,
        },
        #[serde(rename = "trust_event")]
        TrustEvent {
            peer: &'a str,
            kind: &'a str,
            weight: f64,
            reason: &'a str,
        },
        #[serde(rename = "peer_removed")]
        PeerRemoved { peer: &'a str },
        #[serde(rename = "quorum_decision")]
        QuorumDecision {
            key: &'a str,
            outcome: &'a str,
            present_credited: usize,
            present_uncredited: usize,
            absent: usize,
            unresolved: usize,
        },
        #[serde(rename = "commitment_rotated")]
        CommitmentRotated {
            new_pin: &'a str,
            key_count: u32,
            retained_slots: usize,
        },
    }

    #[derive(Serialize)]
    struct Wrapper<'a> {
        ts: u128,
        #[serde(flatten)]
        event: &'a V12Event<'a>,
    }

    pub(super) fn record(event: &V12Event<'_>) {
        let ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let Ok(mut line) = serde_json::to_vec(&Wrapper { ts, event }) else {
            return;
        };
        line.push(b'\n');
        if let Ok(mut guard) = SINK.lock() {
            if let Some(file) = guard.as_mut() {
                let _ = file.write_all(&line);
            }
        }
    }
}
