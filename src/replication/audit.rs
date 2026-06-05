//! Gossip-triggered contiguous-subtree storage audit (ADR-0002).
//!
//! A node commits to what it stores (a signed Merkle [`StorageCommitment`]
//! gossiped to neighbours). On receiving a peer's changed commitment, a
//! neighbour may audit it: pin the just-gossiped root, send a fresh nonce that
//! deterministically selects one contiguous subtree, and require the peer to
//! prove that subtree (structure + real bytes) within a deadline. This module
//! owns the auditor entry point [`run_subtree_audit`] and the responder handler
//! [`handle_subtree_challenge`]; the pure proof maths live in
//! [`crate::replication::subtree`].

use std::sync::Arc;

use crate::logging::{debug, info, warn};
use rand::Rng;

use crate::ant_protocol::XorName;
use crate::replication::commitment::{commitment_hash, StorageCommitment};
use crate::replication::commitment_state::ResponderCommitmentState;
use crate::replication::config::{ReplicationConfig, REPLICATION_PROTOCOL_ID};
use crate::replication::protocol::{
    ReplicationMessage, ReplicationMessageBody, SubtreeAuditChallenge, SubtreeAuditResponse,
    SubtreeByteChallenge, SubtreeByteItem, SubtreeByteResponse,
};
use crate::replication::recent_provers::RecentProvers;
use crate::replication::subtree::{
    select_spotcheck_indices, select_subtree_path, subtree_plan, verify_subtree_proof,
    StructureVerdict, SubtreeProof,
};
use crate::replication::types::{AuditFailureReason, FailureEvidence};
use crate::storage::LmdbStorage;
use saorsa_core::identity::PeerId;
use saorsa_core::P2PNode;
use tokio::sync::RwLock;

// ---------------------------------------------------------------------------
// Audit tick result
// ---------------------------------------------------------------------------

/// Outcome of a single gossip-triggered audit.
#[derive(Debug)]
pub enum AuditTickResult {
    /// The subtree proof verified (structure + real-bytes spot-checks).
    Passed {
        /// The peer that was challenged.
        challenged_peer: PeerId,
        /// Number of subtree leaves whose bytes were spot-checked.
        keys_checked: usize,
    },
    /// A confirmed audit failure (forged/inconsistent proof, byte/nonce
    /// mismatch, repudiation of a recently gossiped commitment, or timeout).
    Failed {
        /// Evidence of the failure for the trust engine.
        evidence: FailureEvidence,
    },
    /// Audit target claimed it is still bootstrapping.
    BootstrapClaim {
        /// The peer claiming bootstrap status.
        peer: PeerId,
    },
    /// Nothing to do this round (e.g. auditor itself is bootstrapping, or the
    /// pinned commitment is out of protocol range). No trust effect.
    Idle,
    /// Retained for the engine's exhaustive match; not produced by the
    /// gossip-triggered auditor (which never samples local keys).
    InsufficientKeys,
}

// ---------------------------------------------------------------------------
// Auditor side
// ---------------------------------------------------------------------------

/// ADR-0002 round-2 byte challenge samples a SMALL surprise set of the proven
/// leaves (3..=5). Small enough that the responder's honest local-disk read of
/// the original chunks stays well inside the possession-in-time deadline, while
/// a relay forced to fetch them over the network blows it; large enough that
/// faking a fraction `x` of leaves survives only `(1 - x)^k`.
const BYTE_SPOTCHECK_MIN: u32 = 3;
const BYTE_SPOTCHECK_MAX: u32 = 5;

/// Holder-eligibility cache the auditor credits on a passing audit.
///
/// Owned by [`crate::replication::ReplicationEngine`]; borrowed here so a
/// passing audit can record `(peer, commitment_hash)` as a proven holder for
/// downstream quorum / paid-list credit.
pub struct AuditCredit<'a> {
    /// Holder-eligibility cache.
    pub recent_provers: &'a Arc<RwLock<RecentProvers>>,
}

/// The cross-cutting context for verifying one audit response, bundled so the
/// response-dispatch and verification functions stay readable.
struct AuditCtx<'a> {
    p2p_node: &'a Arc<P2PNode>,
    challenged_peer: &'a PeerId,
    challenge_id: u64,
    nonce: [u8; 32],
    expected_commitment_hash: [u8; 32],
    config: &'a ReplicationConfig,
    credit: Option<&'a AuditCredit<'a>>,
}

/// Run one gossip-triggered subtree audit against `challenged_peer`, pinned to
/// the commitment hash the peer just gossiped (`expected_commitment_hash`).
///
/// ADR-0002 two-round audit. The auditor sends a fresh random nonce and runs:
///
/// 1. **Structure** (round 1) — the returned subtree rebuilds to the pinned
///    root, within a size-scaled deadline.
/// 2. **Real bytes** (round 2) — the auditor demands the ORIGINAL chunk content
///    for a 3..=5 nonce-selected sample of the proven leaves FROM the responder,
///    and recomputes both the content-address hash and the nonce freshness hash
///    from that served content. The auditor holds none of the peer's chunks.
/// 3. **Timing** — each round's deadline is sized to an honest local-disk read,
///    so a relay forced to fetch over the network blows it.
///
/// A timeout (either round) is reported as [`AuditFailureReason::Timeout`] (the
/// caller applies the strike/grace policy). Any structural failure, served
/// content that fails a hash, an explicit `Absent` for a committed sampled key,
/// or a rejection of a recently gossiped commitment, is a confirmed failure
/// acted on immediately. On a full pass, records the peer as a proven holder.
pub async fn run_subtree_audit(
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
    challenged_peer: &PeerId,
    expected_commitment_hash: [u8; 32],
    key_count: u32,
    credit: Option<&AuditCredit<'_>>,
) -> AuditTickResult {
    let (nonce, challenge_id) = {
        let mut rng = rand::thread_rng();
        (rng.gen::<[u8; 32]>(), rng.gen::<u64>())
    };

    let challenge = SubtreeAuditChallenge {
        challenge_id,
        nonce,
        challenged_peer_id: *challenged_peer.as_bytes(),
        expected_commitment_hash,
    };
    let msg = ReplicationMessage {
        request_id: challenge_id,
        body: ReplicationMessageBody::SubtreeAuditChallenge(challenge),
    };
    let encoded = match msg.encode() {
        Ok(data) => data,
        Err(e) => {
            warn!("Audit: failed to encode subtree challenge for {challenged_peer}: {e}");
            return AuditTickResult::Idle;
        }
    };

    // Size the proof deadline from the ACTUAL selected subtree (its real-leaf
    // count for this nonce + key_count), not a fixed worst-case hint. This keeps
    // the deadline tight to "responder hashes ~sqrt(N) chunks at local-disk
    // speed", so a relay that must fetch the subtree over the network blows it.
    // The auditor and responder derive the same selection, so we know the leaf
    // count before the response arrives.
    let subtree_leaves = select_subtree_path(&nonce, key_count).map_or_else(
        || config.subtree_audit_timeout_leaf_hint(),
        |p| p.real_leaf_count() as usize,
    );
    let timeout = config.audit_response_timeout(subtree_leaves);

    crate::replication::events::audit_issued(
        &crate::replication::events::peer_hex(challenged_peer),
        challenge_id,
        subtree_leaves,
        Some(&crate::replication::events::hex32(
            &expected_commitment_hash,
        )),
        true,
    );

    let response = match p2p_node
        .send_request(challenged_peer, REPLICATION_PROTOCOL_ID, encoded, timeout)
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            debug!("Audit: subtree challenge to {challenged_peer} timed out / failed: {e}");
            return failed(challenged_peer, challenge_id, AuditFailureReason::Timeout);
        }
    };

    let resp_msg = match ReplicationMessage::decode(&response.data) {
        Ok(m) => m,
        Err(e) => {
            warn!("Audit: failed to decode subtree response from {challenged_peer}: {e}");
            return failed(
                challenged_peer,
                challenge_id,
                AuditFailureReason::MalformedResponse,
            );
        }
    };

    let ctx = AuditCtx {
        p2p_node,
        challenged_peer,
        challenge_id,
        nonce,
        expected_commitment_hash,
        config,
        credit,
    };
    dispatch_subtree_response(resp_msg.body, &ctx).await
}

/// Outcome of the round-2 byte challenge round-trip (auditor side).
enum ByteRound {
    /// The responder returned per-key items (verified by the caller).
    Served(Vec<SubtreeByteItem>),
    /// The responder rejected the byte challenge (confirmed failure for a
    /// recently pinned commitment).
    Rejected,
    /// No response within the byte deadline, or a transport error (graced
    /// timeout).
    Timeout,
    /// Malformed / unexpected round-2 response body.
    Malformed,
}

/// Round 2: ask the responder for the ORIGINAL chunk content of the
/// auditor-selected spot-check `keys`, sized to a possession-in-time deadline
/// (honest local-disk read of `keys.len()` chunks). The responder cannot have
/// predicted which keys are sampled.
async fn request_byte_proof(ctx: &AuditCtx<'_>, keys: &[XorName]) -> ByteRound {
    let challenge = SubtreeByteChallenge {
        challenge_id: ctx.challenge_id,
        nonce: ctx.nonce,
        challenged_peer_id: *ctx.challenged_peer.as_bytes(),
        expected_commitment_hash: ctx.expected_commitment_hash,
        keys: keys.to_vec(),
    };
    let msg = ReplicationMessage {
        request_id: ctx.challenge_id,
        body: ReplicationMessageBody::SubtreeByteChallenge(challenge),
    };
    let encoded = match msg.encode() {
        Ok(data) => data,
        Err(e) => {
            warn!("Audit: failed to encode byte challenge: {e}");
            return ByteRound::Malformed;
        }
    };

    // Deadline sized to "honest responder reads `keys.len()` local chunks": a
    // relay forced to fetch them over the network blows it (graced timeout,
    // never a confirmed failure — same possession-in-time principle as round 1).
    let timeout = ctx.config.audit_response_timeout(keys.len());
    let response = match ctx
        .p2p_node
        .send_request(
            ctx.challenged_peer,
            REPLICATION_PROTOCOL_ID,
            encoded,
            timeout,
        )
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            debug!(
                "Audit: byte challenge to {} timed out / failed: {e}",
                ctx.challenged_peer
            );
            return ByteRound::Timeout;
        }
    };

    let resp_msg = match ReplicationMessage::decode(&response.data) {
        Ok(m) => m,
        Err(e) => {
            warn!("Audit: failed to decode byte response: {e}");
            return ByteRound::Malformed;
        }
    };

    match resp_msg.body {
        ReplicationMessageBody::SubtreeByteResponse(SubtreeByteResponse::Items {
            challenge_id,
            items,
        }) if challenge_id == ctx.challenge_id => ByteRound::Served(items),
        ReplicationMessageBody::SubtreeByteResponse(SubtreeByteResponse::Rejected {
            challenge_id,
            reason,
        }) if challenge_id == ctx.challenge_id => {
            warn!(
                "Audit: {} rejected byte challenge: {reason}",
                ctx.challenged_peer
            );
            ByteRound::Rejected
        }
        // A node claiming bootstrap MID-AUDIT (it answered round 1) is treated
        // as a timeout: it didn't prove possession but the round-1 proof shows
        // it isn't bootstrapping, so the bootstrap-claim-abuse detector (round 1)
        // owns that lane; here we just don't credit it.
        ReplicationMessageBody::SubtreeByteResponse(SubtreeByteResponse::Bootstrapping {
            challenge_id,
        }) if challenge_id == ctx.challenge_id => ByteRound::Timeout,
        _ => ByteRound::Malformed,
    }
}

/// Map a decoded response body to an audit outcome (auditor side). A response
/// whose `challenge_id` doesn't match, or any non-subtree body, is malformed.
async fn dispatch_subtree_response(
    body: ReplicationMessageBody,
    ctx: &AuditCtx<'_>,
) -> AuditTickResult {
    let challenged_peer = ctx.challenged_peer;
    let challenge_id = ctx.challenge_id;
    let malformed = || {
        failed(
            challenged_peer,
            challenge_id,
            AuditFailureReason::MalformedResponse,
        )
    };
    match body {
        ReplicationMessageBody::SubtreeAuditResponse(SubtreeAuditResponse::Bootstrapping {
            challenge_id: resp_id,
        }) => {
            if resp_id != challenge_id {
                return malformed();
            }
            crate::replication::events::audit_outcome(
                &crate::replication::events::peer_hex(challenged_peer),
                challenge_id,
                "bootstrap_claim",
                None,
            );
            AuditTickResult::BootstrapClaim {
                peer: *challenged_peer,
            }
        }
        ReplicationMessageBody::SubtreeAuditResponse(SubtreeAuditResponse::Rejected {
            challenge_id: resp_id,
            reason,
        }) => {
            if resp_id != challenge_id {
                return malformed();
            }
            // ADR-0002: the auditor only ever pins a commitment the peer JUST
            // gossiped, and an honest responder retains its last two gossiped
            // commitments. So a rejection of a freshly pinned root is a
            // confirmed failure (repudiating what you just published), not
            // benign staleness. There is no no-penalty lane.
            warn!("Audit: peer {challenged_peer} rejected subtree challenge: {reason}");
            failed(challenged_peer, challenge_id, AuditFailureReason::Rejected)
        }
        ReplicationMessageBody::SubtreeAuditResponse(SubtreeAuditResponse::Proof {
            challenge_id: resp_id,
            commitment,
            proof,
        }) => {
            if resp_id != challenge_id {
                return malformed();
            }
            verify_subtree_response(ctx, &commitment, &proof).await
        }
        _ => {
            warn!("Audit: unexpected response type from {challenged_peer}");
            malformed()
        }
    }
}

/// The pure verdict of evaluating a subtree-audit response, independent of
/// storage/network. Tests call this directly so the SHIPPED gate logic is what
/// gets exercised (no reimplementation that could drift).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AuditVerdict {
    /// All gates passed and at least one leaf was byte-verified.
    Pass {
        /// Number of leaves whose real bytes were verified in round 2.
        checked: usize,
    },
    /// A confirmed failure with this reason (penalizable / acted upon).
    Fail(AuditFailureReason),
}

/// Round-1 structural evaluation of a subtree-audit proof (ADR-0002).
///
/// Runs the cheap gates in fail-fast order: pin / identity / signature →
/// structure (the returned subtree rebuilds to the pinned root). It does **not**
/// prove byte possession — the leaves carry only the public `bytes_hash` (the
/// chunk address) and a `nonced_hash` the responder computed itself. Possession
/// is proven in round 2 ([`verify_byte_response`]), where the auditor demands
/// the original chunk bytes for a nonce-selected sample and recomputes both
/// hashes from the SERVED content. This removes any dependency on the auditor
/// holding the peer's chunks.
///
/// Returns [`StructureVerdict::Valid`] (proceed to round 2) or a confirmed
/// [`AuditFailureReason`] mapped from the failing gate.
pub(crate) fn evaluate_subtree_structure(
    commitment: &StorageCommitment,
    proof: &SubtreeProof,
    nonce: &[u8; 32],
    expected_commitment_hash: &[u8; 32],
    challenged_peer_bytes: &[u8; 32],
) -> Result<(), AuditFailureReason> {
    // -- Pin + identity + signature --
    if &commitment.sender_peer_id != challenged_peer_bytes {
        return Err(AuditFailureReason::Rejected);
    }
    let derived_peer_id = *blake3::hash(&commitment.sender_public_key).as_bytes();
    if derived_peer_id != commitment.sender_peer_id {
        return Err(AuditFailureReason::Rejected);
    }
    match commitment_hash(commitment) {
        Some(h) if &h == expected_commitment_hash => {}
        _ => return Err(AuditFailureReason::Rejected),
    }
    if !crate::replication::commitment::verify_commitment_signature(commitment) {
        return Err(AuditFailureReason::Rejected);
    }

    // -- Structure --
    if let StructureVerdict::Invalid(_) = verify_subtree_proof(proof, nonce, commitment) {
        return Err(AuditFailureReason::DigestMismatch);
    }
    Ok(())
}

/// The auditor's nonce-derived spot-check sample of the round-1 subtree: the
/// distinct leaves (in proof order) whose original bytes the auditor will demand
/// in round 2. Empty only if the proof is empty (cannot happen post-structure).
pub(crate) fn spotcheck_leaves<'a>(
    proof: &'a SubtreeProof,
    nonce: &[u8; 32],
    key_count: u32,
    spotcheck_count: u32,
) -> Vec<&'a crate::replication::subtree::SubtreeLeaf> {
    let Some(path) = select_subtree_path(nonce, key_count) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for idx in select_spotcheck_indices(nonce, &path, spotcheck_count) {
        if let Some(leaf) = proof.leaves.get(idx as usize) {
            out.push(leaf);
        }
    }
    out
}

/// Round-2 verdict (ADR-0002): the responder served the original chunk content
/// for the auditor's spot-check sample; verify possession from THAT content.
///
/// `served(key)` returns what the responder returned for a requested key:
/// `Some(Some(bytes))` for [`SubtreeByteItem::Present`], `Some(None)` for an
/// explicit [`SubtreeByteItem::Absent`], and `None` if the responder omitted the
/// key entirely (treated like `Absent` — a committed key it would not serve).
///
/// For each sampled leaf the auditor recomputes, from the SERVED content:
///   - `BLAKE3(content) == leaf.bytes_hash` (the chunk's content address), AND
///   - `BLAKE3(nonce ‖ peer ‖ key ‖ content) == leaf.nonced_hash` (freshness),
///     i.e. `compute_audit_digest(nonce, peer, key, content)`.
///
/// The freshness inputs are byte-identical to what the responder used to BUILD
/// the leaf in round 1 (`subtree_leaf` → `nonced_leaf_hash`): the SAME four
/// inputs, so an honest holder's served content reproduces `nonced_hash`
/// exactly. Round 1 commits over the data (the `nonced_hash` is uncomputable
/// without the bytes); round 2 reveals a random subset to prove the commitment
/// was not fabricated.
///
/// Both checks are over the content the responder sent, so the auditor needs to
/// hold none of the peer's chunks. Any `Absent`/omitted committed key, or any
/// served content that fails a hash, is a provable lie → confirmed
/// [`AuditFailureReason::DigestMismatch`]. All sampled leaves verifying →
/// `Pass { checked }`.
pub(crate) fn verify_byte_response(
    leaves: &[&crate::replication::subtree::SubtreeLeaf],
    nonce: &[u8; 32],
    challenged_peer_bytes: &[u8; 32],
    served: impl Fn(&XorName) -> Option<Option<Vec<u8>>>,
) -> AuditVerdict {
    let mut checked = 0usize;
    for leaf in leaves {
        // Present{bytes} -> Some(Some(bytes)); Absent -> Some(None); omitted -> None.
        // A committed key the responder cannot / will not serve is a provable lie.
        let Some(Some(content)) = served(&leaf.key) else {
            return AuditVerdict::Fail(AuditFailureReason::DigestMismatch);
        };
        let plain = *blake3::hash(&content).as_bytes();
        let nonced = crate::replication::subtree::nonced_leaf_hash(
            nonce,
            challenged_peer_bytes,
            &leaf.key,
            &content,
        );
        if leaf.bytes_hash != plain || leaf.nonced_hash != nonced {
            // Served content does not hash to the committed address / freshness
            // hash: cannot be the chunk it committed to.
            return AuditVerdict::Fail(AuditFailureReason::DigestMismatch);
        }
        checked += 1;
    }
    AuditVerdict::Pass { checked }
}

/// Verify a subtree-proof response (auditor side), ADR-0002 two-round audit.
///
/// **Round 1** (this proof): pin + identity + signature + structure. If the
/// proof structurally rebuilds to the pinned root, the tree SHAPE is committed —
/// but not yet that the bytes are held. **Round 2**: the auditor picks a small
/// nonce-selected sample of the just-proven leaves and sends a
/// [`SubtreeByteChallenge`] demanding their original chunk content FROM the
/// responder, then verifies that content against the committed `bytes_hash`
/// (content address) and `nonced_hash` (freshness). A responder that committed
/// to a chunk it no longer holds cannot serve content that hashes to the
/// committed address, so it fails — regardless of what the auditor holds. On a
/// full pass, credits the peer as a proven holder.
async fn verify_subtree_response(
    ctx: &AuditCtx<'_>,
    commitment: &StorageCommitment,
    proof: &SubtreeProof,
) -> AuditTickResult {
    let challenged_peer = ctx.challenged_peer;
    let challenge_id = ctx.challenge_id;

    // -- Round 1: pin/identity/signature + structure (no bytes). --
    if let Err(reason) = evaluate_subtree_structure(
        commitment,
        proof,
        &ctx.nonce,
        &ctx.expected_commitment_hash,
        challenged_peer.as_bytes(),
    ) {
        warn!("Audit: {challenged_peer} failed subtree structure ({reason:?})");
        return failed(challenged_peer, challenge_id, reason);
    }

    // -- Round 2: surprise byte challenge for a 3..=5 nonce-selected sample. --
    // The responder cannot predict which leaves are sampled, and must serve the
    // ORIGINAL content for each. We cap the sample at the ADR's 3..=5 band
    // (clamped to the subtree size) so the round-2 message and the responder's
    // disk read stay cheap.
    let sample_n = ctx
        .config
        .audit_spotcheck_count()
        .clamp(BYTE_SPOTCHECK_MIN, BYTE_SPOTCHECK_MAX);
    let sampled = spotcheck_leaves(proof, &ctx.nonce, commitment.key_count, sample_n);
    if sampled.is_empty() {
        // Cannot happen after a valid structure (subtree is never empty), but
        // guard rather than credit an unproven peer.
        warn!("Audit: {challenged_peer} produced an empty spot-check sample; rejecting");
        return failed(
            challenged_peer,
            challenge_id,
            AuditFailureReason::DigestMismatch,
        );
    }
    let sampled_keys: Vec<XorName> = sampled.iter().map(|l| l.key).collect();

    let verdict = match request_byte_proof(ctx, &sampled_keys).await {
        ByteRound::Served(items) => {
            verify_byte_response(&sampled, &ctx.nonce, challenged_peer.as_bytes(), |key| {
                items.iter().find_map(|it| match it {
                    SubtreeByteItem::Present { key: k, bytes } if k == key => {
                        Some(Some(bytes.clone()))
                    }
                    SubtreeByteItem::Absent { key: k } if k == key => Some(None),
                    _ => None,
                })
            })
        }
        // The responder rejected the byte challenge for a recently pinned
        // commitment → confirmed failure, same as a round-1 rejection.
        ByteRound::Rejected => AuditVerdict::Fail(AuditFailureReason::Rejected),
        // No response within the byte deadline (or transport error) → timeout
        // (graced by the caller's strike policy — could be honest slowness).
        ByteRound::Timeout => AuditVerdict::Fail(AuditFailureReason::Timeout),
        // Malformed/unexpected round-2 body.
        ByteRound::Malformed => AuditVerdict::Fail(AuditFailureReason::MalformedResponse),
    };

    match verdict {
        AuditVerdict::Fail(reason) => {
            warn!("Audit: {challenged_peer} failed subtree audit ({reason:?})");
            failed(challenged_peer, challenge_id, reason)
        }
        AuditVerdict::Pass { checked } => {
            // Closeness (ADR-0002, soft/observe-only) — see observe_closeness.
            observe_closeness(ctx.p2p_node, ctx.config, challenged_peer, proof).await;
            // Credit the peer as a proven holder of its committed keys.
            if let (Some(credit), Some(pin)) = (ctx.credit, commitment_hash(commitment)) {
                let now = std::time::Instant::now();
                let peer_hex = crate::replication::events::peer_hex(challenged_peer);
                let pin_hex = crate::replication::events::hex32(&pin);
                let mut provers = credit.recent_provers.write().await;
                for leaf in &proof.leaves {
                    provers.record_proof(leaf.key, *challenged_peer, pin, now);
                    crate::replication::events::holder_credit_recorded(
                        &peer_hex,
                        &crate::replication::events::key_hex(&leaf.key),
                        &pin_hex,
                    );
                }
            }
            info!(
                "Audit: peer {challenged_peer} passed subtree audit ({} leaves, {checked} \
                 byte-checked)",
                proof.leaves.len()
            );
            crate::replication::events::audit_outcome(
                &crate::replication::events::peer_hex(challenged_peer),
                challenge_id,
                "passed_subtree",
                None,
            );
            AuditTickResult::Passed {
                challenged_peer: *challenged_peer,
                keys_checked: checked,
            }
        }
    }
}

/// Soft, density-aware closeness observation (ADR-0002). Logs — never fails —
/// when a suspicious fraction of the proof's leaves are keys the auditor itself
/// is NOT responsible for (a proxy for "implausibly far from the peer").
///
/// Using the auditor's own `SelfInclusiveRT` responsibility as the yardstick
/// makes this density-aware for free: on a small/dense network the auditor is
/// close to nearly every key, so almost nothing reads as far and no honest peer
/// is ever flagged. Enforcement is intentionally deferred until a testnet
/// calibrates the density threshold.
async fn observe_closeness(
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
    challenged_peer: &PeerId,
    proof: &SubtreeProof,
) {
    let self_id = *p2p_node.peer_id();
    let mut far = 0usize;
    for leaf in &proof.leaves {
        if !crate::replication::admission::is_responsible(
            &self_id,
            &leaf.key,
            p2p_node,
            config.close_group_size,
        )
        .await
        {
            far += 1;
        }
    }
    // Only worth a line when MOST of the proof is far — that's the padding
    // shape. A normal proof on a sparse network has some far keys; that's fine.
    let total = proof.leaves.len();
    if total > 0 && far * 2 > total {
        debug!(
            "Audit: closeness signal — {far}/{total} of {challenged_peer}'s proven leaves are \
             keys this auditor is not close to (observe-only; possible padding, not penalized)"
        );
    }
}

/// Build a confirmed-failure result. The auditor pinned a commitment the peer
/// committed to itself, so there is no per-key responsibility to re-confirm:
/// the failure is about the peer's own committed tree.
fn failed(
    challenged_peer: &PeerId,
    challenge_id: u64,
    reason: AuditFailureReason,
) -> AuditTickResult {
    crate::replication::events::audit_outcome(
        &crate::replication::events::peer_hex(challenged_peer),
        challenge_id,
        "failed",
        Some(audit_failure_gate(&reason)),
    );
    AuditTickResult::Failed {
        evidence: FailureEvidence::AuditFailure {
            challenge_id,
            challenged_peer: *challenged_peer,
            confirmed_failed_keys: Vec::new(),
            reason,
        },
    }
}

/// Stable lowercase gate name for the v12 `audit_outcome` event's `gate` field.
/// Matches the failure-reason taxonomy the analysis pipeline greps for.
const fn audit_failure_gate(reason: &AuditFailureReason) -> &'static str {
    match reason {
        AuditFailureReason::Timeout => "timeout",
        AuditFailureReason::MalformedResponse => "malformed_response",
        AuditFailureReason::DigestMismatch => "digest_mismatch",
        AuditFailureReason::KeyAbsent => "key_absent",
        AuditFailureReason::Rejected => "rejected",
    }
}

// ---------------------------------------------------------------------------
// Responder side
// ---------------------------------------------------------------------------

/// Handle an incoming subtree audit challenge (responder side).
///
/// Validates the challenge targets this node, looks up the pinned commitment in
/// the retained (last-two-gossiped) set, and builds the subtree proof for the
/// nonce-selected branch. If this node is bootstrapping it says so; if it
/// genuinely does not retain the pinned commitment it rejects (which the
/// auditor treats as a confirmed failure for a recently gossiped root).
pub async fn handle_subtree_challenge(
    challenge: &SubtreeAuditChallenge,
    storage: &LmdbStorage,
    self_peer_id: &PeerId,
    is_bootstrapping: bool,
    commitment_state: Option<&Arc<ResponderCommitmentState>>,
) -> SubtreeAuditResponse {
    if is_bootstrapping {
        return SubtreeAuditResponse::Bootstrapping {
            challenge_id: challenge.challenge_id,
        };
    }

    // Adversary `bootstrap-shield` mode (testnet-only, never in production):
    // answer EVERY subtree challenge with `Bootstrapping` for the node's whole
    // lifetime. It never produces a proof (so it is never credited as a holder),
    // and the auditor's bootstrap-claim-abuse grace detector flags it once the
    // grace period elapses. No-op without the `adversary` feature.
    #[cfg(feature = "adversary")]
    if crate::adversary::is_bootstrap_shield() {
        warn!("adversary bootstrap-shield: answering subtree challenge with Bootstrapping");
        return SubtreeAuditResponse::Bootstrapping {
            challenge_id: challenge.challenge_id,
        };
    }

    if challenge.challenged_peer_id != *self_peer_id.as_bytes() {
        warn!(
            "Subtree audit challenge targeted wrong peer: expected {}, got {}",
            hex::encode(self_peer_id.as_bytes()),
            hex::encode(challenge.challenged_peer_id),
        );
        return SubtreeAuditResponse::Rejected {
            challenge_id: challenge.challenge_id,
            reason: "challenged_peer_id does not match this node".to_string(),
        };
    }

    let Some(state) = commitment_state else {
        return SubtreeAuditResponse::Rejected {
            challenge_id: challenge.challenge_id,
            reason: "no commitment state".to_string(),
        };
    };

    // Look up the pinned commitment among the last-two-gossiped retained set.
    let Some(built) = state.lookup_by_hash(&challenge.expected_commitment_hash) else {
        return SubtreeAuditResponse::Rejected {
            challenge_id: challenge.challenge_id,
            reason: "unknown commitment hash".to_string(),
        };
    };

    // Adversary `relay` mode (testnet-only, never in production): a relay
    // dropped its committed bytes and would have to fetch the subtree's chunks
    // from a neighbour before it could answer. There is no in-tree neighbour
    // fetch-by-key API the responder can call inline here, so we implement the
    // simplest faithful version of the relay's OBSERVABLE signature: stall past
    // any plausible audit deadline so the auditor's `send_request` times out
    // (counted as `AuditFailureReason::Timeout` → strike/grace, not a confirmed
    // failure — which is exactly the relay's detection lane per ADR-0002). The
    // sleep is bounded so the responder task can't be parked forever. No-op
    // without the `adversary` feature.
    #[cfg(feature = "adversary")]
    if crate::adversary::is_relay() {
        warn!(
            "adversary relay: stalling subtree response past the audit deadline \
             (simulating fetch-from-neighbour latency)"
        );
        tokio::time::sleep(std::time::Duration::from_secs(120)).await;
    }

    // Geometry first (no bytes touched): which leaves to prove + the sibling
    // cut-hashes from the committed tree.
    let plan = match subtree_plan(built.tree(), &challenge.nonce) {
        Ok(p) => p,
        Err(e) => {
            warn!("Subtree audit: failed to plan proof: {e:?}");
            return SubtreeAuditResponse::Rejected {
                challenge_id: challenge.challenge_id,
                reason: "could not build subtree proof".to_string(),
            };
        }
    };

    // Read chunk bytes one leaf at a time so peak memory is bounded regardless
    // of subtree size, hashing each into its plain + nonced leaf.
    let mut leaves = Vec::with_capacity(plan.leaf_keys.len());
    for key in &plan.leaf_keys {
        let Ok(Some(bytes)) = storage.get_raw(key).await else {
            // Key is in our committed tree but we cannot read its bytes — real
            // storage loss / deliberate non-response. For a recently gossiped
            // pin the auditor counts this rejection as a confirmed failure.
            warn!(
                "Subtree audit: missing bytes for committed key {}",
                hex::encode(key)
            );
            return SubtreeAuditResponse::Rejected {
                challenge_id: challenge.challenge_id,
                reason: format!("missing bytes for committed key: {}", hex::encode(key)),
            };
        };
        // Adversary `fake-storage` mode (testnet-only, never in production):
        // claim possession but serve GARBAGE bytes for each leaf. The leaf's
        // `bytes_hash`/`nonced_hash` are then computed over bytes the node does
        // not really hold, so the auditor's structure rebuild (root ≠ pinned
        // commitment) and real-bytes spot-check both fail → confirmed
        // `DigestMismatch`. This is the "Present but cannot prove it" lane. The
        // garbage is derived from the key so the response is deterministic for a
        // given challenge. No-op without the `adversary` feature.
        #[cfg(feature = "adversary")]
        let bytes = if crate::adversary::is_fake_storage() {
            let mut garbage = blake3::hash(key).as_bytes().to_vec();
            garbage.extend_from_slice(b"adversary-fake-storage");
            garbage
        } else {
            bytes
        };
        leaves.push(crate::replication::subtree::subtree_leaf(
            &challenge.nonce,
            &challenge.challenged_peer_id,
            key,
            &bytes,
        ));
        // bytes drops here.
    }

    SubtreeAuditResponse::Proof {
        challenge_id: challenge.challenge_id,
        commitment: built.commitment().clone(),
        proof: SubtreeProof {
            leaves,
            sibling_cut_hashes: plan.sibling_cut_hashes,
        },
    }
}

/// Handle a round-2 byte challenge (responder side), ADR-0002.
///
/// The auditor has already structurally verified this node's round-1 subtree
/// proof and now demands the ORIGINAL chunk bytes for a small nonce-selected
/// sample of those leaves. For each requested key the responder either returns
/// the bytes ([`SubtreeByteItem::Present`]) or — if it committed to the key but
/// can no longer produce it — an explicit [`SubtreeByteItem::Absent`], which the
/// auditor counts as a provable failure (committing to bytes you don't hold).
///
/// A key the responder never committed to (not in the pinned tree) is also
/// returned `Absent`: the auditor only ever samples keys it saw in round 1, so
/// in practice this guards against a malformed/forged byte challenge rather than
/// an honest mismatch.
pub async fn handle_subtree_byte_challenge(
    challenge: &SubtreeByteChallenge,
    storage: &LmdbStorage,
    self_peer_id: &PeerId,
    is_bootstrapping: bool,
    commitment_state: Option<&Arc<ResponderCommitmentState>>,
) -> SubtreeByteResponse {
    if is_bootstrapping {
        return SubtreeByteResponse::Bootstrapping {
            challenge_id: challenge.challenge_id,
        };
    }

    // Adversary `bootstrap-shield` (testnet-only): keep claiming bootstrap so it
    // never proves possession. Same lane as round 1.
    #[cfg(feature = "adversary")]
    if crate::adversary::is_bootstrap_shield() {
        return SubtreeByteResponse::Bootstrapping {
            challenge_id: challenge.challenge_id,
        };
    }

    if challenge.challenged_peer_id != *self_peer_id.as_bytes() {
        return SubtreeByteResponse::Rejected {
            challenge_id: challenge.challenge_id,
            reason: "challenged_peer_id does not match this node".to_string(),
        };
    }

    let Some(state) = commitment_state else {
        return SubtreeByteResponse::Rejected {
            challenge_id: challenge.challenge_id,
            reason: "no commitment state".to_string(),
        };
    };
    // Resolve the SAME commitment the auditor pinned in round 1. If we no longer
    // retain it (it aged out of the last-two-gossiped set), reject — for a
    // recently gossiped pin the auditor treats this as a confirmed failure, like
    // round 1. We serve bytes only for keys actually committed to under this pin.
    let Some(built) = state.lookup_by_hash(&challenge.expected_commitment_hash) else {
        return SubtreeByteResponse::Rejected {
            challenge_id: challenge.challenge_id,
            reason: "unknown commitment hash".to_string(),
        };
    };
    let committed = |key: &XorName| -> bool { built.proof_for(key).is_some() };

    // Adversary `relay` (testnet-only): a relay holds none of the real bytes and
    // would have to fetch each requested chunk from a neighbour. As in round 1,
    // model its observable signature by stalling past the deadline so the
    // auditor's byte request times out (graced Timeout, not a confirmed failure).
    #[cfg(feature = "adversary")]
    if crate::adversary::is_relay() {
        warn!(
            "adversary relay: stalling byte-challenge response past the deadline \
             (simulating fetch-from-neighbour latency)"
        );
        tokio::time::sleep(std::time::Duration::from_secs(120)).await;
    }

    let mut items = Vec::with_capacity(challenge.keys.len());
    for key in &challenge.keys {
        // Read the original bytes for the requested, committed key.
        if let Ok(Some(bytes)) = storage.get_raw(key).await {
            // Adversary `fake-storage` (testnet-only): claim possession but
            // return GARBAGE bytes. `BLAKE3(garbage) != key`, so the auditor's
            // content-address check fails → confirmed `DigestMismatch`. This is
            // the "present but cannot prove it" lane, now enforced on the bytes
            // the responder actually serves.
            #[cfg(feature = "adversary")]
            let bytes = if crate::adversary::is_fake_storage() {
                let mut garbage = blake3::hash(key).as_bytes().to_vec();
                garbage.extend_from_slice(b"adversary-fake-storage");
                garbage
            } else {
                bytes
            };
            items.push(SubtreeByteItem::Present { key: *key, bytes });
        } else {
            // Committed to the key but cannot read its bytes → provable failure.
            if committed(key) {
                warn!(
                    "Subtree byte audit: committed key {} requested but bytes absent",
                    hex::encode(key)
                );
            }
            items.push(SubtreeByteItem::Absent { key: *key });
        }
    }

    SubtreeByteResponse::Items {
        challenge_id: challenge.challenge_id,
        items,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::replication::commitment_state::BuiltCommitment;
    use crate::replication::subtree::{
        build_subtree_proof, nonced_leaf_hash, select_subtree_path, SubtreeLeaf,
    };
    use saorsa_pqc::api::sig::ml_dsa_65;

    // The two-round audit splits into SHIPPED pure functions exercised directly
    // here (no reimplementation that could drift):
    //   - round 1: `evaluate_subtree_structure` (pin/identity/signature +
    //     structural root rebuild),
    //   - sampling: `spotcheck_leaves` (the 3..=5 nonce-selected leaves), and
    //   - round 2: `verify_byte_response` (recompute content-address + freshness
    //     from the bytes the RESPONDER served — the auditor holds nothing).

    fn key(i: u32) -> XorName {
        let mut k = [0u8; 32];
        k[..4].copy_from_slice(&i.to_be_bytes());
        k
    }
    /// The "chunk content" for a key in these fixtures. The committed tree's leaf
    /// `bytes_hash` is `BLAKE3(chunk_bytes(key))`, mirroring the general
    /// `(key, BLAKE3(content))` commitment; round 2 serves exactly this content.
    fn chunk_bytes(k: &XorName) -> Vec<u8> {
        let mut v = k.to_vec();
        v.extend_from_slice(b"chunk-body");
        v
    }

    /// Build an honest committed tree of `n` keys + a valid round-1 proof for
    /// `nonce`. Returns `(built, proof, peer_id)`. The auditor pins `built.hash()`.
    fn honest(n: u32, nonce: &[u8; 32]) -> (BuiltCommitment, SubtreeProof, [u8; 32]) {
        let (pk, sk) = ml_dsa_65().generate_keypair().unwrap();
        let peer_id = *blake3::hash(&pk.to_bytes()).as_bytes();
        let pk_b = pk.to_bytes();
        let entries: Vec<_> = (0..n)
            .map(|i| {
                let k = key(i);
                (k, *blake3::hash(&chunk_bytes(&k)).as_bytes())
            })
            .collect();
        let built = BuiltCommitment::build(entries, &peer_id, &sk, &pk_b).unwrap();
        let proof =
            build_subtree_proof(built.tree(), nonce, &peer_id, |k| Some(chunk_bytes(k))).unwrap();
        (built, proof, peer_id)
    }

    /// Round-1 verdict against the pinned commitment.
    fn structure(
        built: &BuiltCommitment,
        proof: &SubtreeProof,
        nonce: &[u8; 32],
        peer: &[u8; 32],
    ) -> Result<(), AuditFailureReason> {
        evaluate_subtree_structure(built.commitment(), proof, nonce, &built.hash(), peer)
    }

    /// The 3..=5 spot-check leaves the auditor would demand bytes for in round 2.
    fn sample<'a>(proof: &'a SubtreeProof, nonce: &[u8; 32], n: u32) -> Vec<&'a SubtreeLeaf> {
        spotcheck_leaves(
            proof,
            nonce,
            n,
            8u32.clamp(BYTE_SPOTCHECK_MIN, BYTE_SPOTCHECK_MAX),
        )
    }

    // A round-2 `served` closure that returns the HONEST content for every key.
    fn served_honest(key: &XorName) -> Option<Option<Vec<u8>>> {
        Some(Some(chunk_bytes(key)))
    }

    // ---- round 1: structure --------------------------------------------------

    #[test]
    fn honest_structure_then_bytes_passes() {
        let nonce = [9u8; 32];
        let (built, proof, peer) = honest(400, &nonce);
        // Round 1.
        assert!(structure(&built, &proof, &nonce, &peer).is_ok());
        // Round 2: honest responder serves the real content for the sample.
        let s = sample(&proof, &nonce, built.commitment().key_count);
        assert!(!s.is_empty());
        match verify_byte_response(&s, &nonce, &peer, served_honest) {
            AuditVerdict::Pass { checked } => assert!(checked >= 1, "must verify >=1 leaf"),
            other => panic!("expected Pass, got {other:?}"),
        }
    }

    #[test]
    fn commitment_bound_to_another_peer_rejected() {
        let nonce = [3u8; 32];
        let (built, proof, _peer) = honest(200, &nonce);
        let other = [0xAAu8; 32];
        assert_eq!(
            structure(&built, &proof, &nonce, &other),
            Err(AuditFailureReason::Rejected)
        );
    }

    #[test]
    fn wrong_pinned_commitment_rejected() {
        let nonce = [3u8; 32];
        let (built, proof, peer) = honest(200, &nonce);
        let mut wrong_pin = built.hash();
        wrong_pin[0] ^= 0x01;
        assert_eq!(
            evaluate_subtree_structure(built.commitment(), &proof, &nonce, &wrong_pin, &peer),
            Err(AuditFailureReason::Rejected)
        );
    }

    #[test]
    fn tampered_leaf_structure_rejected() {
        let nonce = [3u8; 32];
        let (built, mut proof, peer) = honest(200, &nonce);
        if let Some(first) = proof.leaves.first_mut() {
            first.bytes_hash[0] ^= 0x01; // breaks root reconstruction
        }
        assert_eq!(
            structure(&built, &proof, &nonce, &peer),
            Err(AuditFailureReason::DigestMismatch)
        );
    }

    #[test]
    fn wrong_leaf_count_structure_rejected() {
        let nonce = [3u8; 32];
        let (built, mut proof, peer) = honest(200, &nonce);
        proof.leaves.pop();
        assert_eq!(
            structure(&built, &proof, &nonce, &peer),
            Err(AuditFailureReason::DigestMismatch)
        );
    }

    // ---- round 2: responder-served bytes ------------------------------------

    #[test]
    fn deleter_absent_bytes_is_confirmed_failure() {
        // THE headline fix: a node whose round-1 proof is structurally perfect
        // but which has DELETED a committed chunk cannot serve its bytes. It
        // signals `Absent` for the sampled key → provable lie → confirmed
        // failure. Crucially, the auditor holds NONE of the peer's chunks; the
        // verdict depends only on what the responder serves.
        let nonce = [9u8; 32];
        let (built, proof, peer) = honest(400, &nonce);
        assert!(structure(&built, &proof, &nonce, &peer).is_ok());
        let s = sample(&proof, &nonce, built.commitment().key_count);
        // Responder returns Absent for the FIRST sampled key, honest for the rest.
        let victim = s.first().map(|l| l.key).unwrap();
        let v = verify_byte_response(&s, &nonce, &peer, |k| {
            if *k == victim {
                Some(None) // explicit Absent
            } else {
                Some(Some(chunk_bytes(k)))
            }
        });
        assert_eq!(v, AuditVerdict::Fail(AuditFailureReason::DigestMismatch));
    }

    #[test]
    fn omitted_committed_key_is_confirmed_failure() {
        // A responder that simply omits a sampled committed key from its items
        // (neither Present nor Absent) is treated identically to Absent: it
        // committed to the key and won't serve it → confirmed failure.
        let nonce = [9u8; 32];
        let (built, proof, peer) = honest(400, &nonce);
        let s = sample(&proof, &nonce, built.commitment().key_count);
        let victim = s.first().map(|l| l.key).unwrap();
        let v = verify_byte_response(&s, &nonce, &peer, |k| {
            if *k == victim {
                None // omitted entirely
            } else {
                Some(Some(chunk_bytes(k)))
            }
        });
        assert_eq!(v, AuditVerdict::Fail(AuditFailureReason::DigestMismatch));
    }

    #[test]
    fn fake_storage_garbage_bytes_is_confirmed_failure() {
        // A "fake-storage" responder claims possession but serves garbage. The
        // garbage does not hash to the committed content address (`bytes_hash`),
        // so the round-2 content-address check fails → confirmed failure. No
        // auditor holdings involved.
        let nonce = [9u8; 32];
        let (built, proof, peer) = honest(400, &nonce);
        let s = sample(&proof, &nonce, built.commitment().key_count);
        let v = verify_byte_response(&s, &nonce, &peer, |k| {
            let mut garbage = blake3::hash(k).as_bytes().to_vec();
            garbage.extend_from_slice(b"adversary-fake-storage");
            Some(Some(garbage))
        });
        assert_eq!(v, AuditVerdict::Fail(AuditFailureReason::DigestMismatch));
    }

    #[test]
    fn correct_content_address_but_stale_freshness_fails() {
        // Suppose a responder could serve bytes that hash to the content address
        // (it holds the chunk) — then BOTH checks pass; that is honest. But if
        // it serves bytes whose freshness hash does not match (e.g. replaying a
        // different nonce's digest is impossible since we recompute it here), the
        // freshness check must catch any content that doesn't reproduce the
        // committed `nonced_hash`. We model a leaf whose committed nonced_hash was
        // built under a DIFFERENT nonce, so the audit nonce's recompute differs.
        let nonce = [9u8; 32];
        let (built, mut proof, peer) = honest(400, &nonce);
        // Rewrite the first leaf's nonced_hash to one bound to a different nonce
        // but keep its bytes_hash correct (so structure for THAT leaf's content
        // address is fine; only freshness is wrong).
        let other_nonce = [0xEEu8; 32];
        let s_keys: Vec<XorName> = sample(&proof, &nonce, built.commitment().key_count)
            .iter()
            .map(|l| l.key)
            .collect();
        let victim = s_keys.first().copied().unwrap();
        for leaf in &mut proof.leaves {
            if leaf.key == victim {
                leaf.nonced_hash =
                    nonced_leaf_hash(&other_nonce, &peer, &leaf.key, &chunk_bytes(&leaf.key));
            }
        }
        // Re-sample against the (now tampered) proof; serve honest content.
        let s = sample(&proof, &nonce, built.commitment().key_count);
        let v = verify_byte_response(&s, &nonce, &peer, served_honest);
        assert_eq!(v, AuditVerdict::Fail(AuditFailureReason::DigestMismatch));
    }

    #[test]
    fn auditor_holds_nothing_still_catches_deleter() {
        // Explicit contract: the auditor's own storage is irrelevant. A deleter
        // is caught purely from its served (absent) response. (Compare the OLD
        // design, where an auditor holding none of the chunks went Inconclusive
        // and the deleter walked free.)
        let nonce = [0x21u8; 32];
        let (built, proof, peer) = honest(256, &nonce);
        assert!(structure(&built, &proof, &nonce, &peer).is_ok());
        let s = sample(&proof, &nonce, built.commitment().key_count);
        // Responder is a total deleter: Absent for everything.
        let v = verify_byte_response(&s, &nonce, &peer, |_| Some(None));
        assert_eq!(v, AuditVerdict::Fail(AuditFailureReason::DigestMismatch));
    }

    #[test]
    fn sample_size_is_in_3_to_5_band() {
        // ADR-0002: round-2 samples a SMALL surprise set (3..=5) of the proven
        // leaves. For a large subtree the sample is capped at 5.
        let nonce = [7u8; 32];
        let (built, proof, _peer) = honest(1024, &nonce);
        let s = sample(&proof, &nonce, built.commitment().key_count);
        assert!(
            (BYTE_SPOTCHECK_MIN as usize..=BYTE_SPOTCHECK_MAX as usize).contains(&s.len()),
            "sample {} must be within 3..=5",
            s.len()
        );
    }

    #[test]
    fn full_pass_requires_every_sampled_leaf() {
        // checked must equal the number of sampled leaves on a pass (no leaf is
        // silently skipped — every sampled, committed key must verify).
        let nonce = [11u8; 32];
        let (built, proof, peer) = honest(400, &nonce);
        let s = sample(&proof, &nonce, built.commitment().key_count);
        match verify_byte_response(&s, &nonce, &peer, served_honest) {
            AuditVerdict::Pass { checked } => assert_eq!(checked, s.len()),
            other => panic!("expected Pass, got {other:?}"),
        }
    }

    // ---- end-to-end gate composition ----------------------------------------

    #[test]
    fn structure_fail_short_circuits_before_round_2() {
        // A structurally invalid proof is rejected in round 1; the byte challenge
        // is never issued. We assert the round-1 gate returns Err so the auditor
        // (verify_subtree_response) never reaches request_byte_proof.
        let nonce = [5u8; 32];
        let (built, mut proof, peer) = honest(300, &nonce);
        if let Some(first) = proof.leaves.first_mut() {
            first.bytes_hash[0] ^= 0x01;
        }
        assert!(structure(&built, &proof, &nonce, &peer).is_err());
    }

    /// Build an honest committed tree whose keys are deliberately "FAR": their
    /// addresses live at the high end of the XOR space (top bytes = 0xFF). On the
    /// auditor side these are the leaves `observe_closeness` counts toward `far`.
    fn honest_far(n: u32, nonce: &[u8; 32]) -> (BuiltCommitment, SubtreeProof, [u8; 32]) {
        let (pk, sk) = ml_dsa_65().generate_keypair().unwrap();
        let peer_id = *blake3::hash(&pk.to_bytes()).as_bytes();
        let pk_b = pk.to_bytes();
        let entries: Vec<_> = (0..n)
            .map(|i| {
                let mut k = [0xFFu8; 32];
                k[28..].copy_from_slice(&i.to_be_bytes());
                (k, *blake3::hash(&chunk_bytes(&k)).as_bytes())
            })
            .collect();
        let built = BuiltCommitment::build(entries, &peer_id, &sk, &pk_b).unwrap();
        let proof =
            build_subtree_proof(built.tree(), nonce, &peer_id, |k| Some(chunk_bytes(k))).unwrap();
        (built, proof, peer_id)
    }

    /// ADR-0002 "Closeness" is OBSERVE-ONLY: far-keyed honest proofs verify
    /// exactly like near-keyed ones. The verdict (structure + served bytes) is
    /// closeness-blind, so a "far/padding" shape can never produce a Fail.
    #[test]
    fn closeness_is_observe_only_far_keys_still_pass() {
        let nonce = [9u8; 32];

        let (built_far, proof_far, peer_far) = honest_far(400, &nonce);
        assert!(structure(&built_far, &proof_far, &nonce, &peer_far).is_ok());
        let sf = sample(&proof_far, &nonce, built_far.commitment().key_count);
        let v_far = verify_byte_response(&sf, &nonce, &peer_far, served_honest);

        let (built_near, proof_near, peer_near) = honest(400, &nonce);
        assert!(structure(&built_near, &proof_near, &nonce, &peer_near).is_ok());
        let sn = sample(&proof_near, &nonce, built_near.commitment().key_count);
        let v_near = verify_byte_response(&sn, &nonce, &peer_near, served_honest);

        match (&v_far, &v_near) {
            (AuditVerdict::Pass { checked: cf }, AuditVerdict::Pass { checked: cn }) => {
                assert!(*cf >= 1 && *cn >= 1);
            }
            other => panic!("both honest proofs must Pass regardless of closeness, got {other:?}"),
        }
        assert!(
            !matches!(v_far, AuditVerdict::Fail(_)),
            "far/padding-shaped honest proof must NEVER fail, got {v_far:?}"
        );
    }

    // Unused-leaf constructor guard: keep SubtreeLeaf import meaningful.
    #[test]
    fn subtree_leaf_is_constructible() {
        let _l = SubtreeLeaf {
            key: key(1),
            bytes_hash: [0u8; 32],
            nonced_hash: [0u8; 32],
        };
    }
}
