//! Threat-model proof-of-concept tests for the gossip-triggered
//! contiguous-subtree storage audit (ADR-0002,
//! `docs/.../v13-gossip-subtree-audit`).
//!
//! Each test models a specific storage-binding attack from the original
//! Finding-1 / Finding-2 reports
//! (`notes/security-findings-2026-05-22/{01,02}-*.md`) and asserts that the
//! subtree-audit mechanisms reject it. This file is the single canonical place
//! to look for "does the subtree audit actually close the storage-binding
//! findings?" — each `#[test]` docstring links the attack back to its finding.
//!
//! ## How the auditor is modelled here
//!
//! The production auditor's `verify_subtree_response` (in
//! `src/replication/audit.rs`) is private, so this file reproduces the exact
//! ordered gates it runs — pin, peer-id binding, signature, structural
//! [`verify_subtree_proof`], then a real-bytes spot-check on a few subtree
//! leaves — via the public primitives. The helper [`auditor_accepts`] runs them
//! in the same order with the same failure semantics, so a reviewer can see
//! each attack is caught at the same gate the network code would catch it.
//!
//! ## What changed from the old per-key audit (and why)
//!
//! The OLD audit named individual keys and sampled a per-key Merkle inclusion
//! proof + digest. The subtree audit names NO keys: the nonce alone selects one
//! contiguous subtree, the responder must expand it in full, and a few leaves
//! are byte-checked. Consequently these per-key-only attacks were DROPPED — they
//! have no analogue under subtree sampling:
//!
//!   * "key not in commitment" / overclaim-via-partial-commitment — the auditor
//!     never names a key, so a responder can't be asked to prove an uncommitted
//!     key; it proves whatever the nonce selects from its own committed tree.
//!   * per-key digest order / per-key path tamper — replaced by the subtree
//!     structural checks (leaf count, ascending order, cut-hash count, root
//!     rebuild) and the per-leaf real-bytes spot-check.
//!   * `RecentProvers` holder-credit revocation/rotation tests — those exercised
//!     the cache binding, not the audit proof, and now live with the cache; the
//!     subtree auditor credits per proven leaf (`AuditCredit`) but the credit
//!     binding itself is unchanged and tested elsewhere.
//!
//! Attacks PRESERVED in spirit, ported to the subtree model: fresh-commitment
//! substitution, cross-peer commitment substitution, throwaway-key
//! substitution, wrong-signer, replay-under-fresh-nonce, repudiation of a
//! recently gossiped pin, and the lazy/relay "holds addresses not bytes"
//! fabricated-possession attack. Plus subtree-native structural attacks:
//! tampered cut-hash, wrong leaf count, reordered leaves.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::redundant_clone,
    clippy::cast_possible_truncation,
    clippy::doc_markdown,
    clippy::needless_borrows_for_generic_args
)]

use ant_node::replication::commitment::{
    commitment_hash, leaf_hash, sign_commitment, verify_commitment_signature, MerkleTree,
    StorageCommitment,
};
use ant_node::replication::commitment_state::{BuiltCommitment, ResponderCommitmentState};
use ant_node::replication::subtree::{
    build_subtree_proof, nonced_leaf_hash, select_spotcheck_indices, select_subtree_path,
    verify_subtree_proof, StructureVerdict, SubtreeProof,
};
use saorsa_pqc::api::sig::{ml_dsa_65, MlDsaPublicKey, MlDsaSecretKey};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn keypair() -> (MlDsaPublicKey, MlDsaSecretKey) {
    ml_dsa_65().generate_keypair().unwrap()
}

/// Deterministic chunk bytes for key index `i`. The committed tree is built
/// from `BLAKE3(content(i))`, so an honest proof — which hashes the same bytes —
/// reconstructs the committed root and passes the real-bytes spot-check.
fn content(i: u32) -> Vec<u8> {
    let mut v = key(i).to_vec();
    v.extend_from_slice(b"subtree-audit-chunk-body");
    v.extend_from_slice(&i.to_le_bytes());
    v
}

fn content_hash(i: u32) -> [u8; 32] {
    *blake3::hash(&content(i)).as_bytes()
}

/// Big-endian key so numeric order matches the MerkleTree sort order; this lets
/// us reason about leaf positions when we tamper with them.
fn key(i: u32) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[..4].copy_from_slice(&i.to_be_bytes());
    k
}

/// A responder identity (real ML-DSA keypair) plus its retention state. Peer
/// identity is derived from the public key exactly as in production
/// (saorsa-core `peer_id_from_public_key` = `BLAKE3(pubkey_bytes)`).
struct Responder {
    state: ResponderCommitmentState,
    public_key: MlDsaPublicKey,
    secret_key: MlDsaSecretKey,
    peer_id_bytes: [u8; 32],
}

impl Responder {
    fn new() -> Self {
        let (public_key, secret_key) = keypair();
        let peer_id_bytes = *blake3::hash(&public_key.to_bytes()).as_bytes();
        Self {
            state: ResponderCommitmentState::new(),
            public_key,
            secret_key,
            peer_id_bytes,
        }
    }

    /// Commit to keys `[0, n)` and rotate that commitment into `current`.
    /// Returns the new commitment hash.
    fn commit_to_range(&self, n: u32) -> [u8; 32] {
        let entries: Vec<_> = (0..n).map(|i| (key(i), content_hash(i))).collect();
        let built = BuiltCommitment::build(
            entries,
            &self.peer_id_bytes,
            &self.secret_key,
            &self.public_key.to_bytes(),
        )
        .unwrap();
        let h = built.hash();
        self.state.rotate(built);
        h
    }
}

/// Bytes source for an HONEST responder: it really holds every chunk it
/// committed to, so it can always produce a correct `nonced_hash`.
fn honest_bytes(k: &[u8; 32]) -> Option<Vec<u8>> {
    for i in 0..4096u32 {
        if &key(i) == k {
            return Some(content(i));
        }
    }
    None
}

/// The auditor's full ordered verification, mirroring the production
/// `verify_subtree_response` gates. Returns `Ok(byte_checked_count)` on accept.
///
/// `auditor_local_bytes(k)` is the auditor's OWN copy of a chunk (used for the
/// real-bytes spot-check); a leaf the auditor cannot byte-check is skipped, and
/// if it could check none the audit is inconclusive (`AuditError::Inconclusive`,
/// the production "Idle, no credit, no penalty" outcome) — never a free pass.
fn auditor_accepts(
    challenged_peer_id: &[u8; 32],
    expected_commitment_hash: &[u8; 32],
    nonce: &[u8; 32],
    commitment: &StorageCommitment,
    proof: &SubtreeProof,
    auditor_local_bytes: impl Fn(&[u8; 32]) -> Option<Vec<u8>>,
) -> Result<usize, AuditError> {
    // -- Gate: pin + peer-id binding + signature ----------------------------
    if commitment.sender_peer_id != *challenged_peer_id {
        return Err(AuditError::SenderPeerIdMismatch);
    }
    let derived = *blake3::hash(&commitment.sender_public_key).as_bytes();
    if derived != commitment.sender_peer_id {
        return Err(AuditError::PeerIdKeyMismatch);
    }
    match commitment_hash(commitment) {
        Some(h) if &h == expected_commitment_hash => {}
        _ => return Err(AuditError::CommitmentHashMismatch),
    }
    if !verify_commitment_signature(commitment) {
        return Err(AuditError::SignatureInvalid);
    }

    // -- Gate: structure ----------------------------------------------------
    if let StructureVerdict::Invalid(why) = verify_subtree_proof(proof, nonce, commitment) {
        return Err(AuditError::StructureInvalid(why));
    }

    // -- Gate: real bytes (per-leaf possession) -----------------------------
    let path = select_subtree_path(nonce, commitment.key_count)
        .ok_or(AuditError::StructureInvalid("out-of-protocol key_count"))?;
    let spot = select_spotcheck_indices(nonce, &path, 8);
    let mut checked = 0usize;
    for idx in spot {
        let leaf = proof
            .leaves
            .get(idx as usize)
            .ok_or(AuditError::StructureInvalid("spot index out of range"))?;
        let Some(bytes) = auditor_local_bytes(&leaf.key) else {
            continue; // auditor lacks this chunk; not the responder's fault
        };
        let plain = *blake3::hash(&bytes).as_bytes();
        let nonced = nonced_leaf_hash(nonce, &commitment.sender_peer_id, &leaf.key, &bytes);
        if leaf.bytes_hash != plain || leaf.nonced_hash != nonced {
            return Err(AuditError::RealBytesMismatch);
        }
        checked += 1;
    }
    if checked == 0 {
        // The structurally-valid proof binds only PUBLIC data (the leaf
        // bytes_hash IS the chunk address). With no byte-verified leaf the
        // audit proves nothing about possession — inconclusive, not a pass.
        return Err(AuditError::Inconclusive);
    }
    Ok(checked)
}

#[derive(Debug, PartialEq, Eq)]
enum AuditError {
    SenderPeerIdMismatch,
    PeerIdKeyMismatch,
    CommitmentHashMismatch,
    SignatureInvalid,
    StructureInvalid(&'static str),
    RealBytesMismatch,
    Inconclusive,
}

/// Build an honest subtree proof for `nonce` against the responder's current
/// committed tree, returning `(proof, commitment)` as the auditor would receive
/// them in a `SubtreeAuditResponse::Proof`.
fn honest_proof_and_commitment(
    r: &Responder,
    nonce: &[u8; 32],
) -> (SubtreeProof, StorageCommitment) {
    let built = r.state.current().unwrap();
    let proof = build_subtree_proof(built.tree(), nonce, &r.peer_id_bytes, honest_bytes).unwrap();
    (proof, built.commitment().clone())
}

// ---------------------------------------------------------------------------
// Sanity: the honest path the attack tests are measured against actually passes
// ---------------------------------------------------------------------------

/// Anchor: an honest responder that committed to its keys and still holds the
/// bytes produces a proof the (modelled) auditor accepts. Without this, the
/// rejection assertions below could pass vacuously.
#[test]
fn honest_responder_passes_audit() {
    let nonce = [0xCD; 32];
    let honest = Responder::new();
    let pin = honest.commit_to_range(64);
    let (proof, commitment) = honest_proof_and_commitment(&honest, &nonce);

    let res = auditor_accepts(
        &honest.peer_id_bytes,
        &pin,
        &nonce,
        &commitment,
        &proof,
        honest_bytes,
    );
    assert!(res.is_ok(), "honest path must pass, got {res:?}");
    assert!(res.unwrap() >= 1, "must byte-check at least one leaf");
}

// ---------------------------------------------------------------------------
// Finding 1, Path A: lazy/relay node holds chunk ADDRESSES, not bytes
// ---------------------------------------------------------------------------

/// Attack 1a (Finding 1, Path A) — the storage-binding heart of the subtree
/// audit. A lazy/relay node retained the gossiped commitment and knows every
/// leaf's `bytes_hash` (that value IS the chunk's network address, which is
/// public), but it DROPPED the actual bytes. It fabricates a proof: correct
/// `key` and correct `bytes_hash` for every selected leaf (so the structural
/// root rebuild passes), but it cannot compute the `nonced_hash`, which requires
/// the real bytes under a fresh nonce. It fills in a forged `nonced_hash`.
///
/// The structural gate PASSES (addresses alone rebuild the root), proving that
/// structure is NOT sufficient — exactly the Finding-1 hole. The real-bytes
/// spot-check is what catches it: the auditor recomputes the nonced hash from
/// its own copy of the chunk and finds the forged one wrong.
#[test]
fn relay_holding_only_addresses_caught_by_real_bytes_check() {
    let nonce = [0x77; 32];
    let honest_keyset = Responder::new();
    let pin = honest_keyset.commit_to_range(100);
    let built = honest_keyset.state.current().unwrap();

    // The lazy node fabricates the proof from PUBLIC data only: it knows each
    // leaf key and its bytes_hash (== address), but NOT the bytes, so it forges
    // every nonced_hash.
    let path = select_subtree_path(&nonce, built.commitment().key_count).unwrap();
    let mut leaves = Vec::new();
    for idx in path.leaf_start..path.leaf_end {
        let k = built.tree().key_at(idx as usize).unwrap();
        // bytes_hash is public (== the chunk address); the responder fakes the
        // possession hash because it lacks the bytes.
        let forged_nonced = *blake3::hash(b"i-do-not-have-the-bytes").as_bytes();
        leaves.push(ant_node::replication::subtree::SubtreeLeaf {
            key: k,
            bytes_hash: content_hash(idx),
            nonced_hash: forged_nonced,
        });
    }
    // Real sibling cut-hashes from the committed tree (public, derivable).
    let plan = ant_node::replication::subtree::subtree_plan(built.tree(), &nonce).unwrap();
    let forged = SubtreeProof {
        leaves,
        sibling_cut_hashes: plan.sibling_cut_hashes,
    };

    // Structure alone PASSES — addresses are enough to rebuild the root. This
    // is the precise reason structure is insufficient on its own.
    assert_eq!(
        verify_subtree_proof(&forged, &nonce, built.commitment()),
        StructureVerdict::Valid,
        "address-only proof rebuilds the root (structure cannot bind possession)"
    );

    // The full auditor (with the real-bytes spot-check) rejects: the auditor
    // holds the real chunks and recomputes the nonced hash.
    let res = auditor_accepts(
        &honest_keyset.peer_id_bytes,
        &pin,
        &nonce,
        built.commitment(),
        &forged,
        honest_bytes,
    );
    assert_eq!(
        res,
        Err(AuditError::RealBytesMismatch),
        "forged nonced_hash must be caught by the real-bytes spot-check, got {res:?}"
    );
}

/// Attack 1a, detection-probability framing: a responder that fabricates a
/// FRACTION of leaves (holds some bytes, forged the rest) survives one audit
/// only with probability `(1 - x)^k` over `k` spot-checked leaves. This pins
/// that any spot-check landing on a forged leaf is fatal — the responder cannot
/// predict which leaves are sampled, because the spot-check indices are derived
/// from the same nonce that fixes the whole proof.
#[test]
fn fabricated_fraction_is_caught_when_a_forged_leaf_is_sampled() {
    let nonce = [0x31; 32];
    let r = Responder::new();
    let pin = r.commit_to_range(400);
    let (mut proof, commitment) = honest_proof_and_commitment(&r, &nonce);

    // Forge the nonced hash on every spot-checked position (worst case for the
    // attacker: all sampled leaves are fabricated → guaranteed catch).
    let path = select_subtree_path(&nonce, commitment.key_count).unwrap();
    for idx in select_spotcheck_indices(&nonce, &path, 8) {
        if let Some(leaf) = proof.leaves.get_mut(idx as usize) {
            leaf.nonced_hash[0] ^= 0xFF;
        }
    }

    let res = auditor_accepts(
        &r.peer_id_bytes,
        &pin,
        &nonce,
        &commitment,
        &proof,
        honest_bytes,
    );
    assert_eq!(
        res,
        Err(AuditError::RealBytesMismatch),
        "a forged leaf landing under the spot-check must fail, got {res:?}"
    );
}

/// Attack 1a, inconclusive lane (NOT a free pass): a relay returns a
/// structurally-valid, address-only proof to an auditor that happens to hold
/// NONE of the spot-checked chunks. The auditor cannot byte-verify anything, so
/// it must treat the audit as INCONCLUSIVE — no credit, no penalty — rather than
/// passing the relay for free. This closes the "structure-only pass" hole even
/// when the auditor lacks the bytes.
#[test]
fn relay_with_no_auditor_overlap_is_inconclusive_not_passed() {
    let nonce = [0x19; 32];
    let r = Responder::new();
    let pin = r.commit_to_range(100);
    // Honest structure (real bytes), so structure passes; the point is the
    // auditor holds none of the chunks.
    let (proof, commitment) = honest_proof_and_commitment(&r, &nonce);

    let auditor_holds_nothing = |_k: &[u8; 32]| -> Option<Vec<u8>> { None };
    let res = auditor_accepts(
        &r.peer_id_bytes,
        &pin,
        &nonce,
        &commitment,
        &proof,
        auditor_holds_nothing,
    );
    assert_eq!(
        res,
        Err(AuditError::Inconclusive),
        "no byte-verifiable leaf ⇒ inconclusive, never a free pass, got {res:?}"
    );
}

// ---------------------------------------------------------------------------
// Finding 1, Path B: fresh-commitment substitution
// ---------------------------------------------------------------------------

/// Attack 1b (Finding 1, Path B): a responder builds a FRESH commitment over a
/// different key set and answers with a valid proof against THAT commitment,
/// while the auditor pinned the hash of the commitment the peer actually
/// gossiped. The auditor's pin (`commitment_hash == expected_commitment_hash`)
/// rejects the substitution before any structural work.
#[test]
fn fresh_commitment_substitution_rejected_by_pin() {
    let nonce = [0xCD; 32];

    let original = Responder::new();
    let pinned_hash = original.commit_to_range(64);

    // Same peer rotates to a fresh commitment over a different range; it can
    // build a perfectly valid proof against the NEW commitment.
    let fresh_hash = original.commit_to_range(32);
    assert_ne!(pinned_hash, fresh_hash);
    let (proof, fresh_commitment) = honest_proof_and_commitment(&original, &nonce);

    // Auditor still pins the ORIGINAL hash.
    let res = auditor_accepts(
        &original.peer_id_bytes,
        &pinned_hash, // <- original pin, not fresh_hash
        &nonce,
        &fresh_commitment,
        &proof,
        honest_bytes,
    );
    assert_eq!(
        res,
        Err(AuditError::CommitmentHashMismatch),
        "fresh-commitment substitution must trip the pin, got {res:?}"
    );
}

// ---------------------------------------------------------------------------
// Finding 1, Path C: cross-peer commitment substitution
// ---------------------------------------------------------------------------

/// Attack 1c (Finding 1 — peer impersonation): peer Q lifts peer P's signed
/// commitment from gossip and embeds it in its own response, hoping the auditor
/// verifies P's signature by mistake. The auditor binds the commitment's
/// `sender_peer_id` to the challenged peer; the stolen commitment names P, not
/// Q, so it is rejected before any signature/structure work.
#[test]
fn cross_peer_commitment_substitution_rejected_by_sender_id() {
    let nonce = [0xCD; 32];

    let real_p = Responder::new();
    let p_hash = real_p.commit_to_range(64);
    let (p_proof, p_commitment) = honest_proof_and_commitment(&real_p, &nonce);

    // Auditor is challenging Q (a different peer id) but somehow holds p_hash in
    // its pin (modelling a mis-binding); Q replays P's commitment + proof.
    let q_peer_id = [0xCC; 32];
    let res = auditor_accepts(
        &q_peer_id, // challenged peer is Q
        &p_hash,
        &nonce,
        &p_commitment, // sender_peer_id == P, not Q
        &p_proof,
        honest_bytes,
    );
    assert_eq!(
        res,
        Err(AuditError::SenderPeerIdMismatch),
        "cross-peer substitution must trip the sender-id binding, got {res:?}"
    );
}

/// Attack 1c': throwaway-key substitution. An adversary wants to answer as peer
/// P (whose pubkey it does NOT control). It builds a commitment naming P's
/// peer_id but embedding a throwaway pubkey it can sign with — the signature
/// verifies under the embedded key. The peer-id↔key binding
/// (`peer_id == BLAKE3(embedded_pubkey)`) rejects it: the embedded throwaway key
/// does not hash to P's peer_id.
#[test]
#[allow(clippy::similar_names)]
fn throwaway_key_substitution_rejected_by_pubkey_binding() {
    let nonce = [0xCD; 32];

    // P's real identity (adversary does not hold P's secret key).
    let (p_pubkey, _p_secret) = keypair();
    let p_peer_id = *blake3::hash(&p_pubkey.to_bytes()).as_bytes();

    // Adversary's throwaway keypair.
    let (throwaway_pk, throwaway_sk) = keypair();
    let throwaway_pk_bytes = throwaway_pk.to_bytes();

    // Build a commitment naming P's peer_id but embedding+signing with the
    // throwaway key.
    let entries: Vec<_> = (0..8u32).map(|i| (key(i), content_hash(i))).collect();
    let tree = MerkleTree::build(entries).unwrap();
    let root = tree.root();
    let key_count = tree.key_count();
    let sig = sign_commitment(
        &throwaway_sk,
        &root,
        key_count,
        &p_peer_id, // claims P (the lie)
        &throwaway_pk_bytes,
    )
    .unwrap();
    let bad_commit = StorageCommitment {
        root,
        key_count,
        sender_peer_id: p_peer_id,
        sender_public_key: throwaway_pk_bytes,
        signature: sig,
    };
    let pin = commitment_hash(&bad_commit).unwrap();

    // A perfectly valid proof against the bad commitment's own tree.
    let proof = build_subtree_proof(&tree, &nonce, &p_peer_id, honest_bytes).unwrap();

    let res = auditor_accepts(&p_peer_id, &pin, &nonce, &bad_commit, &proof, honest_bytes);
    assert_eq!(
        res,
        Err(AuditError::PeerIdKeyMismatch),
        "throwaway-key attack must trip the peer-id↔key binding, got {res:?}"
    );
}

/// Attack 1c'' — wrong signer at the signature gate. To isolate the signature
/// gate from the bindings above, the adversary swaps BOTH the embedded pubkey
/// and the sender_peer_id to a consistent (wrong) identity, and re-pins the
/// auditor to the mutated commitment. Now the peer-id binding and pin pass, but
/// the signature was produced under the ORIGINAL secret key over the ORIGINAL
/// payload — it cannot verify under the swapped key.
#[test]
fn wrong_signer_rejected_at_signature_gate() {
    let nonce = [0xCD; 32];

    let responder = Responder::new();
    responder.commit_to_range(16);
    let (proof, commitment) = honest_proof_and_commitment(&responder, &nonce);

    let (wrong_pk, _wrong_sk) = keypair();
    let wrong_pk_bytes = wrong_pk.to_bytes();
    let wrong_peer_id = *blake3::hash(&wrong_pk_bytes).as_bytes();

    let mut bad_commit = commitment.clone();
    bad_commit.sender_public_key = wrong_pk_bytes;
    bad_commit.sender_peer_id = wrong_peer_id;
    let new_pin = commitment_hash(&bad_commit).unwrap();

    // The proof's leaves bind the ORIGINAL peer_id in their nonced hashes, but
    // the signature gate fires BEFORE the structural/real-bytes gates, so it is
    // the first (and asserted) failure.
    let res = auditor_accepts(
        &wrong_peer_id,
        &new_pin,
        &nonce,
        &bad_commit,
        &proof,
        honest_bytes,
    );
    assert_eq!(
        res,
        Err(AuditError::SignatureInvalid),
        "swapped embedded key must trip the signature gate, got {res:?}"
    );
}

// ---------------------------------------------------------------------------
// Finding 1, Path D: replay an old response under a fresh nonce
// ---------------------------------------------------------------------------

/// Attack 1d (Finding 1 — replay): the auditor issues a fresh nonce each audit.
/// The nonce both selects the subtree AND freshens every leaf's possession hash,
/// so a response captured under an old nonce cannot be replayed: the new nonce
/// selects a different subtree (wrong leaf set / cut-hash count) and the stale
/// nonced hashes no longer match. Asserts the structural gate alone already
/// rejects the stale proof under the new nonce.
#[test]
fn audit_response_replay_blocked_by_fresh_nonce() {
    let old_nonce = [0xCD; 32];
    let fresh_nonce = [0xEF; 32];

    let r = Responder::new();
    let pin = r.commit_to_range(256);
    let (stale_proof, commitment) = honest_proof_and_commitment(&r, &old_nonce);

    // Sanity: the stale proof was valid under its own (old) nonce.
    assert_eq!(
        verify_subtree_proof(&stale_proof, &old_nonce, &commitment),
        StructureVerdict::Valid
    );

    // Replayed verbatim under the fresh nonce, it fails — the new nonce selects
    // a different subtree, so even the structure no longer reconstructs.
    let res = auditor_accepts(
        &r.peer_id_bytes,
        &pin,
        &fresh_nonce, // <- different nonce
        &commitment,
        &stale_proof,
        honest_bytes,
    );
    assert!(
        matches!(res, Err(AuditError::StructureInvalid(_))),
        "replay under a fresh nonce must fail the structural gate, got {res:?}"
    );
}

// ---------------------------------------------------------------------------
// Subtree-native structural attacks (replace the old per-key path/order tamper)
// ---------------------------------------------------------------------------

/// Tampering a sibling cut-hash breaks the root rebuild. (Subtree analogue of
/// the old per-key "tamper the inclusion path" attack.)
#[test]
fn tampered_cut_hash_rejected() {
    let nonce = [0x0B; 32];
    let r = Responder::new();
    let pin = r.commit_to_range(256);
    let (mut proof, commitment) = honest_proof_and_commitment(&r, &nonce);
    assert!(
        !proof.sibling_cut_hashes.is_empty(),
        "a 256-leaf tree selects a deep subtree with cut-hashes"
    );
    if let Some(c) = proof.sibling_cut_hashes.first_mut() {
        c[0] ^= 0x01;
    }
    let res = auditor_accepts(
        &r.peer_id_bytes,
        &pin,
        &nonce,
        &commitment,
        &proof,
        honest_bytes,
    );
    assert!(
        matches!(res, Err(AuditError::StructureInvalid(_))),
        "tampered cut-hash must fail structure, got {res:?}"
    );
}

/// Dropping a leaf yields the wrong leaf count for the agreed subtree. The
/// auditor re-derives the exact expected count from `(nonce, key_count)` and
/// rejects.
#[test]
fn wrong_leaf_count_rejected() {
    let nonce = [0x0C; 32];
    let r = Responder::new();
    let pin = r.commit_to_range(100);
    let (mut proof, commitment) = honest_proof_and_commitment(&r, &nonce);
    proof.leaves.pop();
    let res = auditor_accepts(
        &r.peer_id_bytes,
        &pin,
        &nonce,
        &commitment,
        &proof,
        honest_bytes,
    );
    assert_eq!(
        res,
        Err(AuditError::StructureInvalid("wrong leaf count")),
        "dropped leaf must fail the leaf-count check, got {res:?}"
    );
}

/// Reordering leaves violates the strict ascending-key order the committed tree
/// enforces (and would otherwise let a responder shuffle leaves to dodge the
/// spot-check). Rejected structurally.
#[test]
fn reordered_leaves_rejected() {
    let nonce = [0x0D; 32];
    let r = Responder::new();
    let pin = r.commit_to_range(100);
    let (mut proof, commitment) = honest_proof_and_commitment(&r, &nonce);
    assert!(proof.leaves.len() >= 2);
    proof.leaves.swap(0, 1);
    let res = auditor_accepts(
        &r.peer_id_bytes,
        &pin,
        &nonce,
        &commitment,
        &proof,
        honest_bytes,
    );
    assert!(
        matches!(res, Err(AuditError::StructureInvalid(_))),
        "reordered leaves must fail structure, got {res:?}"
    );
}

/// Tampering a leaf's `bytes_hash` (claiming a different chunk at a committed
/// position) breaks the root rebuild — the leaf hash binds (key, bytes_hash).
#[test]
fn tampered_leaf_bytes_hash_rejected() {
    let nonce = [0x0E; 32];
    let r = Responder::new();
    let pin = r.commit_to_range(100);
    let (mut proof, commitment) = honest_proof_and_commitment(&r, &nonce);
    proof.leaves[0].bytes_hash[0] ^= 0x01;
    let res = auditor_accepts(
        &r.peer_id_bytes,
        &pin,
        &nonce,
        &commitment,
        &proof,
        honest_bytes,
    );
    assert!(
        matches!(res, Err(AuditError::StructureInvalid(_))),
        "tampered bytes_hash must fail structure, got {res:?}"
    );
}

// ---------------------------------------------------------------------------
// Repudiation: rejecting a recently-gossiped pinned commitment
// ---------------------------------------------------------------------------

/// Attack: a responder repudiates a commitment it just gossiped — it answers a
/// pin for a commitment it no longer retains. Because the auditor only ever pins
/// a commitment the peer JUST gossiped, and an honest responder retains its last
/// two GOSSIPED commitments, a `lookup_by_hash` miss for a gossiped pin is a
/// confirmed failure. This test pins the retention contract: a gossiped pin
/// stays answerable across the next rotation, but a NEVER-gossiped commitment is
/// dropped on the next rotation (so the responder rightly cannot answer a pin it
/// never put on the wire).
#[test]
fn repudiating_a_gossiped_pin_is_detectable_via_lookup_miss() {
    let r = Responder::new();
    let state = &r.state;

    // c1 is gossiped → must stay answerable across one rotation.
    let h1 = r.commit_to_range(8);
    state.mark_gossiped(h1);
    assert!(
        state.lookup_by_hash(&h1).is_some(),
        "gossiped pin must be answerable immediately"
    );

    // Rotate + gossip c2. c1 is within the last-2-gossiped window → still here.
    let h2 = r.commit_to_range(16);
    state.mark_gossiped(h2);
    assert!(
        state.lookup_by_hash(&h1).is_some(),
        "a gossiped commitment must survive one rotation (no false repudiation)"
    );

    // Rotate + gossip c3. Now the last-2-gossiped are {h3, h2}; h1 has aged out
    // and is legitimately dropped (the auditor would no longer pin it).
    let h3 = r.commit_to_range(24);
    state.mark_gossiped(h3);
    assert!(
        state.lookup_by_hash(&h1).is_none(),
        "h1 aged out of the gossip window"
    );
    assert!(state.lookup_by_hash(&h2).is_some());
    assert!(state.lookup_by_hash(&h3).is_some());

    // The detection edge: a commitment that was NEVER gossiped is dropped on the
    // very next rotation, so a responder asked to answer a pin for an
    // ungossiped-then-rotated commitment returns a lookup MISS — which the
    // auditor (since it only pins gossiped roots) reads as repudiation.
    let r2 = Responder::new();
    let ungossiped = r2.commit_to_range(8);
    assert!(r2.state.lookup_by_hash(&ungossiped).is_some());
    let _next = r2.commit_to_range(16); // rotate without gossiping `ungossiped`
    assert!(
        r2.state.lookup_by_hash(&ungossiped).is_none(),
        "an ungossiped commitment is dropped on the next rotation"
    );
}

// ---------------------------------------------------------------------------
// Cross-check lemmas: the primitives the rejection tests rest on
// ---------------------------------------------------------------------------

/// The commitment-hash pin is sensitive to every field. This underwrites every
/// "pin doesn't match" assertion above.
#[test]
fn commitment_hash_is_field_sensitive() {
    let (pk, sk) = keypair();
    let pk_bytes = pk.to_bytes();
    let sig = sign_commitment(&sk, &[0; 32], 1, &[0; 32], &pk_bytes).unwrap();
    let c1 = StorageCommitment {
        root: [0; 32],
        key_count: 1,
        sender_peer_id: [0; 32],
        sender_public_key: pk_bytes,
        signature: sig,
    };
    let h1 = commitment_hash(&c1).unwrap();

    for mutate in 0..5u8 {
        let mut c = c1.clone();
        match mutate {
            0 => c.root[0] ^= 1,
            1 => c.key_count += 1,
            2 => c.sender_peer_id[0] ^= 1,
            3 => c.signature[0] ^= 1,
            4 => c.sender_public_key[0] ^= 1,
            _ => unreachable!(),
        }
        let h = commitment_hash(&c).unwrap();
        assert_ne!(h, h1, "mutation {mutate} should change commitment_hash");
    }
}

/// The leaf hash binds (key, bytes_hash): same key + different bytes → different
/// leaf → different root. Underwrites the structural rejections.
#[test]
fn leaf_hash_binds_key_and_bytes() {
    let h1 = leaf_hash(&key(1), &content_hash(1));
    let h2 = leaf_hash(&key(1), &content_hash(2));
    let h3 = leaf_hash(&key(2), &content_hash(1));
    assert_ne!(h1, h2);
    assert_ne!(h1, h3);
    assert_ne!(h2, h3);
}

/// The signature verifies under the embedded key and only that key.
#[test]
fn signature_round_trips_correctly() {
    let (pk1, sk1) = keypair();
    let (pk2, _sk2) = keypair();
    let pk1_bytes = pk1.to_bytes();
    let pk2_bytes = pk2.to_bytes();
    let sig = sign_commitment(&sk1, &[7; 32], 42, &[3; 32], &pk1_bytes).unwrap();
    let c = StorageCommitment {
        root: [7; 32],
        key_count: 42,
        sender_peer_id: [3; 32],
        sender_public_key: pk1_bytes,
        signature: sig,
    };
    assert!(verify_commitment_signature(&c));
    let mut c2 = c.clone();
    c2.sender_public_key = pk2_bytes;
    assert!(!verify_commitment_signature(&c2));
}

/// The per-leaf possession hash binds nonce, peer, key, and bytes — the
/// foundation of the real-bytes spot-check. Changing any input changes it, so a
/// responder cannot reuse a possession hash across nonces/peers/keys/chunks.
#[test]
fn nonced_leaf_hash_binds_all_inputs() {
    let base = nonced_leaf_hash(&[1; 32], &[2; 32], &key(3), b"chunk");
    assert_ne!(
        base,
        nonced_leaf_hash(&[9; 32], &[2; 32], &key(3), b"chunk")
    );
    assert_ne!(
        base,
        nonced_leaf_hash(&[1; 32], &[9; 32], &key(3), b"chunk")
    );
    assert_ne!(
        base,
        nonced_leaf_hash(&[1; 32], &[2; 32], &key(9), b"chunk")
    );
    assert_ne!(
        base,
        nonced_leaf_hash(&[1; 32], &[2; 32], &key(3), b"other")
    );
}
