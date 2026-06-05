//! Responder-side commitment builder + rotation state.
//!
//! Phase 2b of the v12 storage-bound audit design. Builds, signs, and
//! caches a [`StorageCommitment`] over the responder's currently-stored
//! key set; serves audit lookups by `expected_commitment_hash`; retains
//! the previous commitment across one rotation so an audit pinned to it
//! does not false-fail at the rotation boundary (v5/v12 §4 retention).
//!
//! Rotation strategy:
//!
//! - `rotate(new_built)` atomically replaces `current` with `new_built`
//!   and demotes the prior `current` to `previous`. The prior
//!   `previous` is dropped.
//! - `lookup(hash)` reads the in-memory map and returns an [`Arc`] to
//!   the matching `BuiltCommitment`, keeping it alive for the audit
//!   response regardless of subsequent rotation (mirrors the `ArcSwap`
//!   semantics specified in v6 §2: an in-flight reader holding its
//!   `Arc` is unaffected by a concurrent rotate).
//!
//! No persistent disk state. Trees are rebuilt from `LmdbStorage` at
//! the next rotation tick. Memory cost is bounded by
//! `2 × (key_count × ~64 bytes + signature_size)` — for 10k keys, ~1.3 MB.

use std::sync::Arc;
use std::time::Instant;

use parking_lot::RwLock;
use saorsa_pqc::api::sig::MlDsaSecretKey;

use crate::ant_protocol::XorName;
use crate::replication::commitment::{
    commitment_hash, sign_commitment, CommitmentError, MerkleTree, StorageCommitment,
};

/// Auditor-side per-peer commitment state.
///
/// Holds two things that together implement v10/v12 §2 step 5 and §6:
///   - `last_commitment`: the most recently received, verified, signed
///     commitment from this peer. `None` if we've evicted it (TTL,
///     sybil cap, peer-removed) or never received one.
///   - `commitment_capable`: a **sticky** boolean that flips to `true`
///     on the first successful gossip ingest and NEVER reverts. Used
///     by holder-eligibility (§6) and bootstrap-claim shield: a peer
///     that has at least once proven it speaks v12 is forever held to
///     that standard. Without stickiness, a peer could flip the flag
///     off by silencing its gossip and downgrade to the weaker legacy
///     audit path.
#[derive(Debug, Clone)]
pub struct PeerCommitmentRecord {
    /// Last verified commitment, or `None` if evicted/expired.
    pub last_commitment: Option<StorageCommitment>,
    /// Sticky: true once this peer has gossiped a valid commitment.
    /// Set on ingest. Never set back to false except by full
    /// `PeerRemoved` cleanup.
    pub commitment_capable: bool,
    /// When `last_commitment` was received. Used for TTL on the
    /// commitment itself (independent of the `commitment_capable`
    /// stickiness — losing the commitment via TTL doesn't make us
    /// forget the peer ever spoke v12).
    pub received_at: Instant,
    /// Last time we performed an ML-DSA signature verify for this
    /// peer's commitment. Used to enforce the §2 step 3 rate limit
    /// (at most one sig verify per peer per 60s).
    pub last_sig_verify_at: Instant,
}

impl PeerCommitmentRecord {
    /// Construct from a freshly-verified commitment. `commitment_capable`
    /// is set to `true` here and must remain so for the lifetime of the
    /// record.
    #[must_use]
    pub fn from_verified(commitment: StorageCommitment, now: Instant) -> Self {
        Self {
            last_commitment: Some(commitment),
            commitment_capable: true,
            received_at: now,
            last_sig_verify_at: now,
        }
    }

    /// Mark commitment-capable without storing a commitment (used when
    /// we've TTL-expired the commitment itself but want to remember the
    /// peer has spoken v12 before).
    #[must_use]
    pub fn capable_but_no_commitment(now: Instant) -> Self {
        Self {
            last_commitment: None,
            commitment_capable: true,
            received_at: now,
            last_sig_verify_at: now,
        }
    }
}

/// A fully-built commitment: signed wire blob, cached hash, Merkle tree
/// for inclusion proofs, and a sorted leaf-index lookup for the auditor's
/// `leaf_index` field.
///
/// Held inside an [`Arc`] so audit responders can grab a reference and
/// build a reply without holding the [`ResponderCommitmentState`] read
/// lock for the duration of the response.
pub struct BuiltCommitment {
    /// The signed wire blob.
    commitment: StorageCommitment,
    /// `commitment_hash(commitment)` — cached so audit lookups don't
    /// re-serialize on every match.
    cached_hash: [u8; 32],
    /// The Merkle tree behind the commitment. `path_for(key)` produces
    /// the inclusion proof; the responder's leaf-index lookup is below.
    tree: MerkleTree,
    /// `sorted_keys[i]` is the key at leaf index `i`. Sorted ascending
    /// so binary search reconstructs `leaf_index` for any key in
    /// `O(log n)`.
    sorted_keys: Vec<XorName>,
}

impl BuiltCommitment {
    /// Build a commitment over `entries = [(key, bytes_hash), ...]` and
    /// sign it with `secret_key`.
    ///
    /// `entries` does not need to be sorted (the inner [`MerkleTree`]
    /// sorts internally); `sender_peer_id` is bound into the signature
    /// and the commitment.
    ///
    /// # Errors
    ///
    /// Returns the wrapped [`CommitmentError`] on empty key sets,
    /// over-cap key counts, duplicates, or signing failures.
    pub fn build(
        entries: Vec<(XorName, [u8; 32])>,
        sender_peer_id: &[u8; 32],
        secret_key: &MlDsaSecretKey,
        sender_public_key: &[u8],
    ) -> Result<Self, CommitmentError> {
        let tree = MerkleTree::build(entries)?;
        let root = tree.root();
        let key_count = tree.key_count();
        let signature = sign_commitment(
            secret_key,
            &root,
            key_count,
            sender_peer_id,
            sender_public_key,
        )?;
        let commitment = StorageCommitment {
            root,
            key_count,
            sender_peer_id: *sender_peer_id,
            sender_public_key: sender_public_key.to_vec(),
            signature,
        };
        // `commitment_hash` only returns None on a postcard serialization
        // failure, which for our fixed-size commitment cannot occur in
        // practice (ML-DSA-65 signature is 3293 bytes). If it ever
        // somehow does, surface as a SignatureFailed so callers don't
        // need a new error variant for an unreachable case.
        let cached_hash = commitment_hash(&commitment).ok_or_else(|| {
            CommitmentError::SignatureFailed("commitment serialization failed".to_string())
        })?;
        // Recover the sorted key list from the tree (path_for uses
        // binary search internally, but we need an explicit list for
        // leaf_index lookup at audit time).
        let sorted_keys: Vec<XorName> = tree.sorted_keys();
        Ok(Self {
            commitment,
            cached_hash,
            tree,
            sorted_keys,
        })
    }

    /// The signed wire blob.
    #[must_use]
    pub fn commitment(&self) -> &StorageCommitment {
        &self.commitment
    }

    /// The cached commitment hash. Equal to
    /// [`crate::replication::commitment::commitment_hash`]
    /// `(self.commitment())`.
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        self.cached_hash
    }

    /// The Merkle tree behind this commitment.
    ///
    /// Used by the subtree-audit responder to plan a proof (select the
    /// nonce-determined branch and read its sibling cut-hashes).
    #[must_use]
    pub fn tree(&self) -> &MerkleTree {
        &self.tree
    }

    /// Inclusion path + leaf index for `key`, if it is in this
    /// commitment. Returns `None` if `key` is not committed.
    #[must_use]
    pub fn proof_for(&self, key: &XorName) -> Option<(Vec<[u8; 32]>, u32)> {
        let idx = self.sorted_keys.binary_search(key).ok()?;
        let path = self.tree.path_for(key)?;
        // u32 cast safe because MerkleTree::build rejects > MAX_COMMITMENT_KEY_COUNT.
        let leaf_index = u32::try_from(idx).unwrap_or(u32::MAX);
        Some((path, leaf_index))
    }
}

/// Number of recently-gossiped commitments a responder stays answerable for
/// (ADR-0002 "you stay answerable for what you publish").
///
/// The auditor only ever pins a commitment it received via gossip, so retaining
/// the last two **actually-gossiped** commitments (plus the current one)
/// guarantees an honest node can always answer a pin the auditor could have
/// formed. Two — not one — absorbs the race where the auditor pins the
/// commitment a node published just before its newest one. Retention is keyed on
/// gossip emission, NOT on the rotation timer: a node that rebuilds its tree
/// faster than it gossips never drops a commitment it actually put on the wire,
/// so it is never wrongly failed for "unknown commitment hash".
const RETAINED_GOSSIPED_COMMITMENTS: usize = 2;

/// Responder retention state (ADR-0002).
///
/// Keeps the current (latest-rotated) commitment plus every commitment whose
/// hash is among the last [`RETAINED_GOSSIPED_COMMITMENTS`] *gossiped* hashes.
/// A built-but-never-gossiped commitment is dropped on the next rotation unless
/// it gets gossiped. Rotation and gossip are the only paths that mutate this.
pub struct ResponderCommitmentState {
    inner: RwLock<Inner>,
}

struct Inner {
    /// Newest-first: `slots[0]` is the current commitment; the rest are
    /// retained because their hash is still in `recently_gossiped`.
    slots: Vec<Arc<BuiltCommitment>>,
    /// Hashes of the last `RETAINED_GOSSIPED_COMMITMENTS` commitments actually
    /// emitted on the wire, newest-first. A commitment is retained iff it is
    /// the current one or its hash appears here.
    recently_gossiped: Vec<[u8; 32]>,
}

impl Default for ResponderCommitmentState {
    fn default() -> Self {
        Self::new()
    }
}

impl ResponderCommitmentState {
    /// Empty state: no commitments yet. Audits before the first rotation
    /// see `None` lookups and the auditor falls back to the legacy plain
    /// digest path.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(Inner {
                slots: Vec::with_capacity(RETAINED_GOSSIPED_COMMITMENTS + 1),
                recently_gossiped: Vec::with_capacity(RETAINED_GOSSIPED_COMMITMENTS),
            }),
        }
    }

    /// Rotate: the freshly-rebuilt commitment becomes `current`. Slots that are
    /// neither the new current nor among the last gossiped hashes are dropped
    /// (a built-but-never-gossiped commitment does not linger).
    pub fn rotate(&self, new_current: BuiltCommitment) {
        let new_current = Arc::new(new_current);
        let mut guard = self.inner.write();
        guard.slots.insert(0, new_current);
        prune_slots(&mut guard);
    }

    /// Record that `hash` was emitted on the wire (gossiped). Keeps the last
    /// [`RETAINED_GOSSIPED_COMMITMENTS`] gossiped hashes so the matching
    /// commitments stay answerable (ADR-0002). Call at every gossip-emit site.
    pub fn mark_gossiped(&self, hash: [u8; 32]) {
        let mut guard = self.inner.write();
        // Move to front (newest), de-duplicating.
        guard.recently_gossiped.retain(|h| h != &hash);
        guard.recently_gossiped.insert(0, hash);
        guard
            .recently_gossiped
            .truncate(RETAINED_GOSSIPED_COMMITMENTS);
        prune_slots(&mut guard);
    }

    /// Look up a commitment by its hash. Returns `Some(arc)` if `hash`
    /// matches any retained slot. The returned `Arc` keeps the
    /// [`BuiltCommitment`] alive for as long as the caller holds it,
    /// even if a concurrent `rotate` ages it out of the retention buffer.
    #[must_use]
    pub fn lookup_by_hash(&self, hash: &[u8; 32]) -> Option<Arc<BuiltCommitment>> {
        let guard = self.inner.read();
        for c in &guard.slots {
            if &c.cached_hash == hash {
                return Some(Arc::clone(c));
            }
        }
        None
    }

    /// Snapshot the current commitment, if any. Used by the gossip
    /// piggyback path: emit `state.current()` on the next outbound
    /// `NeighborSyncRequest`/`Response`.
    #[must_use]
    pub fn current(&self) -> Option<Arc<BuiltCommitment>> {
        self.inner.read().slots.first().map(Arc::clone)
    }

    /// Number of commitment slots currently retained (the current commitment
    /// plus any still-answerable recently-gossiped ones). Used only for the
    /// v12 `commitment_rotated` event's `retained_slots` field; carries no
    /// behavioural meaning.
    #[must_use]
    pub fn retained_slot_count(&self) -> usize {
        self.inner.read().slots.len()
    }

    /// Drop every retained slot. Called when the local store has
    /// transitioned to empty: keeping the previously-advertised
    /// commitment alive would invite audit failures (we can no longer
    /// answer for any of the keys we committed to), and would leave
    /// remote auditors pinning a hash this node will never satisfy
    /// again. After clearing, the gossip piggyback path will emit
    /// `commitment: None` until a fresh rotation occurs.
    ///
    /// This is the one sanctioned escape from the "callers MUST NOT
    /// clear retention by any other mechanism" invariant — empty
    /// storage means there is nothing to retain.
    pub fn clear_all(&self) {
        let mut guard = self.inner.write();
        guard.slots.clear();
        guard.recently_gossiped.clear();
    }
}

/// Keep `slots[0]` (the current commitment) and any slot whose hash is among
/// the recently-gossiped hashes; drop the rest. Idempotent; preserves
/// newest-first order. This is the single place retention is enforced.
fn prune_slots(inner: &mut Inner) {
    let gossiped = &inner.recently_gossiped;
    let mut idx = 0usize;
    inner.slots.retain(|c| {
        let keep = idx == 0 || gossiped.contains(&c.cached_hash);
        idx += 1;
        keep
    });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::replication::commitment::{commitment_hash, leaf_hash, verify_path};
    use saorsa_pqc::api::sig::ml_dsa_65;

    fn key(byte: u8) -> XorName {
        let mut k = [0u8; 32];
        k[0] = byte;
        k
    }

    fn bh(byte: u8) -> [u8; 32] {
        [byte ^ 0x5A; 32]
    }

    fn keypair() -> (saorsa_pqc::api::sig::MlDsaPublicKey, MlDsaSecretKey) {
        ml_dsa_65().generate_keypair().unwrap()
    }

    #[test]
    fn built_commitment_hash_matches_global_hash() {
        let (pk, sk) = keypair();
        let pk_bytes = pk.to_bytes();
        let entries: Vec<_> = (1..=5u8).map(|i| (key(i), bh(i))).collect();
        let built = BuiltCommitment::build(entries, &[0xAB; 32], &sk, &pk_bytes).unwrap();
        let expected = commitment_hash(built.commitment()).unwrap();
        assert_eq!(built.hash(), expected);
    }

    #[test]
    fn built_commitment_proof_verifies_under_its_own_root() {
        let (pk, sk) = keypair();
        let pk_bytes = pk.to_bytes();
        let entries: Vec<_> = (1..=8u8).map(|i| (key(i), bh(i))).collect();
        let built = BuiltCommitment::build(entries.clone(), &[1; 32], &sk, &pk_bytes).unwrap();
        let root = built.commitment().root;
        let key_count = built.commitment().key_count;

        for (k, _) in &entries {
            let (path, leaf_index) = built.proof_for(k).expect("present");
            // Find the bytes_hash for this key.
            let bh_k = entries.iter().find(|(kk, _)| kk == k).unwrap().1;
            let lh = leaf_hash(k, &bh_k);
            assert!(
                verify_path(&lh, &path, leaf_index as usize, key_count, &root),
                "path verify failed for key {k:?}"
            );
        }
    }

    #[test]
    fn proof_for_absent_key_is_none() {
        let (pk, sk) = keypair();
        let pk_bytes = pk.to_bytes();
        let built = BuiltCommitment::build(
            vec![(key(1), bh(1)), (key(2), bh(2))],
            &[0; 32],
            &sk,
            &pk_bytes,
        )
        .unwrap();
        assert!(built.proof_for(&key(99)).is_none());
    }

    #[test]
    fn empty_state_returns_none() {
        let state = ResponderCommitmentState::new();
        assert!(state.current().is_none());
        assert!(state.lookup_by_hash(&[0; 32]).is_none());
    }

    #[test]
    fn clear_all_drops_every_slot() {
        // Empty-storage transition: after clear_all, the gossip path
        // must observe `current() == None` so it stops piggybacking a
        // commitment the node can no longer answer audits against.
        let (pk, sk) = keypair();
        let pk_bytes = pk.to_bytes();
        let state = ResponderCommitmentState::new();
        let peer_id = *blake3::hash(&pk.to_bytes()).as_bytes();

        let c1 = BuiltCommitment::build(vec![(key(1), bh(1))], &peer_id, &sk, &pk_bytes).unwrap();
        let h1 = c1.hash();
        state.rotate(c1);
        state.mark_gossiped(h1); // gossiped → retained across the next rotation
        let c2 = BuiltCommitment::build(vec![(key(2), bh(2))], &peer_id, &sk, &pk_bytes).unwrap();
        let h2 = c2.hash();
        state.rotate(c2);
        state.mark_gossiped(h2);

        assert!(state.current().is_some());
        assert!(state.lookup_by_hash(&h1).is_some());

        state.clear_all();

        assert!(state.current().is_none());
        assert!(state.lookup_by_hash(&h1).is_none());
    }

    #[test]
    fn lookup_arc_outlives_subsequent_rotation() {
        // INV-R2: an in-flight audit responder that grabbed an Arc must
        // be able to finish building the response even after the state
        // rotates that commitment out past the retention window.
        let (pk, sk) = keypair();
        let pk_bytes = pk.to_bytes();
        let state = ResponderCommitmentState::new();

        let c1 = BuiltCommitment::build(vec![(key(1), bh(1))], &[0; 32], &sk, &pk_bytes).unwrap();
        let h1 = c1.hash();
        state.rotate(c1);

        let in_flight = state.lookup_by_hash(&h1).unwrap();

        // c1 was never gossiped, so the next rotation (a new current) drops it
        // from the retention buffer.
        let c2 = BuiltCommitment::build(vec![(key(2), bh(2))], &[0; 32], &sk, &pk_bytes).unwrap();
        state.rotate(c2);
        assert!(state.lookup_by_hash(&h1).is_none());

        // But the in-flight Arc still works (INV: Arc keeps it alive).
        assert_eq!(in_flight.hash(), h1);
        assert!(in_flight.proof_for(&key(1)).is_some());
    }

    #[test]
    fn gossiped_commitment_stays_answerable_across_rotations() {
        // ADR-0002: a commitment that was actually gossiped stays answerable
        // even after rotation, until it falls out of the last-2-gossiped window.
        let (pk, sk) = keypair();
        let pk_bytes = pk.to_bytes();
        let state = ResponderCommitmentState::new();

        let c1 = BuiltCommitment::build(vec![(key(1), bh(1))], &[0; 32], &sk, &pk_bytes).unwrap();
        let h1 = c1.hash();
        state.rotate(c1);
        state.mark_gossiped(h1); // we put c1 on the wire

        // Rotate to c2 and gossip it. c1 is still within the last-2-gossiped.
        let c2 = BuiltCommitment::build(vec![(key(2), bh(2))], &[0; 32], &sk, &pk_bytes).unwrap();
        let h2 = c2.hash();
        state.rotate(c2);
        state.mark_gossiped(h2);
        assert!(
            state.lookup_by_hash(&h1).is_some(),
            "c1 must stay answerable"
        );
        assert!(state.lookup_by_hash(&h2).is_some());

        // Rotate to c3 and gossip it. Now the last-2-gossiped are {h3, h2};
        // h1 has fallen out of the window and is dropped.
        let c3 = BuiltCommitment::build(vec![(key(3), bh(3))], &[0; 32], &sk, &pk_bytes).unwrap();
        let h3 = c3.hash();
        state.rotate(c3);
        state.mark_gossiped(h3);
        assert!(
            state.lookup_by_hash(&h1).is_none(),
            "c1 aged out of gossip window"
        );
        assert!(state.lookup_by_hash(&h2).is_some());
        assert!(state.lookup_by_hash(&h3).is_some());
    }

    #[test]
    fn current_plus_last_two_gossiped_are_simultaneously_answerable() {
        // ADR-0002 "Two, not one": the retention depth must keep BOTH of the
        // last two gossiped commitments answerable at the same time, alongside
        // the current one. This is the property that "absorbs the race where an
        // auditor asks about the commitment a node published just before its
        // newest one". The existing across-rotations test only ever checks two
        // hashes at once; this one proves three DISTINCT commitments are live
        // simultaneously and that the third-oldest gossiped root is dropped —
        // i.e. RETAINED_GOSSIPED_COMMITMENTS is exactly 2, not 1 and not 3.
        let (pk, sk) = keypair();
        let pk_bytes = pk.to_bytes();
        let state = ResponderCommitmentState::new();

        // Gossip three commitments in order: c1, c2, c3. After this the current
        // slot is c3 and the last-two-gossiped are {h3, h2}. But c2 and c1 also
        // need to be checked relative to the window: once c3 is gossiped, the
        // window is {h3, h2}; c1 (the 3rd-oldest gossiped) must be gone.
        let c1 = BuiltCommitment::build(vec![(key(1), bh(1))], &[0; 32], &sk, &pk_bytes).unwrap();
        let h1 = c1.hash();
        state.rotate(c1);
        state.mark_gossiped(h1);

        let c2 = BuiltCommitment::build(vec![(key(2), bh(2))], &[0; 32], &sk, &pk_bytes).unwrap();
        let h2 = c2.hash();
        state.rotate(c2);
        state.mark_gossiped(h2);

        // At this moment: current = c2, last-2-gossiped = {h2, h1}. Both the
        // current AND the previously-gossiped c1 must be answerable — the "two,
        // not one" race window. c1 is the commitment "published just before the
        // newest one" and an auditor may still pin it.
        assert!(
            state.lookup_by_hash(&h1).is_some(),
            "the commitment published just before the newest one must stay answerable"
        );
        assert!(
            state.lookup_by_hash(&h2).is_some(),
            "current must be answerable"
        );
        assert_ne!(h1, h2, "the two retained commitments must be distinct");

        // Now gossip a third distinct commitment c3. Window becomes {h3, h2}.
        // c3 (current) + c2 + c1: c1 must now be dropped (3rd-oldest gossiped),
        // while c2 and c3 remain. This proves depth is exactly 2 beyond... no:
        // depth is 2 gossiped TOTAL including current's hash once gossiped.
        let c3 = BuiltCommitment::build(vec![(key(3), bh(3))], &[0; 32], &sk, &pk_bytes).unwrap();
        let h3 = c3.hash();
        state.rotate(c3);
        state.mark_gossiped(h3);

        assert_ne!(h2, h3);
        assert_ne!(h1, h3);
        assert!(
            state.lookup_by_hash(&h3).is_some(),
            "current (c3) answerable"
        );
        assert!(
            state.lookup_by_hash(&h2).is_some(),
            "c2 (published just before newest) answerable — the race-absorbing slot"
        );
        assert!(
            state.lookup_by_hash(&h1).is_none(),
            "c1 is the 3rd-oldest gossiped root and MUST be dropped — depth is exactly 2"
        );
    }

    #[test]
    fn ungossiped_rebuild_does_not_evict_gossiped_commitment() {
        // The rebuild-faster-than-gossip case: a node rebuilds (rotates) several
        // times without gossiping. The last *gossiped* commitment must remain
        // answerable so the node is not wrongly failed for "unknown hash".
        let (pk, sk) = keypair();
        let pk_bytes = pk.to_bytes();
        let state = ResponderCommitmentState::new();

        let c1 = BuiltCommitment::build(vec![(key(1), bh(1))], &[0; 32], &sk, &pk_bytes).unwrap();
        let h1 = c1.hash();
        state.rotate(c1);
        state.mark_gossiped(h1);

        // Several ungossiped rebuilds.
        for i in 2..=6u8 {
            let c =
                BuiltCommitment::build(vec![(key(i), bh(i))], &[0; 32], &sk, &pk_bytes).unwrap();
            state.rotate(c);
        }
        // h1 was gossiped and is still within the last-2-gossiped window
        // (nothing else was gossiped), so it must still be answerable.
        assert!(
            state.lookup_by_hash(&h1).is_some(),
            "gossiped commitment must survive ungossiped rebuilds"
        );
    }
}
