# ADR-0002 implementation plan (gossip-triggered contiguous-subtree audit)

Working notes, not an ADR. Tracks how we turn ADR-0002 into code. Grounded in a
read of the current `src/replication/` tree. Approach chosen: **new audit module,
reuse the existing Merkle/commitment/gossip/trust primitives, delete the old
per-key audit path.**

## A. What we REUSE unchanged (do not rebuild)

- `commitment.rs`: `StorageCommitment`, `MerkleTree::build`, `leaf_hash`
  (`BLAKE3(DOMAIN_LEAF‖key‖bytes_hash)`), `node_hash`, `root`, `commitment_hash`,
  `sign_commitment` / `verify_commitment_signature`. The self-pairing odd-node
  rule and sorted leaves are the tree shape the subtree walk relies on.
- The freshness digest `compute_audit_digest(nonce, peer_id, key, bytes) =
  BLAKE3(nonce‖peer_id‖key‖bytes)` (protocol.rs) = the ADR's "freshness hash".
  Reuse verbatim for the per-leaf nonced hash.
- Gossip ingest gate sequence in `ingest_peer_commitment` (None / RT-membership /
  peer-id binding / pubkey binding / sig-verify rate-limit / signature). The audit
  trigger hooks in *after* these gates pass.
- Trust/eviction plumbing: `report_trust_event(ApplicationFailure/Success)`,
  `AUDIT_FAILURE_TRUST_WEIGHT`, holder-credit revocation
  (`apply_audit_failure_credit_revocation` / `recent_provers.forget_peer`), the
  `TIMEOUT-EVICTION-DISABLED` rollout switch, responsibility re-confirmation by
  fresh DHT lookup.
- `recent_provers.rs` and its TTL sweep (rides the rotation loop, NOT the audit
  tick — so removing the tick is safe).
- The testnet harness + adversary modes (relay / lazy / chunk-deleter) for
  validation.

## B. What we DELETE / replace (the old per-key audit)

- `AuditChallenge.keys: Vec<XorName>` key list and the auditor-samples-its-own-store
  model (`audit.rs` key sampling + close-group + mature-repair-proof filters).
- The `AuditResponse::Digests` legacy variant and the `CommitmentBound { per_key }`
  per-key-proof response.
- The periodic audit tick loop and the post-bootstrap one-shot tick in
  `start_audit_loop` (mod.rs). Replaced by gossip-trigger.
- The "capable-but-no-current-commitment" Idle shield (audit.rs §3) — unreachable
  once audits are triggered by a fresh commitment.
- The two benign Idle lanes: `unknown commitment hash` and `key not in commitment`.
  The first becomes a confirmed failure (justified by retention); the second
  becomes structurally impossible (auditor challenges the peer's own tree).
- `RepairProof` bookkeeping and the `repair_proofs` field IF nothing else uses it
  (verify during impl — the prune-audit path may still reference it; if so, keep).

## C. New code, by module

### C1. `commitment.rs` — subtree selection + pruned-proof primitives (pure, unit-testable first)

- `fn real_leaves_under(node_depth, node_index, key_count) -> u32` — count of
  non-padding leaves beneath a tree node, from `key_count` + node position alone.
  Pure; both auditor and responder use it. Foundation of the √-floor walk.
- `fn select_subtree_path(nonce: &[u8;32], key_count: u32) -> SubtreePath` — walk
  nonce bits from root, stop at the smallest branch whose `real_leaves_under` ≥
  `ceil(sqrt(key_count))`. Returns `{ depth, path_bits, leaf_range }`.
  - Edge: key_count ≤ small floor (e.g. 4) → whole tree. key_count == 1 → the leaf.
  - DETERMINISTIC + identical on both sides (ADR: nonce-determined branch).
  - Regression target: never returns an all-padding branch (the dead-block bug).
- `fn select_spotcheck_indices(nonce, subtree_leaf_count, k) -> Vec<usize>` —
  k nonce-random positions WITHIN the subtree (ADR: spot-checks within subtree).
- `fn build_subtree_proof(tree, path, nonce, peer_id, bytes_provider) -> SubtreeProof`
  (responder) — expand the selected branch to its leaves (each: key, `bytes_hash`,
  `nonced_hash = compute_audit_digest`), collect one sibling cut-hash per level on
  the path to root. Reuses `leaf_hash`/`node_hash`.
- `fn verify_subtree_proof(proof, nonce, pinned_commitment) -> SubtreeVerdict`
  (auditor) — three checks:
  1. *structure*: re-derive `select_subtree_path` from (nonce, key_count); confirm
     returned branch matches it; rebuild root from leaves + cut-hashes; MUST equal
     `pinned_commitment.root`. Leaf uniqueness + ascending-key order.
  2. *real bytes*: for `select_spotcheck_indices`, recompute `BLAKE3(bytes)` and
     `compute_audit_digest` from bytes the AUDITOR holds (prefer local; optional
     fetch; a slow/failed fetch is never the audited node's failure). Both match.
  3. (timing handled by the caller's response deadline.)

### C2. `protocol.rs` — wire types

- Replace `AuditChallenge` with: `{ challenge_id, nonce, challenged_peer_id,
  expected_commitment_hash: [u8;32] }` (REQUIRED pin; no key list).
- Add `AuditResponse::SubtreeProof { challenge_id, commitment: StorageCommitment,
  selected_leaves: Vec<SubtreeLeaf>, sibling_cut_hashes: Vec<[u8;32]> }`.
  `SubtreeLeaf { key, bytes_hash, nonced_hash }`.
- Keep `Bootstrapping` + `Rejected{reason}`. Drop `Digests` and `CommitmentBound`.
- Protocol id stays `autonomi.ant.replication.v2` (unreleased) — no bump.

### C3. `commitment_state.rs` — retention "last 2 gossiped"

- Today: 4 slots rotated on a 1h timer. Change to: retain the commitments that
  were actually EMITTED on the wire — keep the last 2 distinct gossiped
  commitments + their chunk data, marked at emit time.
- Add `mark_gossiped(commitment_hash)` called from the gossip-emit sites (C4).
- `lookup_by_hash` stays (auditor pins a hash; responder answers if within last-2).
- Verify chunk-data availability: the responder must still hold bytes for the
  selected subtree of a gossiped commitment → retention must pin chunks, not just
  the tree. Confirm interaction with pruning.

### C4. `mod.rs` — gossip trigger + scheduler removal + retention marking

- In `ingest_peer_commitment`, AFTER all gates pass and the record is updated:
  detect *changed* commitment (compare new `commitment_hash` vs cached record's).
  If changed AND not in per-peer cooldown AND `rng < AUDIT_ON_GOSSIP_PROBABILITY`
  → spawn a detached, semaphore-permitted audit of `source` pinned to the just
  ingested root. (Reuses the existing per-peer rate-limit philosophy.)
- Per-peer audit cooldown map: `Arc<RwLock<HashMap<PeerId, Instant>>>`, cleaned in
  PeerRemoved (mirror the existing `audit_timeout_strikes` cleanup).
- Delete the periodic tick + post-bootstrap one-shot in `start_audit_loop`. Keep
  the rotation loop (it drives the recent_provers sweep and commitment rebuild).
- Mark-on-gossip: call `mark_gossiped` at the three emit sites (neighbor-sync
  request snapshot, neighbor-sync response, bootstrap sync).

### C5. `audit.rs` — new auditor + responder entry points

- Responder: `handle_audit_challenge(challenge) -> AuditResponse` — look up pinned
  commitment in last-2-gossiped; if absent → `Rejected{unknown}` (now a real
  failure on the auditor side, justified by retention); else build subtree proof.
- Auditor: `run_gossip_audit(peer, pinned_commitment) -> AuditTickResult` — send
  challenge, await within `audit_response_timeout(subtree_leaf_count)`, call
  `verify_subtree_proof`, map to disposition (C6).
- Delete `audit_tick_with_repair_proofs`, key sampling, eligibility/repair gates,
  the §3 shield.

### C6. Accounting + grace (mod.rs `handle_audit_result` / `handle_failed_audit`)

- Outcomes → dispositions:
  - valid proof + bytes verify → `Passed` (report success, reset timeout strikes).
  - structure/root/byte/nonce mismatch, OR `Rejected{unknown}` on a pinned recent
    root → **confirmed failure, acted on 1st occurrence** (existing ConfirmedPenalize
    path: report ApplicationFailure + revoke holder credit, gated by rollout switch).
  - timeout → strike; penalty only at threshold; gated by rollout switch.
- `key not in commitment` disposition is removed (cannot occur).

### C7. Adaptive timeout grace (ADR "Network Resilience") — timeouts only

- New: track a bounded recent-timeout signal across audited peers. The tolerated
  consecutive-timeout count = `median(recent peer timeout counts) + AUDIT_TIMEOUT_STRIKE_THRESHOLD`.
- Drive it ONLY from timeout/liveness misses, NEVER from deterministic failures
  (so an attacker can't fail-on-purpose to inflate grace).
- Smallest viable structure: a bounded ring of recent per-peer timeout counts;
  compute median on demand. Keep it simple; document the un-inflatable invariant.

### C8. `config.rs` — constants

- Add `AUDIT_ON_GOSSIP_PROBABILITY = 0.2`, `AUDIT_ON_GOSSIP_COOLDOWN_SECS = 1800`
  (30 min), `AUDIT_SPOTCHECK_COUNT = 8`, retention count = 2.
- Reuse `AUDIT_TIMEOUT_STRIKE_THRESHOLD = 3` as the grace constant (timeouts only).
- `audit_response_timeout` already scales with challenged count → feed it the
  subtree leaf count.
- Remove the now-dead `AUDIT_TICK_INTERVAL_*` (or repurpose). Keep
  `COMMITMENT_ROTATION_INTERVAL_SECS` (rotation loop stays).

### C9. Closeness (lenient, density-aware) — `audit.rs` verify

- On selected leaves only: flag a key as suspicious padding only if XOR-distance to
  the peer is implausibly far *relative to observed local/peer data density*.
  Bias hard to false-negative; never penalise on a small/dense network. Implement
  as a soft signal first (log/metric), enforce only once density calibration is
  validated on the testnet.

## D. Test plan (maps to ADR Validation; write alongside each module)

- C1 pure unit tests FIRST (no network): selection determinism (auditor==responder);
  √-floor never selects all-padding across many padded key_counts (dead-block
  regression); root rebuild from pruned proof; spot-check catches a fabricated-nonced
  responder at `(1−x)^k`; subtree size ≈ √N in balanced trees, larger under padding.
- Integration: possession verifies local + fetched; `unknown-hash`-now-fails;
  retention-keeps-last-2-gossiped (answerable) and a 3rd-old root rejected; timeout
  sizing; detect-on-1st-fail (deterministic) vs strike (timeout); adaptive grace
  responds to broad timeouts but NOT to deterministic failures; gossip flood does
  not multiply audits (cooldown + probability + semaphore hold).
- Simulation: uniform vs clustered shedder detection rates at locked constants.
- `cfd` (fmt + clippy, no `#[allow]`s, no panics/unwrap/expect) green before done.

## E. Sequencing (smallest-risk first; each step compiles + tests green)

1. C1 selection + proof primitives + their pure unit tests. (No wire, no network.)
2. C2 wire types (swap challenge/response). Compile the crate; fix call sites.
3. C5 responder + auditor entry points using C1/C2.
4. C3 retention (last-2-gossiped) + C4 mark-on-gossip emit sites.
5. C4 gossip trigger in ingest + delete periodic tick. C8 constants.
6. C6 accounting wiring + C7 adaptive grace.
7. C9 closeness (soft first).
8. Full `cfd` + integration tests + simulation. Adversarial re-review. Testnet.

## F. Open items to confirm before/while coding

- Spot-check fetch fallback: auditor fetches a few subtree leaves it lacks, OR
  strictly local-only (skip byte-check if it holds none that round)? (ADR currently
  allows optional fetch; pending your call.)
- Retention vs pruning interaction: confirm chunk bytes for the last-2-gossiped
  commitments are protected from the pruner.
- `RepairProof` removal: confirm the prune-audit path doesn't still need it before
  deleting.
