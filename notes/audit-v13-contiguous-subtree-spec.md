# v13 audit redesign — gossip-triggered contiguous-subtree storage proof

Status: DRAFT SPEC for review (no code yet). Branch: `grumbach/audit-on-gossip`,
based on PR #113 head. This is a follow-up to #113, NOT folded into it — it is a
second breaking change to the audit challenge/response format and ships as its
own protocol revision once #113 is merged and the network has upgraded.

Goal: make a node prove it actually holds the data it committed to, with a
*light* (small-proof) audit that is **triggered by gossip** and run as
**probabilistic random exams**, with **no silent no-penalty escape lane**.

---

## 1. Why change the v12 (#113) audit

v12 works (testnet-confirmed: relay + data-shedders caught), but has three
shapes we want to change:

1. **Audit is decoupled from gossip.** It fires on a random 10–20 min tick and
   pins whatever commitment it last cached, which routinely lags the peer's
   real commitment. That lag is the *only* reason `unknown commitment hash` must
   be treated as benign (no penalty) — a silent escape lane an upgraded
   malicious node can ride once eviction is re-enabled.
2. **Per-key scattered sampling** sends `sqrt(N)` independent inclusion proofs
   (`sqrt(N)·log N` hashes).
3. The auditor samples keys from *its own* store, which is why
   `key not in commitment` exists and is benign.

This spec replaces the audit *scheduling* and the *proof shape*, while reusing
v12's cryptographic primitives (BLAKE3 Merkle tree, ML-DSA-signed commitment,
`H(nonce‖peer‖key‖bytes)` possession digest, the 5 gossip-ingest gates).

---

## 2. Model overview (what the network does)

- **Gossip (UNCHANGED from v12):** a node periodically gossips its signed
  `StorageCommitment` = { plain-tree root, key_count, sender_peer_id, pubkey,
  signature }. Light: one root, no key list.
- **Trigger:** receiving a peer's *changed* commitment gossip is what may launch
  an audit of that peer. Not every gossip → audit: fire with probability `p`
  and a per-peer cooldown ("random exams", keeps load low, surprise to the
  audited). The audit pins the **just-received** root.
- **Challenge:** auditor sends a fresh random nonce `N` (+ the pinned root). `N`
  deterministically selects ONE contiguous subtree of the committed tree.
- **Response (subtree proof):** the audited node returns that one subtree
  expanded to its ≈`sqrt(key_count)` leaves (each with its plain leaf hash and a
  nonce-fresh hash), plus the `log` sibling cut-hashes on the path to the root.
  Everything outside the selected subtree is a single cut-hash per sibling — no
  data touched there.
- **Verify:** reconstruct the plain root from the proof and check it equals the
  pinned (gossiped) root; for the selected leaves, confirm possession by
  rehashing the bytes (locally held, else fetched) with and without `N`; check
  leaf uniqueness; require the response within a time bound.
- **Accounting:** every failure (bad proof, wrong root, missing/forged bytes,
  timeout past the strike threshold, or repudiating a recently-gossiped root)
  is recorded. No `Idle` no-penalty lane for a node repudiating what it just
  gossiped. (Trust *reporting* remains gated by the #113
  `TIMEOUT-EVICTION-DISABLED` rollout switch; accounting runs regardless.)

---

## 3. Contiguous-subtree selection (deterministic from N + key_count)

Both sides know `key_count` (in the commitment) and therefore the tree depth
`D = ceil(log2(key_count))` (v12 tree self-pairs odd nodes, so depth is fixed by
key_count).

Target subtree leaf count ≈ `sqrt(key_count)`, i.e. select down to depth
`d_sel = max(0, D - ceil(log2(sqrt(key_count)))) = ceil(D/2)` levels from the
root (so the subtree spans `2^(D - d_sel) ≈ sqrt(key_count)` leaves).

Walk from the root consuming `N`'s bits: bit = 1 → take the left child, bit = 0
→ take the right child, for `d_sel` steps. The node reached is the **selected
subtree root**; its descendant leaves are the **selected leaves**.

Notes / edge cases:
- `key_count == 1`: D = 0, subtree = the single leaf. Trivial proof.
- Small trees (`key_count` ≤ a floor, say 4): just challenge all leaves (subtree
  = whole tree); `sqrt` rounding is meaningless there.
- The selection MUST be reproducible by the auditor to reconstruct the root, and
  by the responder to know which leaves to expand. Both derive `d_sel` and the
  bit-walk identically from `(N, key_count)`. Spec a single shared helper
  `select_subtree_path(nonce, key_count) -> (depth, path_bits)` used by both.
- `N` is 32 bytes = 256 bits ≫ any realistic `D`, so we never run out of bits.

---

## 4. Wire format (the breaking change)

### Challenge (extends v12 `AuditChallenge`)
v12 sends an explicit `keys: Vec<XorName>` + `expected_commitment_hash`. v13
replaces the key list with subtree selection:
```
AuditChallengeV13 {
    challenge_id: u64,
    nonce: [u8; 32],              // selects subtree AND freshens leaf hashes
    challenged_peer_id: [u8; 32],
    expected_commitment_hash: [u8; 32],   // the pinned (gossiped) root's commitment hash; REQUIRED in v13
}
```
No key list — the subtree is derived from `nonce + key_count`. (`key_count` is
known to the auditor from the gossiped commitment it pinned.)

### Response (new `SubtreeProof` variant)
```
AuditResponseV13::SubtreeProof {
    challenge_id: u64,
    commitment: StorageCommitment,        // the pinned commitment, so the auditor re-derives key_count + verifies the sig/root binding (v12 gates 2a/2b/2c/3 reused)
    selected_leaves: Vec<SubtreeLeaf>,     // the ~sqrt(N) leaves of the selected subtree, in tree order
    sibling_cut_hashes: Vec<[u8;32]>,      // one per level on the path root->subtree, the UNSELECTED sibling subtree roots (plain)
}

SubtreeLeaf {
    key: XorName,
    bytes_hash: [u8;32],     // H(bytes) — the plain leaf value (v12 leaf = BLAKE3(DOMAIN_LEAF || key || bytes_hash))
    nonced_hash: [u8;32],    // H(N || bytes) — fresh possession proof for THIS audit
}
```
Rejection variants retained for genuine cases (see §6): `Bootstrapping`,
`Rejected{reason}`.

Size: `selected_leaves` ≈ `sqrt(N)` × ~96 B + `sibling_cut_hashes` ≈ `D/2` × 32 B.
For N=10k: ~100 leaves ≈ 9.6 KB + ~7 cut hashes. Small.

---

## 5. Verification (auditor side)

1. **Pin + signature gates (reuse v12):** `commitment.sender_peer_id ==
   challenged_peer`; `BLAKE3(pubkey)==peer_id`; ML-DSA sig valid;
   `commitment_hash(commitment) == expected_commitment_hash` (the pinned root).
   Any mismatch → fail (this is a confirmed misbehaviour, not staleness, because
   the pin is the root the peer *just gossiped* — see retention §7).
2. **Derive** `(d_sel, path_bits) = select_subtree_path(nonce, commitment.key_count)`.
3. **Structural:** `selected_leaves.len() == expected subtree leaf count` for
   that path; `sibling_cut_hashes.len() == d_sel`; leaves are unique and in
   ascending key order (v12 sorts leaves by key for deterministic roots).
4. **Reconstruct root:** build the selected subtree root from
   `leaf_hash(key_i, bytes_hash_i)` over `selected_leaves` (v12 leaf hashing +
   node hashing, self-pair on odd). Then fold up through `sibling_cut_hashes`
   using `path_bits` (selected child on the side dictated by the bit, sibling =
   cut hash) to a candidate root. **Candidate root MUST equal
   `commitment.root`.** This proves: the selected subtree genuinely belongs to
   the committed tree, AND the cut hashes are consistent with the committed root
   (the responder can't fake the unselected regions without breaking the root).
5. **Possession of selected leaves:** for each selected leaf:
   - Obtain the chunk bytes: from local store if held (the common case among
     close-group peers), else fetch from the network (anywhere — see §8 relay
     note).
   - Confirm `BLAKE3(bytes) == bytes_hash` (leaf consistency) AND
     `H(N ‖ bytes) == nonced_hash`. Both must hold. The nonced check is the
     fresh-possession proof: the responder could only produce `nonced_hash`
     correctly by having the bytes at challenge time.
6. **Timing:** the whole response must arrive within `audit_response_timeout`
   sized for hashing `sqrt(N)` chunks at local-disk speed × slack (reuse v12's
   formula, scaled to the subtree leaf count). A relay/lazy node missing
   selected leaves must fetch them over the network → blows the deadline.

All-pass → `Passed`. Any structural/root/possession failure → confirmed audit
failure (`Rejected`-class), accounted + credit-revoked. Timeout → strike
(accounted; penalty gated by the rollout switch).

---

## 6. Disposition of every outcome (no Idle escape)

| Outcome | v12 today | v13 |
|---|---|---|
| Valid subtree proof, bytes verify | Passed | **Passed** |
| Root reconstruction ≠ pinned root | (n/a) | **Confirmed failure** (forged/inconsistent tree) |
| `bytes_hash`/`nonced_hash` mismatch on a selected leaf | DigestMismatch failure | **Confirmed failure** (byte loss / fake) |
| `unknown commitment hash` (peer can't answer the root it *just gossiped*) | benign `Idle`, no penalty | **Confirmed failure** — retention (§7) guarantees an honest node retains the last-2 gossiped trees, so repudiating one is misbehaviour, not lag |
| `key not in commitment` | benign `Idle` | **DOES NOT EXIST** — auditor no longer names keys; it challenges a subtree of the peer's *own* committed tree, so every challenged leaf is by construction in the commitment |
| Timeout | strike → (penalty disabled in #113) | same: strike, accounted, penalty gated by rollout switch |
| Peer not responsible for the key set anymore (topology churn) | `Idle` | n/a — challenge is over the peer's own committed tree; responsibility/closeness is checked separately (§9), not a per-key skip |
| §3 capable-but-no-current-commitment | `Idle` | **unreachable on the gossip-triggered path** (audit is triggered BY a fresh commitment, so one always exists); only relevant to an optional backstop tick |

The two v12 benign-`Idle` escapes are eliminated: one becomes impossible
(`key not in commitment`), the other becomes a confirmed failure
(`unknown hash`, justified by retention).

---

## 7. Retention: "commit to what you gossip, challengeable until next-next gossip"

Responder keeps, with chunk data, the trees for the **last 2 GOSSIPED
commitments** (not last-2-rotations): the current gossiped one and the previous
gossiped one. Rationale for 2 (not 1): absorbs the race where an auditor pins
gossip Gₙ while the node has already gossiped Gₙ₊₁ — the auditor's in-flight
challenge for Gₙ is still answerable. A challenge pinned to anything older than
the last 2 gossiped roots may legitimately `Rejected{unknown}`; the auditor only
ever pins the freshly-received root (it audits on gossip), so in practice it
always pins Gₙ or Gₙ₊₁.

Implementation: change `ResponderCommitmentState` retention from N-slots-by-
rotation to "retain the last 2 commitments that were emitted on the wire +
their referenced chunks." Mark-on-gossip. Memory bound: 2 trees + their chunks;
chunks are retained (not pruned) until they fall out of the last-2-gossiped
window. This is the storage cost the user accepted.

Because of this, an honest node challenged on a root it gossiped within the last
2 gossip cycles can ALWAYS answer → `unknown commitment hash` for such a root is
provably misbehaviour → safe to treat as a confirmed failure (closes the v12
escape).

---

## 8. Threat model + accepted tradeoffs

- **Relay (stores nothing, fetches on demand):** must fetch+hash `sqrt(N)` chunks
  for the selected subtree under the response deadline. Fetch-from-anywhere is
  fine — the defense is *time*: a relay can't fetch+hash its subtree as fast as
  a storer reads local disk. Caught by timeout. (Same mechanism as v12, now over
  a contiguous subtree.)
- **Data-shedder (deletes a fraction `f`):** caught only if a deleted chunk
  falls in the nonce-selected subtree (a `~1/sqrt(N)` region). ACCEPTED
  TRADEOFF: per-audit coverage is concentrated, not whole-keyspace. Convergence
  comes from *frequent random-nonce audits* selecting different subtrees over
  time. Quantify in the spec review: with audit probability `p` per gossip and
  gossip interval `g`, expected audits/hour and expected time-to-detection for a
  given `f` must be computed and deemed acceptable. (If too slow, raise `p`,
  shrink cooldown, or select >1 subtree per audit.)
- **Tree-padding / size inflation:** v13 does NOT fully verify the whole key set
  (only the selected subtree + cut hashes), so a node could still pad unselected
  regions with junk leaves to inflate `key_count`. PARTIALLY mitigated: §9
  closeness check on *selected* leaves only. Full size/closeness/uniqueness
  auditing over the whole key set is explicitly OUT OF SCOPE here (it needs the
  whole leaf set; that's the quote-quantity-audit follow-up). State this limit.
- **Nonce grinding:** the responder cannot grind `N` (auditor picks it). The
  auditor picking `N` adaptively gains nothing (it wants to catch cheating, not
  cause false failures).
- **Replay:** `nonced_hash = H(N‖bytes)` with fresh `N` per challenge prevents
  replay of a prior response.

---

## 9. Closeness / responsibility

For each selected leaf's `key`, optionally check XOR-closeness to
`challenged_peer_id` (a node should only commit to keys near its address). A
selected leaf whose key is implausibly far from the peer is evidence of padding
→ failure. Cheap (only on selected leaves). Decide in review whether to include
in v1 of v13 or defer with the full key-set audit.

---

## 10. Scheduling, probability, cooldown, load

- Trigger in `ingest_peer_commitment` on a *changed* commitment: with prob
  `AUDIT_ON_GOSSIP_PROBABILITY` (start 0.1) and per-peer cooldown
  `AUDIT_ON_GOSSIP_COOLDOWN` (start 5 min), spawn a detached audit (permit-gated
  by the existing send semaphore) of the gossiper, pinned to the just-ingested
  root.
- Backstop tick: OPEN DECISION (user leaning pure-gossip-triggered). If pure,
  delete the periodic random tick + the §3 shield branch; a silent peer is
  handled by holder-credit TTL (it stops being credited). If kept, run it slow
  (hours) for GC + re-challenging long-silent peers.
- Flood safety: cooldown + semaphore bound audits-per-peer and global
  concurrency; v12's 60s-per-peer sig-verify rate-limit throttles how often a
  peer's gossip is even processed.

---

## 11. Implementation surface (for the later impl plan)

- `protocol.rs`: new `AuditChallenge` (drop key list, require pin) +
  `AuditResponse::SubtreeProof`. Bump audit protocol/version marker.
- `commitment.rs`: `select_subtree_path(nonce, key_count)`; subtree-root
  reconstruction from selected leaves + sibling cut-hashes; the `nonced_hash`
  leaf helper.
- `commitment_state.rs`: last-2-gossiped retention + chunk retention; `mark_gossiped`.
- `audit.rs`: responder builds the pruned subtree proof (expand selected subtree,
  collect sibling cut-hashes, compute plain+nonced leaf hashes from local bytes);
  auditor verifier (§5); failure dispositions (§6).
- `mod.rs`: gossip-trigger plumbing (ingest → probabilistic spawn), retention
  marking at the gossip-emit sites, remove/repurpose the random tick.
- `config.rs`: `AUDIT_ON_GOSSIP_PROBABILITY`, `AUDIT_ON_GOSSIP_COOLDOWN`,
  subtree target-size policy, retention count (=2).
- Tests: selection determinism; root reconstruction from pruned proof;
  possession (local + fetched); unknown-hash-now-fails; retention-keeps-last-2;
  timeout sizing; flood doesn't amplify; coverage-convergence simulation for a
  given `f`.

---

## 12. OPEN QUESTIONS for review

1. **Coverage math:** compute expected detection time for `f = 1%/5%/10%` given
   `p` and gossip cadence; confirm acceptable or tune `p`/cooldown/#subtrees.
2. **Backstop tick:** keep slow or pure-gossip-only?
3. **Closeness check (§9):** in v13.0 or deferred?
4. **>1 subtree per audit?** Selecting k independent subtrees (k small) trades a
   little proof size for much better per-audit coverage — cheap insurance
   against the concentrated-coverage weakness. Worth considering.
5. **Interaction with #113 rollout:** v13 is a 3rd protocol id (`.v3`)? Or does
   it supersede `.v2` before `.v2` ever ships? Sequencing decision.
