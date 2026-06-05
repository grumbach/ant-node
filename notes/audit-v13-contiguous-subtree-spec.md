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
  deterministically selects ONE contiguous subtree of the committed tree — the
  smallest contiguous branch that still holds ≥ `sqrt(real key_count)` real
  (non-padding) leaves (§3 floor rule, so padding can't dodge the selection).
- **Response (subtree proof):** the audited node returns that one subtree
  expanded to its ≈`sqrt(key_count)` leaves (each with its plain leaf hash and a
  nonce-fresh hash), plus the `log` sibling cut-hashes on the path to the root.
  Everything outside the selected subtree is a single cut-hash per sibling — no
  data touched there.
- **Verify (three layers):** (a) *structure* — reconstruct the plain root from the
  proof and check it equals the pinned (gossiped) root; check leaf uniqueness/order;
  (b) *real bytes* — spot-check `k`≈8 nonce-random leaves WITHIN the subtree by
  re-deriving their bytes (locally held, else fetched) and confirming both `H(bytes)`
  and `H(N‖bytes)` match (defeats a node that rebuilt the plain tree from addresses
  and faked the nonced tree); (c) *possession-in-time* — require the response within
  a time bound a relay can't meet by fetching.
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

**Stop condition = "branch must hold ≥ √(real_chunk_count) real leaves" (NOT a
fixed depth).** A fixed `d_sel = ceil(D/2)` is buggy under padding: when the tree
is mostly padding (key_count just above a power of two, or D odd), a fixed-depth
subtree can land on a block that is entirely (or mostly) padding leaves, so the
nonce selects ~0 real leaves and the audit trivially passes — catching nothing.
Up to ~38% of fixed-depth blocks can be dead in the worst padding case.

Fix (per design decision): walk the nonce bits down from the root only **until
the current subtree node covers ≥ √(key_count) REAL (non-padding) leaves, then
stop.** Real leaves fill slots `0..key_count-1` in sorted key order; everything
to the right is padding. So the count of real leaves under any node at
`(depth, index)` is a pure function of `key_count` and the node's slot span —
computable by BOTH sides (the auditor has `key_count`; the responder has the
tree). Walk:

```
node = root
loop:
    if real_leaves_under(node, key_count) < ceil(sqrt(key_count)) * 2:  # going deeper would drop below √N
        stop  # 'node' is the selected subtree root
    bit = next nonce bit; node = bit==1 ? node.left : node.right
    if real_leaves_under(node, key_count) < ceil(sqrt(key_count)):
        node = node.parent; stop  # don't descend past the √N floor
```

Consequence: in a balanced/full tree the walk stops near depth `D/2` (subtree ≈
√N), identical to before. In a **high-padding** tree it stops EARLY (shallower),
so the selected branch is larger — possibly half or a quarter of the tree, or in
the extreme the whole tree — whatever the smallest contiguous branch is that
still contains ≥ √(real key_count) real leaves. The proof is bigger in that case,
but the selected branch is GUARANTEED to hold ≥ √N real chunks, which kills the
dead-block problem at its source (no nonce can select an all-padding region).

Notes / edge cases:
- `key_count == 1`: D = 0, subtree = the single leaf. Trivial proof.
- Small trees (`key_count` ≤ a floor, say 4): just challenge all leaves (subtree
  = whole tree); `sqrt` rounding is meaningless there.
- The selection MUST be reproducible by the auditor to reconstruct the root, and
  by the responder to know which leaves to expand. Both derive the stop depth and
  the bit-walk identically from `(N, key_count)` via the real-leaf-count rule.
  Spec a single shared helper
  `select_subtree_path(nonce, key_count) -> (depth, path_bits)` used by both,
  where the walk terminates on the √(real key_count) floor above (NOT a fixed
  `ceil(D/2)`).
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
5. **Structure-vs-bytes are two distinct proofs — verify both.** The subtree
   proof in step 4 proves the responder knows the *tree structure* (Merkle
   inclusion of the selected leaves under the committed root). It does NOT, by
   itself, prove the leaves are backed by real bytes: a cheater can rebuild the
   PLAIN tree from chunk addresses alone (in v12 a leaf's `bytes_hash` IS the
   chunk address `H(bytes)`, which is public), and then fabricate the
   `nonced_hash` values without ever holding the bytes. The nonced spot-check
   below is what binds the tree to real data.

   **5a — possession spot-checks (the "is the tree backed by real bytes" proof).**
   Pick `AUDIT_SPOTCHECK_COUNT` (5–10) leaves at nonce-derived random positions
   **within the selected subtree** (not across the whole tree — keeps the proof
   to the leaves already present, no extra inclusion paths). For each spot-check
   leaf, the auditor obtains the chunk bytes:
   - from local store if held (the common case among close-group peers), else
     fetch from the network (anywhere — see §8 relay note),
   then confirms `BLAKE3(bytes) == bytes_hash` (leaf consistency, ties the leaf to
   its claimed address) AND `H(N ‖ bytes) == nonced_hash` (fresh possession). Both
   must hold. Because the auditor chooses the spot-check positions from `N` and
   the responder cannot predict them, matching on `k` random leaves is a
   probabilistic proof the WHOLE selected subtree is byte-backed: a responder that
   fabricated a fraction `x` of nonced leaves survives only with probability
   `(1−x)^k` (k=10, x=20% → 11%; x=50% → 0.1%). This realness guarantee accrues
   over the rest of the tree across successive audits as the nonce moves the
   selected subtree.
   - The non-spot-checked selected leaves still carry their `nonced_hash` in the
     proof (used for the structural root reconstruction in step 4); the auditor
     simply doesn't fetch+verify their bytes this round. Spot-checks are the
     subset whose bytes it actually re-derives.
6. **Timing (the relay/possession-in-time proof):** the whole response must
   arrive within `audit_response_timeout` sized for hashing the selected subtree's
   leaves at local-disk speed × slack (reuse v12's formula, scaled to the subtree
   leaf count). This is a SEPARATE signal from 5a: a relay/lazy node missing the
   selected leaves must fetch them over the network → blows the deadline, whether
   or not it could eventually fabricate hashes. (Three layers total: step 4 =
   structure, step 5a = real-bytes, step 6 = possession-in-time.)

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

**Detect-on-1st-fail for storage failures; multi-strike ONLY for timeouts.**
Storage-possession failures (root reconstruction ≠ pinned root,
`bytes_hash`/`nonced_hash` mismatch, repudiating a recently-gossiped root) are
**deterministic and non-flaky** — a node that fails one has provably lost/faked
data, and re-asking cannot make it pass honestly. Requiring N consecutive strikes
for these only multiplies time-to-detection (≈ ×N) for zero false-positive
benefit, so they are **accounted on the first failure** (a single confirmed
failure → penalty, gated by the rollout switch). The 3-strike grace remains
**only** for `Timeout`, which IS flaky (transient network loss, GC pause, load) —
there the grace prevents false-positiving honest-but-slow nodes. So: confirmed
crypto/possession failure = 1 strike to penalty; timeout = N consecutive strikes
(reset on any success).

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
- **Data-shedder (deletes a fraction `f`):** two regimes, quantified in the
  coverage analysis (§12.1):
  - *Uniform/random deletions:* caught FAST. A node dropping `f` of its chunks
    uniformly dirties the selected subtree with prob ≈ `1 − (1−f)^√N`, which for
    any non-trivial `f` is ~1 within a couple of audits. (And the §5a spot-checks
    add a second catch path for fabricated leaves.)
  - *Clustered/adversarial deletions:* a deleter that drops whole aligned blocks
    of keys (worst case) dirties only ~`f` of the selectable subtrees, so per-audit
    catch ≈ `f` — a FLOOR independent of N and of subtree size. Bigger subtrees do
    not help; permuting key positions does not help (the adversary chooses which
    keys to drop). The only lever is audit RATE over time.
  ACCEPTED TRADEOFF, justified economically: **there is no financial motivation to
  shed a small `f`.** Shedding 1% saves ~1% storage for near-certain eventual
  detection — irrational. A rational attacker sheds a LARGE fraction to actually
  save resources, and at the clustered floor `q ≈ f` that is caught fast: f=50% →
  ~50% catch per audit → detected within 1–2 audits; f=20% → ~1 audit; even worst-
  case clustered f=10% → median ~1h at the §10 rate. So we explicitly DO NOT
  optimise for catching tiny `f` quickly; we optimise for catching meaningful
  shedding fast, which the design does. Convergence for the uniform case comes from
  frequent random-nonce audits selecting different subtrees over time. (If ever too
  slow, the lever is raise `p` / shrink cooldown — NOT more subtrees per audit,
  which the floor shows doesn't move the clustered number.)
- **Fabricated nonced tree (holds addresses, not bytes):** a node that kept only
  chunk *addresses* could rebuild the plain tree and pass the §4 structural check,
  but must still answer the §5a nonced spot-checks with real bytes. Faking a
  fraction `x` of nonced leaves survives only `(1−x)^k` (k=5–10). Caught by §5a.
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
  `AUDIT_ON_GOSSIP_PROBABILITY` and per-peer cooldown `AUDIT_ON_GOSSIP_COOLDOWN`,
  spawn a detached audit (permit-gated by the existing send semaphore) of the
  gossiper, pinned to the just-ingested root.
- **Locked constants (per §12.1 analysis + decision §12.2 that we only need to
  catch meaningful shedding fast):**
  - `AUDIT_ON_GOSSIP_PROBABILITY = 0.2`
  - `AUDIT_ON_GOSSIP_COOLDOWN = 30 min` (per-peer)
  - gossip interval `g ≈ 10 min` (unchanged from v12 cadence)
  - subtree target = `√(key_count)` real leaves (§3 floor rule)
  - `AUDIT_SPOTCHECK_COUNT = 8` (§5a; in [5,10])
  These give ≈ 8–10 audits/hr per node (each a small √N proof), catching a
  rational large-`f` shedder within ~1–2 audits and worst-case clustered f=10%
  within ~1h. Because there is no incentive to shed tiny `f` (§8), we do NOT
  provision the higher rate the analysis flagged for catching f=1% within a day —
  these constants are sized for meaningful shedding, keeping steady-state audit
  traffic low.
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
- `commitment.rs`: `select_subtree_path(nonce, key_count)` terminating on the
  √(real key_count) floor (§3, NOT fixed ceil(D/2)); `real_leaves_under(node,
  key_count)` helper used by the walk and by the auditor to reproduce it;
  subtree-root reconstruction from selected leaves + sibling cut-hashes; the
  `nonced_hash` leaf helper; `select_spotcheck_positions(nonce, subtree_leaf_count,
  k)` for §5a.
- `commitment_state.rs`: last-2-gossiped retention + chunk retention; `mark_gossiped`.
- `audit.rs`: responder builds the pruned subtree proof (expand selected subtree,
  collect sibling cut-hashes, compute plain+nonced leaf hashes from local bytes);
  auditor verifier (§5: structural root reconstruction + §5a nonced spot-check on
  k leaves within the subtree + §6 timing); failure dispositions (§6) with
  detect-on-1st-fail for crypto/possession failures, N-strike only for timeouts.
- `mod.rs`: gossip-trigger plumbing (ingest → probabilistic spawn), retention
  marking at the gossip-emit sites, remove/repurpose the random tick.
- `config.rs`: `AUDIT_ON_GOSSIP_PROBABILITY` (=0.2), `AUDIT_ON_GOSSIP_COOLDOWN`
  (=30 min), `AUDIT_SPOTCHECK_COUNT` (=8), subtree target-size policy (√ real
  key_count floor), retention count (=2). Detect-on-1st-fail vs timeout-strike
  threshold reuse the #113 `AUDIT_TIMEOUT_STRIKE_THRESHOLD` (timeouts only).
- Tests: selection determinism; √-floor walk never selects an all-padding block
  (regression for the dead-block bug) across padded key_counts; root
  reconstruction from pruned proof; possession (local + fetched); §5a spot-check
  catches a fabricated-nonced-tree responder (holds addresses, fakes nonced
  leaves) with the expected `(1−x)^k` probability; detect-on-1st-fail for crypto
  failure vs N-strike for timeout; unknown-hash-now-fails; retention-keeps-last-2;
  timeout sizing; flood doesn't amplify; clustered-vs-uniform shedder detection
  simulation (q≈f floor for clustered, fast for uniform) at the locked constants.

---

## 12. DECISIONS (resolved in review)

1. **Coverage math:** RESOLVED (dedicated analysis). Findings:
   - *Geometry bug found & fixed:* fixed-depth `ceil(D/2)` selection leaves up to
     ~38% dead/all-padding blocks under padding → §3 rewritten to the
     "√(real key_count) floor" walk (select among real leaves only). REQUIRED.
   - *Uniform deletions:* P(catch)/audit ≈ `1 − (1−f)^√N` — fast.
   - *Clustered/adversarial deletions:* P(catch)/audit ≈ `f` — a floor independent
     of N and subtree size; permutation doesn't help. The lever is audit RATE.
   - *Coverage ≠ detection:* full subtree-position coverage is slow (~620 audits at
     N=10k), but detection does NOT require coverage (uniform → spread; clustered →
     rate over time). The earlier "covers tree in a couple audits" intuition is
     false for coverage but irrelevant to detection.
   - *Detect-on-1st-fail* for storage/possession failures (deterministic), N-strike
     ONLY for timeouts (flaky). Folded into §6.
   - *Locked constants:* `p = 0.2`, cooldown `30 min`, `g ≈ 10 min`, subtree `√N`,
     `AUDIT_SPOTCHECK_COUNT = 8` → ≈ 8–10 audits/hr/node. Sized (per §12.2 economic
     argument) to catch *meaningful* shedding within 1–2 audits, NOT to chase
     uneconomical f=1%. Folded into §10.
   - *Realness layer added:* §5a nonced spot-checks (within selected subtree) bind
     the tree to real bytes, defeating the "hold addresses, fake nonced tree"
     attack — orthogonal to coverage. Per design decision: spot-checks drawn from
     WITHIN the selected subtree (no extra inclusion paths), realness over the rest
     of the tree accrues across audits.
2. **Backstop tick:** RESOLVED — **pure gossip-triggered.** Remove the periodic
   random audit tick entirely IF nothing else depends on it (check: the
   post-bootstrap-drain one-shot tick, and any GC it drives — `recent_provers`
   TTL sweep, strike-map hygiene; if those need a driver, keep a minimal GC
   timer that does NOT audit, or fold the sweeps into another existing loop).
   The §3 capable-but-no-current-commitment shield is then dead code (gossip
   trigger always has a current commitment) and is removed. A silent peer is
   handled by holder-credit TTL — it simply stops being credited.
3. **Closeness check (§9):** RESOLVED — **include, but lenient and
   density-aware.** Reject a selected leaf's key only if it is implausibly far
   from the peer relative to the *observed data density* — i.e. compare against
   how much overlap the auditor sees among its own / its peers' holdings. On a
   small/dense network (e.g. 20 nodes where everyone holds almost everything),
   "far" keys are NORMAL and MUST NOT trigger failures — do not kick everyone.
   The closeness bound must scale with density: tight only when the network is
   large/sparse enough that a node holding far keys is genuinely anomalous.
   Treat closeness as anti-padding insurance, biased heavily toward
   false-negative (miss some padding) over false-positive (never wrongly kick a
   dense-network node).
4. **>1 subtree per audit:** RESOLVED — **NO.** One nonce → one deterministic
   branch. Random nonce per audit selects a different branch each time, so the
   whole tree is covered over a few audits. Adding k subtrees does not change
   the steady-state detection guarantee (time provides the coverage); it only
   front-loads it at extra proof cost. Keep single-subtree.
5. **Protocol id:** RESOLVED — **stay on `.v2`.** Do not introduce a `.v3`. v13
   audit changes land within the v2 replication protocol (the audit
   challenge/response are carried under `REPLICATION_PROTOCOL_ID` already; the
   shape change rides the same id since v2 is not yet released — no separate
   version split needed).
