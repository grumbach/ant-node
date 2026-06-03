# PR #113 (v12 storage-bound audit) — Testnet Verdict

**Run:** 2026-06-02, 04:13Z–07:06Z (~2h53m). 400 ant-node services across 5
DigitalOcean regions + 1 local-Anvil EVM host. ~$3-4 cloud spend. All infra
torn down (verified 0 droplets remaining).

PR head: `3d97ca5` (`grumbach/storage-commitment-audit`).

---

## Bottom line

**NOT yet proven production-ready. Do not ship to a network where being wrong
risks thousands of live nodes — on the strength of this run.** The run did not
produce the evidence that PR #113 *correctly evicts bad nodes without harming
good ones*. It produced the opposite signal on both halves, plus enough
testnet-artifact contamination that the result must be read as **"inconclusive,
leaning concerning"** rather than a clean pass or a clean fail.

Two findings stand out, one likely-real and one artifact-contaminated:

### Finding 1 (likely real, needs follow-up): storage-deletion goes unpunished
Nodes that deleted ~50% of their stored chunks every 2 min (lazy /
chunk-deleter modes) were **not caught** by the storage-bound audit:

| Signal | Count over the run |
|---|---|
| Audit failures via storage gates (`bytes_hash` / `missing_bytes`) | **0** |
| Audit failures via `key_not_in_commitment` | 1 (chunk-deleter) |
| `holder_credit_dropped` (the credit-revocation path) | **0, network-wide** |
| Audits **passed** by chunk-deleter / lazy nodes | 24 |

**Mechanism observed (from a chunk-deleter's own logs):** after each deletion
the node simply **rotates to a fresh, smaller `StorageCommitment` covering only
what it still holds** (`key_count` seen bouncing 26→13→…→27 as it deletes and
the workload re-seeds it). The auditor pins the *latest gossiped* commitment, so
the node answers correctly for its current (shrunken) keyset and **passes**. The
two credit-revocation triggers never fired: the audit-failure path
(`apply_audit_failure_credit_revocation`) needs a *confirmed* DigestMismatch /
KeyAbsent / Rejected, and `forget_commitment` needs an "unknown commitment
hash" — neither occurs when the attacker gossips a valid fresh commitment for
less data.

**Why this matters:** a node paid to store data can drop it, continuously
re-commit to whatever it still has, keep its holder credit on the survivors, and
suffer **no trust penalty, no eviction, no credit revocation.** Whether that is
acceptable ("honest shrinkage — it no longer claims the dropped keys") or a real
hole ("it was paid for those chunks and dropped them with zero consequence")
is the central design question PR #113's reviewers must answer. This run shows
the audit **does not** turn deletion into a punishable event under continuous
re-commitment.

*Caveat:* `relay` adversaries (which fetch bytes from neighbours at audit time)
**were** pressured — 49 failures across 16/20 relay slots — but via `timeout`,
not a storage gate.

### Finding 2 (artifact-contaminated): honest nodes took the most failures
| Target mode | trust app-failures | distinct slots | RT-removed slots |
|---|---:|---:|---:|
| honest (360 slots) | 72 | 43 | **52** |
| relay (20) | 49 | 16 | 2 |
| chunk-deleter (4) | 1 | 1 | 0 |
| lazy (4) | 1 | 1 | 0 |

On its face this is a **false-positive failure** (P2): 43 honest slots accused,
52 honest slots evicted from routing tables. **But every single honest failure
was `gate=timeout`** — not a storage-integrity verdict. The honest nodes were
not accused of lying about storage; they were slow to answer audits within the
deadline. This is heavily confounded by the testnet's accelerated configuration
(see artifacts below): a 2 s audit-response floor, 2-min commitment rotation
racing the audit, and 80 nodes/8-core boxes at load ≈ 1.0/core. **I cannot
cleanly separate "v12 false-positives honest nodes" from "accelerated testnet
starves honest audit responses" with this dataset.** The honest timeout
eviction rate (~12% of honest slots) would still be alarming in production, but
production's slower cadence + the responsibility-confirmation step would absorb
much of it.

---

## What DID work (verified)
- **Network health:** 400 nodes formed, ~60-peer routing tables, replication +
  commitment gossip flowing (270k gossip_ingest, 9.8k commitment rotations).
- **Payment path:** uploads/downloads against the local Anvil EVM succeeded at
  **99.7% / 99.8%** — payment verification + storage end-to-end works.
- **Honest audits pass:** 1,282 `passed_commitment_bound` against honest nodes —
  the happy path (commit → gossip → audit → verify → credit) is functional.
- **Gossip-ingest gates fire:** `rt_gate`, `sig_verify_rate_limited` observed;
  no forged-commitment acceptances.

## Testnet artifacts that limit confidence (must be controlled in a re-run)
1. **Cadence was time-accelerated** (env knobs I added, production defaults
   unchanged in source): commitment rotation 1 h→**120 s**, audit 10-20 min→
   **60-120 s**, neighbour-sync 10-20 min + 1 h cooldown→**45-90 s / 120 s**.
   Necessary to get any audit cycles inside a 4 h budget, but it makes rotation
   race audits and inflates timeouts. The audit *logic/gates* are unchanged —
   only timer durations.
2. **2 s `audit_response_floor` + 80 nodes/8 cores** → timeout-prone under load,
   the dominant (and confounding) failure mode.
3. **Harness gap — 6 of 7 adversary modes were unwired no-ops in the staged
   code.** Only `relay` misbehaved out of the box. I wired the
   **lazy/chunk-deleter** deleter mid-run (Finding 1 relies on it). **silent,
   throwaway-key, fake-storage, bootstrap-shield were never exercised** — their
   `is_*()` hooks exist but have no call sites in the node. **No claim is made
   about those four modes.**

## Recommended re-run to get a clean verdict
- Keep cadences nearer production (or only modestly accelerated) and raise
  `audit_response_floor` for the accelerated case so timeouts stop dominating.
- Fewer nodes per box (≤20/8-core) to remove CPU-contention timeouts.
- Wire the remaining 4 adversary modes before claiming coverage.
- Specifically instrument the delete→re-commit→audit window to confirm whether
  credit revocation *can* ever fire against a re-committing deleter, or whether
  Finding 1 is a genuine design gap.

## Provenance
Raw event logs (287k events, 400 files) + workload CSV under
`scripts/testnet-v12/collected/v12verify/`; safety copy in `~/.Trash/`.
Per-mode breakdown reproducible from those logs.
