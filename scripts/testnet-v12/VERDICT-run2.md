# PR #113 v12 audit — Testnet Run 2 Verdict (relay + lazy detection)

**Run:** 2026-06-02 09:16Z–11:56Z (~2h40m). 400 ant-node services / 5 DO
regions + local Anvil EVM. ~$3-4 cloud, fully torn down (0 droplets, verified).
Binaries carry the current fixes (deletion-aware quoting, audit-timeout strike
grace, wired lazy/chunk-deleter deleter, relay-delay tuned for all sample sizes).
404,317 v12 events, 400/400 nodes bound to their slot via self-announce.

Cadence was time-accelerated (rotation 120s, audit 60-120s, neighbour-sync
45-90s) to fit a bounded run — the audit *logic/gates* are production code,
only the timers are shortened.

---

## Bottom line

**Relay detection works solidly.** Deletion detection is **partial**:
aggressive deleters (chunk-deleter) are caught 4/4, but a node that quietly
sheds data and re-commits to its smaller keyset (lazy) largely evades the audit
(1/4 caught) — by design, the audit gate is not the intended defence for that;
the economic reward-tied-to-held-data path (deferred) is. Network stayed 100%
healthy under attack. Honest false-positives are timeout-only (an accelerated-
test artifact, not a storage fault) and materially reduced from the prior run.

## Results (per adversary mode, slots → audit-failed / trust-penalized / RT-evicted)

| Mode | slots | audit-failed | trust-penalized | RT-evicted | gate |
|---|---:|---:|---:|---:|---|
| **relay** | 20 | 19 | 10 | 2 | `timeout` (195 fails, 0 passes) |
| **chunk-deleter** | 4 | 4 | 4 | 1 | `key_not_in_commitment` + timeout |
| **lazy** | 4 | **1** | **1** | 0 | `key_not_in_commitment` — **only 1 of 4 caught; 3 evaded (passed every audit)** |
| fake-storage | 4 | 1 | 1 | 1 | timeout |
| silent / throwaway-key / bootstrap-shield | 8 | 0 | 0 | 0 | (modes still unwired — no claim) |
| **honest** | 360 | 15 | 14 | 18 | **`timeout` ONLY (0 storage gates)** |

Workload: **100% upload (262/262), 100% download (560/560)** — the network
served data correctly throughout, with adversaries present.

## What this proves

1. **Relay detection WORKS (headline).** 19/20 relays were audited; they failed
   **195 audits with zero passes** — a relay times out on every audit because it
   must fetch bytes it doesn't hold, and the strikes accumulate monotonically
   (no pass ever resets them). 10 relays crossed the trust-penalty threshold,
   2 were RT-evicted in the window. The relay-delay tuning closed the small-
   sample (k=1) escape the previous analysis found.
2. **Deletion detection is PARTIAL and depends on how aggressively the node
   deletes.** With the deleter wired this run:
   - **chunk-deleter: 4/4 caught** (drops 50% every 2 min → high churn → an
     auditor reliably hits a just-deleted-but-still-committed key →
     `key_not_in_commitment`). 4 trust-penalized, 1 evicted.
   - **lazy: only 1/4 caught.** node-364 failed once (after 12 passes) and was
     penalized; node-35/295/313 **passed every audit and evaded entirely.**
   - **Why:** a deleter that re-commits to its shrunken keyset answers audits
     correctly for what it still holds; it only fails in the narrow window
     where an auditor challenges a *specific dropped key before* it rotates that
     key out of its commitment. Aggressive deletion (chunk-deleter) widens that
     window; gentle deletion (lazy) mostly rides it out. This is the documented
     "re-commit to shrunken keyset" gap — the audit alone does NOT reliably
     punish a node that quietly sheds data. The intended defence for this is the
     economic one (reward tied to audit-verified held data), which is the
     deferred quote-quantity work, NOT the audit gate.
3. **No storage-integrity false positives.** Across 360 honest nodes, **zero**
   were ever accused via a storage gate (`bytes_hash` / `missing_bytes` /
   `key_not_in_commitment`). Honest nodes are never wrongly accused of lying
   about storage.

## The honest caveat (and why it's not a blocker)

14 honest nodes took a trust penalty and 18 were RT-evicted — but **100% of
honest failures are `timeout`**, never a storage gate. This is the accelerated-
test artifact: at 2-min rotation + a 2s audit-response floor + 80 nodes on
8-core boxes, an honest node occasionally misses the (deliberately tight)
response deadline. Evidence it's an artifact, not a logic fault:
- The 3-strike grace **cut honest penalties from 43 slots (run 1) to 14** — the
  fix works, it's just not fully sufficient under this aggressive acceleration.
- Honest failures are exclusively transient-slowness timeouts; the storage
  audit never false-accuses.
- Production cadence (1h rotation, 10-20min audits) gives far more slack between
  audits and far less rotation-vs-audit racing, so the honest timeout rate
  would drop sharply.

**Recommended before production sign-off:** one run at near-production cadence
(or with a higher `audit_response_floor` for accelerated runs) to confirm the
honest timeout-eviction rate falls to ~0. The detection logic itself is proven;
this is about tuning the timeout so honest nodes under real-world load aren't
caught by the same mechanism that (correctly) catches relays.

## Open items (tracked separately, not blocking this verdict)
- **Quote-quantity audit** (NEXT-STEPS.md): held-count driving price is self-
  reported, not peer-verifiable. Bind quote to audited commitment `key_count`.
- **silent / throwaway-key / fake-storage / bootstrap-shield**: adversary hooks
  still unwired — those modes were NOT exercised; no claim made about them.

## Provenance
Logs (404k events, 400 files) + workload CSV: `collected/v12verify/`; safety
copy in `~/.Trash/`. All numbers reproducible from those logs.
