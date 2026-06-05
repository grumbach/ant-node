# ADR-0002 — overnight implementation + review status

Working notes (not an ADR). State of the gossip-triggered contiguous-subtree
storage audit after the overnight implementation/review/testnet pass.

## What was built (C1–C9, all on this branch)

The audit was implemented from scratch on top of the existing Merkle/commitment/
gossip/trust primitives (those were reused, not rebuilt):

- **subtree.rs** — pure proof core: nonce-determined √-real-leaf-floor subtree
  selection (dead-block bug avoided), three-layer verify (structure / real-bytes
  nonced spot-check / possession-in-time), pruned-proof build, spot-check
  selection. Full-range honest-proof regression test (N=5..=600 × many nonces).
- **protocol.rs** — new `SubtreeAuditChallenge` / `SubtreeAuditResponse`
  (`Proof`/`Bootstrapping`/`Rejected`). The pre-existing single-key
  `AuditChallenge`/`AuditResponse` (on `main`) were LEFT INTACT and now serve the
  prune-confirmation audit ONLY (`pruning::handle_prune_audit_challenge`).
- **audit.rs** — responder `handle_subtree_challenge`; auditor `run_subtree_audit`
  + the pure, testable `evaluate_subtree_audit` verdict (Pass/Fail/Inconclusive);
  density-aware closeness observation (soft/observe-only per ADR).
- **commitment_state.rs** — retention changed to "last 2 GOSSIPED commitments"
  (`mark_gossiped` at all three emit sites), replacing 4-slot rotation. Closes the
  rebuild-faster-than-gossip false-positive.
- **mod.rs** — gossip trigger in `ingest_peer_commitment` (fires on EVERY valid
  gossip, cooldown+probability gated; `commitment:None` downgrade audited vs last
  cached); accounting (detect-on-1st-fail for deterministic, strike-grace for
  timeout, no benign Idle lane); bounded adaptive timeout grace.
- **config.rs** — `AUDIT_ON_GOSSIP_PROBABILITY=0.2`, `AUDIT_ON_GOSSIP_COOLDOWN_SECS=1800`,
  `AUDIT_SPOTCHECK_COUNT=8`, retention=2.
- Deleted the entire old per-key audit machinery (`commitment_audit.rs`,
  `CommitmentBoundResult`, the per-key builders/outcome).

## Reviews run

1. **Multi-agent adversarial review** (Claude) — found the CRITICAL self-pairing
   geometry bug (proof reconstruction mismatched the left-packed tree for ~70% of
   sizes → would convict honest nodes) and the skippable-possession HIGH. Both fixed
   and regression-guarded.
2. **Test-usefulness review** (Claude) — found the auditor verdict logic was only
   tested via a reimplementation (drift risk). Fixed by extracting the pure
   `evaluate_subtree_audit` and testing the shipped function; added cooldown/flood
   tests, tightened the detection simulation, added constant tripwires.
3. **codex (gpt-5, high reasoning) ADR review** — found 4 substantive issues, all
   fixed: trigger-only-on-changed (stable-keyset node audited once); cooldown after
   probability (flood multiplies lotteries); fixed 1000-leaf timeout (~402s, made
   fetch-on-demand practical); adaptive-grace bugs (strike cap unreachable, wrong
   population, upper-median).
4. **codex re-review of the fixes** — confirmed 2 RESOLVED, 4 PARTIALLY, and caught
   1 NEW regression I'd introduced (eager all-leaf byte preload → multi-GB spike).
   Fixed: bounded the preload to ~2×spotcheck chunks. Residuals are documented
   design choices (probabilistic non-sampled-forgery catch; bootstrap audits one
   cycle late; timeout-constant tuning to be validated empirically on testnet).

## Quality gates

- `cargo test --lib`: 574 pass, 0 fail.
- `cargo test --features test-utils --test poc_commitment_audit_attacks`: 18 pass.
- `cargo test --features test-utils --test poc_audit_handler_live`: 6 pass.
- `cargo clippy --all-features --lib -- -D clippy::panic -D clippy::unwrap_used -D clippy::expect_used`: clean (0).
- No `#[allow]` to silence clippy in production code; no panic/unwrap/expect.

## Local testnet (this tree's live multi-node harness)

Test-only engine hooks (gated `#[cfg(any(test, feature="test-utils"))]`):
`rebuild_commitment_now`, `audit_peer_now`, `inject_peer_commitment_for_test`.
`tests/e2e/subtree_audit_testnet.rs` spins a real 10-node network and drives the
SHIPPED audit over the live wire:
- honest holder → Passed (≥1 byte-verified leaf);
- node that deleted its committed bytes → Failed (confirmed);
- honest node across 8 fresh-nonce audits → never a false Failed.

First run was flaky (depended on neighbor-sync gossip reaching the auditor in 5s →
`Idle`). Rewritten to seed the auditor's commitment cache deterministically
(`inject_peer_commitment_for_test`), so the audit wire path is exercised without
gossip-timing flake. (Neighbor-sync propagation itself is covered by the existing
neighbor-sync e2e tests.)

## Per-ADR-point confirmation (adversarial + codex)

Every one of the 8 Decision points was confirmed twice — by a dedicated
adversarial Claude agent AND by codex (high reasoning) — and each is now backed
by a load-bearing test:

| Point | Verdict | Confirming test |
|---|---|---|
| Trigger | faithful (bootstrap exception now in ADR) | `losing_lottery_still_consumes_cooldown_window` (now calls shipped `audit_launch_decision`), cooldown/flood tests |
| Subtree selection | faithful | `responder_cannot_substitute_a_different_branch`, full-range honest-proof, never-empty |
| The proof + 3 checks | faithful | `single_forged_leaf_at_sampled_position_fails`, `checked_zero_is_never_a_pass`, tamper tests |
| Retention | faithful | `current_plus_last_two_gossiped_are_simultaneously_answerable`, ungossiped-rebuild |
| Accounting & false positives | faithful | `deterministic_failure_penalizes_first_time_under_inflated_grace`, e2e glue |
| Closeness | faithful (observe-only) | `closeness_is_observe_only_far_keys_still_pass` |
| Network resilience | faithful (codex bugs fixed) | `even_count_takes_lower_median_and_sybil_cohort_cannot_exceed_grace_bound` |
| Delete/separation | faithful | live prune-audit-still-works e2e |

Two items codex's per-point pass surfaced and I fixed:
1. The trigger flood test was VACUOUS (reimplemented the gate order locally) →
   extracted the shipped `audit_launch_decision` (cooldown-first-then-lottery) and
   the test now calls it, so a reorder regression fails CI.
2. Bootstrap-sync ingests valid gossip without triggering an audit (intentional —
   the node may itself be bootstrapping) → the ADR Trigger bullet now documents
   this exception, so the implementation is faithful to the (clarified) ADR.

Codex's remaining notes were "no dedicated single-purpose test" for behaviours
already covered by composite tests (KeyAbsent-impossible is structural — the
subtree challenge has no key list; live observe_closeness needs a DHT). Not bugs.

Final gates after the confirmation pass: 583 lib tests, 6+18 poc tests, 3 live
testnet tests — all pass; clippy strict-clean; fmt clean.

## For tomorrow's large-scale real testnet

- The timeout-constant margin (honest-disk vs relay-fetch) is the one item best
  validated empirically at scale — measure real honest-responder latency vs a relay
  forced to fetch, and tighten `AUDIT_RESPONSE_HONEST_MULTIPLIER` /
  `AUDIT_HONEST_READ_BPS` if the margin is too generous.
- Eviction trust-reporting for timeouts stays gated off (`TIMEOUT-EVICTION-DISABLED`)
  this release; confirmed failures DO report. Re-enable timeout eviction once the
  fleet has upgraded.
- Adversary modes for the large testnet (relay / lazy / chunk-deleter) live in the
  separate testnet harness (saorsa/ant-node scripts/testnet-v12), not this tree.
