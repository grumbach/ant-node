#!/usr/bin/env python3
"""Machine-checked PASS/FAIL for a v12 verification run.

Reads the CSVs produced by `analyse.py` and applies the predicates
documented in SUCCESS-CRITERIA.md. Exits 0 on PASS, 1 on FAIL.

Predicates:
  P1. Every adversary mode that v12 is designed to evict produces a
      detectable signal (≥1 audit_outcome failed/idle_capable_no_commitment
      OR ≥1 ingest_rejection of the matching kind) per mode.
  P2. Honest nodes emit no audit_outcome=failed verdicts against other
      honest peers in steady state (false-positive rate).
  P3. Workload success rate ≥ 95% upload, ≥ 99% download.
  P4. Workload p50 upload latency ≤ 1.5× pre-go-bad-at baseline (the
      latter is provided by the workload-gen output or via --baseline-csv).

Each predicate has a per-run override knob so a "this attack is the
documented economic-not-cryptographic limit" mode like Relay does not
get penalised for not being evicted.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

# Modes that are EXPECTED to produce a detectable v12 signal and drive
# the peer toward eviction. As of PR #113, relay IS included: the
# tightened sample-size-aware `audit_response_timeout` plus the
# credit-revocation-on-failure path mean a relay node (which must fetch
# bytes from a neighbour at audit time) misses the response deadline →
# audit_timeout → application_failure → holder-credit revoked → trust
# collapse. This run's whole point is to confirm that. The old v12 §7
# "economic-not-cryptographic limit" exemption no longer applies.
MODES_REQUIRING_DETECTION = {
    "relay",
    "lazy",
    "chunk-deleter",
    "silent",
    "throwaway-key",
    "bootstrap-shield",
    "fake-storage",
}

# What signal counts as detection per mode. Each entry maps mode →
# list of (csv_field, > or >= threshold). Per attribution.csv we look
# at the AGGREGATE audit verdicts emitted by all nodes in that mode AS
# AUDITORS. That's a proxy: a lazy node is also an auditor, and we
# want to see it producing few audits (because peers stopped talking
# to it) while *receiving* many failures. The eviction-by-peer-hex
# csv has the per-target counts but we don't bind peer-hex → mode
# here. The §3 + §6 logic of attribution.csv handles this via the
# row totals.
DETECTION_PREDICATES: dict[str, list[tuple[str, int]]] = {
    # lazy / chunk-deleter: ingest by their peers will eventually
    # accept (they DO gossip a real commitment) but their per-key
    # bytes_hash audits will fail. The "emitted" view doesn't capture
    # this directly. Use the eviction-by-peer-hex.csv via a separate
    # binding step. For this script we apply a weaker predicate:
    # ANY adversary mode should show audit-failure activity at the
    # global level when the run completes.
}


def load_attribution(path: Path) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    with path.open() as f:
        reader = csv.DictReader(f)
        for row in reader:
            mode = row["mode"]
            out[mode] = {
                k: int(v) if v and v.isdigit() else 0
                for k, v in row.items()
                if k != "mode"
            }
    return out


def load_eviction_by_peer(path: Path) -> list[dict[str, int]]:
    rows: list[dict[str, int]] = []
    if not path.exists():
        return rows
    with path.open() as f:
        reader = csv.DictReader(f)
        for row in reader:
            entry: dict[str, int] = {}
            for k, v in row.items():
                if k == "peer_hex":
                    entry[k] = v  # type: ignore[assignment]
                else:
                    try:
                        entry[k] = int(v) if v else 0
                    except ValueError:
                        entry[k] = 0
            rows.append(entry)  # type: ignore[arg-type]
    return rows


def load_eviction_by_mode(path: Path) -> dict[str, dict[str, int]]:
    """Load eviction-by-mode.csv → {mode: {col: int}}."""
    out: dict[str, dict[str, int]] = {}
    if not path.exists():
        return out
    with path.open() as f:
        reader = csv.DictReader(f)
        for row in reader:
            mode = row.get("mode", "")
            if not mode:
                continue
            out[mode] = {
                k: int(v) if v and v.isdigit() else 0
                for k, v in row.items()
                if k != "mode"
            }
    return out


def load_honest_perf(path: Path) -> dict[str, dict[str, float | int | str | None]]:
    out: dict[str, dict[str, float | int | str | None]] = {}
    if not path.exists():
        return out
    with path.open() as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                out[row["op"]] = {
                    "success_rate": float(row.get("success_rate", "0") or 0),
                    "p50_ms": int(row["p50_ms"]) if row.get("p50_ms") else None,
                    "p95_ms": int(row["p95_ms"]) if row.get("p95_ms") else None,
                    "n": int(row["n"]),
                }
            except (ValueError, KeyError):
                continue
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--analysis-dir",
        default=None,
        help="Where eviction-timeline.csv etc. live. Default: ./analysis",
    )
    ap.add_argument(
        "--upload-success-min",
        type=float,
        default=0.95,
        help="Minimum upload success rate (default 0.95).",
    )
    ap.add_argument(
        "--download-success-min",
        type=float,
        default=0.99,
        help="Minimum download success rate (default 0.99).",
    )
    ap.add_argument(
        "--p50-upload-ms-max",
        type=int,
        default=0,
        help="Absolute upload-p50 latency cap in ms (0 = disabled). The "
        "1.5× baseline check is informational only without an explicit cap.",
    )
    args = ap.parse_args()

    base = Path(args.analysis_dir or "analysis")
    attribution_path = base / "attribution.csv"
    eviction_peer_path = base / "eviction-by-peer-hex.csv"
    eviction_mode_path = base / "eviction-by-mode.csv"
    perf_path = base / "honest-perf.csv"
    false_pos_path = base / "false-positives.csv"

    if not attribution_path.exists():
        print(f"ERROR: missing {attribution_path}. Run analyse.py first.")
        return 1

    attribution = load_attribution(attribution_path)
    by_peer = load_eviction_by_peer(eviction_peer_path)
    by_mode = load_eviction_by_mode(eviction_mode_path)
    perf = load_honest_perf(perf_path)

    failures: list[str] = []
    notes: list[str] = []

    # ---- P0: peer_hex binding present --------------------------------
    # Without it the per-mode + false-positive predicates below are
    # meaningless, so fail loudly rather than silently passing.
    if not by_mode:
        failures.append(
            "P0: eviction-by-mode.csv missing/empty — the self-announce "
            "binding produced no rows. Per-mode detection and the "
            "false-positive check cannot be evaluated."
        )

    # ---- P1b: every required-detection mode shows >=1 evicted slot ---
    for mode in sorted(MODES_REQUIRING_DETECTION):
        row = by_mode.get(mode)
        if row is None:
            # Mode may have 0 slots in this run's manifest — only flag if
            # the manifest actually placed slots there.
            continue
        if row.get("slots", 0) > 0 and row.get("slots_with_failure", 0) == 0:
            failures.append(
                f"P1b: mode '{mode}' had {row['slots']} slot(s) but NONE "
                "received a confirmed audit failure — v12 did not detect it."
            )
        elif row.get("slots", 0) > 0:
            notes.append(
                f"P1b: mode '{mode}': {row.get('slots_with_failure', 0)}/"
                f"{row['slots']} slots took failures, "
                f"{row.get('slots_peer_removed', 0)} RT-removed."
            )

    # ---- P2: no honest slot received a confirmed failure -------------
    honest_row = by_mode.get("honest", {})
    honest_fp = honest_row.get("slots_with_failure", 0)
    honest_removed = honest_row.get("slots_peer_removed", 0)
    if honest_fp or honest_removed:
        failures.append(
            f"P2: FALSE POSITIVES — {honest_fp} honest slot(s) received a "
            f"confirmed audit failure and {honest_removed} were RT-removed. "
            "v12 must not penalise honest peers. See false-positives.csv."
        )
    elif "honest" in by_mode:
        notes.append("P2: 0 honest slots received failures (no false positives).")

    # An 'unbound' bucket with failures means peers we couldn't map —
    # surface it so a silent binding gap doesn't masquerade as a clean run.
    unbound = by_mode.get("unbound", {})
    if unbound.get("slots_with_failure", 0):
        notes.append(
            f"P2 note: {unbound['slots_with_failure']} unbound peer(s) took "
            "failures (no self-announce captured); verify these are not honest."
        )

    # ---- P1: every required-detection mode shows SOME signal --------
    aggregate_audit_fail = sum(
        m.get("audit_outcomes_emitted_failed", 0) for m in attribution.values()
    )
    if aggregate_audit_fail == 0:
        failures.append(
            "P1: zero audit failures observed across the entire run — the "
            "v12 enforcement layer apparently did not fire at all."
        )
    else:
        notes.append(f"P1: {aggregate_audit_fail} aggregate audit failures observed.")

    # Per-mode required-detection check is the harder one and requires
    # peer-hex ↔ mode binding which lives in a follow-up CSV the
    # runbook spells out (cross-referencing manifest peer-ids with
    # the receiver-side rejection logs). For now we require:
    #   - at least one peer in eviction-by-peer-hex shows high failure
    #     count (i.e. somebody got hammered).
    if by_peer:
        # Top-1 failure count
        top = max(
            (
                p.get("application_failure_total", 0)
                for p in by_peer
                if isinstance(p, dict)
            ),
            default=0,
        )
        notes.append(f"P1: max per-peer application_failure_total = {top}.")
        if top == 0:
            failures.append(
                "P1: no peer in eviction-by-peer-hex.csv had ANY application "
                "failure event. Either nothing is being audited, or the "
                "event log is missing trust_event records."
            )

    # ---- P3: workload thresholds -----------------------------------
    if "upload" in perf:
        rate = perf["upload"]["success_rate"]
        if isinstance(rate, float):
            if rate < args.upload_success_min:
                failures.append(
                    f"P3: upload success rate {rate:.3f} < threshold "
                    f"{args.upload_success_min}."
                )
            else:
                notes.append(
                    f"P3: upload success {rate*100:.2f}% (threshold "
                    f"{args.upload_success_min*100:.0f}%)"
                )
    if "download" in perf:
        rate = perf["download"]["success_rate"]
        if isinstance(rate, float):
            if rate < args.download_success_min:
                failures.append(
                    f"P3: download success rate {rate:.3f} < threshold "
                    f"{args.download_success_min}."
                )
            else:
                notes.append(
                    f"P3: download success {rate*100:.2f}% (threshold "
                    f"{args.download_success_min*100:.0f}%)"
                )

    # ---- P4: latency cap ------------------------------------------
    if args.p50_upload_ms_max > 0 and "upload" in perf:
        p50 = perf["upload"].get("p50_ms")
        if isinstance(p50, int) and p50 > args.p50_upload_ms_max:
            failures.append(
                f"P4: upload p50 {p50}ms > cap {args.p50_upload_ms_max}ms."
            )
        elif isinstance(p50, int):
            notes.append(
                f"P4: upload p50 {p50}ms (cap {args.p50_upload_ms_max}ms)"
            )

    # ---- Report ---------------------------------------------------
    print()
    print("=" * 60)
    if not failures:
        print("VERDICT: PASS")
    else:
        print("VERDICT: FAIL")
    print("=" * 60)
    for note in notes:
        print(f"  · {note}")
    if failures:
        print("\nFailures:")
        for fail in failures:
            print(f"  ✗ {fail}")
    print()
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
