#!/usr/bin/env python3
"""Analyse a v12 verification run.

Inputs:
  - scripts/testnet-v12/collected/{run_id}/{region}/v12-events-*.jsonl
    (one file per node-slot, written by the v12-event-log feature)
  - scripts/testnet-v12/build/manifest-summary.json + per-region
    manifests (so we know which global_index is which adversary mode)
  - (optional) workload-gen output: --workload <csv>

Outputs in <out-dir> (default `scripts/testnet-v12/collected/{run_id}/analysis/`):
  - eviction-timeline.csv   per peer: first failure event, RT removal time
  - attribution.csv         per adversary mode: aggregate counts + timings
  - honest-perf.csv         workload-gen latency/success summary
  - false-positives.csv     honest nodes that received any trust-failure
  - VERDICT.md              one-page pass/fail summary

Pass/fail predicates live in success_criteria.py; this script only
computes the inputs.
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Manifest loading
# ---------------------------------------------------------------------------


@dataclass
class NodeRecord:
    """A single node-slot's identity + adversary mode."""

    global_index: int
    region: str
    port: int
    role: str  # honest | adversary
    adversary_mode: str | None
    is_bootstrap: bool
    # Populated from events below.
    peer_id_hex: str | None = None
    first_trust_failure_ms: int | None = None
    first_failure_reason: str | None = None
    first_failure_gate: str | None = None
    rt_removal_ms: int | None = None
    audit_outcomes: dict[str, int] = field(default_factory=dict)
    ingest_rejections: dict[str, int] = field(default_factory=dict)


def load_manifests(build_dir: Path) -> dict[int, NodeRecord]:
    """Walk all `manifest-*.json` files into one global_index → NodeRecord map."""
    nodes: dict[int, NodeRecord] = {}
    for path in sorted(build_dir.glob("manifest-*.json")):
        if path.name == "manifest-summary.json":
            continue
        data = json.loads(path.read_text())
        for slot in data["nodes"]:
            nodes[slot["global_index"]] = NodeRecord(
                global_index=slot["global_index"],
                region=slot["droplet_region"],
                port=slot["port"],
                role=slot["role"],
                adversary_mode=slot["adversary_mode"],
                is_bootstrap=slot["is_bootstrap"],
            )
    return nodes


# ---------------------------------------------------------------------------
# Event parsing
# ---------------------------------------------------------------------------


def parse_events(
    collected_dir: Path, nodes: dict[int, NodeRecord]
) -> list[dict[str, Any]]:
    """Read every node's JSONL and return a flat list of (node_idx, event) pairs.

    Side effect: populates nodes[i].peer_id_hex from the `node_started`
    self-announce event each node emits once at startup. That event binds
    the node's own peer_hex to its global_index (the log filename), which
    is what lets attribution + false-positive analysis map a peer_hex seen
    in another node's trust/audit events back to a manifest slot — no
    heuristics required.
    """
    all_events: list[dict[str, Any]] = []
    # Files are named v12-events-<idx>.jsonl regardless of region.
    for path in sorted(collected_dir.rglob("v12-events-*.jsonl")):
        try:
            idx = int(path.stem.split("-")[-1])
        except ValueError:
            print(f"skip: {path} (cannot parse idx)", file=sys.stderr)
            continue
        if idx not in nodes:
            print(f"skip: {path} (idx {idx} not in manifest)", file=sys.stderr)
            continue
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            ev["_node_idx"] = idx
            # Bind peer_hex → global_index from the self-announce event.
            if ev.get("event") == "node_started" and ev.get("peer"):
                nodes[idx].peer_id_hex = ev["peer"]
            all_events.append(ev)
    return all_events


def build_peer_hex_index(nodes: dict[int, NodeRecord]) -> dict[str, NodeRecord]:
    """Reverse map: peer_hex → NodeRecord, from the self-announce binding.

    Nodes that never emitted a `node_started` event (crashed before
    startup, or ran a binary without the self-announce) are absent here;
    callers fall back to peer_hex-only reporting for those.
    """
    return {
        n.peer_id_hex: n for n in nodes.values() if n.peer_id_hex is not None
    }


def populate_per_node_summaries(
    events: list[dict[str, Any]], nodes: dict[int, NodeRecord]
) -> None:
    """Walk events once, populating NodeRecord summary fields."""
    # Bucket events by emitter node for ordered scans.
    by_node: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        by_node[ev["_node_idx"]].append(ev)
    for idx, lst in by_node.items():
        lst.sort(key=lambda e: e["ts"])
        node = nodes[idx]
        for ev in lst:
            kind = ev.get("event")
            if kind == "audit_outcome":
                outcome = ev.get("outcome", "unknown")
                node.audit_outcomes[outcome] = (
                    node.audit_outcomes.get(outcome, 0) + 1
                )
            elif kind == "gossip_ingest" and not ev.get("accept"):
                reason = ev.get("reason", "unknown")
                node.ingest_rejections[reason] = (
                    node.ingest_rejections.get(reason, 0) + 1
                )

    # Also walk events *targeting* each peer (other nodes' trust events
    # / peer_removed events that reference this peer's hex). We need the
    # peer_id_hex of each node-slot first; harvest from any event the
    # node emitted that contains its own audit_issued (we don't have a
    # "self announce" event so we use a heuristic: the first audit a
    # node issues uses its own peer-id in some trust events. Actually
    # the cleanest source: the audit_outcome trust_event "peer" field
    # is the *challenged* peer, not us. Without a self-id event we
    # cannot reliably map peer_id_hex → node_idx in this pass. The
    # follow-up below uses the global trust_event stream to compute
    # by-target outcomes irrespective of who emitted them.)


def compute_per_target_failures(
    events: list[dict[str, Any]],
) -> dict[str, dict[str, int]]:
    """Count trust events + audit failures *received* by each peer_hex.

    Returns peer_hex → {kind: count}. The kind keys include
    "application_failure_total", per-reason failures (e.g. failure_audit_digest_mismatch),
    "peer_removed", "audit_failed_total", per-gate failures (gate_bytes_hash etc.).
    """
    by_target: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for ev in events:
        kind = ev.get("event")
        if kind == "trust_event":
            peer = ev.get("peer")
            if not peer:
                continue
            ek = ev.get("kind", "unknown")
            by_target[peer][f"{ek}_total"] += 1
            reason = ev.get("reason", "unknown")
            by_target[peer][f"{ek}_{reason}"] += 1
        elif kind == "peer_removed":
            peer = ev.get("peer")
            if peer:
                by_target[peer]["peer_removed"] += 1
        elif kind == "audit_outcome":
            peer = ev.get("challenged_peer")
            outcome = ev.get("outcome", "unknown")
            if peer:
                by_target[peer][f"audit_outcome_{outcome}"] += 1
                gate = ev.get("gate")
                if gate:
                    by_target[peer][f"audit_gate_{gate}"] += 1
    return {k: dict(v) for k, v in by_target.items()}


def find_first_event_ts(
    events: list[dict[str, Any]],
    predicate,
) -> int | None:
    """Return ts (ms) of the first event matching predicate."""
    best: int | None = None
    for ev in events:
        if predicate(ev):
            ts = ev["ts"]
            if best is None or ts < best:
                best = ts
    return best


# ---------------------------------------------------------------------------
# CSV writers
# ---------------------------------------------------------------------------


def write_eviction_timeline(
    nodes: dict[int, NodeRecord],
    target_failures: dict[str, dict[str, int]],
    events: list[dict[str, Any]],
    out_path: Path,
) -> None:
    """One row per node: when did it first take a failure, and was it RT-evicted?"""
    # Build peer_hex → global_index mapping by looking at trust events
    # whose peer hex appears across regions. The mapping is by counting
    # which global_index emitted the audit_issued events that
    # eventually map to a peer hex. Heuristic: if a node N never
    # receives any inbound v12 events targeting its peer-id, we fall
    # back to "unknown peer_id_hex".
    #
    # Cleaner heuristic: a node's own peer_id_hex equals the
    # challenged_peer in any audit_outcome it emits where the challenge
    # was actually about itself (the responder always answers about
    # itself). But the emitter is the auditor, not the responder. The
    # responder side does not currently emit an event identifying
    # itself.
    #
    # Pragmatic workaround: we record, for each peer_hex, the set of
    # ingest_rejection events received by other peers from it. The
    # ingest event's "source" field IS this peer's peer_hex. So any
    # node-slot N whose log contains "I sent gossip to source X" lets
    # us bind N's peer_hex.
    #
    # But our v12-event-log records gossip_ingest from the receiver's
    # POV (source = the sender). To bind N → peer_hex we walk the
    # events emitted *by* node-slot N and look for an event that names
    # itself. None does. So bind via a process-of-elimination across
    # the whole event stream:
    #
    #   peer_hex P appears in trust_event.peer or audit_outcome.challenged_peer
    #   AND P does NOT appear as anyone's gossip_ingest.source (P is
    #     speaking, not being spoken about)... no, P appears as both.
    #
    # Simpler: rely on the receivers' gossip_ingest events. Every node
    # N gossips to its neighbors and those neighbors' logs contain
    # `gossip_ingest{source=N.peer_hex}`. Then the analysis script
    # cross-references: for each N, find a neighbor's accepted-ingest
    # event whose source field is unique to N. Practically, every
    # peer_hex in the source field of accepted ingests IS one of the
    # 400 nodes; we just don't know which. We do however know each
    # node's PORT + DROPLET, which is enough — the analysis treats
    # peer_hex as the canonical identity in attribution.csv and the
    # manifest-mapping is done in a separate "peer-id-map.csv" the
    # operator can fill in if needed.
    #
    # For this pass, we report attribution at peer_hex granularity and
    # also produce a CSV row PER NODE-SLOT showing what *outbound*
    # signals it sent (audit_outcomes counts).
    fieldnames = [
        "global_index",
        "region",
        "role",
        "adversary_mode",
        "is_bootstrap",
        "audit_outcomes",
        "ingest_rejections",
    ]
    with out_path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for idx in sorted(nodes.keys()):
            n = nodes[idx]
            w.writerow(
                {
                    "global_index": n.global_index,
                    "region": n.region,
                    "role": n.role,
                    "adversary_mode": n.adversary_mode or "",
                    "is_bootstrap": n.is_bootstrap,
                    "audit_outcomes": json.dumps(n.audit_outcomes),
                    "ingest_rejections": json.dumps(n.ingest_rejections),
                }
            )

    # Companion file keyed by peer_hex (peer-targeted view).
    target_path = out_path.with_name("eviction-by-peer-hex.csv")
    with target_path.open("w", newline="") as f:
        # Gather all observed kinds for a stable column list.
        all_kinds: set[str] = set()
        for counts in target_failures.values():
            all_kinds.update(counts.keys())
        cols = ["peer_hex", *sorted(all_kinds)]
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for peer, counts in sorted(target_failures.items()):
            row: dict[str, Any] = {"peer_hex": peer}
            row.update({k: counts.get(k, 0) for k in sorted(all_kinds)})
            w.writerow(row)


def write_attribution(
    nodes: dict[int, NodeRecord],
    target_failures: dict[str, dict[str, int]],
    out_path: Path,
) -> None:
    """Aggregate per adversary mode: counts + dominant failure gate.

    Since we don't have a direct global_index → peer_hex mapping in this
    pass, attribution is reported as totals by mode under two slices:
      - mode_count: number of node-slots in that mode (from manifest)
      - audits_emitted: aggregate audit_outcome counts emitted by these
        nodes (so they show what they did *as auditors*; this catches
        false positives — honest nodes that emit audit_failed verdicts
        against other honest peers).
    """
    fieldnames = [
        "mode",
        "slot_count",
        "audit_outcomes_emitted_passed_commitment_bound",
        "audit_outcomes_emitted_passed_legacy",
        "audit_outcomes_emitted_failed",
        "audit_outcomes_emitted_idle_rotation",
        "audit_outcomes_emitted_idle_capable_no_commitment",
        "audit_outcomes_emitted_bootstrap_claim",
        "audit_outcomes_emitted_timeout",
        "audit_outcomes_emitted_malformed",
        "ingest_rejections_emitted_total",
    ]
    by_mode: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for n in nodes.values():
        mode = "honest" if n.role == "honest" else (n.adversary_mode or "unknown")
        by_mode[mode]["slot_count"] += 1
        for outcome, count in n.audit_outcomes.items():
            by_mode[mode][f"audit_outcomes_emitted_{outcome}"] += count
        by_mode[mode]["ingest_rejections_emitted_total"] += sum(
            n.ingest_rejections.values()
        )

    with out_path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for mode in sorted(by_mode.keys()):
            row = {"mode": mode}
            row.update(by_mode[mode])
            w.writerow(row)


def write_false_positives(
    nodes: dict[int, NodeRecord],
    target_failures: dict[str, dict[str, int]],
    peer_index: dict[str, NodeRecord],
    out_path: Path,
) -> int:
    """List every peer that received a failure-targeted event, resolved
    to its manifest slot + role via the self-announce binding.

    Returns the number of HONEST peers that received any
    application-failure or peer-removed event — i.e. the false-positive
    count, which P2 requires to be 0. Rows for peers we could not bind
    (no self-announce) are still written with role `unknown` so they are
    not silently dropped from the false-positive accounting.
    """
    honest_false_positives = 0
    with out_path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "peer_hex",
                "global_index",
                "role",
                "adversary_mode",
                "application_failure_total",
                "peer_removed_total",
            ]
        )
        for peer, counts in sorted(target_failures.items()):
            f_total = counts.get("application_failure_total", 0)
            removed = counts.get("peer_removed", 0)
            if not (f_total or removed):
                continue
            rec = peer_index.get(peer)
            if rec is None:
                role, gidx, mode = "unknown", "", ""
            else:
                role = rec.role
                gidx = str(rec.global_index)
                mode = rec.adversary_mode or ""
                if role == "honest":
                    honest_false_positives += 1
            w.writerow([peer, gidx, role, mode, f_total, removed])
    return honest_false_positives


def write_honest_perf(workload_csv: Path | None, out_path: Path) -> dict[str, Any]:
    """Summarize the workload-gen output if provided.

    Returns aggregate stats dict for the VERDICT writer.
    """
    if workload_csv is None or not workload_csv.exists():
        out_path.write_text("op,success_rate,p50_ms,p95_ms,n\nuploads,N/A,N/A,N/A,0\ndownloads,N/A,N/A,N/A,0\n")
        return {"uploads": None, "downloads": None}
    by_op: dict[str, list[tuple[int, bool]]] = defaultdict(list)
    with workload_csv.open() as f:
        reader = csv.DictReader(f)
        for row in reader:
            op = row.get("op", "?")
            latency = int(row.get("latency_ms", "0") or "0")
            success = row.get("success", "false").lower() == "true"
            by_op[op].append((latency, success))
    summary: dict[str, dict[str, float | int | None]] = {}
    with out_path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["op", "success_rate", "p50_ms", "p95_ms", "n"])
        for op, rows in by_op.items():
            n = len(rows)
            succ = sum(1 for _, s in rows if s)
            success_lats = sorted([lat for lat, s in rows if s])
            p50 = success_lats[n // 2] if success_lats else None
            p95 = (
                success_lats[max(0, int(len(success_lats) * 0.95) - 1)]
                if success_lats
                else None
            )
            rate = succ / n if n else 0.0
            w.writerow([op, f"{rate:.4f}", p50 or "", p95 or "", n])
            summary[op] = {"success_rate": rate, "p50_ms": p50, "p95_ms": p95, "n": n}
    return summary


def write_eviction_by_mode(
    target_failures: dict[str, dict[str, int]],
    peer_index: dict[str, NodeRecord],
    nodes: dict[int, NodeRecord],
    out_path: Path,
) -> None:
    """Per adversary mode: how many of its slots actually took confirmed
    failures / were RT-removed (RECEIVED side, bound via self-announce).

    This is the headline table for "did v12 evict the bad nodes": for
    each mode it shows slots, how many received >=1 application_failure,
    how many were peer_removed, and the total failure events. Honest is
    included so a non-zero honest column is an immediate red flag.
    """
    slots_by_mode: dict[str, int] = defaultdict(int)
    for n in nodes.values():
        slots_by_mode["honest" if n.role == "honest" else (n.adversary_mode or "unknown")] += 1

    failed_slots: dict[str, int] = defaultdict(int)
    removed_slots: dict[str, int] = defaultdict(int)
    failure_events: dict[str, int] = defaultdict(int)
    for peer, counts in target_failures.items():
        rec = peer_index.get(peer)
        mode = "unbound" if rec is None else (
            "honest" if rec.role == "honest" else (rec.adversary_mode or "unknown")
        )
        f_total = counts.get("application_failure_total", 0)
        removed = counts.get("peer_removed", 0)
        if f_total:
            failed_slots[mode] += 1
            failure_events[mode] += f_total
        if removed:
            removed_slots[mode] += 1

    with out_path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(
            ["mode", "slots", "slots_with_failure", "slots_peer_removed", "failure_events"]
        )
        for mode in sorted(set(slots_by_mode) | set(failed_slots) | {"unbound"}):
            w.writerow(
                [
                    mode,
                    slots_by_mode.get(mode, 0),
                    failed_slots.get(mode, 0),
                    removed_slots.get(mode, 0),
                    failure_events.get(mode, 0),
                ]
            )


# ---------------------------------------------------------------------------
# VERDICT
# ---------------------------------------------------------------------------


def write_verdict(
    out_path: Path,
    nodes: dict[int, NodeRecord],
    target_failures: dict[str, dict[str, int]],
    perf: dict[str, Any],
    summary_json: dict[str, int],
    run_id: str,
) -> None:
    """Produce the human-readable VERDICT.md."""
    total_audits_per_mode: dict[str, int] = defaultdict(int)
    total_ingest_rejections_per_mode: dict[str, int] = defaultdict(int)
    for n in nodes.values():
        mode = "honest" if n.role == "honest" else (n.adversary_mode or "unknown")
        total_audits_per_mode[mode] += sum(n.audit_outcomes.values())
        total_ingest_rejections_per_mode[mode] += sum(n.ingest_rejections.values())

    lines: list[str] = []
    lines.append(f"# v12 Testnet Verification — Run {run_id}")
    lines.append("")
    lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}")
    lines.append("")
    lines.append("## Fleet composition")
    lines.append("")
    lines.append("| Mode | Slot count | Audit verdicts emitted | Ingest rejections emitted |")
    lines.append("|---|---:|---:|---:|")
    for mode in sorted({n.adversary_mode or "honest" for n in nodes.values()}):
        slots = sum(
            1
            for n in nodes.values()
            if (n.adversary_mode or "honest") == mode
        )
        lines.append(
            f"| {mode} | {slots} | {total_audits_per_mode[mode]} | {total_ingest_rejections_per_mode[mode]} |"
        )
    lines.append("")
    lines.append("## Workload performance (workload-gen)")
    lines.append("")
    if perf:
        for op, s in perf.items():
            if not s:
                lines.append(f"- **{op}**: no data")
            else:
                lines.append(
                    f"- **{op}**: success {s['success_rate']*100:.2f}% "
                    f"(n={s['n']}); p50 {s['p50_ms']} ms; p95 {s['p95_ms']} ms"
                )
    else:
        lines.append("- (no workload-gen csv supplied)")
    lines.append("")
    lines.append("## Targeted failures (by peer_hex)")
    lines.append("")
    by_target_total = sorted(
        target_failures.items(),
        key=lambda kv: kv[1].get("application_failure_total", 0),
        reverse=True,
    )[:20]
    lines.append("Top 20 peers by failure count:")
    lines.append("")
    lines.append("| Peer hex | Failures | Peer removed |")
    lines.append("|---|---:|---:|")
    for peer, counts in by_target_total:
        lines.append(
            f"| `{peer[:16]}…` | {counts.get('application_failure_total', 0)} "
            f"| {counts.get('peer_removed', 0)} |"
        )
    lines.append("")
    lines.append("## Next steps")
    lines.append("")
    lines.append("Run `success_criteria.py` against the CSVs in this directory")
    lines.append("to produce the machine-checked PASS/FAIL.")
    out_path.write_text("\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-id", required=True)
    ap.add_argument(
        "--collected-dir",
        default=None,
        help="Where v12-events-*.jsonl files live. Default: scripts/testnet-v12/collected/<run_id>",
    )
    ap.add_argument(
        "--build-dir",
        default="scripts/testnet-v12/build",
        help="Where manifest-*.json files live.",
    )
    ap.add_argument("--out-dir", default=None)
    ap.add_argument("--workload", default=None, help="Optional workload-gen CSV.")
    args = ap.parse_args()

    collected = Path(
        args.collected_dir
        or f"scripts/testnet-v12/collected/{args.run_id}"
    )
    build = Path(args.build_dir)
    out = Path(args.out_dir or collected / "analysis")
    out.mkdir(parents=True, exist_ok=True)

    print(f"Loading manifest from {build} …")
    nodes = load_manifests(build)
    print(f"Loaded {len(nodes)} node-slot records.")

    print(f"Parsing events from {collected} …")
    events = parse_events(collected, nodes)
    print(f"Read {len(events)} events.")

    populate_per_node_summaries(events, nodes)
    target_failures = compute_per_target_failures(events)
    peer_index = build_peer_hex_index(nodes)
    bound = len(peer_index)
    print(
        f"Bound {bound}/{len(nodes)} node-slots to a peer_hex via self-announce."
    )
    if bound < len(nodes):
        print(
            f"WARNING: {len(nodes) - bound} slots had no node_started event — "
            "their received-failure attribution will show role=unknown.",
            file=sys.stderr,
        )

    summary_path = build / "manifest-summary.json"
    summary_json = (
        json.loads(summary_path.read_text())
        if summary_path.exists()
        else {}
    )

    write_eviction_timeline(nodes, target_failures, events, out / "eviction-timeline.csv")
    write_attribution(nodes, target_failures, out / "attribution.csv")
    write_eviction_by_mode(target_failures, peer_index, nodes, out / "eviction-by-mode.csv")
    honest_fp = write_false_positives(
        nodes, target_failures, peer_index, out / "false-positives.csv"
    )
    print(f"Honest false positives (slots that received failures): {honest_fp}")

    workload_csv = Path(args.workload) if args.workload else None
    perf = write_honest_perf(workload_csv, out / "honest-perf.csv")

    write_verdict(
        out / "VERDICT.md", nodes, target_failures, perf, summary_json, args.run_id
    )
    print(f"Done. Output in {out}.")


if __name__ == "__main__":
    main()
