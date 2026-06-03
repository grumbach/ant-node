#!/usr/bin/env python3
"""Generate per-droplet node manifests for the v12 verification testnet.

Output: one JSON file per worker droplet (in `scripts/testnet-v12/build/`)
describing each of the 80 node slots:
  - whether it's honest or adversary
  - if adversary, which mode
  - port (10000 + idx)
  - whether it's a bootstrap node (first 6 nodes overall — always honest)

Adversary share is `--adversary-share` (0.07 for run A, 0.22 for run B).
Modes within the adversary set use the per-mode weights below so each
attack class gets ~equal representation.

Usage:
  gen-manifest.py --run-id A --adversary-share 0.07
  gen-manifest.py --run-id B --adversary-share 0.22
"""

from __future__ import annotations

import argparse
import json
import random
from dataclasses import asdict, dataclass
from pathlib import Path

REGIONS = ["nyc1", "sfo3", "lon1", "ams3", "sgp1"]
NODES_PER_DROPLET = 80
TOTAL_NODES = NODES_PER_DROPLET * len(REGIONS)
BOOTSTRAP_COUNT = 6  # always honest, fixed across runs

# Per-mode share of the adversary cohort. Sums to 1.0.
#
# Run "relay-10pct": 400 nodes, --adversary-share 0.10 => 40 bad (10%).
# relay weighted at 0.50 => exactly 20 relay nodes = 5% of the fleet =
# half the adversaries (the relay attack this PR's audit-timeout defence
# targets: nodes that don't store, just relay from neighbours at audit
# time). The pre-trim weighted pool lands on exactly 40 for these
# weights, so the split is deterministic with no rounding drift:
#   relay 20, lazy 4, chunk-deleter 4, silent 4, fake-storage 4,
#   throwaway-key 2, bootstrap-shield 2.
ADVERSARY_MODE_WEIGHTS = {
    "relay": 0.50,
    "lazy": 0.10,
    "chunk-deleter": 0.10,
    "silent": 0.10,
    "fake-storage": 0.10,
    "throwaway-key": 0.05,
    "bootstrap-shield": 0.05,
}


@dataclass
class NodeSlot:
    """One node-slot on one droplet. Maps to a single systemd unit."""

    droplet_index: int  # 0..4
    droplet_region: str
    node_index: int  # 0..79 within droplet
    global_index: int  # 0..399 across the whole fleet
    port: int  # 10000..10079
    role: str  # "honest" | "adversary"
    adversary_mode: str | None  # if role == adversary
    is_bootstrap: bool


def assign_adversary_modes(
    seed: int, share: float
) -> dict[int, str | None]:
    """Map global_index → adversary mode (or None for honest)."""
    rng = random.Random(seed)
    target = int(TOTAL_NODES * share)
    # Bootstrap nodes (0..BOOTSTRAP_COUNT-1) are always honest.
    candidate = list(range(BOOTSTRAP_COUNT, TOTAL_NODES))
    rng.shuffle(candidate)
    adversary_indices = candidate[:target]

    # Now distribute the target across modes per weights.
    weighted_pool: list[str] = []
    for mode, w in ADVERSARY_MODE_WEIGHTS.items():
        count = max(1, int(round(target * w)))
        weighted_pool.extend([mode] * count)
    # Trim or pad to exactly `target`.
    rng.shuffle(weighted_pool)
    weighted_pool = weighted_pool[:target]
    while len(weighted_pool) < target:
        weighted_pool.append("lazy")

    mode_by_idx: dict[int, str | None] = {i: None for i in range(TOTAL_NODES)}
    for idx, mode in zip(adversary_indices, weighted_pool):
        mode_by_idx[idx] = mode
    return mode_by_idx


def build_manifest(seed: int, share: float) -> list[NodeSlot]:
    """Build the 400-slot manifest deterministically from seed."""
    mode_by_idx = assign_adversary_modes(seed, share)
    slots: list[NodeSlot] = []
    for droplet_index, region in enumerate(REGIONS):
        for node_index in range(NODES_PER_DROPLET):
            global_index = droplet_index * NODES_PER_DROPLET + node_index
            mode = mode_by_idx[global_index]
            slot = NodeSlot(
                droplet_index=droplet_index,
                droplet_region=region,
                node_index=node_index,
                global_index=global_index,
                port=10000 + node_index,
                role="adversary" if mode else "honest",
                adversary_mode=mode,
                is_bootstrap=global_index < BOOTSTRAP_COUNT,
            )
            slots.append(slot)
    return slots


def write_per_droplet(slots: list[NodeSlot], out_dir: Path) -> None:
    """Split the manifest into 5 per-droplet JSON files."""
    out_dir.mkdir(parents=True, exist_ok=True)
    for droplet_index, region in enumerate(REGIONS):
        per = [s for s in slots if s.droplet_index == droplet_index]
        path = out_dir / f"manifest-{region}.json"
        with path.open("w") as f:
            json.dump(
                {
                    "droplet_index": droplet_index,
                    "region": region,
                    "nodes": [asdict(s) for s in per],
                },
                f,
                indent=2,
            )


def write_summary(slots: list[NodeSlot], out_dir: Path) -> None:
    """One global summary file for the runbook / analysis script."""
    summary: dict[str, int] = {"honest": 0}
    for mode in ADVERSARY_MODE_WEIGHTS:
        summary[mode] = 0
    for s in slots:
        if s.adversary_mode is None:
            summary["honest"] += 1
        else:
            summary[s.adversary_mode] += 1
    summary["total"] = len(slots)
    summary["bootstrap"] = sum(1 for s in slots if s.is_bootstrap)
    with (out_dir / "manifest-summary.json").open("w") as f:
        json.dump(summary, f, indent=2)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-id", required=True, help="Short label, e.g. A or B")
    ap.add_argument(
        "--adversary-share",
        type=float,
        required=True,
        help="Fraction of nodes that are adversary (0.07 for run A, 0.22 for run B)",
    )
    ap.add_argument(
        "--seed",
        type=int,
        default=42,
        help="RNG seed — keep fixed across runs so the same logical peer "
        "stays in the same mode for regression analysis.",
    )
    ap.add_argument(
        "--out-dir",
        default="scripts/testnet-v12/build",
        help="Where to drop the manifest JSON files.",
    )
    args = ap.parse_args()

    slots = build_manifest(args.seed, args.adversary_share)
    out_dir = Path(args.out_dir)
    write_per_droplet(slots, out_dir)
    write_summary(slots, out_dir)
    summary = json.loads((out_dir / "manifest-summary.json").read_text())
    print(f"Run {args.run_id}: {summary}")


if __name__ == "__main__":
    main()
