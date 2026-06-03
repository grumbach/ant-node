# v12 storage-bound audit — large-testnet verification harness

Confirms PR #113 (storage-bound audit) **evicts misbehaving nodes** while
**never penalising honest ones**, on a 400-node DigitalOcean network with
~10% adversaries, paying against a **local Anvil EVM** (no Arbitrum).

## What it proves

For each adversary mode, the run answers two questions automatically:

1. **Detection/eviction** — did v12 produce a confirmed audit failure
   (and ideally an RT removal) against the bad slots?  (`P1b`)
2. **No false positives** — did any *honest* slot receive a confirmed
   failure or get RT-removed?  Must be zero.  (`P2`)

Plus workload health: upload ≥95%, download ≥99% success (`P3`).

The peer↔slot binding that makes this airtight comes from a
`node_started` self-announce event each node emits at startup (binds its
`peer_hex` to its `global_index`/role). No manual cross-referencing.

## Fleet

| Component | Count | Size | Notes |
|---|---|---|---|
| workers | 5 | s-8vcpu-16gb | 80 ant-node services each = 400 |
| monitor | 1 | s-2vcpu-4gb | log target |
| client  | 1 | s-2vcpu-4gb | runs the workload |
| evm     | 1 | s-2vcpu-4gb | local Anvil + ANT token/vault |

Adversary split (10%, deterministic seed): relay 20, lazy 4,
chunk-deleter 4, silent 4, fake-storage 4, throwaway-key 2,
bootstrap-shield 2. Bootstrap nodes (6) are always honest.

## Binaries (built by `deploy/build-binaries.sh`, linux-musl)

- `ant-node` — honest node, `--features v12-event-log`.
- `ant-node-adversary` — `--features adversary,v12-event-log`.
- `ant-evm-testnet` — `--features evm-host`; stands up Anvil + deploys
  the ANT token + payment vault, emits connection JSON.
- `ant` — the client (built from `../../../ant-client`, musl).

All four must be present in `build/` before a run.

## Prerequisites

- `terraform`, `jq`, `ssh`, `rsync`, `python3` locally.
- Docker running locally **only if cross-building** binaries on macOS
  (`build-binaries.sh` uses `cross`). Not needed at run time.
- Env: `TF_VAR_do_token` (DO API token) and `TF_VAR_ssh_key_fingerprint`
  (an SSH key already on the DO account). The EVM VM installs Foundry
  (anvil) itself at boot.

## One-command run

```bash
export TF_VAR_do_token=...           # from .env.testnet DIGITALOCEAN_TOKEN
export TF_VAR_ssh_key_fingerprint=...
bash scripts/testnet-v12/run-testnet.sh
```

Tunables (env): `RUN_ID` (v12verify), `ADVERSARY_SHARE` (0.10),
`DURATION_SEC` (14400 = 4h), `GO_BAD_AFTER_MIN` (10), `FORM_WAIT_SEC`
(180). The script blocks for the whole window, then prints the verdict
and leaves the droplets up. Tear down with `deploy/teardown.sh`.

## Manual steps (what run-testnet.sh chains)

```bash
cd scripts/testnet-v12
( cd terraform && terraform apply -auto-approve -var run_id=v12verify )
bash deploy/deploy-evm.sh                                   # local EVM first
python3 deploy/gen-manifest.py --run-id v12verify --adversary-share 0.10 \
    --out-dir build
bash deploy/deploy-workers.sh                               # 400 nodes
bash workload/deploy-workload.sh                            # paying workload
RUN_ID=v12verify bash deploy/collect-logs.sh --continuous   # logs (Ctrl-C to stop)
RUN_ID=v12verify bash workload/pull-workload.sh
python3 analysis/analyse.py --run-id v12verify \
    --collected-dir collected/v12verify --build-dir build \
    --workload collected/v12verify/workload.csv
python3 analysis/success_criteria.py \
    --analysis-dir collected/v12verify/analysis            # PASS/FAIL
```

`deploy-evm.sh` MUST run before workers/workload — both read the EVM
connection details it writes to `build/evm-info.json`. Nodes get
`--evm-rpc-url/--evm-payment-token/--evm-payment-vault`; the client gets
`--evm-network local --devnet-manifest …` plus the funded `SECRET_KEY`.

## Outputs (`collected/<run_id>/analysis/`)

- `VERDICT.md` — human summary (fleet, workload, top failed peers).
- `eviction-by-mode.csv` — **headline**: slots / slots_with_failure /
  slots_peer_removed / failure_events, per mode. Honest row should be all
  zeros after the failure columns.
- `false-positives.csv` — every peer that took a failure, resolved to
  global_index + role. Any `role=honest` row is a P2 failure.
- `attribution.csv` — per-mode audit verdicts emitted (auditor side).
- `eviction-by-peer-hex.csv` — raw per-peer failure counts.
- `honest-perf.csv` — workload success rates + latencies.

## Production safety

All instrumentation is behind `cfg(feature = "v12-event-log")`,
adversary behaviour behind `cfg(feature = "adversary")`, and the EVM host
behind `evm-host` — none are in `default`. A default/release build is
byte-identical to before this harness existed (verified: the production
`ant-node` binary contains no `node_started`/`ANT_V12_EVENT_LOG` strings).
