#!/usr/bin/env bash
# v12 storage-bound-audit verification testnet — single GO entry point.
#
# One command stands up the whole run and produces a PASS/FAIL verdict:
#   1. terraform apply         — 5 workers + monitor + client + EVM droplet
#   2. deploy-evm.sh           — local Anvil chain + ANT token/vault
#   3. gen-manifest.py         — 400-slot manifest (10% adversary)
#   4. deploy-workers.sh       — 400 ant-node services (honest + adversary)
#   5. deploy-workload.sh      — upload/download workload (pays via local EVM)
#   6. collect-logs.sh         — continuous log pull for DURATION
#   7. pull-workload + analyse — produce CSVs + VERDICT.md + PASS/FAIL
#
# Prerequisites (fail fast below if missing):
#   - terraform, jq, ssh, rsync, python3 installed locally.
#   - TF_VAR_do_token       — DigitalOcean API token.
#   - TF_VAR_ssh_key_fingerprint — fingerprint of an SSH key on the DO account.
#   - build/ant, build/ant-node, build/ant-node-adversary, build/ant-evm-testnet
#     present (run deploy/build-binaries.sh first; the ant client comes from
#     ../../../ant-client).
#
# Tunables (env):
#   RUN_ID            run label / droplet prefix          (default v12verify)
#   ADVERSARY_SHARE   fraction of nodes that are bad       (default 0.10)
#   DURATION_SEC      workload + collection duration       (default 14400 = 4h)
#   GO_BAD_AFTER_MIN  minutes before adversaries misbehave (default 10)
#   FORM_WAIT_SEC     pause after worker deploy before workload (default 180)
#
# This script does NOT run terraform destroy. Tear down with
# deploy/teardown.sh when you've pulled everything you need.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TF_DIR="${SCRIPT_DIR}/terraform"
BUILD_DIR="${SCRIPT_DIR}/build"
DEPLOY="${SCRIPT_DIR}/deploy"
WORKLOAD="${SCRIPT_DIR}/workload"
ANALYSIS="${SCRIPT_DIR}/analysis"

RUN_ID="${RUN_ID:-v12verify}"
ADVERSARY_SHARE="${ADVERSARY_SHARE:-0.10}"
DURATION_SEC="${DURATION_SEC:-14400}"
GO_BAD_AFTER_MIN="${GO_BAD_AFTER_MIN:-10}"
FORM_WAIT_SEC="${FORM_WAIT_SEC:-180}"

export RUN_ID DURATION_SEC GO_BAD_AFTER_MIN

log() { echo; echo "============================================================"; echo "  $*"; echo "============================================================"; }

# ---- Preflight -----------------------------------------------------------
log "Preflight checks"
for tool in terraform jq ssh rsync python3; do
    command -v "${tool}" >/dev/null 2>&1 || { echo "MISSING tool: ${tool}"; exit 1; }
done

# Auto-load the DO token from the saorsa secrets file if not already in
# the environment (DIGITALOCEAN_TOKEN in claude_secrets.md / .env.testnet).
SECRETS_FILE="${SECRETS_FILE:-${SCRIPT_DIR}/../../../claude_secrets.md}"
if [[ -z "${TF_VAR_do_token:-}" && -f "${SECRETS_FILE}" ]]; then
    TF_VAR_do_token="$(grep -m1 '^DIGITALOCEAN_TOKEN=' "${SECRETS_FILE}" | cut -d= -f2-)"
    export TF_VAR_do_token
fi
# SSH key fingerprint: default to the `anselme-testnet-2026` DO key,
# whose private half is ~/.ssh/testnet_ed25519. Override via env.
TF_VAR_ssh_key_fingerprint="${TF_VAR_ssh_key_fingerprint:-a4:2d:e7:e2:b6:33:7a:3f:c9:c4:a4:12:0c:6c:28:6b}"
export TF_VAR_ssh_key_fingerprint
SSH_KEY="${SSH_KEY:-${HOME}/.ssh/testnet_ed25519}"
export SSH_KEY

: "${TF_VAR_do_token:?Set TF_VAR_do_token (DigitalOcean API token) or provide ${SECRETS_FILE}}"
[[ -f "${SSH_KEY}" ]] || echo "WARNING: ${SSH_KEY} not found — SSH to droplets may fail. Set SSH_KEY=..."
for b in ant ant-node ant-node-adversary ant-evm-testnet; do
    [[ -x "${BUILD_DIR}/${b}" ]] || { echo "MISSING binary: ${BUILD_DIR}/${b} (run deploy/build-binaries.sh)"; exit 1; }
done
echo "OK. RUN_ID=${RUN_ID} adversary_share=${ADVERSARY_SHARE} duration=${DURATION_SEC}s go_bad_after=${GO_BAD_AFTER_MIN}m"

# ---- 1. terraform --------------------------------------------------------
log "1/7 terraform apply"
( cd "${TF_DIR}" && terraform init -input=false && terraform apply -auto-approve -var "run_id=${RUN_ID}" )
echo "Droplets up. Giving cloud-init ~60s to install packages + Foundry…"
python3 -c 'import time; time.sleep(60)'

# ---- 2. local EVM --------------------------------------------------------
log "2/7 deploy local EVM (Anvil + contracts)"
bash "${DEPLOY}/deploy-evm.sh"

# ---- 3. manifest ---------------------------------------------------------
log "3/7 generate node manifest (${ADVERSARY_SHARE} adversary)"
( cd "${SCRIPT_DIR}/.." && python3 "${DEPLOY}/gen-manifest.py" --run-id "${RUN_ID}" --adversary-share "${ADVERSARY_SHARE}" --out-dir "${BUILD_DIR}" )

# ---- 4. workers ----------------------------------------------------------
log "4/7 deploy 400 ant-node services"
bash "${DEPLOY}/deploy-workers.sh"
echo "Letting the network form for ${FORM_WAIT_SEC}s before starting the workload…"
python3 -c "import time; time.sleep(${FORM_WAIT_SEC})"

# ---- 5. workload ---------------------------------------------------------
log "5/7 deploy workload generator"
bash "${WORKLOAD}/deploy-workload.sh"

# ---- 6. collection -------------------------------------------------------
log "6/7 collect logs for ${DURATION_SEC}s (continuous, 60s interval)"
# Run collection in the foreground for the whole window so the run is a
# single blocking command. Ctrl-C stops collection early (the testnet
# keeps running; re-run collect-logs.sh / analyse manually if so).
COLLECT_DEADLINE=$(( $(date +%s) + DURATION_SEC ))
while [[ $(date +%s) -lt ${COLLECT_DEADLINE} ]]; do
    RUN_ID="${RUN_ID}" bash "${DEPLOY}/collect-logs.sh" || true
    remaining=$(( COLLECT_DEADLINE - $(date +%s) ))
    echo "  …collected; ${remaining}s remaining"
    [[ ${remaining} -le 0 ]] && break
    python3 -c "import time; time.sleep(min(60, ${remaining}))"
done

# ---- 7. pull + analyse ---------------------------------------------------
log "7/7 pull workload CSV + analyse"
RUN_ID="${RUN_ID}" bash "${WORKLOAD}/pull-workload.sh" || true
WORKLOAD_CSV="${SCRIPT_DIR}/collected/${RUN_ID}/workload.csv"
( cd "${SCRIPT_DIR}/.." && python3 "${ANALYSIS}/analyse.py" \
    --run-id "${RUN_ID}" \
    --collected-dir "${SCRIPT_DIR}/collected/${RUN_ID}" \
    --build-dir "${BUILD_DIR}" \
    --workload "${WORKLOAD_CSV}" )

ANALYSIS_OUT="${SCRIPT_DIR}/collected/${RUN_ID}/analysis"
log "VERDICT"
python3 "${ANALYSIS}/success_criteria.py" --analysis-dir "${ANALYSIS_OUT}"
VERDICT_RC=$?

echo
echo "Artifacts:"
echo "  Verdict markdown : ${ANALYSIS_OUT}/VERDICT.md"
echo "  Eviction by mode : ${ANALYSIS_OUT}/eviction-by-mode.csv"
echo "  False positives  : ${ANALYSIS_OUT}/false-positives.csv"
echo "  Attribution      : ${ANALYSIS_OUT}/attribution.csv"
echo "  Raw event logs   : ${SCRIPT_DIR}/collected/${RUN_ID}/"
echo
echo "Testnet droplets are STILL RUNNING. Tear down with: bash ${DEPLOY}/teardown.sh"
exit ${VERDICT_RC}
