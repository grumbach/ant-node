#!/usr/bin/env bash
# rsync v12 event logs from every worker to the monitor droplet.
#
# Intended to run as a background task on the local machine OR as a
# cron on the monitor itself. Default: pull-mode from local (simpler;
# no need to install ssh keys on the monitor).
#
# Output layout on the puller's local disk:
#   collected/{run_id}/{region}/v12-events-{global_idx}.jsonl
#
# If `--continuous` is passed, the script loops forever with a 60s
# interval until SIGINT.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TF_DIR="${SCRIPT_DIR}/../terraform"
RUN_ID="${RUN_ID:-v12verify}"
LOCAL_BASE="${LOCAL_BASE:-${SCRIPT_DIR}/../collected/${RUN_ID}}"

CONTINUOUS=0
if [[ "${1:-}" == "--continuous" ]]; then
    CONTINUOUS=1
fi

mkdir -p "${LOCAL_BASE}"
SSH_KEY="${SSH_KEY:-${HOME}/.ssh/testnet_ed25519}"
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15)
[[ -f "${SSH_KEY}" ]] && SSH_OPTS+=(-i "${SSH_KEY}")

WORKER_IPS_JSON="$(cd "${TF_DIR}" && terraform output -json worker_ips)"

pull_once() {
    for row in $(jq -c 'to_entries | .[]' <<<"${WORKER_IPS_JSON}"); do
        REGION=$(jq -r '.key' <<<"${row}")
        IP=$(jq -r '.value' <<<"${row}")
        DEST="${LOCAL_BASE}/${REGION}"
        mkdir -p "${DEST}"
        # Pull both the v12 event JSONL files and the ant-node tracing
        # logs (the latter for ad-hoc forensics if attribution gets
        # confusing).
        rsync -az --partial -e "ssh ${SSH_OPTS[*]}" \
            "root@${IP}:/var/log/ant-nodes/v12-events-*.jsonl" \
            "${DEST}/" 2>/dev/null || true
    done
}

if [[ ${CONTINUOUS} -eq 1 ]]; then
    echo "Continuous-mode log collection. Ctrl-C to stop."
    trap 'echo; echo "Stopped."; exit 0' INT
    while true; do
        pull_once
        sleep 60
    done
else
    pull_once
    echo "Logs pulled to ${LOCAL_BASE}"
    echo "(Run with --continuous to keep pulling every 60s.)"
fi
