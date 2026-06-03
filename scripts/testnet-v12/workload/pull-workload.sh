#!/usr/bin/env bash
# Pull the workload-gen CSV back from the client droplet.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TF_DIR="${SCRIPT_DIR}/../terraform"
RUN_ID="${RUN_ID:-v12verify}"
DEST="${SCRIPT_DIR}/../collected/${RUN_ID}/workload.csv"

CLIENT_IP="$(cd "${TF_DIR}" && terraform output -raw client_ip)"
mkdir -p "$(dirname "${DEST}")"

SSH_KEY="${SSH_KEY:-${HOME}/.ssh/testnet_ed25519}"
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15)
[[ -f "${SSH_KEY}" ]] && SSH_OPTS+=(-i "${SSH_KEY}")
rsync -az -e "ssh ${SSH_OPTS[*]}" "root@${CLIENT_IP}:/var/log/v12-workload.csv" "${DEST}"
echo "Workload CSV → ${DEST}"
wc -l "${DEST}"
