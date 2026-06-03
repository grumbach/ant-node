#!/usr/bin/env bash
# Stand up the local-EVM host on the `evm` droplet and capture its
# connection details for the node + workload deploy steps.
#
# Must run BEFORE deploy-workers.sh and deploy-workload.sh: those read
# the EVM info file this script produces.
#
# Steps:
#   1. rsync the ant-evm-testnet binary to the evm droplet.
#   2. Start it under systemd, bound to 0.0.0.0:8545, deploying the ANT
#      token + payment vault.
#   3. Pull back the emitted JSON, rewrite the 0.0.0.0 bind host to the
#      droplet's reachable public IP, and write it to
#      build/evm-info.json (consumed by the other deploy scripts).
#
# Idempotent: re-running restarts the chain (a fresh chain means fresh
# contract addresses, so always re-run the node/workload deploy after).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/../build"
TF_DIR="${SCRIPT_DIR}/../terraform"
EVM_PORT="${EVM_PORT:-8545}"

if [[ ! -x "${BUILD_DIR}/ant-evm-testnet" ]]; then
    echo "ERROR: ${BUILD_DIR}/ant-evm-testnet missing. Run build-binaries.sh first."
    exit 1
fi

EVM_IP="$(cd "${TF_DIR}" && terraform output -raw evm_ip)"
echo "=== Deploying local EVM to ${EVM_IP}:${EVM_PORT} ==="

SSH_KEY="${SSH_KEY:-${HOME}/.ssh/testnet_ed25519}"
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15)
[[ -f "${SSH_KEY}" ]] && SSH_OPTS+=(-i "${SSH_KEY}")

# 1. Upload the binary.
rsync -az -e "ssh ${SSH_OPTS[*]}" \
    "${BUILD_DIR}/ant-evm-testnet" \
    "root@${EVM_IP}:/usr/local/bin/"

# 2. Start it under systemd. Wait for anvil (foundry) to be present (the
#    cloud-init install may still be finishing on a fresh droplet).
ssh "${SSH_OPTS[@]}" "root@${EVM_IP}" "EVM_PORT=${EVM_PORT} bash -s" <<'REMOTE'
set -euo pipefail
chmod +x /usr/local/bin/ant-evm-testnet
mkdir -p /var/lib/ant-evm

# Make sure anvil is installed (terraform user_data installs Foundry;
# guard against a slow cloud-init by installing here if missing).
if ! command -v anvil >/dev/null 2>&1 && [[ ! -x /root/.foundry/bin/anvil ]]; then
    echo "anvil not found yet; installing Foundry…"
    export HOME=/root
    curl -L https://foundry.paradigm.xyz | bash
    /root/.foundry/bin/foundryup
    ln -sf /root/.foundry/bin/anvil /usr/local/bin/anvil
fi

cat > /etc/systemd/system/ant-evm.service <<UNIT
[Unit]
Description=v12 local EVM host (Anvil + ANT token + payment vault)
After=network.target

[Service]
Type=simple
Environment=ANVIL_IP_ADDR=0.0.0.0
Environment=ANVIL_PORT=${EVM_PORT}
Environment=PATH=/root/.foundry/bin:/usr/local/bin:/usr/bin:/bin
ExecStart=/usr/local/bin/ant-evm-testnet --out /var/lib/ant-evm/evm-info.json
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now ant-evm.service

# Wait for the info file (contract deploy takes a few seconds).
for i in $(seq 1 60); do
    [[ -s /var/lib/ant-evm/evm-info.json ]] && break
    sleep 2
done
if [[ ! -s /var/lib/ant-evm/evm-info.json ]]; then
    echo "ERROR: EVM info file never appeared; service logs:"
    journalctl -u ant-evm.service --no-pager | tail -40
    exit 1
fi
echo "EVM info ready:"
cat /var/lib/ant-evm/evm-info.json
REMOTE

# 3. Pull the info file and rewrite the bind host (0.0.0.0) to the
#    droplet's reachable public IP so nodes can dial it.
mkdir -p "${BUILD_DIR}"
rsync -az -e "ssh ${SSH_OPTS[*]}" \
    "root@${EVM_IP}:/var/lib/ant-evm/evm-info.json" \
    "${BUILD_DIR}/evm-info.raw.json"

jq --arg ip "${EVM_IP}" --arg port "${EVM_PORT}" \
    '.rpc_url = "http://\($ip):\($port)/"' \
    "${BUILD_DIR}/evm-info.raw.json" > "${BUILD_DIR}/evm-info.json"

echo
echo "=== Local EVM ready ==="
echo "  RPC:   $(jq -r .rpc_url "${BUILD_DIR}/evm-info.json")"
echo "  token: $(jq -r .payment_token_address "${BUILD_DIR}/evm-info.json")"
echo "  vault: $(jq -r .payment_vault_address "${BUILD_DIR}/evm-info.json")"
echo "Info written to ${BUILD_DIR}/evm-info.json (consumed by deploy-workers.sh + deploy-workload.sh)."
