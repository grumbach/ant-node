#!/usr/bin/env bash
# Deploy v12 verification testnet to the 5 worker droplets.
#
# Assumes:
#   - terraform apply has succeeded; outputs available via
#     `terraform output -json` from scripts/testnet-v12/terraform/.
#   - build-binaries.sh ran; binaries in scripts/testnet-v12/build/.
#   - gen-manifest.py ran; manifests in scripts/testnet-v12/build/.
#
# Per worker:
#   1. rsync the two binaries + manifest.
#   2. Render systemd units (one per node slot) from the manifest.
#   3. Start the units. Bootstrap nodes (global_index 0..5) start first
#      so the rest can find them.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/../build"
TF_DIR="${SCRIPT_DIR}/../terraform"

if [[ ! -x "${BUILD_DIR}/ant-node" ]] || [[ ! -x "${BUILD_DIR}/ant-node-adversary" ]]; then
    echo "ERROR: binaries missing. Run build-binaries.sh first."
    exit 1
fi

# Local-EVM connection details (produced by deploy-evm.sh). Every node
# verifies payments against this chain via --evm-rpc-url, so payment
# verification never reaches Arbitrum mainnet.
EVM_INFO="${BUILD_DIR}/evm-info.json"
if [[ ! -s "${EVM_INFO}" ]]; then
    echo "ERROR: ${EVM_INFO} missing. Run deploy-evm.sh first."
    exit 1
fi
EVM_RPC_URL="$(jq -r .rpc_url "${EVM_INFO}")"
EVM_TOKEN="$(jq -r .payment_token_address "${EVM_INFO}")"
EVM_VAULT="$(jq -r .payment_vault_address "${EVM_INFO}")"
echo "Local EVM: rpc=${EVM_RPC_URL} token=${EVM_TOKEN} vault=${EVM_VAULT}"

# Grab the IPs from terraform outputs.
WORKER_IPS_JSON="$(cd "${TF_DIR}" && terraform output -json worker_ips)"

# go_bad_at = NOW + GO_BAD_AFTER_MIN minutes — lets the 400-node network
# form + the first commitment gossip propagate before adversaries start
# misbehaving, while keeping the control window short. Default 10 min,
# which for a 4h run leaves ~3h50m of bad behaviour: ~20+ audit ticks
# (~10 min cadence), ample time for detection + eviction to surface.
GO_BAD_AFTER_MIN="${GO_BAD_AFTER_MIN:-10}"
GO_BAD_AT=$(( $(date +%s) + GO_BAD_AFTER_MIN * 60 ))
echo "Adversary go-bad-at: $(date -d @${GO_BAD_AT} -u +%FT%TZ 2>/dev/null || date -r ${GO_BAD_AT} -u +%FT%TZ) (now+${GO_BAD_AFTER_MIN}m)"

# Bootstrap peer list — 2 bootstrap nodes each on the first 3 droplets = 6.
BOOTSTRAP_PEERS=()
for region_idx in 0 1 2; do
    region="$(jq -r ". | to_entries[${region_idx}].key" <<<"${WORKER_IPS_JSON}")"
    ip="$(jq -r ".\"${region}\"" <<<"${WORKER_IPS_JSON}")"
    BOOTSTRAP_PEERS+=("${ip}:10000")
    BOOTSTRAP_PEERS+=("${ip}:10001")
done
BOOTSTRAP_CSV="$(IFS=,; echo "${BOOTSTRAP_PEERS[*]}")"
echo "Bootstrap peers: ${BOOTSTRAP_CSV}"

# SSH key: default to the testnet key whose DO fingerprint terraform
# uploads. Override with SSH_KEY=/path/to/key.
SSH_KEY="${SSH_KEY:-${HOME}/.ssh/testnet_ed25519}"
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15)
[[ -f "${SSH_KEY}" ]] && SSH_OPTS+=(-i "${SSH_KEY}")

deploy_one_worker() {
    local region="$1"
    local ip="$2"
    local manifest="${BUILD_DIR}/manifest-${region}.json"
    if [[ ! -f "${manifest}" ]]; then
        echo "ERROR: ${manifest} missing"
        return 1
    fi
    echo "=== Deploying to ${region} (${ip}) ==="

    # 1. Upload binaries + manifest.
    rsync -az -e "ssh ${SSH_OPTS[*]}" \
        "${BUILD_DIR}/ant-node" \
        "${BUILD_DIR}/ant-node-adversary" \
        "${manifest}" \
        "root@${ip}:/usr/local/bin/"

    # 2. Render systemd units + start.
    ssh "${SSH_OPTS[@]}" "root@${ip}" "GO_BAD_AT=${GO_BAD_AT} BOOTSTRAP_CSV='${BOOTSTRAP_CSV}' EVM_RPC_URL='${EVM_RPC_URL}' EVM_TOKEN='${EVM_TOKEN}' EVM_VAULT='${EVM_VAULT}' bash -s" <<'REMOTE'
set -euo pipefail
MANIFEST_FILE=$(ls /usr/local/bin/manifest-*.json | head -n1)
chmod +x /usr/local/bin/ant-node /usr/local/bin/ant-node-adversary

# Render one systemd unit per node-slot in the manifest.
jq -c '.nodes[]' "${MANIFEST_FILE}" | while read -r row; do
    GLOBAL_IDX=$(jq -r '.global_index' <<<"${row}")
    NODE_IDX=$(jq -r '.node_index' <<<"${row}")
    PORT=$(jq -r '.port' <<<"${row}")
    ROLE=$(jq -r '.role' <<<"${row}")
    MODE=$(jq -r '.adversary_mode // ""' <<<"${row}")
    IS_BOOTSTRAP=$(jq -r '.is_bootstrap' <<<"${row}")

    if [[ "${ROLE}" == "adversary" ]]; then
        BIN=/usr/local/bin/ant-node-adversary
        EXTRA_ENV="Environment=ANT_ADVERSARY_MODE=${MODE}
Environment=ANT_ADVERSARY_GO_BAD_AT_UNIX_SEC=${GO_BAD_AT}"
    else
        BIN=/usr/local/bin/ant-node
        EXTRA_ENV=""
    fi
    # Bootstrap nodes start with no bootstrap peers (they ARE bootstrap).
    # Non-bootstrap nodes get repeated --bootstrap <addr> flags (the
    # clap Vec<SocketAddr> parser requires one flag per entry; ANT_BOOTSTRAP
    # env var only accepts a single addr).
    if [[ "${IS_BOOTSTRAP}" == "true" ]]; then
        BOOT_ARG_LINE=""
    else
        # Build repeated --bootstrap flags
        BOOT_ARG_LINE=""
        IFS=',' read -ra ADDRS <<<"${BOOTSTRAP_CSV}"
        for addr in "${ADDRS[@]}"; do
            BOOT_ARG_LINE="${BOOT_ARG_LINE} --bootstrap ${addr}"
        done
    fi

    LOG_PATH="/var/log/ant-nodes/v12-events-${GLOBAL_IDX}.jsonl"
    DATA_DIR="/var/lib/ant-nodes/node-${GLOBAL_IDX}"
    mkdir -p "$(dirname "${LOG_PATH}")" "${DATA_DIR}"

    cat > "/etc/systemd/system/antnode-${GLOBAL_IDX}.service" <<UNIT
[Unit]
Description=ant-node ${GLOBAL_IDX} (${ROLE}${MODE:+/${MODE}})
After=network.target

[Service]
Type=simple
ExecStart=${BIN} --port ${PORT} --root-dir ${DATA_DIR}${BOOT_ARG_LINE} --enable-logging --log-format json --log-dir /var/log/ant-nodes/node-${GLOBAL_IDX} --network-mode testnet --rewards-address 0xEaA8517B1b7AE0DA592331Fb7fE8760365B9A2A0 --evm-rpc-url ${EVM_RPC_URL} --evm-payment-token ${EVM_TOKEN} --evm-payment-vault ${EVM_VAULT}
Environment=ANT_V12_EVENT_LOG=${LOG_PATH}
${EXTRA_ENV}
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
UNIT
done

systemctl daemon-reload

# Start bootstrap nodes first.
for idx in $(jq -r '.nodes[] | select(.is_bootstrap) | .global_index' "${MANIFEST_FILE}"); do
    systemctl enable --now "antnode-${idx}.service" || true
done
sleep 5
# Then everybody else.
for idx in $(jq -r '.nodes[] | select(.is_bootstrap | not) | .global_index' "${MANIFEST_FILE}"); do
    systemctl enable --now "antnode-${idx}.service" || true
done

echo "Started $(jq '.nodes | length' "${MANIFEST_FILE}") node-slot units on $(hostname)"
REMOTE
}

# Sequential deploy so failures are easy to debug. ~1 min per droplet.
for row in $(jq -c 'to_entries | .[]' <<<"${WORKER_IPS_JSON}"); do
    REGION=$(jq -r '.key' <<<"${row}")
    IP=$(jq -r '.value' <<<"${row}")
    deploy_one_worker "${REGION}" "${IP}"
done

echo
echo "All workers deployed. Adversary nodes will turn on at $(date -d @${GO_BAD_AT} -u +%FT%TZ 2>/dev/null || date -r ${GO_BAD_AT} -u +%FT%TZ)."
