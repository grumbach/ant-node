#!/usr/bin/env bash
# Deploy the workload generator to the client droplet and start it as
# a systemd service. Assumes:
#   - terraform apply has succeeded.
#   - `ant` binary is available at scripts/testnet-v12/build/ant
#     (caller produces it via `cargo build --release --bin ant` in
#      ../ant-client/ant-cli; we don't build it here to keep the
#     workspace boundary clean).
#   - The fleet has been up for at least a couple minutes so the
#     bootstrap peers respond.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TF_DIR="${SCRIPT_DIR}/../terraform"
BUILD_DIR="${SCRIPT_DIR}/../build"
DURATION_SEC="${DURATION_SEC:-14400}"  # 4h default (override via env)

if [[ ! -x "${BUILD_DIR}/ant" ]]; then
    echo "ERROR: ${BUILD_DIR}/ant not found."
    echo "Build it with:"
    echo "  (cd ../ant-client && cargo build --release --target x86_64-unknown-linux-musl --bin ant)"
    echo "  cp ../ant-client/target/x86_64-unknown-linux-musl/release/ant ${BUILD_DIR}/ant"
    exit 1
fi

# Local-EVM info (from deploy-evm.sh): the client pays for uploads, so it
# needs the funded key + a DevnetManifest pointing at the local chain.
EVM_INFO="${BUILD_DIR}/evm-info.json"
if [[ ! -s "${EVM_INFO}" ]]; then
    echo "ERROR: ${EVM_INFO} missing. Run deploy-evm.sh first."
    exit 1
fi
SECRET_KEY="$(jq -r .funded_private_key "${EVM_INFO}")"

CLIENT_IP="$(cd "${TF_DIR}" && terraform output -raw client_ip)"
WORKER_IPS_JSON="$(cd "${TF_DIR}" && terraform output -json worker_ips)"

# Use the first two worker droplets as bootstrap peers — they have
# node 0 and 1 running on port 10000 and 10001 respectively.
B0_REGION="$(jq -r '. | to_entries[0].key' <<<"${WORKER_IPS_JSON}")"
B1_REGION="$(jq -r '. | to_entries[1].key' <<<"${WORKER_IPS_JSON}")"
B0_IP="$(jq -r ".\"${B0_REGION}\"" <<<"${WORKER_IPS_JSON}")"
B1_IP="$(jq -r ".\"${B1_REGION}\"" <<<"${WORKER_IPS_JSON}")"
BOOTSTRAP_CSV="${B0_IP}:10000,${B1_IP}:10000"

echo "Client: ${CLIENT_IP}, bootstrap: ${BOOTSTRAP_CSV}, duration: ${DURATION_SEC}s"

# Build the DevnetManifest the `ant` client expects for --evm-network
# local. Bootstrap is supplied via the CLI flag (which takes priority),
# so the manifest's bootstrap list can stay empty.
DEVNET_MANIFEST="${BUILD_DIR}/devnet-manifest.json"
jq -n \
    --slurpfile evm "${EVM_INFO}" \
    '{
        base_port: 10000,
        node_count: 0,
        bootstrap: [],
        data_dir: "/var/lib/ant-workload",
        created_at: "v12verify",
        evm: {
            rpc_url: $evm[0].rpc_url,
            wallet_private_key: $evm[0].funded_private_key,
            payment_token_address: $evm[0].payment_token_address,
            payment_vault_address: $evm[0].payment_vault_address
        }
    }' > "${DEVNET_MANIFEST}"

SSH_KEY="${SSH_KEY:-${HOME}/.ssh/testnet_ed25519}"
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15)
[[ -f "${SSH_KEY}" ]] && SSH_OPTS+=(-i "${SSH_KEY}")

# Upload ant binary + workload-gen script + devnet manifest.
rsync -az -e "ssh ${SSH_OPTS[*]}" \
    "${BUILD_DIR}/ant" \
    "${SCRIPT_DIR}/workload-gen.py" \
    "${DEVNET_MANIFEST}" \
    "root@${CLIENT_IP}:/usr/local/bin/"

ssh "${SSH_OPTS[@]}" "root@${CLIENT_IP}" "BOOTSTRAP_CSV='${BOOTSTRAP_CSV}' DURATION_SEC=${DURATION_SEC} SECRET_KEY='${SECRET_KEY}' bash -s" <<'REMOTE'
set -euo pipefail
chmod +x /usr/local/bin/ant /usr/local/bin/workload-gen.py

cat > /etc/systemd/system/v12-workload.service <<UNIT
[Unit]
Description=v12 verification workload generator
After=network.target

[Service]
Type=simple
# ant-core resolves its data/config dir from HOME (panics with
# HomeDirNotFound otherwise); systemd starts with no HOME, so set it.
Environment=HOME=/root
Environment=XDG_DATA_HOME=/root/.local/share
Environment=XDG_CONFIG_HOME=/root/.config
Environment=SECRET_KEY=${SECRET_KEY}
ExecStart=/usr/local/bin/workload-gen.py --ant-bin /usr/local/bin/ant --bootstrap ${BOOTSTRAP_CSV} --devnet-manifest /usr/local/bin/devnet-manifest.json --csv /var/log/v12-workload.csv --duration ${DURATION_SEC}
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now v12-workload.service
echo "v12-workload.service started; CSV at /var/log/v12-workload.csv"
REMOTE
