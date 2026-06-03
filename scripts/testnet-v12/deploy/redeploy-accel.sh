#!/usr/bin/env bash
# Fast in-place redeploy: swap the freshly-built node binaries onto every
# worker and inject the time-acceleration env vars into the existing
# systemd units, then restart all node services. Avoids re-rendering the
# whole manifest — reuses the units deploy-workers.sh already wrote.
#
# Acceleration (testnet-only; production defaults are 1h rotation /
# 10-20min audits):
#   ANT_COMMITMENT_ROTATION_SECS  rotation cadence  (default 120)
#   ANT_AUDIT_TICK_MIN_SECS       audit min cadence (default 60)
#   ANT_AUDIT_TICK_MAX_SECS       audit max cadence (default 120)
#
# Also re-arms the adversary go-bad-at to NOW + GO_BAD_AFTER_MIN (default
# 3) so misbehaviour resumes shortly after the restart.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/../build"
TF_DIR="${SCRIPT_DIR}/../terraform"
SSH_KEY="${SSH_KEY:-${HOME}/.ssh/testnet_ed25519}"
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15)
[[ -f "${SSH_KEY}" ]] && SSH_OPTS+=(-i "${SSH_KEY}")

ROT="${ANT_COMMITMENT_ROTATION_SECS:-120}"
AMIN="${ANT_AUDIT_TICK_MIN_SECS:-60}"
AMAX="${ANT_AUDIT_TICK_MAX_SECS:-120}"
NSMIN="${ANT_NEIGHBOR_SYNC_MIN_SECS:-45}"
NSMAX="${ANT_NEIGHBOR_SYNC_MAX_SECS:-90}"
NSCD="${ANT_NEIGHBOR_SYNC_COOLDOWN_SECS:-120}"
DEL_AFTER="${ANT_ADVERSARY_DELETE_AFTER_SEC:-120}"
DEL_EVERY="${ANT_ADVERSARY_DELETE_EVERY_SEC:-120}"
GO_BAD_AFTER_MIN="${GO_BAD_AFTER_MIN:-3}"
GO_BAD_AT=$(( $(date +%s) + GO_BAD_AFTER_MIN * 60 ))

WORKER_IPS_JSON="$(cd "${TF_DIR}" && terraform output -json worker_ips)"
echo "Accel: rotation=${ROT}s audit=[${AMIN},${AMAX}]s | adversary go-bad-at=$(date -u -d @${GO_BAD_AT} +%FT%TZ 2>/dev/null || date -u -r ${GO_BAD_AT} +%FT%TZ)"

for row in $(jq -c 'to_entries | .[]' <<<"${WORKER_IPS_JSON}"); do
    region=$(jq -r '.key' <<<"${row}")
    ip=$(jq -r '.value' <<<"${row}")
    echo "=== ${region} (${ip}) ==="
    # Swap binaries.
    rsync -az -e "ssh ${SSH_OPTS[*]}" \
        "${BUILD_DIR}/ant-node" "${BUILD_DIR}/ant-node-adversary" \
        "root@${ip}:/usr/local/bin/"
    ssh "${SSH_OPTS[@]}" "root@${ip}" \
        "ROT=${ROT} AMIN=${AMIN} AMAX=${AMAX} NSMIN=${NSMIN} NSMAX=${NSMAX} NSCD=${NSCD} DEL_AFTER=${DEL_AFTER} DEL_EVERY=${DEL_EVERY} GO_BAD_AT=${GO_BAD_AT} bash -s" <<'REMOTE'
set -euo pipefail
chmod +x /usr/local/bin/ant-node /usr/local/bin/ant-node-adversary
# Inject accel env + refresh adversary go-bad-at into every unit via a
# systemd drop-in (clean: doesn't touch the original unit file).
for unit in /etc/systemd/system/antnode-*.service; do
    name=$(basename "${unit}" .service)
    mkdir -p "/etc/systemd/system/${name}.service.d"
    cat > "/etc/systemd/system/${name}.service.d/accel.conf" <<CONF
[Service]
Environment=ANT_COMMITMENT_ROTATION_SECS=${ROT}
Environment=ANT_AUDIT_TICK_MIN_SECS=${AMIN}
Environment=ANT_AUDIT_TICK_MAX_SECS=${AMAX}
Environment=ANT_NEIGHBOR_SYNC_MIN_SECS=${NSMIN}
Environment=ANT_NEIGHBOR_SYNC_MAX_SECS=${NSMAX}
Environment=ANT_NEIGHBOR_SYNC_COOLDOWN_SECS=${NSCD}
Environment=ANT_ADVERSARY_GO_BAD_AT_UNIX_SEC=${GO_BAD_AT}
Environment=ANT_ADVERSARY_DELETE_AFTER_SEC=${DEL_AFTER}
Environment=ANT_ADVERSARY_DELETE_EVERY_SEC=${DEL_EVERY}
CONF
done
systemctl daemon-reload
# Restart bootstrap nodes first, then the rest.
for idx in $(ls /etc/systemd/system/antnode-*.service | sed 's#.*antnode-##;s#.service##' | sort -n); do
    systemctl restart "antnode-${idx}.service" || true
done
echo "restarted $(ls /etc/systemd/system/antnode-*.service | wc -l) units on $(hostname)"
REMOTE
done
echo "All workers redeployed with accelerated cadence."
