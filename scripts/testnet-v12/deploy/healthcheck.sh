#!/usr/bin/env bash
# Quick health snapshot of the v12 testnet across all 5 workers + EVM +
# client. Read-only; safe to run any time. Surfaces:
#   - how many antnode-* units are active per worker
#   - v12 event-log line counts + a breakdown of event types
#   - whether node_started / gossip_ingest(accepted) / audit_outcome /
#     trust_event(application_failure) are present yet
#   - workload service status + last few CSV rows on the client
#   - EVM chain liveness
#
# Used by the operator (and the autonomous run) to decide go/no-go on the
# setup before committing to the long collection window.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TF_DIR="${SCRIPT_DIR}/../terraform"
SSH_KEY="${SSH_KEY:-${HOME}/.ssh/testnet_ed25519}"
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10)
[[ -f "${SSH_KEY}" ]] && SSH_OPTS+=(-i "${SSH_KEY}")

WORKER_IPS_JSON="$(cd "${TF_DIR}" && terraform output -json worker_ips)"
EVM_IP="$(cd "${TF_DIR}" && terraform output -raw evm_ip)"
CLIENT_IP="$(cd "${TF_DIR}" && terraform output -raw client_ip)"

echo "================ v12 testnet health @ $(date -u +%FT%TZ) ================"

for row in $(jq -c 'to_entries | .[]' <<<"${WORKER_IPS_JSON}"); do
    region=$(jq -r '.key' <<<"${row}")
    ip=$(jq -r '.value' <<<"${row}")
    # All commands run remotely in one shot to minimise round-trips.
    ssh "${SSH_OPTS[@]}" "root@${ip}" "REGION='${region}' bash -s" <<'REMOTE'
active=$(systemctl list-units 'antnode-*.service' --state=active --no-legend 2>/dev/null | wc -l)
failed=$(systemctl list-units 'antnode-*.service' --state=failed --no-legend 2>/dev/null | wc -l)
total=$(ls /etc/systemd/system/antnode-*.service 2>/dev/null | wc -l)
lines=$(cat /var/log/ant-nodes/v12-events-*.jsonl 2>/dev/null | wc -l)
echo "[$REGION] units active=$active failed=$failed total=$total | event-log lines=$lines"
# Event-type histogram across this droplet's logs (cheap; jq over cat).
cat /var/log/ant-nodes/v12-events-*.jsonl 2>/dev/null \
  | jq -r '.event' 2>/dev/null | sort | uniq -c | sort -rn \
  | sed 's/^/    /' | head -12
REMOTE
done

echo
echo "---- EVM ----"
curl -s --max-time 8 -X POST "http://${EVM_IP}:8545" -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' || echo "EVM RPC unreachable"
echo

echo "---- Client / workload ----"
ssh "${SSH_OPTS[@]}" "root@${CLIENT_IP}" bash -s <<'REMOTE'
systemctl is-active v12-workload.service 2>/dev/null || echo "workload not active"
if [[ -f /var/log/v12-workload.csv ]]; then
    total=$(($(wc -l < /var/log/v12-workload.csv) - 1))
    up_ok=$(grep -c ',upload,.*,true,' /var/log/v12-workload.csv 2>/dev/null || echo 0)
    up_all=$(grep -c ',upload,' /var/log/v12-workload.csv 2>/dev/null || echo 0)
    dn_ok=$(grep -c ',download,.*,true,' /var/log/v12-workload.csv 2>/dev/null || echo 0)
    dn_all=$(grep -c ',download,' /var/log/v12-workload.csv 2>/dev/null || echo 0)
    echo "workload rows=$total upload_ok=$up_ok/$up_all download_ok=$dn_ok/$dn_all"
    echo "last 3 rows:"; tail -3 /var/log/v12-workload.csv | sed 's/^/    /'
else
    echo "no workload CSV yet"
fi
REMOTE
echo "========================================================================"
