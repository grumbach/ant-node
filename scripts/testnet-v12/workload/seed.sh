#!/usr/bin/env bash
# Aggressive one-shot network seeder. Runs N parallel `ant chunk put`
# loops for DURATION seconds with small random payloads, so the 400-node
# network accumulates stored records fast enough that commitment rotation
# (hourly) + audits (10-20 min) actually have data to operate on.
#
# Runs ON the client droplet. Env:
#   PAR        parallel uploaders            (default 8)
#   DURATION   seconds to keep seeding       (default 1800)
#   SIZE       payload bytes per chunk       (default 65536 = 64 KiB)
#   BOOTSTRAP  ant --bootstrap CSV           (required)
#   MANIFEST   devnet manifest path          (default /usr/local/bin/devnet-manifest.json)
#   SECRET_KEY funded key                    (required, from env)

set -uo pipefail
PAR="${PAR:-8}"
DURATION="${DURATION:-1800}"
SIZE="${SIZE:-65536}"
ANT="${ANT:-/usr/local/bin/ant}"
MANIFEST="${MANIFEST:-/usr/local/bin/devnet-manifest.json}"
BOOTSTRAP="${BOOTSTRAP:?set BOOTSTRAP}"
: "${SECRET_KEY:?set SECRET_KEY}"
export HOME=/root XDG_DATA_HOME=/root/.local/share XDG_CONFIG_HOME=/root/.config

# Build repeated --bootstrap flags.
BOOT_ARGS=()
IFS=',' read -ra ADDRS <<<"${BOOTSTRAP}"
for a in "${ADDRS[@]}"; do [[ -n "$a" ]] && BOOT_ARGS+=(--bootstrap "$a"); done

STOP=$(( $(date +%s) + DURATION ))
COUNT_FILE=/tmp/seed-count
: > "${COUNT_FILE}"

uploader() {
    local id="$1"
    local n=0 ok=0
    while [[ $(date +%s) -lt ${STOP} ]]; do
        if head -c "${SIZE}" /dev/urandom \
            | "${ANT}" "${BOOT_ARGS[@]}" --evm-network local --devnet-manifest "${MANIFEST}" chunk put >/dev/null 2>&1; then
            ok=$((ok+1))
        fi
        n=$((n+1))
    done
    echo "uploader ${id}: ${ok}/${n} ok" | tee -a "${COUNT_FILE}"
}

echo "Seeding: ${PAR} uploaders x ${SIZE}B for ${DURATION}s (until $(date -u -d @${STOP} +%FT%TZ 2>/dev/null || date -u -r ${STOP} +%FT%TZ))"
for i in $(seq 1 "${PAR}"); do uploader "$i" & done
wait
echo "=== seed complete ==="
cat "${COUNT_FILE}"
