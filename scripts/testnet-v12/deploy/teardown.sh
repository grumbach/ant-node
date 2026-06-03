#!/usr/bin/env bash
# Tear down the v12 verification testnet.
#
# Idempotent: safe to run if no droplets exist. Removes the entire
# terraform state.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TF_DIR="${SCRIPT_DIR}/../terraform"

echo "=== Tearing down v12 verification testnet ==="
echo "This will destroy all droplets tagged 'v12verify'. Continue? [y/N]"
read -r ans
if [[ "${ans}" != "y" && "${ans}" != "Y" ]]; then
    echo "Aborted."
    exit 1
fi

(cd "${TF_DIR}" && terraform destroy -auto-approve)
echo "Done. Local collected logs remain under scripts/testnet-v12/collected/."
