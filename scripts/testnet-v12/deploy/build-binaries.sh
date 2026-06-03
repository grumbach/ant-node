#!/usr/bin/env bash
# Build linux-x86_64 binaries needed for the v12 verification testnet.
#
# Produces two binaries in scripts/testnet-v12/build/:
#   - ant-node           (honest binary; v12-event-log feature on for
#                         attribution; adversary feature OFF so the
#                         path graph is provably honest)
#   - ant-node-adversary (adversary feature ON + v12-event-log)
#
# Requires `cross` if building on macOS, otherwise plain `cargo`. Set
# CROSS=1 to force cross-rs.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
OUT_DIR="${SCRIPT_DIR}/../build"
TARGET="x86_64-unknown-linux-musl"

mkdir -p "${OUT_DIR}"

# Pick cross vs cargo. On a linux host we can use plain cargo with the
# musl target. On macOS we need cross-rs or docker.
if [[ "$(uname -s)" == "Linux" && -z "${CROSS:-}" ]]; then
    BUILDER=cargo
else
    BUILDER=cross
    if ! command -v cross >/dev/null 2>&1; then
        echo "ERROR: macOS/CROSS build path needs cross-rs. Install with:"
        echo "  cargo install cross --git https://github.com/cross-rs/cross"
        exit 1
    fi
fi

echo "=== Building ant-node (honest, v12-event-log on) ==="
(cd "${REPO_ROOT}" && "${BUILDER}" build \
    --release \
    --target "${TARGET}" \
    --bin ant-node \
    --features v12-event-log)
cp "${REPO_ROOT}/target/${TARGET}/release/ant-node" "${OUT_DIR}/ant-node"

echo "=== Building ant-node-adversary ==="
(cd "${REPO_ROOT}" && "${BUILDER}" build \
    --release \
    --target "${TARGET}" \
    --bin ant-node-adversary \
    --features "adversary,v12-event-log")
cp "${REPO_ROOT}/target/${TARGET}/release/ant-node-adversary" "${OUT_DIR}/ant-node-adversary"

echo "=== Building ant-evm-testnet (local Anvil host) ==="
(cd "${REPO_ROOT}" && "${BUILDER}" build \
    --release \
    --target "${TARGET}" \
    --bin ant-evm-testnet \
    --features evm-host)
cp "${REPO_ROOT}/target/${TARGET}/release/ant-evm-testnet" "${OUT_DIR}/ant-evm-testnet"

echo "=== Stripping binaries ==="
strip "${OUT_DIR}/ant-node" || true
strip "${OUT_DIR}/ant-node-adversary" || true
strip "${OUT_DIR}/ant-evm-testnet" || true

ls -lh "${OUT_DIR}/"
echo
echo "Binaries ready at ${OUT_DIR}/"
