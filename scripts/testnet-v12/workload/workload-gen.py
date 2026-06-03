#!/usr/bin/env python3
"""Honest-network upload/download workload generator.

Runs continuously on the client droplet for the duration of the testnet
run. Every `upload_interval` it uploads a random 4 MB chunk; every
`download_interval` it picks `download_sample` random previously-uploaded
chunks and re-fetches them. Each operation's latency + outcome is
appended to a CSV consumed by `analyse.py`.

Payment: uploads pay via EVM, so the client needs the local-EVM devnet
manifest (`--devnet-manifest`, `--evm-network local`) and the funded
wallet key in the `SECRET_KEY` env var. `deploy-workload.sh` wires all
three from the EVM info produced by `deploy-evm.sh`.

The `ant` CLI surface used here:
  ant --bootstrap IP:PORT [--bootstrap IP:PORT ...] \\
      --evm-network local --devnet-manifest M chunk put [FILE]
  ant ... chunk get ADDRESS
Global flags (`--bootstrap`, `--evm-network`, `--devnet-manifest`) MUST
precede the `chunk` subcommand.

Usage:
  SECRET_KEY=0x... workload-gen.py \\
    --ant-bin /usr/local/bin/ant \\
    --bootstrap 10.0.0.1:10000,10.0.0.2:10000 \\
    --devnet-manifest /usr/local/bin/devnet-manifest.json \\
    --csv /var/log/v12-workload.csv \\
    --duration 86400
"""

from __future__ import annotations

import argparse
import csv
import random
import secrets
import subprocess
import sys
import threading
import time
from pathlib import Path

CHUNK_SIZE = 4 * 1024 * 1024
DEFAULT_UPLOAD_INTERVAL_SEC = 5.0
DEFAULT_DOWNLOAD_INTERVAL_SEC = 60.0
DEFAULT_DOWNLOAD_SAMPLE = 10
DEFAULT_TIMEOUT_SEC = 60.0


def _global_args(ant_bin: str, bootstrap: str, manifest: str) -> list[str]:
    """Build the leading `ant` invocation: binary + global flags.

    `--bootstrap` takes one SocketAddr per flag (the clap Vec parser
    rejects a comma list), so the CSV is split into repeated flags.
    """
    argv = [ant_bin]
    for addr in bootstrap.split(","):
        addr = addr.strip()
        if addr:
            argv += ["--bootstrap", addr]
    argv += ["--evm-network", "local", "--devnet-manifest", manifest]
    return argv


def upload_one(
    ant_bin: str, bootstrap: str, manifest: str, payload: bytes
) -> tuple[bool, int, str]:
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            [*_global_args(ant_bin, bootstrap, manifest), "chunk", "put"],
            input=payload,
            capture_output=True,
            timeout=DEFAULT_TIMEOUT_SEC,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False, int((time.perf_counter() - start) * 1000), "timeout"
    elapsed_ms = int((time.perf_counter() - start) * 1000)
    if proc.returncode != 0:
        return False, elapsed_ms, proc.stderr.decode("utf-8", "replace")[:200]
    out = proc.stdout.decode("utf-8", "replace").strip().splitlines()
    if not out:
        return False, elapsed_ms, "empty stdout"
    addr = out[-1].strip()
    if len(addr) != 64:
        return False, elapsed_ms, f"unexpected stdout: {addr[:32]}"
    return True, elapsed_ms, addr


def download_one(
    ant_bin: str, bootstrap: str, manifest: str, addr: str
) -> tuple[bool, int, str]:
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            [*_global_args(ant_bin, bootstrap, manifest), "chunk", "get", addr],
            capture_output=True,
            timeout=DEFAULT_TIMEOUT_SEC,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False, int((time.perf_counter() - start) * 1000), "timeout"
    elapsed_ms = int((time.perf_counter() - start) * 1000)
    if proc.returncode != 0:
        return False, elapsed_ms, proc.stderr.decode("utf-8", "replace")[:200]
    return True, elapsed_ms, ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ant-bin", required=True)
    ap.add_argument("--bootstrap", required=True)
    ap.add_argument(
        "--devnet-manifest",
        required=True,
        help="Path to the DevnetManifest JSON with EVM info (for --evm-network local).",
    )
    ap.add_argument("--csv", required=True)
    ap.add_argument("--duration", type=float, default=86400.0)
    ap.add_argument("--upload-interval", type=float, default=DEFAULT_UPLOAD_INTERVAL_SEC)
    ap.add_argument("--download-interval", type=float, default=DEFAULT_DOWNLOAD_INTERVAL_SEC)
    ap.add_argument("--download-sample", type=int, default=DEFAULT_DOWNLOAD_SAMPLE)
    args = ap.parse_args()

    csv_path = Path(args.csv)
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    new_file = not csv_path.exists()
    csv_file = csv_path.open("a", newline="", buffering=1)
    writer = csv.writer(csv_file)
    if new_file:
        writer.writerow(["ts_iso", "op", "latency_ms", "success", "address_or_err"])

    addrs: list[str] = []
    addrs_lock = threading.Lock()
    stop_at = time.time() + args.duration

    print(
        f"workload-gen: starting; will stop at "
        f"{time.strftime('%FT%TZ', time.gmtime(stop_at))}"
    )

    def emit(op: str, latency_ms: int, success: bool, payload: str) -> None:
        ts = time.strftime("%FT%TZ", time.gmtime())
        writer.writerow([ts, op, latency_ms, "true" if success else "false", payload])

    def upload_loop() -> None:
        while time.time() < stop_at:
            payload = secrets.token_bytes(CHUNK_SIZE)
            ok, ms, payload_or_err = upload_one(
                args.ant_bin, args.bootstrap, args.devnet_manifest, payload
            )
            emit("upload", ms, ok, payload_or_err)
            if ok:
                with addrs_lock:
                    addrs.append(payload_or_err)
            else:
                print(f"upload FAIL ({ms}ms): {payload_or_err[:80]}", file=sys.stderr)
            time.sleep(args.upload_interval)

    def download_loop() -> None:
        time.sleep(30)  # let the first few uploads land
        while time.time() < stop_at:
            with addrs_lock:
                snapshot = list(addrs)
            if len(snapshot) < args.download_sample:
                time.sleep(args.download_interval)
                continue
            sample = random.sample(snapshot, args.download_sample)
            for addr in sample:
                ok, ms, err = download_one(
                    args.ant_bin, args.bootstrap, args.devnet_manifest, addr
                )
                emit("download", ms, ok, addr if ok else err)
                if not ok:
                    print(
                        f"download FAIL {addr[:16]} ({ms}ms): {err[:80]}",
                        file=sys.stderr,
                    )
            time.sleep(args.download_interval)

    t_up = threading.Thread(target=upload_loop, daemon=True)
    t_dn = threading.Thread(target=download_loop, daemon=True)
    t_up.start()
    t_dn.start()

    try:
        while time.time() < stop_at:
            time.sleep(10)
    except KeyboardInterrupt:
        print("\nworkload-gen: SIGINT received, stopping.")
    csv_file.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
