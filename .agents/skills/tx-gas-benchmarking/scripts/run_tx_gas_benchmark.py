#!/usr/bin/env python3
"""Run a verifier benchmark, preserve receipts, and optionally own a local Anvil child."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

import parse_tx_gas as gas


def chain_id(rpc_url: str) -> int:
    request = urllib.request.Request(
        rpc_url,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=1) as response:
        return int(json.load(response)["result"], 16)


def resolve_script(raw: str) -> tuple[Path, str]:
    if raw in gas.MODE_SPECS:
        family = gas.MODE_SPECS[raw]["script_family"]
        matches = sorted((gas.PROJECT_ROOT / "script").glob(f"{family}*.s.sol"))
        if len(matches) != 1:
            raise ValueError(f"Mode {raw!r} matched {len(matches)} scripts; pass an explicit script path.")
        return matches[0], raw
    path = Path(raw)
    if not path.is_absolute():
        path = gas.PROJECT_ROOT / path
    if not path.is_file():
        raise ValueError(f"Benchmark script not found: {path}")
    return path.resolve(), gas.classify_mode(raw)


def artifact_version(path: Path):
    try:
        stat = path.stat()
        return stat.st_ino, stat.st_mtime_ns, stat.st_size
    except FileNotFoundError:
        return None


def run(args) -> int:
    script, mode = resolve_script(args.target)
    extra = args.forge_args
    if extra[:1] == ["--"]:
        extra = extra[1:]
    for arg in extra:
        if arg.split("=", 1)[0] in {"--rpc-url", "--private-key", "--broadcast-dir"}:
            raise ValueError(f"{arg} overrides receipt tracking; use RPC_URL/PRIVATE_KEY and the default broadcast directory.")
    if args.start_anvil and os.environ.get("RPC_URL"):
        raise ValueError("Unset RPC_URL when using --start-anvil; choose the local port with --port.")
    if args.snapshot_dir:
        snapshot = Path(args.snapshot_dir).resolve()
        snapshot.mkdir(parents=True, exist_ok=False)
    else:
        snapshot = Path(tempfile.mkdtemp(prefix="whir-tx-gas-"))
    print(f"Benchmark evidence: {snapshot}", flush=True)

    node = None
    node_log = None
    rpc_url = os.environ.get("RPC_URL", "http://127.0.0.1:8545")
    try:
        if args.start_anvil:
            # Refuse an occupied port before starting; never adopt that listener.
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", args.port))
                port = probe.getsockname()[1]
            rpc_url = f"http://127.0.0.1:{port}"
            node_log = (snapshot / "anvil.log").open("w")
            node = subprocess.Popen(
                ["anvil", "--silent", "--host", "127.0.0.1", "--port", str(port),
                 "--code-size-limit", "65536"],
                stdout=node_log, stderr=subprocess.STDOUT,
            )
            deadline = time.monotonic() + 10
            while True:
                if node.poll() is not None:
                    raise RuntimeError(f"Anvil exited during startup; inspect {snapshot / 'anvil.log'}")
                try:
                    if chain_id(rpc_url) == 31337 and node.poll() is None:
                        break
                except (OSError, ValueError, KeyError, urllib.error.URLError):
                    pass
                if time.monotonic() >= deadline:
                    raise RuntimeError(f"Anvil readiness timeout; inspect {snapshot / 'anvil.log'}")
                time.sleep(0.1)

        actual_chain_id = chain_id(rpc_url)
        latest = gas.BROADCAST_DIR / script.name / str(actual_chain_id) / "run-latest.json"
        previous = artifact_version(latest)
        if previous is not None:
            shutil.copy2(latest, snapshot / "previous-run.json")
        manifest = {"script": script.name, "mode": mode, "chain_id": actual_chain_id,
                    "managed_anvil": node is not None, "anvil_pid": node.pid if node else None,
                    "started_at_unix": time.time()}
        (snapshot / "run-info.json").write_text(json.dumps(manifest, indent=2) + "\n")
        with (snapshot / "forge-version.txt").open("w") as version_log:
            subprocess.run(["forge", "--version"], stdout=version_log, check=True)
        key = os.environ.get("PRIVATE_KEY", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
        command = ["forge", "script", str(script), "--rpc-url", rpc_url, "--broadcast", "--slow",
                   "--code-size-limit", "65536", "--private-key", key]
        if mode == "wrapper":
            command.extend(["--tc", "MeasureTxGas"])
        with (snapshot / "forge.log").open("w") as log:
            completed = subprocess.run(command + extra, cwd=gas.PROJECT_ROOT,
                                       stdout=log, stderr=subprocess.STDOUT)
        print((snapshot / "forge.log").read_text(), end="")
        current = artifact_version(latest)
        fresh = current is not None and current != previous
        if fresh:
            shutil.copy2(latest, snapshot / "run.json")
        manifest.update(forge_exit_code=completed.returncode, fresh_receipts=fresh)
        (snapshot / "run-info.json").write_text(json.dumps(manifest, indent=2) + "\n")
        if completed.returncode:
            raise RuntimeError(f"Forge failed with exit code {completed.returncode}; evidence is in {snapshot}")
        if not fresh:
            raise RuntimeError(f"Forge did not produce a fresh {latest}; previous receipts are not this run's result.")
        metrics = gas.read_metrics(snapshot / "run.json", mode)
        (snapshot / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n")
        gas.print_metrics(metrics, f"{script.name} [{snapshot / 'run.json'}]")
        return 0
    finally:
        # Only terminate the child created by this invocation. Existing-server mode
        # never creates a Popen handle and cannot enter this cleanup branch.
        if node is not None:
            if node.poll() is None:
                node.terminate()
                try:
                    node.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    node.kill()
                    node.wait()
            else:
                node.wait()
        if node_log is not None:
            node_log.close()


def handle_signal(signum, _frame):
    # SystemExit lets subprocess.run terminate its active child before cleanup.
    raise SystemExit(128 + signum)


def main() -> int:
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--start-anvil", action="store_true", help="Start and stop only this run's local Anvil child")
    parser.add_argument("--port", type=int, default=18549, help="Managed Anvil port; 0 selects a free port (default: 18549)")
    parser.add_argument("--snapshot-dir", help="New directory for receipts and logs; must not already exist")
    parser.add_argument("target", help="Explicit script path or unambiguous native/direct/blob/wrapper alias")
    parser.add_argument("forge_args", nargs=argparse.REMAINDER, help="Extra forge arguments after the target")
    args = parser.parse_args()
    try:
        return run(args)
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Benchmark interrupted; the managed Anvil child has been stopped.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
