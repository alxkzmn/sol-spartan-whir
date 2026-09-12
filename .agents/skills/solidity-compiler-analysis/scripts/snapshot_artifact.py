#!/usr/bin/env python3
"""Preserve a Foundry contract artifact, optimized IR, and runtime metadata."""

import argparse
import hashlib
import json
from pathlib import Path
import re


def snapshot(artifact, source, contract, out_dir):
    raw = artifact.read_bytes()
    data = json.loads(raw)
    ir = data.get("irOptimized")
    if not isinstance(ir, str) or not ir.strip():
        raise ValueError("Optimized IR missing; use a fresh targeted --extra-output irOptimized build")
    metadata = data.get("metadata") or data.get("rawMetadata")
    if isinstance(metadata, str):
        metadata = json.loads(metadata)
    if not isinstance(metadata, dict):
        raise ValueError("Compiler metadata missing")
    settings = metadata.get("settings", {})
    if settings.get("compilationTarget") != {source: contract}:
        raise ValueError("Artifact compilationTarget does not match --source and --contract")
    runtime = data.get("deployedBytecode", {}).get("object", "")
    if not isinstance(runtime, str):
        raise ValueError("Invalid deployed bytecode object")
    runtime = runtime.removeprefix("0x")
    if not runtime or len(runtime) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", runtime):
        raise ValueError("Deployed bytecode must be nonempty, even-length linked hex")
    runtime_bytes = bytes.fromhex(runtime)
    summary = {
        "schema_version": 1,
        "source": source,
        "contract": contract,
        "compiler": metadata.get("compiler"),
        "settings": settings,
        "sources": metadata.get("sources", {}),
        "artifact_sha256": hashlib.sha256(raw).hexdigest(),
        "ir_sha256": hashlib.sha256(ir.encode()).hexdigest(),
        "deployed_runtime_bytes": len(runtime_bytes),
        "runtime_sha256": hashlib.sha256(runtime_bytes).hexdigest(),
        "link_references": data["deployedBytecode"].get("linkReferences", {}),
        "immutable_references": data["deployedBytecode"].get("immutableReferences", {}),
    }
    out_dir.mkdir(parents=True, exist_ok=False)
    (out_dir / "artifact.json").write_bytes(raw)
    (out_dir / "optimized.yul").write_text(ir)
    (out_dir / "runtime.hex").write_text("0x" + runtime + "\n")
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return len(runtime_bytes)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--source", required=True, help="Exact source key from compilationTarget")
    parser.add_argument("--contract", required=True)
    parser.add_argument("--out-dir", type=Path, required=True, help="New evidence directory")
    args = parser.parse_args()
    try:
        size = snapshot(args.artifact, args.source, args.contract, args.out_dir)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, f"Snapshot failed: {exc}\n")
    print(f"Deployed runtime: {size} bytes; snapshot: {args.out_dir}")


if __name__ == "__main__":
    main()
