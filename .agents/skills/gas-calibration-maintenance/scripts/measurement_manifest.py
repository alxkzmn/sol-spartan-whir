#!/usr/bin/env python3
"""Capture or check source and input hashes for a local calibration run."""

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True


def source_fingerprints(root):
    path = root / "quintic_schedule_scorer.py"
    spec = importlib.util.spec_from_file_location("calibration_scorer", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.build_calibration_source_fingerprints()


def file_record(path, root, manifest_dir):
    path = path.resolve()
    try:
        relative = path.relative_to(root)
        scope = "project"
    except ValueError:
        relative = Path(os.path.relpath(path, manifest_dir))
        scope = "manifest"
    raw = path.read_bytes()
    return {"scope": scope, "path": relative.as_posix(), "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest()}


def capture(root, output, inputs):
    files = sorted({(root / "foundry.toml").resolve(), *(p.resolve() for p in inputs)})
    if output.resolve() in files:
        raise ValueError("The output manifest cannot be an input")
    value = {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source_fingerprints": source_fingerprints(root),
        "files": [file_record(p, root, output.resolve().parent) for p in files],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def check(root, manifest):
    value = json.loads(manifest.read_text())
    if value.get("schema_version") != 1 or not value.get("files"):
        raise ValueError("Unsupported or incomplete manifest")
    failures = []
    if value.get("source_fingerprints") != source_fingerprints(root):
        failures.append("calibration source files or coverage changed")
    has_config = False
    for item in value["files"]:
        scope = item["scope"]
        if scope not in ("project", "manifest") or Path(item["path"]).is_absolute():
            raise ValueError("Invalid manifest path scope")
        base = root if scope == "project" else manifest.resolve().parent
        path = base / item["path"]
        has_config |= path.resolve() == (root / "foundry.toml").resolve()
        try:
            actual = file_record(path, root, manifest.resolve().parent)
        except OSError:
            failures.append(f"missing or unreadable: {item['path']}")
            continue
        if actual != item:
            failures.append(f"changed: {item['path']}")
    if not has_config:
        failures.append("foundry.toml is missing from the manifest")
    if failures:
        raise ValueError("; ".join(failures))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    capture_parser = sub.add_parser("capture")
    capture_parser.add_argument("--out", required=True, type=Path)
    capture_parser.add_argument("--input", action="append", type=Path, default=[])
    check_parser = sub.add_parser("check")
    check_parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    root = Path.cwd().resolve()
    try:
        if args.action == "capture":
            capture(root, args.out, args.input)
            print(f"Captured source and input hashes: {args.out}")
        else:
            check(root, args.manifest)
            print("Source and input hashes match; measurement provenance needs separate verification.")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, f"Manifest {args.action} failed: {exc}\n")


if __name__ == "__main__":
    main()
