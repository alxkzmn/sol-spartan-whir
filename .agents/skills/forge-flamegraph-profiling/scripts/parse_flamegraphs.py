#!/usr/bin/env python3
"""Parse Foundry flamegraph SVG title entries for Spartan-WHIR profiling."""

from __future__ import annotations

import argparse
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

TITLE_RE = re.compile(r"(.+)\(([0-9,]+) gas, ([0-9.]+)%\)\s*$", re.DOTALL)


def _find_project_root() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "foundry.toml").exists():
            return parent
    raise RuntimeError(
        "Could not find sol-spartan-whir project root above parse_flamegraphs.py"
    )


PROJECT_ROOT = _find_project_root()


def parse_svg(path: Path):
    root = ET.parse(path).getroot()
    parsed = []
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] != "title":
            continue
        match = TITLE_RE.fullmatch("".join(element.itertext()))
        if match:
            name, gas, pct = match.groups()
            parsed.append((name.strip(), int(gas.replace(",", "")), float(pct)))
    if not parsed:
        raise ValueError(f"No Foundry gas title entries in {path}")
    parsed.sort(key=lambda item: -item[1])
    return parsed


def resolve_paths(args_paths: list[str], cache_dir: Path) -> list[Path]:
    if args_paths:
        resolved = []
        for raw in args_paths:
            path = Path(raw)
            if not path.is_absolute() and not path.exists():
                cache_path = cache_dir / raw
                path = cache_path if cache_path.exists() else path
            resolved.append(path)
        return resolved
    return sorted(cache_dir.glob("flamegraph_*.svg"))


def label_for(path: Path) -> str:
    name = path.name
    if name.startswith("flamegraph_WhirGasProfileTest_") and name.endswith(".svg"):
        return name.removeprefix("flamegraph_WhirGasProfileTest_").removesuffix(".svg")
    return name


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Parse Foundry flamegraph SVG title entries and print the largest gas hotspots"
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="SVG paths. If omitted, parse every flamegraph_*.svg under cache/.",
    )
    parser.add_argument(
        "--cache-dir",
        default=str(PROJECT_ROOT / "cache"),
        help="Cache directory to scan when no SVG paths are passed",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=15,
        help="Rows to print per SVG (default: 15)",
    )
    args = parser.parse_args()

    cache_dir = Path(args.cache_dir)
    any_found = False
    failed = False
    for path in resolve_paths(args.paths, cache_dir):
        if not path.exists():
            print(f"MISSING: {path}", file=sys.stderr)
            failed = True
            continue
        any_found = True
        try:
            parsed = parse_svg(path)
        except (OSError, ET.ParseError, ValueError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            failed = True
            continue
        print(f"\n=== {label_for(path)} (top {args.limit}) ===")
        for name, gas, pct in parsed[: args.limit]:
            print(f"{gas:>10,}  {pct:>5.1f}%  {name}")

    if not any_found:
        print("No flamegraph SVGs found; pass the exact generated artifact path.", file=sys.stderr)
    if failed or not any_found:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
