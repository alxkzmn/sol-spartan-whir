#!/usr/bin/env python3
"""Parse broadcast JSON artifacts from Anvil tx-gas measurement scripts.

Usage:
    python3 .agents/skills/tx-gas-benchmarking/scripts/parse_tx_gas.py
    python3 .agents/skills/tx-gas-benchmarking/scripts/parse_tx_gas.py native
    python3 .agents/skills/tx-gas-benchmarking/scripts/parse_tx_gas.py \
        script/WhirBlobNativeTxBenchmark_lir6_ff5_rsv1.s.sol
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def _find_project_root() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "foundry.toml").exists() and (parent / "broadcast").exists():
            return parent
    raise RuntimeError(
        "Could not find sol-spartan-whir project root above parse_tx_gas.py"
    )


PROJECT_ROOT = _find_project_root()
BROADCAST_DIR = PROJECT_ROOT / "broadcast"

MODE_SPECS = {
    "native": {
        "script_family": "WhirBlobNativeTxBenchmark",
        "label": "Native blob tx (EOA -> WhirBlobVerifierNative4.verify)",
        "verify_receipt_idx": 1,
        "min_receipts": 2,
    },
    "direct": {
        "script_family": "WhirTxBenchmark",
        "label": "Direct tx (EOA -> WhirVerifier4.verify)",
        "verify_receipt_idx": 1,
        "min_receipts": 2,
    },
    "blob": {
        "script_family": "WhirBlobTxBenchmark",
        "label": "Blob tx (EOA -> WhirBlobVerifier4.verify)",
        "verify_receipt_idx": 2,
        "min_receipts": 3,
    },
    "wrapper": {
        "script_family": "MeasureTxGas",
        "label": "Wrapper tx (EOA -> VerifyWrapper -> WhirVerifier4.verify)",
        "verify_receipt_idx": 2,
        "min_receipts": 3,
    },
}


def calldata_breakdown(hex_input: str) -> dict:
    raw = bytes.fromhex(hex_input[2:] if hex_input.startswith("0x") else hex_input)
    zero = sum(1 for b in raw if b == 0)
    nonzero = len(raw) - zero
    gas = 4 * zero + 16 * nonzero
    return {
        "total_bytes": len(raw),
        "zero_bytes": zero,
        "nonzero_bytes": nonzero,
        "calldata_gas": gas,
        "intrinsic_plus_calldata": 21_000 + gas,
    }


def classify_mode(raw: str) -> str:
    if raw in MODE_SPECS:
        return raw

    name = Path(raw).name
    for mode, spec in MODE_SPECS.items():
        if name.startswith(spec["script_family"]):
            return mode

    known = ", ".join(MODE_SPECS)
    raise ValueError(f"Unknown mode or script path: {raw}. Use one of: {known}")


def explicit_broadcast_json(raw: str) -> Path:
    return BROADCAST_DIR / Path(raw).name / "31337" / "run-latest.json"


def find_broadcast_json(mode: str) -> Path | None:
    family = MODE_SPECS[mode]["script_family"]
    matches = sorted(
        BROADCAST_DIR.glob(f"{family}*.s.sol/31337/run-latest.json"),
        key=lambda path: (path.stat().st_mtime, str(path)),
        reverse=True,
    )
    if not matches:
        return None

    if len(matches) > 1:
        print(
            f"Multiple broadcast artifacts matched {family}; using newest: {matches[0]}"
        )

    return matches[0]


def _parse_broadcast(
    json_path: Path, label: str, verify_receipt_idx: int, min_receipts: int
):
    if not json_path.exists():
        print(f"Not found: {json_path}")
        print("Run the corresponding benchmark script against Anvil first.")
        return

    with json_path.open() as f:
        data = json.load(f)

    if len(data["receipts"]) < min_receipts:
        print(
            f"ERROR: receipts array has <{min_receipts} entries — broadcast likely failed."
        )
        print("Did you pass --private-key? Use the skill helper for the full command.")
        return

    gas_used = int(data["receipts"][verify_receipt_idx]["gasUsed"], 16)
    inp = data["transactions"][verify_receipt_idx]["transaction"]["input"]
    cd = calldata_breakdown(inp)
    exec_remainder = gas_used - cd["intrinsic_plus_calldata"]

    print(f"=== {label} ===")
    print(f"  Total tx gas:         {gas_used:>12,}")
    print(f"  Intrinsic + calldata: {cd['intrinsic_plus_calldata']:>12,}")
    print(f"    calldata bytes:     {cd['total_bytes']:>12,}")
    print(f"    zero bytes:         {cd['zero_bytes']:>12,}")
    print(f"    nonzero bytes:      {cd['nonzero_bytes']:>12,}")
    print(f"    calldata gas:       {cd['calldata_gas']:>12,}")
    print(f"    intrinsic:          {21_000:>12,}")
    print(f"  Execution remainder:  {exec_remainder:>12,}")
    return gas_used, cd, exec_remainder


def parse_target(raw: str):
    mode = classify_mode(raw)
    spec = MODE_SPECS[mode]
    is_explicit = raw not in MODE_SPECS
    json_path = (
        explicit_broadcast_json(raw) if is_explicit else find_broadcast_json(mode)
    )
    if json_path is None:
        family = spec["script_family"]
        print(f"Not found: {BROADCAST_DIR}/{family}*.s.sol/31337/run-latest.json")
        print("Run the corresponding benchmark script against Anvil first.")
        return None

    label = f"{spec['label']} [{Path(raw).name}]" if is_explicit else spec["label"]

    return _parse_broadcast(
        json_path,
        label,
        verify_receipt_idx=spec["verify_receipt_idx"],
        min_receipts=spec["min_receipts"],
    )


def main():
    default_targets = list(MODE_SPECS)
    targets = sys.argv[1:] if len(sys.argv) > 1 else default_targets

    results = {}
    for raw in targets:
        try:
            mode = classify_mode(raw)
        except ValueError as exc:
            print(exc)
            sys.exit(1)

        results[mode] = parse_target(raw)
        print()

    if results.get("direct") and results.get("wrapper"):
        d_gas, d_cd, d_exec = results["direct"]
        w_gas, w_cd, w_exec = results["wrapper"]
        overhead = w_exec - d_exec
        print("=== Comparison (wrapper vs direct) ===")
        print(f"  Wrapper overhead:     {overhead:>12,}")
        print(
            f"  Calldata delta:       {w_cd['intrinsic_plus_calldata'] - d_cd['intrinsic_plus_calldata']:>+12,}"
        )
        print(f"  Total tx delta:       {w_gas - d_gas:>+12,}")


if __name__ == "__main__":
    main()
