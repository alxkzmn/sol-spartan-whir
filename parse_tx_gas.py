#!/usr/bin/env python3
"""Parse broadcast JSON artifacts from anvil tx-gas measurement scripts.

Usage:
    python3 parse_tx_gas.py              # parse all available modes
    python3 parse_tx_gas.py native       # native blob verifier (production path)
    python3 parse_tx_gas.py direct       # typed verifier
    python3 parse_tx_gas.py blob         # blob decode-and-delegate verifier
    python3 parse_tx_gas.py wrapper      # typed wrapper verifier
"""

import json
import sys
from pathlib import Path

BROADCAST_DIR = Path(__file__).parent / "broadcast"
NATIVE_JSON = BROADCAST_DIR / "WhirBlobNativeTxBenchmark.s.sol/31337/run-latest.json"
DIRECT_JSON = BROADCAST_DIR / "WhirTxBenchmark.s.sol/31337/run-latest.json"
BLOB_JSON = BROADCAST_DIR / "WhirBlobTxBenchmark.s.sol/31337/run-latest.json"
WRAPPER_JSON = BROADCAST_DIR / "MeasureTxGas.s.sol/31337/run-latest.json"


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


def _parse_broadcast(json_path, label, verify_receipt_idx, min_receipts):
    """Generic parser for any benchmark broadcast JSON.

    Args:
        json_path: Path to the broadcast run-latest.json
        label: Human-readable label for the output header
        verify_receipt_idx: Index of the verify receipt in the receipts array
        min_receipts: Minimum expected receipts (CREATE(s) + CALL)
    """
    if not json_path.exists():
        print(f"Not found: {json_path}")
        print(
            "Run the corresponding benchmark script against anvil first (see AGENTS.md)."
        )
        return

    with open(json_path) as f:
        data = json.load(f)

    if len(data["receipts"]) < min_receipts:
        print(
            f"ERROR: receipts array has <{min_receipts} entries — broadcast likely failed."
        )
        print("Did you pass --private-key? See AGENTS.md for the full command.")
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


def parse_native():
    return _parse_broadcast(
        NATIVE_JSON,
        "Native blob tx (EOA -> WhirBlobVerifierNative4.verify)",
        verify_receipt_idx=1,
        min_receipts=2,
    )


def parse_direct():
    return _parse_broadcast(
        DIRECT_JSON,
        "Direct tx (EOA -> WhirVerifier4.verify)",
        verify_receipt_idx=1,
        min_receipts=2,
    )


def parse_blob():
    return _parse_broadcast(
        BLOB_JSON,
        "Blob tx (EOA -> WhirBlobVerifier4.verify)",
        verify_receipt_idx=2,
        min_receipts=3,
    )


def parse_wrapper():
    return _parse_broadcast(
        WRAPPER_JSON,
        "Wrapper tx (EOA -> VerifyWrapper -> WhirVerifier4.verify)",
        verify_receipt_idx=2,
        min_receipts=3,
    )


def main():
    all_modes = ["native", "direct", "blob", "wrapper"]
    parsers = {
        "native": parse_native,
        "direct": parse_direct,
        "blob": parse_blob,
        "wrapper": parse_wrapper,
    }
    modes = sys.argv[1:] if len(sys.argv) > 1 else all_modes

    results = {}
    for mode in modes:
        if mode not in parsers:
            print(f"Unknown mode: {mode}. Use one of: {', '.join(all_modes)}")
            sys.exit(1)
        results[mode] = parsers[mode]()
        print()

    # If both direct and wrapper are available, print comparison
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
