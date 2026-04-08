#!/usr/bin/env python3
"""Parse broadcast JSON artifacts from anvil tx-gas measurement scripts.

Usage:
    python3 parse_tx_gas.py              # parse both direct + wrapper
    python3 parse_tx_gas.py direct       # parse direct tx only
    python3 parse_tx_gas.py wrapper      # parse wrapper tx only
"""

import json
import sys
from pathlib import Path

BROADCAST_DIR = Path(__file__).parent / "broadcast"
DIRECT_JSON = BROADCAST_DIR / "WhirTxBenchmark.s.sol/31337/run-latest.json"
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


def parse_direct():
    if not DIRECT_JSON.exists():
        print(f"Not found: {DIRECT_JSON}")
        print("Run WhirTxBenchmark.s.sol against anvil first (see AGENTS.md).")
        return

    with open(DIRECT_JSON) as f:
        data = json.load(f)

    if len(data["receipts"]) < 2:
        print("ERROR: receipts array has <2 entries — broadcast likely failed.")
        print("Did you pass --private-key? See AGENTS.md for the full command.")
        return

    # Receipt[0] = CREATE, Receipt[1] = verify CALL
    gas_used = int(data["receipts"][1]["gasUsed"], 16)

    # Calldata from tx[1] input
    inp = data["transactions"][1]["transaction"]["input"]
    cd = calldata_breakdown(inp)

    exec_remainder = gas_used - cd["intrinsic_plus_calldata"]

    print("=== Direct tx (EOA -> WhirVerifier4.verify) ===")
    print(f"  Total tx gas:         {gas_used:>12,}")
    print(f"  Intrinsic + calldata: {cd['intrinsic_plus_calldata']:>12,}")
    print(f"    calldata bytes:     {cd['total_bytes']:>12,}")
    print(f"    zero bytes:         {cd['zero_bytes']:>12,}")
    print(f"    nonzero bytes:      {cd['nonzero_bytes']:>12,}")
    print(f"    calldata gas:       {cd['calldata_gas']:>12,}")
    print(f"    intrinsic:          {21_000:>12,}")
    print(f"  Execution remainder:  {exec_remainder:>12,}")
    return gas_used, cd, exec_remainder


def parse_wrapper():
    if not WRAPPER_JSON.exists():
        print(f"Not found: {WRAPPER_JSON}")
        print("Run MeasureTxGas.s.sol against anvil first (see AGENTS.md).")
        return

    with open(WRAPPER_JSON) as f:
        data = json.load(f)

    if len(data["receipts"]) < 3:
        print("ERROR: receipts array has <3 entries — broadcast likely failed.")
        print("Did you pass --private-key and --tc MeasureTxGas? See AGENTS.md.")
        return

    # Receipt[0] = WhirVerifier4 CREATE
    # Receipt[1] = VerifyWrapper CREATE
    # Receipt[2] = verifyAndStore CALL
    gas_used = int(data["receipts"][2]["gasUsed"], 16)

    # Calldata from tx[2] input
    inp = data["transactions"][2]["transaction"]["input"]
    cd = calldata_breakdown(inp)

    exec_remainder = gas_used - cd["intrinsic_plus_calldata"]

    print("=== Wrapper tx (EOA -> VerifyWrapper -> WhirVerifier4.verify) ===")
    print(f"  Total tx gas:         {gas_used:>12,}")
    print(f"  Intrinsic + calldata: {cd['intrinsic_plus_calldata']:>12,}")
    print(f"    calldata bytes:     {cd['total_bytes']:>12,}")
    print(f"    zero bytes:         {cd['zero_bytes']:>12,}")
    print(f"    nonzero bytes:      {cd['nonzero_bytes']:>12,}")
    print(f"    calldata gas:       {cd['calldata_gas']:>12,}")
    print(f"    intrinsic:          {21_000:>12,}")
    print(f"  Execution remainder:  {exec_remainder:>12,}")
    return gas_used, cd, exec_remainder


def main():
    modes = sys.argv[1:] if len(sys.argv) > 1 else ["direct", "wrapper"]

    direct_result = None
    wrapper_result = None

    for mode in modes:
        if mode == "direct":
            direct_result = parse_direct()
        elif mode == "wrapper":
            wrapper_result = parse_wrapper()
        else:
            print(f"Unknown mode: {mode}. Use 'direct' or 'wrapper'.")
            sys.exit(1)
        print()

    # If both are available, print comparison
    if direct_result and wrapper_result:
        d_gas, d_cd, d_exec = direct_result
        w_gas, w_cd, w_exec = wrapper_result
        overhead = w_exec - d_exec
        print("=== Comparison ===")
        print(f"  Wrapper overhead:     {overhead:>12,}")
        print(
            f"  Calldata delta:       {w_cd['intrinsic_plus_calldata'] - d_cd['intrinsic_plus_calldata']:>+12,}"
        )
        print(f"  Total tx delta:       {w_gas - d_gas:>+12,}")


if __name__ == "__main__":
    main()
