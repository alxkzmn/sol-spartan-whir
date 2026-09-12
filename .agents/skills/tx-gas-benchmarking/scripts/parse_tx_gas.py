#!/usr/bin/env python3
"""Parse verifier broadcast receipts or compare preserved benchmark runs."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


def _find_project_root() -> Path:
    for parent in Path(__file__).resolve().parents:
        if (parent / "foundry.toml").exists():
            return parent
    raise RuntimeError("Could not find foundry.toml above parse_tx_gas.py")


PROJECT_ROOT = _find_project_root()
BROADCAST_DIR = PROJECT_ROOT / "broadcast"
MODE_SPECS = {
    "native": {"script_family": "WhirBlobNativeTxBenchmark", "verify_receipt_idx": 1, "min_receipts": 2},
    "direct": {"script_family": "WhirTxBenchmark", "verify_receipt_idx": 1, "min_receipts": 2},
    "blob": {"script_family": "WhirBlobTxBenchmark", "verify_receipt_idx": 2, "min_receipts": 3},
    "wrapper": {"script_family": "MeasureTxGas", "verify_receipt_idx": 2, "min_receipts": 3},
    "leanvm": {"script_family": "LeanVm", "verify_receipt_idx": 1, "min_receipts": 2},
}


def classify_mode(raw: str) -> str:
    if raw in MODE_SPECS:
        return raw
    for mode, spec in MODE_SPECS.items():
        if Path(raw).name.startswith(spec["script_family"]):
            return mode
    raise ValueError(f"Unknown benchmark mode or script: {raw}")


def find_artifact(raw: str) -> Path:
    mode = classify_mode(raw)
    if raw not in MODE_SPECS:
        return BROADCAST_DIR / Path(raw).name / "31337" / "run-latest.json"
    matches = sorted(BROADCAST_DIR.glob(f"{MODE_SPECS[mode]['script_family']}*.s.sol/31337/run-latest.json"))
    if len(matches) != 1:
        raise ValueError(f"Mode {mode!r} matched {len(matches)} artifacts; pass an explicit script or --artifact.")
    return matches[0]


def _integer(value) -> int:
    return int(value, 0) if isinstance(value, str) else int(value)


def calldata_breakdown(hex_input: str) -> dict:
    raw = bytes.fromhex(hex_input.removeprefix("0x"))
    zero = raw.count(0)
    cost = 4 * zero + 16 * (len(raw) - zero)
    return {"total_bytes": len(raw), "zero_bytes": zero, "nonzero_bytes": len(raw) - zero,
            "calldata_gas": cost, "intrinsic_plus_calldata": 21_000 + cost,
            "calldata_sha256": hashlib.sha256(raw).hexdigest()}


def read_metrics(path: Path, mode: str) -> dict:
    data = json.loads(path.read_text())
    spec = MODE_SPECS[mode]
    transactions, receipts = data["transactions"], data["receipts"]
    count = spec["min_receipts"]
    if len(transactions) < count or len(receipts) < count:
        raise ValueError(f"{path}: fewer than {count} transactions/receipts; broadcast is incomplete")
    if data.get("pending"):
        raise ValueError(f"{path}: broadcast still has pending transactions")
    # Transaction order identifies the known benchmark call. Match its receipt by
    # hash because RPC receipt order need not match broadcast transaction order.
    selected = None
    for index, transaction in enumerate(transactions[:count]):
        tx_hash = transaction["hash"]
        matches = [r for r in receipts if r.get("transactionHash") == tx_hash]
        if not tx_hash or len(matches) != 1:
            raise ValueError(f"{path}: expected one receipt for transaction {index}")
        receipt = matches[0]
        if _integer(receipt["status"]) != 1:
            raise ValueError(f"{path}: transaction {index} reverted ({tx_hash})")
        if index == spec["verify_receipt_idx"]:
            selected = transaction, receipt
    transaction, receipt = selected
    total = _integer(receipt["gasUsed"])
    calldata = calldata_breakdown(transaction["transaction"]["input"])
    execution = total - calldata["intrinsic_plus_calldata"]
    if execution < 0:
        raise ValueError(f"{path}: gas is below the supported 21,000 + calldata accounting model")
    return {"mode": mode, "chain_id": data.get("chain"), "transaction_hash": transaction["hash"],
            "contract_name": transaction.get("contractName"), "function": transaction.get("function"),
            "transaction_gas": total, "intrinsic_gas": 21_000, "execution_gas": execution, **calldata}


def print_metrics(metrics: dict, label: str) -> None:
    print(f"=== {label} ===")
    for title, key in (("Total tx gas", "transaction_gas"), ("Intrinsic + calldata", "intrinsic_plus_calldata"),
                       ("Calldata bytes", "total_bytes"), ("Zero bytes", "zero_bytes"),
                       ("Nonzero bytes", "nonzero_bytes"), ("Calldata gas", "calldata_gas"),
                       ("Intrinsic gas", "intrinsic_gas"), ("Execution remainder", "execution_gas")):
        print(f"  {title:<22} {metrics[key]:>12,}")
    print(f"  Calldata SHA-256       {metrics['calldata_sha256']}")


def compare(before: Path, after: Path, mode: str) -> None:
    old, new = read_metrics(before, mode), read_metrics(after, mode)
    for key in ("chain_id", "contract_name", "function", "calldata_sha256"):
        if old[key] != new[key]:
            raise ValueError(f"Cannot compare these runs: {key} differs")
    print_metrics(old, f"Before: {before}")
    print_metrics(new, f"After: {after}")
    print("=== Delta (after - before; identical calldata) ===")
    print(f"  Total tx gas          {new['transaction_gas'] - old['transaction_gas']:>+12,}")
    print(f"  Execution gas         {new['execution_gas'] - old['execution_gas']:>+12,}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("targets", nargs="*", help="Legacy mode aliases or explicit script paths (chain 31337)")
    parser.add_argument("--mode", choices=MODE_SPECS, help="Required for preserved artifact paths")
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--artifact", type=Path, help="Parse this exact saved broadcast JSON")
    selection.add_argument("--compare", type=Path, nargs=2, metavar=("BEFORE", "AFTER"))
    args = parser.parse_args()
    if (args.artifact or args.compare) and (not args.mode or args.targets):
        parser.error("Use --mode with --artifact or --compare, without positional targets")
    if args.mode and not (args.artifact or args.compare):
        parser.error("--mode requires --artifact or --compare")
    try:
        if args.artifact:
            print_metrics(read_metrics(args.artifact, args.mode), str(args.artifact))
        elif args.compare:
            compare(*args.compare, args.mode)
        else:
            results = {}
            for raw in args.targets or MODE_SPECS:
                mode = classify_mode(raw)
                results[mode] = read_metrics(find_artifact(raw), mode)
                print_metrics(results[mode], raw)
            if "direct" in results and "wrapper" in results:
                old, new = results["direct"], results["wrapper"]
                print("=== Wrapper versus direct ===")
                print(f"  Execution overhead    {new['execution_gas'] - old['execution_gas']:>+12,}")
                print(f"  Calldata delta        {new['calldata_gas'] - old['calldata_gas']:>+12,}")
                print(f"  Total tx delta        {new['transaction_gas'] - old['transaction_gas']:>+12,}")
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
