#!/usr/bin/env python3
import json
from pathlib import Path

SCRIPT_PATH = Path("script/Ext8PrecompilePhase1Benchmark.s.sol")
ARTIFACT = Path("broadcast") / SCRIPT_PATH.stem / "31337" / "run-latest.json"
LABELS = [
    "deploy_harness",
    "noop_mul_clean",
    "noop_square_clean",
    "eq22_software",
    "eq22_noop",
    "eq22_precompile",
    "round0_select_only_software",
    "round0_select_only_noop",
    "round0_select_only_precompile",
    "round0_eq_select_software",
    "round0_eq_select_noop",
    "round0_eq_select_precompile",
]


def main() -> None:
    raw = json.loads(ARTIFACT.read_text())
    txs = [
        tx
        for tx in raw["transactions"]
        if tx.get("transactionType") != "CREATE2_DEPLOYER"
    ]
    receipts = raw["receipts"]
    if len(txs) != len(receipts):
        raise SystemExit(
            f"transaction/receipt mismatch: {len(txs)} txs vs {len(receipts)} receipts"
        )
    if len(receipts) != len(LABELS):
        raise SystemExit(f"expected {len(LABELS)} receipts, found {len(receipts)}")

    print(f"artifact: {ARTIFACT}")
    for label, receipt in zip(LABELS, receipts):
        gas_used = int(receipt["gasUsed"], 16)
        print(f"{label}: {gas_used}")

    noop_mul = int(receipts[1]["gasUsed"], 16)
    noop_square = int(receipts[2]["gasUsed"], 16)
    eq_soft = int(receipts[3]["gasUsed"], 16)
    eq_pre = int(receipts[5]["gasUsed"], 16)
    sel_soft = int(receipts[6]["gasUsed"], 16)
    sel_pre = int(receipts[8]["gasUsed"], 16)
    combined_soft = int(receipts[9]["gasUsed"], 16)
    combined_pre = int(receipts[11]["gasUsed"], 16)

    print("---")
    print(f"eq_only_delta: {eq_soft - eq_pre}")
    print(f"select_only_delta: {sel_soft - sel_pre}")
    print(f"combined_delta: {combined_soft - combined_pre}")
    print(f"clean_transport_mul: {noop_mul}")
    print(f"clean_transport_square: {noop_square}")


if __name__ == "__main__":
    main()
