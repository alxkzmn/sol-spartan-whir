#!/usr/bin/env python3
import argparse
import json
import subprocess
from pathlib import Path

DEFAULT_RPC_URL = "http://127.0.0.1:18547"
DEFAULT_PRIVATE_KEY = (
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
)
MODULUS = 0x7F000001


def run(args: list[str]) -> str:
    completed = subprocess.run(args, check=True, text=True, capture_output=True)
    return completed.stdout


def deploy_harness(rpc_url: str, private_key: str) -> str:
    out = run(
        [
            "forge",
            "create",
            "test/helpers/Ext8PrecompileHarness.sol:Ext8PrecompileHarness",
            "--rpc-url",
            rpc_url,
            "--private-key",
            private_key,
            "--broadcast",
        ]
    )
    for line in out.splitlines():
        if line.startswith("Deployed to:"):
            return line.split(":", 1)[1].strip()
    raise RuntimeError(f"failed to parse deployed harness address:\n{out}")


def cast_send(
    rpc_url: str,
    private_key: str,
    harness: str,
    signature: str,
    args: list[str],
    gas_limit: int,
) -> int:
    out = run(
        [
            "cast",
            "send",
            harness,
            signature,
            *args,
            "--rpc-url",
            rpc_url,
            "--private-key",
            private_key,
            "--gas-limit",
            str(gas_limit),
            "--json",
        ]
    )
    receipt = json.loads(out)
    if receipt.get("status") != "0x1":
        raise RuntimeError(f"transaction reverted for {signature}: {receipt}")
    return int(receipt["gasUsed"], 16)


def array_arg(values: list[str | int]) -> str:
    return "[" + ",".join(hex(v) if isinstance(v, int) else v for v in values) + "]"


def from_base(value: int) -> int:
    return value << 224


def run_arithmetic(
    rpc_url: str,
    private_key: str,
    harness: str,
    vectors_path: Path,
    chunk_size: int,
    gas_limit: int,
) -> None:
    vectors = json.loads(vectors_path.read_text())["vectors"]
    total_gas = 0
    for start in range(0, len(vectors), chunk_size):
        chunk = vectors[start : start + chunk_size]
        gas = cast_send(
            rpc_url,
            private_key,
            harness,
            "checkArithmeticVectorsTx(uint256[],uint256[],uint256[],uint256[])(bool)",
            [
                array_arg([v["packed_a"] for v in chunk]),
                array_arg([v["packed_b"] for v in chunk]),
                array_arg([v["packed_mul"] for v in chunk]),
                array_arg([v["packed_square_a"] for v in chunk]),
            ],
            gas_limit,
        )
        total_gas += gas
        print(f"arithmetic_chunk start={start} count={len(chunk)} gas={gas}")
    print(f"arithmetic_vectors={len(vectors)}")
    print(f"arithmetic_total_gas={total_gas}")


def run_benchmarks(
    rpc_url: str, private_key: str, harness: str, gas_limit: int
) -> None:
    full_point = [from_base((i % 17) + 1) for i in range(22)]
    sel_vars = [((i + 1) * 7 % (MODULUS - 1)) + 1 for i in range(24)]
    challenge = from_base(7)
    ood_point = from_base(5)
    eq_eval = from_base(11)

    # Avoid charging the first measured call for the zero-to-nonzero SSTORE on lastResult.
    cast_send(
        rpc_url,
        private_key,
        harness,
        "benchmarkNoopSquareClean(uint256)",
        [hex(ood_point)],
        gas_limit,
    )

    calls = [
        (
            "noop_mul_clean",
            "benchmarkNoopMulClean(uint256,uint256)",
            [ood_point, eq_eval],
        ),
        ("noop_square_clean", "benchmarkNoopSquareClean(uint256)", [ood_point]),
        (
            "eq22_software",
            "benchmarkEqExpanded22Software(uint256,uint256[])",
            [ood_point, full_point],
        ),
        (
            "eq22_noop",
            "benchmarkEqExpanded22Noop(uint256,uint256[])",
            [ood_point, full_point],
        ),
        (
            "eq22_precompile",
            "benchmarkEqExpanded22Precompile(uint256,uint256[])",
            [ood_point, full_point],
        ),
        (
            "eq18_software",
            "benchmarkEqExpanded18Software(uint256,uint256[])",
            [ood_point, full_point],
        ),
        (
            "eq18_noop",
            "benchmarkEqExpanded18Noop(uint256,uint256[])",
            [ood_point, full_point],
        ),
        (
            "eq18_precompile",
            "benchmarkEqExpanded18Precompile(uint256,uint256[])",
            [ood_point, full_point],
        ),
        (
            "eq14_software",
            "benchmarkEqExpanded14Software(uint256,uint256[])",
            [ood_point, full_point],
        ),
        (
            "eq14_noop",
            "benchmarkEqExpanded14Noop(uint256,uint256[])",
            [ood_point, full_point],
        ),
        (
            "eq14_precompile",
            "benchmarkEqExpanded14Precompile(uint256,uint256[])",
            [ood_point, full_point],
        ),
        (
            "eq10_software",
            "benchmarkEqExpanded10Software(uint256,uint256[])",
            [ood_point, full_point],
        ),
        (
            "eq10_noop",
            "benchmarkEqExpanded10Noop(uint256,uint256[])",
            [ood_point, full_point],
        ),
        (
            "eq10_precompile",
            "benchmarkEqExpanded10Precompile(uint256,uint256[])",
            [ood_point, full_point],
        ),
        (
            "round0_select_only_software",
            "benchmarkRound0SelectOnlySoftware(uint256,uint256,uint256[],uint256[])",
            [challenge, eq_eval, sel_vars, full_point],
        ),
        (
            "round0_select_only_noop",
            "benchmarkRound0SelectOnlyNoop(uint256,uint256,uint256[],uint256[])",
            [challenge, eq_eval, sel_vars, full_point],
        ),
        (
            "round0_select_only_precompile",
            "benchmarkRound0SelectOnlyPrecompile(uint256,uint256,uint256[],uint256[])",
            [challenge, eq_eval, sel_vars, full_point],
        ),
        (
            "round0_eq_select_software",
            "benchmarkRound0EqSelectSoftware(uint256,uint256,uint256[],uint256[])",
            [challenge, ood_point, sel_vars, full_point],
        ),
        (
            "round0_eq_select_noop",
            "benchmarkRound0EqSelectNoop(uint256,uint256,uint256[],uint256[])",
            [challenge, ood_point, sel_vars, full_point],
        ),
        (
            "round0_eq_select_precompile",
            "benchmarkRound0EqSelectPrecompile(uint256,uint256,uint256[],uint256[])",
            [challenge, ood_point, sel_vars, full_point],
        ),
        (
            "round1_select_only_software",
            "benchmarkRound1SelectOnlySoftware(uint256,uint256,uint256[],uint256[])",
            [challenge, eq_eval, sel_vars, full_point],
        ),
        (
            "round1_select_only_noop",
            "benchmarkRound1SelectOnlyNoop(uint256,uint256,uint256[],uint256[])",
            [challenge, eq_eval, sel_vars, full_point],
        ),
        (
            "round1_select_only_precompile",
            "benchmarkRound1SelectOnlyPrecompile(uint256,uint256,uint256[],uint256[])",
            [challenge, eq_eval, sel_vars, full_point],
        ),
        (
            "round1_eq_select_software",
            "benchmarkRound1EqSelectSoftware(uint256,uint256,uint256[],uint256[])",
            [challenge, ood_point, sel_vars, full_point],
        ),
        (
            "round1_eq_select_noop",
            "benchmarkRound1EqSelectNoop(uint256,uint256,uint256[],uint256[])",
            [challenge, ood_point, sel_vars, full_point],
        ),
        (
            "round1_eq_select_precompile",
            "benchmarkRound1EqSelectPrecompile(uint256,uint256,uint256[],uint256[])",
            [challenge, ood_point, sel_vars, full_point],
        ),
        (
            "round2_select_only_software",
            "benchmarkRound2SelectOnlySoftware(uint256,uint256,uint256[],uint256[])",
            [challenge, eq_eval, sel_vars, full_point],
        ),
        (
            "round2_select_only_noop",
            "benchmarkRound2SelectOnlyNoop(uint256,uint256,uint256[],uint256[])",
            [challenge, eq_eval, sel_vars, full_point],
        ),
        (
            "round2_select_only_precompile",
            "benchmarkRound2SelectOnlyPrecompile(uint256,uint256,uint256[],uint256[])",
            [challenge, eq_eval, sel_vars, full_point],
        ),
        (
            "round2_eq_select_software",
            "benchmarkRound2EqSelectSoftware(uint256,uint256,uint256[],uint256[])",
            [challenge, ood_point, sel_vars, full_point],
        ),
        (
            "round2_eq_select_noop",
            "benchmarkRound2EqSelectNoop(uint256,uint256,uint256[],uint256[])",
            [challenge, ood_point, sel_vars, full_point],
        ),
        (
            "round2_eq_select_precompile",
            "benchmarkRound2EqSelectPrecompile(uint256,uint256,uint256[],uint256[])",
            [challenge, ood_point, sel_vars, full_point],
        ),
    ]

    gas_by_label: dict[str, int] = {}
    for label, signature, raw_args in calls:
        encoded_args = [
            array_arg(arg) if isinstance(arg, list) else hex(arg) for arg in raw_args
        ]
        gas = cast_send(
            rpc_url, private_key, harness, signature, encoded_args, gas_limit
        )
        gas_by_label[label] = gas
        print(f"{label}: {gas}")

    print("---")
    eq_delta = sum(
        gas_by_label[f"eq{arity}_software"] - gas_by_label[f"eq{arity}_precompile"]
        for arity in (22, 18, 14, 10)
    )
    select_delta = sum(
        gas_by_label[f"round{round_idx}_select_only_software"]
        - gas_by_label[f"round{round_idx}_select_only_precompile"]
        for round_idx in (0, 1, 2)
    )
    combined_delta = sum(
        gas_by_label[f"round{round_idx}_eq_select_software"]
        - gas_by_label[f"round{round_idx}_eq_select_precompile"]
        for round_idx in (0, 1, 2)
    )
    print(f"eq_only_delta: {eq_delta}")
    print(f"select_only_delta: {select_delta}")
    print(f"combined_delta: {combined_delta}")
    print(f"clean_transport_mul_tx_gas: {gas_by_label['noop_mul_clean']}")
    print(f"clean_transport_square_tx_gas: {gas_by_label['noop_square_clean']}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rpc-url", default=DEFAULT_RPC_URL)
    parser.add_argument("--private-key", default=DEFAULT_PRIVATE_KEY)
    parser.add_argument("--harness")
    parser.add_argument(
        "--vectors", type=Path, default=Path("testdata/ext8_precompile_vectors.json")
    )
    parser.add_argument("--chunk-size", type=int, default=250)
    parser.add_argument("--gas-limit", type=int, default=30_000_000)
    parser.add_argument("--skip-arithmetic", action="store_true")
    parser.add_argument("--skip-benchmarks", action="store_true")
    args = parser.parse_args()

    harness = args.harness or deploy_harness(args.rpc_url, args.private_key)
    print(f"harness={harness}")

    if not args.skip_arithmetic:
        run_arithmetic(
            args.rpc_url,
            args.private_key,
            harness,
            args.vectors,
            args.chunk_size,
            args.gas_limit,
        )
    if not args.skip_benchmarks:
        run_benchmarks(args.rpc_url, args.private_key, harness, args.gas_limit)


if __name__ == "__main__":
    main()
