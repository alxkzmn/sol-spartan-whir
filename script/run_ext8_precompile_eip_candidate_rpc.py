#!/usr/bin/env python3
import argparse
import json
import subprocess
from pathlib import Path
from typing import Any

DEFAULT_RPC_URL = "http://127.0.0.1:18547"
DEFAULT_PRIVATE_KEY = (
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
)
HARNESS_CONTRACT = "test/helpers/Ext8PrecompileHarness.sol:Ext8PrecompileHarness"
BATCH_SIZES = [1, 4, 8, 16, 32, 64, 128, 256]
STANDALONE_GATE_N = 256
STANDALONE_SAVING_THRESHOLD = 50_000

# These are deliberately rough and conservative. They only matter if a candidate
# already clears the transport and real-precompile gates.
ESTIMATED_FULL_VERIFIER_COUNTS = {
    "add": 2_500,
    "sub": 2_200,
    "mul_base": 950,
}

STANDALONE_CALLS = {
    "add": {
        "software": "benchmarkAddLoopSoftware(uint256[],uint256[])",
        "noop": "benchmarkAddLoopNoop(uint256[],uint256[])",
        "precompile": "benchmarkAddLoopPrecompile(uint256[],uint256[])",
        "args": ("packedA", "packedB"),
        "schedule_key": "ext8_add",
    },
    "sub": {
        "software": "benchmarkSubLoopSoftware(uint256[],uint256[])",
        "noop": "benchmarkSubLoopNoop(uint256[],uint256[])",
        "precompile": "benchmarkSubLoopPrecompile(uint256[],uint256[])",
        "args": ("packedA", "packedB"),
        "schedule_key": "ext8_sub",
    },
    "mul_base": {
        "software": "benchmarkMulBaseLoopSoftware(uint256[],uint256[])",
        "noop": "benchmarkMulBaseLoopNoop(uint256[],uint256[])",
        "precompile": "benchmarkMulBaseLoopPrecompile(uint256[],uint256[])",
        "args": ("packedA", "scalars"),
        "schedule_key": "ext8_mul_base",
    },
}

BATCH_CALLS = {
    "mul": {
        "software": "benchmarkMulBatchSoftware(uint256[],uint256[])",
        "scalar_noop": "benchmarkMulLoopNoop(uint256[],uint256[])",
        "scalar_precompile": "benchmarkMulLoopPrecompile(uint256[],uint256[])",
        "batch_noop": "benchmarkMulBatchNoop(uint256[],uint256[])",
        "batch_precompile": "benchmarkMulBatchPrecompile(uint256[],uint256[])",
        "args": ("packedA", "packedB"),
        "schedule_key": "ext8_mul_batch",
    },
    "square": {
        "software": "benchmarkSquareBatchSoftware(uint256[])",
        "scalar_noop": "benchmarkSquareLoopNoop(uint256[])",
        "scalar_precompile": "benchmarkSquareLoopPrecompile(uint256[])",
        "batch_noop": "benchmarkSquareBatchNoop(uint256[])",
        "batch_precompile": "benchmarkSquareBatchPrecompile(uint256[])",
        "args": ("packedA",),
        "schedule_key": "ext8_square_batch",
    },
    "mul_base": {
        "software": "benchmarkMulBaseBatchSoftware(uint256[],uint256[])",
        "scalar_noop": "benchmarkMulBaseLoopNoop(uint256[],uint256[])",
        "scalar_precompile": "benchmarkMulBaseLoopPrecompile(uint256[],uint256[])",
        "batch_noop": "benchmarkMulBaseBatchNoop(uint256[],uint256[])",
        "batch_precompile": "benchmarkMulBaseBatchPrecompile(uint256[],uint256[])",
        "args": ("packedA", "scalars"),
        "schedule_key": "ext8_mul_base_batch",
    },
}


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def run(args: list[str], *, cwd: Path) -> str:
    return subprocess.run(
        args, cwd=cwd, check=True, text=True, capture_output=True
    ).stdout


def deploy_harness(rpc_url: str, private_key: str, gas_limit: int, cwd: Path) -> str:
    out = run(
        [
            "forge",
            "create",
            HARNESS_CONTRACT,
            "--rpc-url",
            rpc_url,
            "--private-key",
            private_key,
            "--broadcast",
            "--gas-limit",
            str(gas_limit),
        ],
        cwd=cwd,
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
    cwd: Path,
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
        ],
        cwd=cwd,
    )
    receipt = json.loads(out)
    if receipt.get("status") != "0x1":
        raise RuntimeError(f"transaction reverted for {signature}: {receipt}")
    return int(receipt["gasUsed"], 16)


def array_arg(values: list[str]) -> str:
    return "[" + ",".join(values) + "]"


def load_vectors(path: Path) -> dict[str, list[str]]:
    raw = json.loads(path.read_text())
    vectors = raw["vectors"]
    required = [
        "packed_a",
        "packed_b",
        "scalar",
        "packed_add",
        "packed_sub",
        "packed_mul",
        "packed_square_a",
        "packed_mul_base",
    ]
    for key in required:
        if key not in vectors[0]:
            raise RuntimeError(
                f"vectors missing {key}; regenerate ext8_precompile_vectors.json"
            )
    return {
        "packedA": [v["packed_a"] for v in vectors],
        "packedB": [v["packed_b"] for v in vectors],
        "scalars": [v["scalar"] for v in vectors],
        "expectedAdd": [v["packed_add"] for v in vectors],
        "expectedSub": [v["packed_sub"] for v in vectors],
        "expectedMul": [v["packed_mul"] for v in vectors],
        "expectedSquareA": [v["packed_square_a"] for v in vectors],
        "expectedMulBase": [v["packed_mul_base"] for v in vectors],
    }


def sliced_args(
    vectors: dict[str, list[str]], names: tuple[str, ...], n: int
) -> list[str]:
    return [array_arg(vectors[name][:n]) for name in names]


def run_correctness(
    rpc_url: str,
    private_key: str,
    harness: str,
    vectors: dict[str, list[str]],
    chunk_size: int,
    gas_limit: int,
    cwd: Path,
) -> int:
    total = len(vectors["packedA"])
    total_gas = 0
    for start in range(0, total, chunk_size):
        end = min(start + chunk_size, total)
        args = [
            array_arg(vectors["packedA"][start:end]),
            array_arg(vectors["packedB"][start:end]),
            array_arg(vectors["scalars"][start:end]),
            array_arg(vectors["expectedAdd"][start:end]),
            array_arg(vectors["expectedSub"][start:end]),
            array_arg(vectors["expectedMul"][start:end]),
            array_arg(vectors["expectedSquareA"][start:end]),
            array_arg(vectors["expectedMulBase"][start:end]),
        ]
        gas = cast_send(
            rpc_url,
            private_key,
            harness,
            "checkExtendedArithmeticVectorsTx(uint256[],uint256[],uint256[],uint256[],uint256[],uint256[],uint256[],uint256[])(bool)",
            args,
            gas_limit,
            cwd,
        )
        total_gas += gas
        print(f"correctness_chunk_start={start} count={end - start} gas={gas}")
    print(f"correctness_vectors={total}")
    print(f"correctness_total_gas={total_gas}")
    return total_gas


def run_call(
    label: str,
    signature: str,
    args: list[str],
    rpc_url: str,
    private_key: str,
    harness: str,
    gas_limit: int,
    cwd: Path,
) -> int:
    gas = cast_send(rpc_url, private_key, harness, signature, args, gas_limit, cwd)
    print(f"{label}={gas}")
    return gas


def ratio_pass(lhs: int, rhs: int, numerator: int, denominator: int) -> bool:
    return lhs * denominator <= rhs * numerator


def analyze_standalone(name: str, gas: dict[str, int]) -> dict[str, Any]:
    n = STANDALONE_GATE_N
    software = gas["software"]
    noop = gas["noop"]
    real = gas["precompile"]
    transport_pass = ratio_pass(noop, software, 85, 100)
    real_pass = ratio_pass(real, software, 85, 100)
    per_op_saving = (software - real) / n
    projected = round(per_op_saving * ESTIMATED_FULL_VERIFIER_COUNTS[name])
    projected_pass = projected >= STANDALONE_SAVING_THRESHOLD
    passed = transport_pass and real_pass and projected_pass
    return {
        "software": software,
        "noop": noop,
        "precompile": real,
        "software_per_op": software / n,
        "noop_per_op": noop / n,
        "precompile_per_op": real / n,
        "estimated_full_verifier_count": ESTIMATED_FULL_VERIFIER_COUNTS[name],
        "projected_full_verifier_saving": projected,
        "transport_gate": transport_pass,
        "real_gate": real_pass,
        "projected_gate": projected_pass,
        "pass": passed,
    }


def analyze_batch(results: dict[int, dict[str, int]]) -> dict[str, Any]:
    rows = []
    for n, gas in results.items():
        scalar_noop_per_op = gas["scalar_noop"] / n
        scalar_real_per_op = gas["scalar_precompile"] / n
        batch_noop_per_op = gas["batch_noop"] / n
        batch_real_per_op = gas["batch_precompile"] / n
        rows.append(
            {
                "n": n,
                "software": gas["software"],
                "scalar_noop": gas["scalar_noop"],
                "scalar_precompile": gas["scalar_precompile"],
                "batch_noop": gas["batch_noop"],
                "batch_precompile": gas["batch_precompile"],
                "software_per_op": gas["software"] / n,
                "scalar_noop_per_op": scalar_noop_per_op,
                "scalar_precompile_per_op": scalar_real_per_op,
                "batch_noop_per_op": batch_noop_per_op,
                "batch_precompile_per_op": batch_real_per_op,
                "noop_beats_scalar_noop": batch_noop_per_op < scalar_noop_per_op,
                "batch_beats_scalar_precompile_20pct": batch_real_per_op
                <= scalar_real_per_op * 0.8,
            }
        )
    amortizes_by_16 = any(
        row["n"] <= 16 and row["noop_beats_scalar_noop"] for row in rows
    )
    real_beats_by_20pct = any(
        row["batch_beats_scalar_precompile_20pct"] for row in rows
    )
    useful_not_only_256 = any(
        row["n"] <= 64 and row["batch_beats_scalar_precompile_20pct"] for row in rows
    )
    return {
        "rows": rows,
        "amortizes_by_16_gate": amortizes_by_16,
        "real_batch_gate": real_beats_by_20pct,
        "realistic_size_gate": useful_not_only_256,
        "pass": amortizes_by_16 and real_beats_by_20pct and useful_not_only_256,
    }


def main() -> None:
    cwd = project_root()
    parser = argparse.ArgumentParser()
    parser.add_argument("--rpc-url", default=DEFAULT_RPC_URL)
    parser.add_argument("--private-key", default=DEFAULT_PRIVATE_KEY)
    parser.add_argument("--harness")
    parser.add_argument("--gas-limit", type=int, default=30_000_000)
    parser.add_argument("--chunk-size", type=int, default=100)
    parser.add_argument("--skip-correctness", action="store_true")
    parser.add_argument(
        "--vectors", type=Path, default=cwd / "testdata/ext8_precompile_vectors.json"
    )
    parser.add_argument(
        "--gas-schedule",
        type=Path,
        default=cwd / "testdata/ext8_precompile_gas_schedule.json",
    )
    args = parser.parse_args()

    vectors = load_vectors(args.vectors)
    schedule = json.loads(args.gas_schedule.read_text())
    harness = args.harness or deploy_harness(
        args.rpc_url, args.private_key, args.gas_limit, cwd
    )
    print(f"harness={harness}")

    if not args.skip_correctness:
        run_correctness(
            args.rpc_url,
            args.private_key,
            harness,
            vectors,
            args.chunk_size,
            args.gas_limit,
            cwd,
        )

    # Avoid charging the first measured call for zero-to-nonzero SSTORE on lastResult.
    run_call(
        "warmup_noop_square",
        "benchmarkNoopSquareClean(uint256)",
        [vectors["packedA"][0]],
        args.rpc_url,
        args.private_key,
        harness,
        args.gas_limit,
        cwd,
    )

    summary: dict[str, Any] = {"standalone": {}, "batch": {}, "assigned_gas": {}}

    n = STANDALONE_GATE_N
    for name, config in STANDALONE_CALLS.items():
        call_args = sliced_args(vectors, config["args"], n)
        gas = {}
        for variant in ("software", "noop", "precompile"):
            gas[variant] = run_call(
                f"standalone_{name}_{variant}_n{n}",
                config[variant],
                call_args,
                args.rpc_url,
                args.private_key,
                harness,
                args.gas_limit,
                cwd,
            )
        summary["assigned_gas"][name] = schedule[config["schedule_key"]][
            "assigned_base_gas"
        ]
        summary["standalone"][name] = analyze_standalone(name, gas)

    for name, config in BATCH_CALLS.items():
        op_results = {}
        summary["assigned_gas"][f"{name}_batch_per_item"] = schedule[
            config["schedule_key"]
        ]["assigned_base_gas"]
        for n in BATCH_SIZES:
            call_args = sliced_args(vectors, config["args"], n)
            gas = {}
            for variant in (
                "software",
                "scalar_noop",
                "scalar_precompile",
                "batch_noop",
                "batch_precompile",
            ):
                gas[variant] = run_call(
                    f"batch_{name}_{variant}_n{n}",
                    config[variant],
                    call_args,
                    args.rpc_url,
                    args.private_key,
                    harness,
                    args.gas_limit,
                    cwd,
                )
            op_results[n] = gas
        summary["batch"][name] = analyze_batch(op_results)

    print("---")
    print("candidate_summary_json=" + json.dumps(summary, sort_keys=True))
    for name, result in summary["standalone"].items():
        print(
            f"standalone_decision_{name}=pass:{str(result['pass']).lower()} "
            f"transport:{str(result['transport_gate']).lower()} "
            f"real:{str(result['real_gate']).lower()} "
            f"projected:{str(result['projected_gate']).lower()} "
            f"projected_saving:{result['projected_full_verifier_saving']}"
        )
    for name, result in summary["batch"].items():
        print(
            f"batch_decision_{name}=pass:{str(result['pass']).lower()} "
            f"amortizes_by_16:{str(result['amortizes_by_16_gate']).lower()} "
            f"real_batch:{str(result['real_batch_gate']).lower()} "
            f"realistic_size:{str(result['realistic_size_gate']).lower()}"
        )


if __name__ == "__main__":
    main()
