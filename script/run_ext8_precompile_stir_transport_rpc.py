#!/usr/bin/env python3
import argparse
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

DEFAULT_RPC_URL = "http://127.0.0.1:18547"
DEFAULT_PRIVATE_KEY = (
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
)
HARNESS_CONTRACT = "test/helpers/Ext8PrecompileHarness.sol:Ext8PrecompileHarness"

HEADER_BYTES = 18
STATEMENT_POINT_ARITY = 22
STATEMENT_EVALUATIONS = 1
EFFECTIVE_DIGEST_BYTES = 20
EXT8_ROW_BYTES = 512
ROUND0_NUM_QUERIES = 24
ROUND1_NUM_QUERIES = 16
ROUND2_NUM_QUERIES = 12
FINAL_NUM_QUERIES = 10
ROW_LEN = 16
INITIAL_SUMCHECK_EVALS = 8
ROUND_SUMCHECK_EVALS = 8
FINAL_POLY_LEN = 64

FOLD_MULS_PER_ROW = 15
GATE_THRESHOLD = 300_000


@dataclass(frozen=True)
class RowSlices:
    round1: bytes
    round2: bytes
    final: bytes

    @property
    def combined(self) -> bytes:
        return self.round1 + self.round2 + self.final


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


def u16_be(blob: bytes, offset: int) -> int:
    return int.from_bytes(blob[offset : offset + 2], "big")


def extract_row_slices(blob: bytes) -> RowSlices:
    round0_decomm_len = u16_be(blob, 10)
    round1_decomm_len = u16_be(blob, 12)
    round2_decomm_len = u16_be(blob, 14)
    final_decomm_len = u16_be(blob, 16)

    offset = (
        HEADER_BYTES
        + STATEMENT_POINT_ARITY * 32
        + STATEMENT_EVALUATIONS * 32
        + EFFECTIVE_DIGEST_BYTES
        + 32
        + INITIAL_SUMCHECK_EVALS * 32
    )

    offset += EFFECTIVE_DIGEST_BYTES + 32 + 4
    offset += ROUND0_NUM_QUERIES * ROW_LEN * 4
    offset += round0_decomm_len * EFFECTIVE_DIGEST_BYTES
    offset += ROUND_SUMCHECK_EVALS * 32

    offset += EFFECTIVE_DIGEST_BYTES + 32 + 4
    round1_offset = offset
    round1_len = ROUND1_NUM_QUERIES * EXT8_ROW_BYTES
    offset += round1_len
    offset += round1_decomm_len * EFFECTIVE_DIGEST_BYTES
    offset += ROUND_SUMCHECK_EVALS * 32

    offset += EFFECTIVE_DIGEST_BYTES + 32 + 4
    round2_offset = offset
    round2_len = ROUND2_NUM_QUERIES * EXT8_ROW_BYTES
    offset += round2_len
    offset += round2_decomm_len * EFFECTIVE_DIGEST_BYTES
    offset += ROUND_SUMCHECK_EVALS * 32

    offset += FINAL_POLY_LEN * 32 + 4
    final_offset = offset
    final_len = FINAL_NUM_QUERIES * EXT8_ROW_BYTES
    offset += final_len
    offset += final_decomm_len * EFFECTIVE_DIGEST_BYTES

    if offset + 12 * 32 != len(blob):
        raise ValueError(
            f"unexpected parsed blob length: parsed={offset + 12 * 32} actual={len(blob)}"
        )

    return RowSlices(
        round1=blob[round1_offset : round1_offset + round1_len],
        round2=blob[round2_offset : round2_offset + round2_len],
        final=blob[final_offset : final_offset + final_len],
    )


def pack_ext8(limbs: list[int]) -> int:
    if len(limbs) != 8:
        raise ValueError("expected 8 limbs")
    out = 0
    for limb in limbs:
        out = (out << 32) | limb
    return out


def row_arg(rows: bytes) -> str:
    return "0x" + rows.hex()


def hex_arg(value: int) -> str:
    return hex(value)


def bench_rows(
    label: str,
    rows: bytes,
    rpc_url: str,
    private_key: str,
    harness: str,
    gas_limit: int,
    cwd: Path,
    points: list[int],
) -> dict[str, int]:
    common_args = [row_arg(rows), *(hex_arg(point) for point in points)]
    signatures = {
        "software": "benchmarkStirRowsSoftware(bytes,uint256,uint256,uint256,uint256)",
        "noop": "benchmarkStirRowsNoop(bytes,uint256,uint256,uint256,uint256)",
        "precompile": "benchmarkStirRowsPrecompile(bytes,uint256,uint256,uint256,uint256)",
    }
    result = {}
    for variant, signature in signatures.items():
        gas = cast_send(
            rpc_url, private_key, harness, signature, common_args, gas_limit, cwd
        )
        result[variant] = gas
        print(f"{label}_{variant}_gas={gas}")
    return result


def main() -> None:
    cwd = project_root()

    parser = argparse.ArgumentParser()
    parser.add_argument("--rpc-url", default=DEFAULT_RPC_URL)
    parser.add_argument("--private-key", default=DEFAULT_PRIVATE_KEY)
    parser.add_argument("--harness")
    parser.add_argument("--gas-limit", type=int, default=30_000_000)
    parser.add_argument(
        "--blob",
        type=Path,
        default=cwd / "testdata/octic_whir_k22_jb100_lir6_ff4_rsv1_success.blob",
    )
    parser.add_argument(
        "--gas-schedule",
        type=Path,
        default=cwd / "testdata/ext8_precompile_gas_schedule.json",
    )
    args = parser.parse_args()

    schedule = json.loads(args.gas_schedule.read_text())
    assigned_mul_gas = int(schedule["ext8_mul"]["assigned_base_gas"])

    rows = extract_row_slices(args.blob.read_bytes())
    print(f"round1_rows={len(rows.round1) // EXT8_ROW_BYTES}")
    print(f"round2_rows={len(rows.round2) // EXT8_ROW_BYTES}")
    print(f"final_rows={len(rows.final) // EXT8_ROW_BYTES}")
    print(f"combined_rows={len(rows.combined) // EXT8_ROW_BYTES}")
    print(f"assigned_mul_gas={assigned_mul_gas}")

    harness = args.harness or deploy_harness(
        args.rpc_url, args.private_key, args.gas_limit, cwd
    )
    print(f"harness={harness}")

    points = [
        pack_ext8([1, 2, 3, 4, 5, 6, 7, 8]),
        pack_ext8([9, 10, 11, 12, 13, 14, 15, 16]),
        pack_ext8([17, 18, 19, 20, 21, 22, 23, 24]),
        pack_ext8([25, 26, 27, 28, 29, 30, 31, 32]),
    ]

    # Avoid charging the first measured call for zero-to-nonzero SSTORE on lastResult.
    cast_send(
        args.rpc_url,
        args.private_key,
        harness,
        "benchmarkNoopSquareClean(uint256)",
        [hex_arg(points[0])],
        args.gas_limit,
        cwd,
    )

    for label, row_bytes in (
        ("round1", rows.round1),
        ("round2", rows.round2),
        ("final", rows.final),
    ):
        bench_rows(
            label,
            row_bytes,
            args.rpc_url,
            args.private_key,
            harness,
            args.gas_limit,
            cwd,
            points,
        )

    combined = bench_rows(
        "combined",
        rows.combined,
        args.rpc_url,
        args.private_key,
        harness,
        args.gas_limit,
        cwd,
        points,
    )

    fold_mul_count = (len(rows.combined) // EXT8_ROW_BYTES) * FOLD_MULS_PER_ROW
    assigned_mul_total = fold_mul_count * assigned_mul_gas
    projected_saving = combined["software"] - combined["noop"] - assigned_mul_total
    actual_saving = combined["software"] - combined["precompile"]

    print("---")
    print(f"fold_mul_count={fold_mul_count}")
    print(f"assigned_mul_total={assigned_mul_total}")
    print(f"projected_net_saving={projected_saving}")
    print(f"actual_row_precompile_saving={actual_saving}")
    print(f"gate_threshold={GATE_THRESHOLD}")
    print(f"gate_pass={str(projected_saving >= GATE_THRESHOLD).lower()}")


if __name__ == "__main__":
    main()
