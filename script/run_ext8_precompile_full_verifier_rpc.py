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

BASELINE_CONTRACT = (
    "src/whir/k22_jb100_lir6_ff4_rsv1/"
    "WhirBlobVerifierNative8_k22_jb100_lir6_ff4_rsv1.sol:"
    "WhirBlobVerifierNative8_k22_jb100_lir6_ff4_rsv1"
)
PRECOMPILE_CONTRACT = (
    "src/whir/k22_jb100_lir6_ff4_rsv1_precompile_phase1/"
    "WhirBlobVerifierNative8_k22_jb100_lir6_ff4_rsv1_precompile_phase1.sol:"
    "WhirBlobVerifierNative8_k22_jb100_lir6_ff4_rsv1_precompile_phase1"
)

VERIFY_SIGNATURE = "verify(bytes32,bytes)(bool)"
HEADER_BYTES = 18
STATEMENT_POINT_ARITY = 22
STATEMENT_EVALUATIONS = 1
EFFECTIVE_DIGEST_BYTES = 20


@dataclass(frozen=True)
class TxGas:
    gas_used: int
    calldata_bytes: int
    zero_bytes: int
    nonzero_bytes: int
    calldata_gas: int

    @property
    def execution_gas(self) -> int:
        return self.gas_used - 21_000 - self.calldata_gas


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def run(
    args: list[str], *, cwd: Path, check: bool = True
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, check=check, text=True, capture_output=True)


def run_stdout(args: list[str], *, cwd: Path) -> str:
    return run(args, cwd=cwd).stdout


def deploy_contract(
    rpc_url: str, private_key: str, contract: str, gas_limit: int, cwd: Path
) -> str:
    out = run_stdout(
        [
            "forge",
            "create",
            contract,
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
    raise RuntimeError(f"failed to parse deployed contract address:\n{out}")


def load_blob(fixtures_dir: Path, name: str) -> str:
    return "0x" + (fixtures_dir / name).read_bytes().hex()


def success_commitment_from_blob(success_blob_hex: str) -> str:
    blob = bytes.fromhex(success_blob_hex[2:])
    commitment_offset = (
        HEADER_BYTES + STATEMENT_POINT_ARITY * 32 + STATEMENT_EVALUATIONS * 32
    )
    digest = blob[commitment_offset : commitment_offset + EFFECTIVE_DIGEST_BYTES]
    if len(digest) != EFFECTIVE_DIGEST_BYTES:
        raise ValueError("success blob is too short to contain initial commitment")
    return "0x" + digest.hex() + ("00" * 12)


def verify_calldata(commitment: str, blob_hex: str, cwd: Path) -> str:
    return run_stdout(
        ["cast", "calldata", VERIFY_SIGNATURE, commitment, blob_hex],
        cwd=cwd,
    ).strip()


def calldata_gas(calldata_hex: str) -> tuple[int, int, int]:
    data = bytes.fromhex(calldata_hex[2:])
    zero = sum(1 for byte in data if byte == 0)
    nonzero = len(data) - zero
    return zero, nonzero, zero * 4 + nonzero * 16


def cast_call(
    rpc_url: str,
    address: str,
    commitment: str,
    blob_hex: str,
    cwd: Path,
) -> subprocess.CompletedProcess[str]:
    return run(
        [
            "cast",
            "call",
            address,
            VERIFY_SIGNATURE,
            commitment,
            blob_hex,
            "--rpc-url",
            rpc_url,
        ],
        cwd=cwd,
        check=False,
    )


def call_returns_true(result: subprocess.CompletedProcess[str]) -> bool:
    if result.returncode != 0:
        return False
    value = result.stdout.strip().lower()
    return value == "true" or value.endswith("1")


def cast_send(
    rpc_url: str,
    private_key: str,
    address: str,
    commitment: str,
    blob_hex: str,
    gas_limit: int,
    cwd: Path,
) -> int:
    out = run_stdout(
        [
            "cast",
            "send",
            address,
            VERIFY_SIGNATURE,
            commitment,
            blob_hex,
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
        raise RuntimeError(f"verify transaction reverted: {receipt}")
    return int(receipt["gasUsed"], 16)


def measure_success_tx(
    label: str,
    rpc_url: str,
    private_key: str,
    address: str,
    commitment: str,
    blob_hex: str,
    gas_limit: int,
    cwd: Path,
) -> TxGas:
    calldata = verify_calldata(commitment, blob_hex, cwd)
    zero, nonzero, call_gas = calldata_gas(calldata)
    gas_used = cast_send(
        rpc_url, private_key, address, commitment, blob_hex, gas_limit, cwd
    )
    result = TxGas(gas_used, len(bytes.fromhex(calldata[2:])), zero, nonzero, call_gas)
    print(f"{label}_tx_gas={result.gas_used}")
    print(f"{label}_calldata_bytes={result.calldata_bytes}")
    print(f"{label}_calldata_zero_bytes={result.zero_bytes}")
    print(f"{label}_calldata_nonzero_bytes={result.nonzero_bytes}")
    print(f"{label}_calldata_gas={result.calldata_gas}")
    print(f"{label}_execution_gas={result.execution_gas}")
    return result


def assert_same_call_behavior(
    case: str,
    rpc_url: str,
    baseline: str,
    precompile: str,
    commitment: str,
    blob_hex: str,
    expect_success: bool,
    cwd: Path,
) -> None:
    baseline_result = cast_call(rpc_url, baseline, commitment, blob_hex, cwd)
    precompile_result = cast_call(rpc_url, precompile, commitment, blob_hex, cwd)

    baseline_success = call_returns_true(baseline_result)
    precompile_success = call_returns_true(precompile_result)
    if expect_success:
        if not baseline_success or not precompile_success:
            raise RuntimeError(
                f"{case}: expected both calls to return true\n"
                f"baseline rc={baseline_result.returncode} stdout={baseline_result.stdout} stderr={baseline_result.stderr}\n"
                f"precompile rc={precompile_result.returncode} stdout={precompile_result.stdout} stderr={precompile_result.stderr}"
            )
        print(f"{case}_call_behavior=both_true")
        return

    baseline_reverted = baseline_result.returncode != 0
    precompile_reverted = precompile_result.returncode != 0
    if baseline_reverted != precompile_reverted:
        raise RuntimeError(
            f"{case}: baseline/precompile behavior mismatch\n"
            f"baseline rc={baseline_result.returncode} stdout={baseline_result.stdout} stderr={baseline_result.stderr}\n"
            f"precompile rc={precompile_result.returncode} stdout={precompile_result.stdout} stderr={precompile_result.stderr}"
        )
    if not baseline_reverted:
        raise RuntimeError(f"{case}: expected both calls to revert, but both succeeded")
    print(f"{case}_call_behavior=both_revert")


def main() -> None:
    cwd = project_root()

    parser = argparse.ArgumentParser()
    parser.add_argument("--rpc-url", default=DEFAULT_RPC_URL)
    parser.add_argument("--private-key", default=DEFAULT_PRIVATE_KEY)
    parser.add_argument("--fixtures-dir", type=Path, default=cwd / "testdata")
    parser.add_argument("--baseline")
    parser.add_argument("--precompile")
    parser.add_argument("--gas-limit", type=int, default=30_000_000)
    args = parser.parse_args()

    fixtures_dir = args.fixtures_dir
    success_blob = load_blob(
        fixtures_dir, "octic_whir_k22_jb100_lir6_ff4_rsv1_success.blob"
    )
    commitment = success_commitment_from_blob(success_blob)
    print(f"expected_commitment={commitment}")

    baseline = args.baseline or deploy_contract(
        args.rpc_url, args.private_key, BASELINE_CONTRACT, args.gas_limit, cwd
    )
    precompile = args.precompile or deploy_contract(
        args.rpc_url, args.private_key, PRECOMPILE_CONTRACT, args.gas_limit, cwd
    )
    print(f"baseline={baseline}")
    print(f"precompile={precompile}")

    assert_same_call_behavior(
        "success",
        args.rpc_url,
        baseline,
        precompile,
        commitment,
        success_blob,
        True,
        cwd,
    )

    for case in (
        "failure_bad_commitment",
        "failure_bad_stir_query",
        "failure_bad_ood_or_transcript_mismatch",
    ):
        blob = load_blob(
            fixtures_dir, f"octic_whir_k22_jb100_lir6_ff4_rsv1_{case}.blob"
        )
        assert_same_call_behavior(
            case, args.rpc_url, baseline, precompile, commitment, blob, False, cwd
        )

    baseline_gas = measure_success_tx(
        "baseline",
        args.rpc_url,
        args.private_key,
        baseline,
        commitment,
        success_blob,
        args.gas_limit,
        cwd,
    )
    precompile_gas = measure_success_tx(
        "precompile",
        args.rpc_url,
        args.private_key,
        precompile,
        commitment,
        success_blob,
        args.gas_limit,
        cwd,
    )
    print("---")
    print(f"tx_gas_delta={baseline_gas.gas_used - precompile_gas.gas_used}")
    print(
        f"execution_gas_delta={baseline_gas.execution_gas - precompile_gas.execution_gas}"
    )


if __name__ == "__main__":
    main()
