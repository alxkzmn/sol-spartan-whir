#!/usr/bin/env python3
"""Build ordinal verifier-score calibration JSON from native tx-gas measurements."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

import quintic_schedule_scorer as scorer


PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_TX_ARTIFACTS = {
    "quartic_lir6_ff5_rsv1": PROJECT_ROOT
    / "broadcast"
    / "WhirBlobNativeTxBenchmark_lir6_ff5_rsv1.s.sol"
    / "31337"
    / "run-latest.json",
    "quartic_lir11_ff5_rsv3": PROJECT_ROOT
    / "broadcast"
    / "WhirBlobNativeTxBenchmark_lir11_ff5_rsv3.s.sol"
    / "31337"
    / "run-latest.json",
    "octic_k22_jb100_lir6_ff4_rsv1": PROJECT_ROOT
    / "broadcast"
    / "WhirBlobNativeTxBenchmark_k22_jb100_lir6_ff4_rsv1.s.sol"
    / "31337"
    / "run-latest.json",
}
VERIFY_RECEIPT_INDEX = 1
CALIBRATION_BUCKETS = ("merkle", "folding", "transcript", "sumcheck", "calldata")
TRANSCRIPT_SUBPHASE_BUCKETS = {
    "setup": "transcript_setup",
    "round_parse": "transcript_round_parse",
    "observe_final_poly": "transcript_observe_final_poly",
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase-log", required=True, help="Forge -vv output with CALIBRATION lines")
    parser.add_argument("--gas-log", required=True, help="Forge -vv output with BENCH lines")
    parser.add_argument(
        "--reference-schedule",
        required=True,
        help="Rust-emitted calibration reference schedule JSON",
    )
    parser.add_argument("--out", required=True, help="Calibration JSON output path")
    parser.add_argument("--quartic-tx-artifact", type=Path, default=DEFAULT_TX_ARTIFACTS["quartic_lir6_ff5_rsv1"])
    parser.add_argument("--quartic-lir11-tx-artifact", type=Path, default=DEFAULT_TX_ARTIFACTS["quartic_lir11_ff5_rsv3"])
    parser.add_argument("--octic-tx-artifact", type=Path, default=DEFAULT_TX_ARTIFACTS["octic_k22_jb100_lir6_ff4_rsv1"])
    args = parser.parse_args()

    phase_rows = read_phase_rows(Path(args.phase_log))
    reference_schedule = read_reference_schedule(Path(args.reference_schedule))
    bench_rows = scorer.read_bench_lines(Path(args.gas_log))
    scorer.check_compiler_settings(bench_rows)
    gas = scorer.gas_map(bench_rows)
    tx_artifacts = {
        "quartic_lir6_ff5_rsv1": Path(args.quartic_tx_artifact),
        "quartic_lir11_ff5_rsv3": Path(args.quartic_lir11_tx_artifact),
        "octic_k22_jb100_lir6_ff4_rsv1": Path(args.octic_tx_artifact),
    }
    references = [
        build_reference(reference, rows, tx_artifacts[reference], gas, reference_schedule["candidates"])
        for reference, rows in sorted(phase_rows.items())
    ]

    out = {
        "schema_version": 1,
        "method": "ordinal verifier score checked against native verifier ordering",
        "phase_source": display_path(Path(args.phase_log)),
        "gas_source": display_path(Path(args.gas_log)),
        "gas_metrics_available": sorted(gas.keys()),
        "reference_schedule_source": display_path(Path(args.reference_schedule)),
        "whir_p3_revision": reference_schedule["whir_p3_revision"],
        "whir_p3_dirty": reference_schedule["whir_p3_dirty"],
        "references": references,
    }
    output_path = Path(args.out)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(PROJECT_ROOT))
    except ValueError:
        return path.name


def read_phase_rows(path: Path) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    with path.open() as f:
        for line in f:
            marker = "CALIBRATION:"
            if marker not in line:
                continue
            payload = json.loads(line.split(marker, 1)[1].strip())
            reference = payload["reference"]
            row = rows.setdefault(reference, {"buckets": {}})
            if payload["kind"] == "metadata":
                row["metadata"] = payload
            elif payload["kind"] == "bucket":
                row["buckets"][payload["bucket"]] = int(payload["gas"])
            else:
                raise SystemExit(f"unknown calibration row kind: {payload['kind']}")
    if not rows:
        raise SystemExit(f"no CALIBRATION lines found in {path}")
    return rows


def read_reference_schedule(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise SystemExit(f"missing calibration reference schedule: {path}")
    data = json.loads(path.read_text())
    candidates = {
        entry["reference"]: entry["candidate"]
        for entry in data.get("references", [])
    }
    if not candidates:
        raise SystemExit(f"{path}: no calibration reference candidates found")
    return {
        "whir_p3_revision": data.get("whir_p3_revision"),
        "whir_p3_dirty": bool(data.get("whir_p3_dirty")),
        "candidates": candidates,
    }


def build_reference(
    reference: str,
    rows: dict[str, Any],
    tx_artifact: Path,
    gas: dict[str, int],
    reference_candidates: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    metadata = rows.get("metadata")
    if metadata is None:
        raise SystemExit(f"{reference}: missing metadata row")
    buckets = dict(rows.get("buckets") or {})
    missing = [bucket for bucket in CALIBRATION_BUCKETS if bucket != "calldata" and bucket not in buckets]
    if missing:
        raise SystemExit(f"{reference}: missing phase buckets {missing}")

    tx = read_tx_artifact(tx_artifact)
    buckets["calldata"] = tx["calldata_gas"]
    if reference not in reference_candidates:
        raise SystemExit(f"{reference}: missing Rust-emitted calibration reference schedule")
    reference_candidate = copy.deepcopy(reference_candidates[reference])
    counts = reference_candidate.setdefault("encoding_counts", {})
    counts["native_blob_nonzero_bytes"] = tx["nonzero_bytes"]
    counts["native_blob_zero_bytes"] = tx["zero_bytes"]
    tracking_gas = scorer.MetricTrackingGas(gas)
    bucket_scores, largest_terms = scorer.score_bucket_details(reference_candidate, tracking_gas)
    verifier_score = sum(bucket_scores.values())
    bucket_ratios = {
        bucket: (
            bucket_scores[bucket] / buckets[bucket]
            if buckets.get(bucket, 0) > 0
            else None
        )
        for bucket in CALIBRATION_BUCKETS
        if bucket in bucket_scores and bucket in buckets
    }

    return {
        "label": metadata["contract"],
        "reference": reference,
        "fixture": metadata["fixture"],
        "tx_artifact": display_path(tx_artifact),
        "measured_total_tx_gas": tx["total_tx_gas"],
        "verifier_score": verifier_score,
        "measured_native_execution_gas": metadata["native_execution_gas"],
        "phase_sum": metadata["phase_sum"],
        "phase_breakdown_available": int(metadata["phase_sum"]) > 0,
        "tx_execution_remainder": tx["execution_remainder"],
        "measured_buckets": buckets,
        "measured_transcript_subphase": transcript_subphase(buckets),
        "bucket_scores": bucket_scores,
        "bucket_score_ratios": bucket_ratios,
        "largest_weighted_terms": largest_terms,
        "metrics_used": sorted(tracking_gas.metrics_used),
        "reference_counts": reference_candidate,
    }


def transcript_subphase(buckets: dict[str, int]) -> dict[str, int] | None:
    if not any(key in buckets for key in TRANSCRIPT_SUBPHASE_BUCKETS.values()):
        return None
    return {
        label: int(buckets.get(bucket, 0))
        for label, bucket in TRANSCRIPT_SUBPHASE_BUCKETS.items()
    }


def read_tx_artifact(path: Path) -> dict[str, int]:
    if not path.exists():
        raise SystemExit(f"missing tx benchmark artifact: {path}")
    data = json.loads(path.read_text())
    if len(data.get("receipts", [])) <= VERIFY_RECEIPT_INDEX:
        raise SystemExit(f"{path}: receipts array does not contain verify tx at index {VERIFY_RECEIPT_INDEX}")
    if len(data.get("transactions", [])) <= VERIFY_RECEIPT_INDEX:
        raise SystemExit(f"{path}: transactions array does not contain verify tx at index {VERIFY_RECEIPT_INDEX}")

    gas_used = int(data["receipts"][VERIFY_RECEIPT_INDEX]["gasUsed"], 16)
    tx = data["transactions"][VERIFY_RECEIPT_INDEX]
    raw_input = (tx.get("transaction") or tx).get("input")
    if not raw_input:
        raise SystemExit(f"{path}: verify transaction input missing")
    calldata = bytes.fromhex(raw_input[2:] if raw_input.startswith("0x") else raw_input)
    zero = sum(1 for byte in calldata if byte == 0)
    nonzero = len(calldata) - zero
    calldata_gas = 4 * zero + 16 * nonzero
    return {
        "total_tx_gas": gas_used,
        "calldata_bytes": len(calldata),
        "zero_bytes": zero,
        "nonzero_bytes": nonzero,
        "calldata_gas": calldata_gas,
        "execution_remainder": gas_used - 21_000 - calldata_gas,
    }


if __name__ == "__main__":
    main()
