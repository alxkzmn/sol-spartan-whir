#!/usr/bin/env python3
"""Score quintic WHIR schedules from Rust schedule JSON and Solidity gas microbenchmarks.

This script intentionally does not derive WHIR rounds, security, query counts, or
Merkle geometry. Those values must come from the Rust schedule dump.
"""

from __future__ import annotations

import argparse
import copy
import json
import math
from pathlib import Path
from typing import Any

REQUIRED_SOLC_VERSION = "0.8.28"
REQUIRED_VIA_IR = True
REQUIRED_OPTIMIZER_RUNS = 833
STRUCTURAL_PREFILTER_CAP = 120
DEFAULT_TARGET_SECURITY_BITS = 100.0
DEFAULT_TARGET_MERKLE_SECURITY_BITS = 80
DEFAULT_MAX_DERIVED_POW_BITS = 30
NATIVE_TX_GAS_SHORTLIST_SIZE = 5

CALIBRATION_BUCKETS = ("merkle", "folding", "transcript", "sumcheck", "calldata")
# Folding is known to overestimate until we have an end-to-end WHIR-round
# benchmark. The quartic transcript bucket currently includes setup/parse
# work, so its ratio remains diagnostic until phase attribution is split finer.
CALIBRATION_RATIO_BOUNDS = {
    "calldata": (0.99, 1.01),
    "merkle": (0.70, 1.30),
    "sumcheck": (0.70, 1.30),
    "transcript": (0.70, 1.30),
    "folding": (0.70, 8.00),
}
PROVER_ESTIMATE_FEATURES = (
    "log_pow_work_score",
    "requested_pow_bits",
    "folding_factor",
    "folding_factor_rest",
    "starting_log_inv_rate",
    "rs_domain_initial_reduction_factor",
    "is_constant_from_second_round",
    "lir_times_rsv",
    "ff_times_rsv",
    "ff_times_lir",
    "rsv_squared",
    "lir4_ff5",
    "lir4_ff6",
)
PROVER_ESTIMATE_NEIGHBORS = 6
PROVER_ESTIMATE_DISTANCE_EPSILON = 1e-9
PROVER_ESTIMATE_MIN_POW_FACTOR = 1.0
PROVER_ESTIMATE_MAX_MEASURED_ERROR = 0.10
PROVER_ESTIMATE_HOLDOUT_COUNT = 5
PROVER_ESTIMATE_EXTRAPOLATION_PERCENTILE = 0.95


class MissingGasMetric(Exception):
    pass


class MetricTrackingGas(dict[str, int]):
    """Gas table wrapper that records every benchmark metric the scorer reads."""

    def __init__(self, values: dict[str, int]):
        super().__init__(values)
        self.metrics_used: set[str] = set()

    def __getitem__(self, metric: str) -> int:
        self.metrics_used.add(metric)
        return super().__getitem__(metric)


class TargetConfig:
    def __init__(
        self, security_bits: float, merkle_security_bits: int, max_derived_pow_bits: int
    ):
        self.security_bits = security_bits
        self.merkle_security_bits = merkle_security_bits
        self.max_derived_pow_bits = max_derived_pow_bits


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--schedule", required=True, help="Rust schedule dump JSON")
    parser.add_argument(
        "--gas", required=True, help="Forge output containing BENCH:{...} lines"
    )
    parser.add_argument("--rust-timings", help="Optional Rust prover timing JSON")
    parser.add_argument(
        "--prover-calibration-schedule",
        action="append",
        default=[],
        help="Additional Rust schedule dump JSON used only to fit the prover-time estimator",
    )
    parser.add_argument(
        "--pow-calibration", required=True, help="Rust PoW calibration JSON"
    )
    parser.add_argument("--calibration", help="Optional calibration gate JSON")
    parser.add_argument(
        "--out-dir", default=".", help="Directory for schedule_scores outputs"
    )
    parser.add_argument(
        "--target-security-bits",
        type=float,
        default=DEFAULT_TARGET_SECURITY_BITS,
        help="Achieved-security threshold for ranking; derivation may request a higher guard value",
    )
    parser.add_argument(
        "--target-merkle-security-bits",
        type=int,
        default=DEFAULT_TARGET_MERKLE_SECURITY_BITS,
        help="Merkle security threshold for ranking",
    )
    parser.add_argument(
        "--max-derived-pow-bits",
        type=int,
        default=DEFAULT_MAX_DERIVED_POW_BITS,
        help="Maximum derived PoW bits allowed for ranking",
    )
    parser.add_argument(
        "--require-calibration",
        action="store_true",
        help="Fail unless the calibration JSON passes all gates",
    )
    parser.add_argument(
        "--plot-x-max-fraction",
        type=float,
        help="For Pareto SVGs, crop the x-axis to this fraction of the full data range",
    )
    parser.add_argument(
        "--plot-y-max-fraction",
        type=float,
        help="For Pareto SVGs, crop the y-axis to this fraction of the full data range",
    )
    parser.add_argument(
        "--plot-row-work-x-max-fraction",
        type=float,
        help="Override x-axis crop fraction for row-work Pareto SVGs",
    )
    parser.add_argument(
        "--plot-row-work-y-max-fraction",
        type=float,
        help="Override y-axis crop fraction for row-work Pareto SVGs",
    )
    parser.add_argument(
        "--plot-verifier-x-max-fraction",
        type=float,
        help="Override x-axis crop fraction for verifier-score Pareto SVGs",
    )
    parser.add_argument(
        "--plot-verifier-y-max-fraction",
        type=float,
        help="Override y-axis crop fraction for verifier-score Pareto SVGs",
    )
    parser.add_argument(
        "--plot-mixed-measured-axis-multiple",
        type=float,
        help="For mixed measured/modeled plots, crop both axes at this multiple of the measured-point maxima",
    )
    parser.add_argument(
        "--plot-max-derived-pow-bits",
        type=int,
        help="Only include candidates whose max_derived_pow_bits is at or below this value in Pareto SVGs",
    )
    parser.add_argument(
        "--implemented-label",
        action="append",
        default=[],
        help="Candidate label to mark as already implemented in JSON, CSV, and Pareto SVGs",
    )
    args = parser.parse_args()

    schedule = read_json(Path(args.schedule))
    benches = read_bench_lines(Path(args.gas))
    rust_timings = read_json(Path(args.rust_timings)) if args.rust_timings else None
    prover_calibration_schedules = [
        read_json(Path(path)) for path in args.prover_calibration_schedule
    ]
    pow_calibration = (
        read_json(Path(args.pow_calibration)) if args.pow_calibration else None
    )
    calibration = read_json(Path(args.calibration)) if args.calibration else None

    check_compiler_settings(benches)
    check_schedule_revision(schedule)
    for extra_schedule in prover_calibration_schedules:
        check_schedule_revision(extra_schedule)
    check_calibration_revision(schedule, calibration)
    check_rust_timings(rust_timings)
    pow_seconds_per_unit = calibrated_pow_seconds_per_unit(pow_calibration)
    gas = gas_map(benches)
    calibration_overrides = calibrated_candidate_overrides(calibration)
    quintic_scale = quintic_verifier_score_scale(calibration)
    target = TargetConfig(
        security_bits=args.target_security_bits,
        merkle_security_bits=args.target_merkle_security_bits,
        max_derived_pow_bits=args.max_derived_pow_bits,
    )

    candidates = schedule.get("candidates", [])
    prefilter_labels = structural_prefilter(candidates, target, pow_seconds_per_unit)
    scores = [
        score_candidate(
            candidate_with_calibration_overrides(candidate, calibration_overrides),
            gas,
            rust_timings,
            candidate["label"] in prefilter_labels,
            target,
            pow_seconds_per_unit,
            quintic_scale["scale"],
        )
        for candidate in candidates
    ]

    kernel_warnings = validate_quintic_kernel_bounds(gas)
    if kernel_warnings:
        for score in scores:
            score.setdefault("warnings", []).extend(kernel_warnings)

    calibration_result = evaluate_calibration(calibration)
    apply_selection(scores, calibration_result)
    extra_prover_scores = extra_prover_training_scores(
        prover_calibration_schedules,
        rust_timings,
        pow_seconds_per_unit,
        {score["label"] for score in scores},
    )
    prover_estimate = apply_prover_estimates(scores, extra_prover_scores)
    mark_implemented_scores(scores, args.implemented_label)

    if args.require_calibration and not calibration_result["accepted"]:
        raise SystemExit(f"calibration gate failed: {calibration_result['reason']}")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    write_json(
        out_dir / "schedule_scores.json",
        {
            "schema_version": 1,
            "schedule_source": display_path(Path(args.schedule)),
            "prover_calibration_schedule_sources": [
                display_path(Path(path)) for path in args.prover_calibration_schedule
            ],
            "gas_source": display_path(Path(args.gas)),
            "pow_calibration_source": (
                display_path(Path(args.pow_calibration))
                if args.pow_calibration
                else None
            ),
            "pow_seconds_per_work_unit": pow_seconds_per_unit,
            "derivation_security_bits_requested": schedule.get(
                "security_level_bits_requested"
            ),
            "target_security_bits": target.security_bits,
            "target_merkle_security_bits": target.merkle_security_bits,
            "max_derived_pow_bits": target.max_derived_pow_bits,
            "calibration": calibration_result,
            "quintic_verifier_score_calibration": quintic_scale,
            "prover_estimate": prover_estimate,
            "implemented_labels": args.implemented_label,
            "plot_axis_limits": plot_axis_limits(args),
            "selection_policy": selection_policy(scores),
            "warnings": kernel_warnings,
            "scores": scores,
        },
    )
    write_plots(out_dir, scores, plot_axis_limits(args))


def calibrated_candidate_overrides(
    calibration: dict[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    if calibration is None:
        return {}
    overrides = {}
    for ref in calibration.get("references", []):
        counts = ref.get("reference_counts") or {}
        label = counts.get("label")
        if label:
            overrides[label] = counts
    return overrides


def quintic_verifier_score_scale(calibration: dict[str, Any] | None) -> dict[str, Any]:
    references = []
    if calibration is not None:
        for ref in calibration.get("references", []):
            counts = ref.get("reference_counts") or {}
            if int(counts.get("extension_degree") or 0) != 5:
                continue
            measured = float(ref.get("measured_total_tx_gas") or 0.0)
            scored = float(ref.get("verifier_score") or 0.0)
            if measured > 0.0 and scored > 0.0:
                references.append(
                    {
                        "reference": ref.get("reference"),
                        "label": ref.get("label"),
                        "measured_total_tx_gas": int(measured),
                        "raw_verifier_score": int(scored),
                        "scale": measured / scored,
                    }
                )
    if not references:
        return {
            "mode": "raw_microbench_score",
            "scale": 1.0,
            "references": [],
        }
    scale = sum(float(ref["scale"]) for ref in references) / len(references)

    return {
        "mode": "quintic_native_tx_gas_scaled_score",
        "scale": scale,
        "references": references,
        "note": (
            "Applied only to extension-degree-5 candidates. The score remains an ordering aid, "
            "but the x-axis is normalized to the measured optimized quintic native verifier."
        ),
    }


def candidate_with_calibration_overrides(
    candidate: dict[str, Any],
    overrides: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    override = overrides.get(candidate["label"])
    if override is None:
        return candidate
    merged = copy.deepcopy(candidate)
    for key, value in override.items():
        if key == "encoding_counts":
            merged_counts = dict(merged.get("encoding_counts") or {})
            merged_counts.update(value)
            merged["encoding_counts"] = merged_counts
        else:
            merged[key] = value
    return merged


def read_json(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    with path.open() as f:
        return json.load(f)


def write_json(path: Path, value: Any) -> None:
    with path.open("w") as f:
        json.dump(value, f, indent=2, sort_keys=True)
        f.write("\n")


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(Path.cwd().resolve()))
    except ValueError:
        return path.name


def read_bench_lines(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open() as f:
        for line in f:
            marker = "BENCH:"
            if marker not in line:
                continue
            payload = line.split(marker, 1)[1].strip()
            rows.append(json.loads(payload))
    if not rows:
        raise SystemExit(f"no BENCH lines found in {path}")
    return rows


def check_compiler_settings(rows: list[dict[str, Any]]) -> None:
    settings = [row for row in rows if row.get("metric") == "compiler_settings"]
    if not settings:
        raise SystemExit("missing BENCH compiler_settings row")
    row = settings[-1]
    actual = (
        row.get("solc_version"),
        row.get("via_ir"),
        int(row.get("optimizer_runs")),
    )
    expected = (REQUIRED_SOLC_VERSION, REQUIRED_VIA_IR, REQUIRED_OPTIMIZER_RUNS)
    if actual != expected:
        raise SystemExit(
            f"compiler settings mismatch: got {actual}, expected {expected}"
        )


def check_schedule_revision(schedule: dict[str, Any]) -> None:
    revisions = {
        candidate.get("whir_p3_revision")
        for candidate in schedule.get("candidates", [])
        if candidate.get("whir_p3_revision")
    }
    if len(revisions) > 1:
        raise SystemExit(
            f"mixed whir-p3 revisions in schedule rows: {sorted(revisions)}"
        )
    if schedule.get("whir_p3_revision") in ("", None, "unknown"):
        raise SystemExit("schedule dump is missing whir_p3_revision")


def check_calibration_revision(
    schedule: dict[str, Any], calibration: dict[str, Any] | None
) -> None:
    if calibration is None:
        return
    schedule_revision = schedule.get("whir_p3_revision")
    calibration_revision = calibration.get("whir_p3_revision")
    if calibration_revision in ("", None, "unknown"):
        raise SystemExit("calibration JSON is missing whir_p3_revision")
    if calibration_revision != schedule_revision:
        raise SystemExit(
            f"calibration whir-p3 revision {calibration_revision} does not match schedule {schedule_revision}"
        )


def check_rust_timings(rust_timings: dict[str, Any] | None) -> None:
    if rust_timings is None:
        return
    if rust_timings.get("measurement_kind") != "actual_whir_commit_prove":
        raise SystemExit(
            "rust timings must use measurement_kind=actual_whir_commit_prove"
        )
    rows = rust_timings.get("by_label") or []
    if rows and rust_timings.get("build_profile") != "release":
        raise SystemExit(
            "rust timings with measured candidates must come from a release build"
        )
    if rows and rust_timings.get("target_cpu_native") is not True:
        raise SystemExit(
            "rust timings with measured candidates must use target-cpu=native"
        )
    for row in rows:
        if row.get("build_profile") != "release":
            raise SystemExit(
                f"rust timing row {row.get('label')} must come from a release build"
            )
        if row.get("target_cpu_native") is not True:
            raise SystemExit(
                f"rust timing row {row.get('label')} must use target-cpu=native"
            )


def gas_map(rows: list[dict[str, Any]]) -> dict[str, int]:
    out: dict[str, int] = {}
    for row in rows:
        metric = row.get("metric")
        if metric and "gas" in row:
            out[metric] = int(row["gas"])
    return out


def target_eligible(candidate: dict[str, Any], target: TargetConfig) -> bool:
    target_eval = candidate.get("target_evaluation")
    if (
        isinstance(target_eval, dict)
        and float(target_eval.get("target_security_bits", -1.0)) == target.security_bits
        and int(target_eval.get("target_merkle_security_bits", -1))
        == target.merkle_security_bits
        and int(target_eval.get("target_max_derived_pow_bits", -1))
        == target.max_derived_pow_bits
    ):
        return bool(target_eval.get("target_eligible"))
    return (
        bool(candidate.get("selectable"))
        and (candidate.get("security_bits_achieved") or 0) >= target.security_bits
        and (candidate.get("merkle_security_bits_achieved") or 0)
        >= target.merkle_security_bits
        and candidate.get("max_derived_pow_bits") is not None
        and int(candidate["max_derived_pow_bits"]) <= target.max_derived_pow_bits
    )


def calibrated_pow_seconds_per_unit(pow_calibration: dict[str, Any] | None) -> float:
    if pow_calibration is None:
        return 1.0
    if pow_calibration.get("measurement_kind") != "quintic_pow_grind_calibration":
        raise SystemExit(
            "pow calibration must use measurement_kind=quintic_pow_grind_calibration"
        )
    if pow_calibration.get("build_profile") != "release":
        raise SystemExit("pow calibration must come from a release build")
    if pow_calibration.get("target_cpu_native") is not True:
        raise SystemExit("pow calibration must use target-cpu=native")
    value = float(pow_calibration.get("seconds_per_pow_unit_median") or 0.0)
    if value <= 0.0:
        raise SystemExit("pow calibration missing positive seconds_per_pow_unit_median")
    return value


def structural_prefilter(
    candidates: list[dict[str, Any]],
    target: TargetConfig,
    pow_seconds_per_unit: float,
) -> set[str]:
    selectable = [
        c
        for c in candidates
        if target_eligible(c, target) and c.get("structural_score") is not None
    ]
    if not selectable:
        return set()
    best_structural = min(int(c["structural_score"]) for c in selectable)
    best_pow = min(pow_work_score(c, pow_seconds_per_unit) for c in selectable)
    kept = [
        c
        for c in selectable
        if int(c["structural_score"]) <= math.ceil(best_structural * 2.0)
        or pow_work_score(c, pow_seconds_per_unit) <= best_pow * 2.0
    ]
    kept.sort(
        key=lambda c: (
            prefilter_score(c, best_structural, best_pow, pow_seconds_per_unit),
            int(c["structural_score"]),
            pow_work_units(c),
        )
    )
    return {c["label"] for c in kept[:STRUCTURAL_PREFILTER_CAP]}


def prefilter_score(
    candidate: dict[str, Any],
    best_structural: int,
    best_pow: float,
    pow_seconds_per_unit: float,
) -> float:
    structural = int(candidate.get("structural_score") or 0) / max(1, best_structural)
    pow_score = pow_work_score(candidate, pow_seconds_per_unit) / max(1e-18, best_pow)
    return structural + pow_score


def score_candidate(
    candidate: dict[str, Any],
    gas: dict[str, int],
    rust_timings: dict[str, Any] | None,
    passes_prefilter: bool,
    target: TargetConfig,
    pow_seconds_per_unit: float,
    quintic_verifier_score_scale: float,
) -> dict[str, Any]:
    counts = candidate.get("encoding_counts", {})
    missing_metric = None
    try:
        bucket_scores, _largest_terms = score_bucket_details(candidate, gas)
        raw_verifier_score = sum(bucket_scores.values())
        if extension_degree(candidate) == 5 and quintic_verifier_score_scale != 1.0:
            bucket_scores = {
                bucket: int(round(value * quintic_verifier_score_scale))
                for bucket, value in bucket_scores.items()
            }
            verifier_score = int(
                round(raw_verifier_score * quintic_verifier_score_scale)
            )
        else:
            verifier_score = raw_verifier_score
    except MissingGasMetric as err:
        missing_metric = str(err)
        bucket_scores = {
            "merkle": 0,
            "folding": 0,
            "transcript": 0,
            "sumcheck": 0,
            "calldata": score_calldata(counts),
        }
        verifier_score = None
        raw_verifier_score = None
    prover_time_score = score_prover(candidate, rust_timings)
    pow_units = pow_work_units(candidate)
    pow_score = pow_work_score(candidate, pow_seconds_per_unit)
    prover_timed_out = prover_timeout(candidate, rust_timings)
    max_pow = candidate.get("max_derived_pow_bits")
    selectable = bool(candidate.get("selectable"))
    has_derived_config = (
        candidate.get("security_bits_achieved") is not None and max_pow is not None
    )
    target_ok = target_eligible(candidate, target)
    total_query_rows = candidate.get("total_query_rows")
    total_row_values = candidate.get("total_row_values")
    row_work_score = None
    if total_query_rows is not None and total_row_values is not None:
        row_work_score = int(total_query_rows) * int(total_row_values)

    rejection_reasons = []
    if not has_derived_config:
        rejection_reasons.append(
            candidate.get("rejection_reason") or "invalid schedule"
        )
    if not selectable:
        rejection_reasons.append(
            candidate.get("not_selectable_reason") or "not selectable"
        )
    if not passes_prefilter and selectable and target_ok:
        rejection_reasons.append("outside structural prefilter")
    if (candidate.get("security_bits_achieved") or 0) < target.security_bits:
        rejection_reasons.append(f"security_bits_achieved < {target.security_bits:g}")
    if (
        candidate.get("merkle_security_bits_achieved") or 0
    ) < target.merkle_security_bits:
        rejection_reasons.append(
            f"merkle_security_bits_achieved < {target.merkle_security_bits}"
        )
    if max_pow is None or int(max_pow) > target.max_derived_pow_bits:
        rejection_reasons.append(
            f"max_derived_pow_bits > {target.max_derived_pow_bits}"
        )
    if int(candidate.get("starting_log_inv_rate") or 0) > 6:
        rejection_reasons.append("starting_log_inv_rate > 6")
    if prover_timed_out:
        rejection_reasons.append("prover timing timed out")
    if (
        rust_timings is not None
        and prover_time_score is None
        and selectable
        and target_ok
    ):
        rejection_reasons.append("missing actual prover timing")
    if missing_metric is not None:
        rejection_reasons.append(f"missing gas metric {missing_metric}")

    return {
        "label": candidate["label"],
        "selectable": selectable,
        "not_selectable_reason": candidate.get("not_selectable_reason"),
        "derivation_valid": bool(candidate.get("valid")),
        "target_eligible": target_ok,
        "passes_structural_prefilter": passes_prefilter,
        "accepted_for_ranking": not rejection_reasons,
        "rejection_reasons": rejection_reasons,
        "folding_variant": candidate["folding_schedule"]["variant"],
        "requested_pow_bits": candidate.get("requested_pow_bits"),
        "folding_factor": candidate["folding_schedule"]["first_round"],
        "folding_factor_rest": candidate["folding_schedule"]["rest"],
        "starting_log_inv_rate": candidate["starting_log_inv_rate"],
        "rs_domain_initial_reduction_factor": candidate[
            "rs_domain_initial_reduction_factor"
        ],
        "security_bits_achieved": candidate.get("security_bits_achieved"),
        "merkle_security_bits_achieved": candidate.get("merkle_security_bits_achieved"),
        "max_derived_pow_bits": max_pow,
        "total_query_rows": total_query_rows,
        "total_row_values": total_row_values,
        "row_work_score": row_work_score,
        "structural_score": candidate.get("structural_score"),
        "pow_bits_schedule": pow_bits_schedule(candidate),
        "pow_work_units": pow_units,
        "pow_work_score": pow_score,
        "raw_verifier_score": raw_verifier_score,
        "verifier_score": verifier_score,
        "prover_time_score": prover_time_score,
        "prover_timed_out": prover_timed_out,
        "calldata_gas_score": bucket_scores["calldata"],
        "bucket_scores": bucket_scores,
    }


def score_bucket_details(
    candidate: dict[str, Any], gas: dict[str, int]
) -> tuple[dict[str, int], dict[str, int]]:
    terms = {
        "merkle": score_merkle_terms(candidate, gas),
        "folding": score_folding_terms(candidate, gas),
        "transcript": score_transcript_terms(candidate, gas),
        "sumcheck": score_sumcheck_terms(candidate, gas),
        "calldata": score_calldata_terms(candidate.get("encoding_counts", {})),
    }
    return (
        {bucket: int(sum(values)) for bucket, values in terms.items()},
        {bucket: int(max(values) if values else 0) for bucket, values in terms.items()},
    )


def score_merkle_terms(candidate: dict[str, Any], gas: dict[str, int]) -> list[int]:
    terms = []
    compress_cost = gas_value(gas, "merkle_compress_node")
    degree = extension_degree(candidate)
    ood_leaves = int(candidate.get("commitment_ood_samples") or 0)
    for row in round_rows(candidate):
        geom = row["merkle_geometry"]
        row_len = row["row_len"]
        if row["row_kind"] == "base":
            leaf_metric = f"hash_leaf_base_row_len_{row_len}"
        else:
            leaf_metric = f"hash_leaf_ext{degree}_row_len_{row_len}"
        terms.append(int(geom["query_count"]) * gas_value(gas, leaf_metric))
        terms.append(int(geom["compressions"]) * compress_cost)
        terms.append(int(geom["query_count"]) * row_fold_gas(candidate, row, gas))
        terms.append(sample_stir_queries_gas(row, gas))
        if int(row.get("pow_bits") or 0) > 0:
            terms.append(verify_pow_gas(int(row["pow_bits"]), gas))
        ood_leaves += int(row.get("ood_samples") or 0)
    if ood_leaves:
        terms.append(ood_leaves * gas_value(gas, f"hash_leaf_ext{degree}_row_len_1"))
    return terms


def score_folding_terms(candidate: dict[str, Any], gas: dict[str, int]) -> list[int]:
    terms = []
    degree = extension_degree(candidate)
    # The depth-level eq-poly benches overcharge the reference verifier because
    # they do not match the specialized constraint loops used by native verifiers.
    coordinate_steps = sum(
        int(row["depth"]) * int(row["count"])
        for row in candidate.get("eq_poly_depth_counts") or []
    )
    if coordinate_steps:
        terms.append(coordinate_steps * gas_value(gas, f"ext{degree}_eq_poly_step"))
    inverse_count = int(candidate.get("inverse_count") or 0)
    if inverse_count:
        terms.append(inverse_count * gas_value(gas, f"ext{degree}_inv"))
    packing_count = int(candidate.get("packing_validation_count") or 0)
    if packing_count:
        terms.append(packing_count * gas_value(gas, f"ext{degree}_validate_packed"))
    return terms


def score_transcript_terms(candidate: dict[str, Any], gas: dict[str, int]) -> list[int]:
    # The lir6 calibration transcript bucket also includes setup/round-parse calldata work;
    # low transcript ratios there are expected until the harness splits parse work from observes.
    counts = candidate.get("encoding_counts", {})
    degree = extension_degree(candidate)
    ext_elements = int(counts.get("transcript_ext5_elements") or 0)
    base_elements = int(counts.get("transcript_base_elements") or 0)
    hashes = int(counts.get("transcript_hashes") or 0)
    return [
        int(score_batch(gas, f"observe_ext{degree}_batch_", ext_elements)),
        int(score_batch(gas, "observe_base_batch_", base_elements)),
        int(score_batch(gas, "observe_hash_u64_batch_", hashes)),
    ]


def score_sumcheck_terms(candidate: dict[str, Any], gas: dict[str, int]) -> list[int]:
    degree = extension_degree(candidate)
    rounds = int(candidate.get("extrapolate_count") or 0)
    return [
        rounds * int(score_batch(gas, f"observe_ext{degree}_batch_", 2)),
        rounds * gas_value(gas, f"ext{degree}_extrapolate_012"),
    ]


def row_fold_gas(
    candidate: dict[str, Any], row: dict[str, Any], gas: dict[str, int]
) -> int:
    degree = extension_degree(candidate)
    metric = (
        f"base_to_ext{degree}_hypercube_dim{row['folding_factor']}"
        if row["row_kind"] == "base"
        else f"ext{degree}_hypercube_dim{row['folding_factor']}"
    )
    return gas_value(gas, metric)


def sample_stir_queries_gas(row: dict[str, Any], gas: dict[str, int]) -> int:
    # Benchmarks are emitted at 8-bit intervals; round up so deeper domains are not undercharged.
    depth = int(row.get("depth") or 0)
    metric_bits = min(24, max(8, ((depth + 7) // 8) * 8))
    return gas_value(gas, f"sample_stir_queries_bits_{metric_bits}")


def verify_pow_gas(pow_bits: int, gas: dict[str, int]) -> int:
    metric_bits = min(24, max(8, ((pow_bits + 7) // 8) * 8))
    return gas_value(gas, f"verify_pow_bits_{metric_bits}")


def score_calldata(counts: dict[str, Any]) -> int:
    return sum(score_calldata_terms(counts))


def score_calldata_terms(counts: dict[str, Any]) -> list[int]:
    nonzero = int(counts.get("native_blob_nonzero_bytes") or 0)
    zero = int(counts.get("native_blob_zero_bytes") or 0)
    return [16 * nonzero, 4 * zero]


def extension_degree(candidate: dict[str, Any]) -> int:
    return int(candidate.get("extension_degree") or 5)


def pow_bits_schedule(candidate: dict[str, Any]) -> list[int]:
    existing = candidate.get("pow_bits_schedule")
    if existing:
        return [int(bits) for bits in existing]
    bits = []
    for key in (
        "starting_folding_pow_bits",
        "final_pow_bits",
        "final_folding_pow_bits",
    ):
        value = candidate.get(key)
        if value:
            bits.append(int(value))
    for row in candidate.get("rounds") or []:
        if row.get("pow_bits"):
            bits.append(int(row["pow_bits"]))
        if row.get("folding_pow_bits"):
            bits.append(int(row["folding_pow_bits"]))
    return bits


def pow_work_units(candidate: dict[str, Any]) -> int:
    existing = candidate.get("pow_work_units")
    if existing is not None:
        return int(existing)
    return sum(1 << bits for bits in pow_bits_schedule(candidate))


def pow_work_score(candidate: dict[str, Any], pow_seconds_per_unit: float) -> float:
    return pow_work_units(candidate) * pow_seconds_per_unit


def score_prover(
    candidate: dict[str, Any], rust_timings: dict[str, Any] | None
) -> float | None:
    row = prover_timing_row(candidate, rust_timings)
    if (
        row is not None
        and row.get("status") in ("ok", "partial_ok", "timeout")
        and row.get("seconds") is not None
    ):
        return float(row["seconds"])
    return None


def prover_timeout(
    candidate: dict[str, Any], rust_timings: dict[str, Any] | None
) -> bool:
    row = prover_timing_row(candidate, rust_timings)
    return bool(row and row.get("timed_out"))


def prover_timing_row(
    candidate: dict[str, Any], rust_timings: dict[str, Any] | None
) -> dict[str, Any] | None:
    if rust_timings is None:
        return None
    by_label_raw = rust_timings.get("by_label", {})
    by_label = (
        {row["label"]: row for row in by_label_raw}
        if isinstance(by_label_raw, list)
        else by_label_raw
    )
    return by_label.get(candidate["label"])


def gas_value(gas: dict[str, int], metric: str) -> int:
    if metric not in gas:
        raise MissingGasMetric(metric)
    return gas[metric]


def score_batch(gas: dict[str, int], prefix: str, count: int) -> float:
    if count <= 0:
        return 0.0
    one = gas_value(gas, f"{prefix}1")
    sixteen = gas_value(gas, f"{prefix}16")
    per_element = max(0.0, (sixteen - one) / 15.0)
    fixed = max(0.0, one - per_element)
    return fixed + per_element * count


def round_rows(candidate: dict[str, Any]) -> list[dict[str, Any]]:
    rows = list(candidate.get("rounds") or [])
    if candidate.get("final_round"):
        rows.append(candidate["final_round"])
    return rows


def evaluate_calibration(calibration: dict[str, Any] | None) -> dict[str, Any]:
    if calibration is None:
        return {
            "accepted": False,
            "ordinal_accepted": False,
            "bucket_validation_accepted": False,
            "reason": "calibration JSON not provided",
            "references": [],
            "bucket_validation_failures": ["calibration JSON not provided"],
            "bucket_ratio_bounds": CALIBRATION_RATIO_BOUNDS,
        }

    references = calibration.get("references", [])
    available_metrics = set(calibration.get("gas_metrics_available") or [])
    failures = []
    bucket_failures = []
    enriched_references = []
    if not available_metrics:
        failures.append("calibration JSON missing gas_metrics_available")
    if len(references) < 2:
        failures.append(
            "at least two calibration references are required for ordinal checking"
        )
    for ref in references:
        enriched_ref = dict(ref)
        label = ref.get("label", "<unknown>")
        metrics_used = set(ref.get("metrics_used") or [])
        if not metrics_used:
            failures.append(f"{label}: missing metrics_used")
        missing_metrics = sorted(metrics_used - available_metrics)
        if missing_metrics:
            failures.append(
                f"{label}: scorer metrics missing from BENCH log: {missing_metrics}"
            )
        if "measured_total_tx_gas" not in ref:
            failures.append(f"{label}: missing measured_total_tx_gas")
        if "verifier_score" not in ref:
            failures.append(f"{label}: missing verifier_score")
        measured_buckets = ref.get("measured_buckets", {})
        bucket_scores = ref.get("bucket_scores", {})
        phase_breakdown_available = bool(ref.get("phase_breakdown_available", True))
        for bucket in CALIBRATION_BUCKETS:
            if bucket not in measured_buckets or bucket not in bucket_scores:
                if phase_breakdown_available:
                    failures.append(f"{label}: missing {bucket} bucket")
                continue
            if (
                phase_breakdown_available
                and int(measured_buckets[bucket]) > 0
                and int(bucket_scores[bucket]) <= 0
            ):
                failures.append(
                    f"{label}: {bucket} has measured gas but zero verifier score"
                )
        bucket_ratios = {}
        if phase_breakdown_available:
            for bucket in CALIBRATION_BUCKETS:
                if bucket not in measured_buckets or bucket not in bucket_scores:
                    continue
                measured = int(measured_buckets[bucket])
                scored = int(bucket_scores[bucket])
                if measured == 0:
                    bucket_ratios[bucket] = None
                    if bucket != "calldata" and scored > 0:
                        bucket_failures.append(
                            f"{label}: {bucket} measured bucket is zero but verifier score is {scored}; "
                            "phase log capture is missing or degenerate"
                        )
                    continue
                ratio = scored / measured
                bucket_ratios[bucket] = ratio
                lower, upper = CALIBRATION_RATIO_BOUNDS[bucket]
                if ratio < lower or ratio > upper:
                    bucket_failures.append(
                        f"{label}: {bucket} score/measured ratio {ratio:.3g} outside [{lower:g}, {upper:g}]"
                    )
        else:
            enriched_ref["bucket_validation_skipped"] = (
                "phase_breakdown_available=false; reference used for total-score calibration only"
            )
            for bucket in CALIBRATION_BUCKETS:
                if bucket not in measured_buckets or bucket not in bucket_scores:
                    continue
                measured = int(measured_buckets[bucket])
                bucket_ratios[bucket] = (
                    bucket_scores[bucket] / measured if measured > 0 else None
                )
        enriched_ref["bucket_score_ratios"] = bucket_ratios
        enriched_references.append(enriched_ref)

    order_refs = [
        ref
        for ref in references
        if "measured_total_tx_gas" in ref
        and "verifier_score" in ref
        and bool(ref.get("ordinal_gate_participant", True))
    ]
    for i, lhs in enumerate(order_refs):
        for rhs in order_refs[i + 1 :]:
            lhs_measured = float(lhs["measured_total_tx_gas"])
            rhs_measured = float(rhs["measured_total_tx_gas"])
            lhs_score = float(lhs["verifier_score"])
            rhs_score = float(rhs["verifier_score"])
            measured_cmp = compare(lhs_measured, rhs_measured)
            score_cmp = compare(lhs_score, rhs_score)
            if measured_cmp != 0 and score_cmp != measured_cmp:
                failures.append(
                    "reference order mismatch: "
                    f"{lhs.get('reference', lhs.get('label'))} vs {rhs.get('reference', rhs.get('label'))}"
                )

    ordinal_accepted = not failures
    bucket_validation_accepted = not bucket_failures
    return {
        "accepted": ordinal_accepted,
        "ordinal_accepted": ordinal_accepted,
        "bucket_validation_accepted": bucket_validation_accepted,
        "reason": "; ".join(failures) if failures else "passed",
        "bucket_validation_reason": (
            "; ".join(bucket_failures) if bucket_failures else "passed"
        ),
        "mode": "ordinal_with_bucket_diagnostics",
        "bucket_ratio_bounds": CALIBRATION_RATIO_BOUNDS,
        "bucket_validation_failures": bucket_failures,
        "references": enriched_references,
    }


def compare(lhs: float, rhs: float) -> int:
    if lhs < rhs:
        return -1
    if lhs > rhs:
        return 1
    return 0


def apply_selection(
    scores: list[dict[str, Any]], calibration_result: dict[str, Any]
) -> None:
    """Fail closed when the ordinal verifier-score calibration is missing or fails."""

    if not calibration_result.get("accepted"):
        for score in scores:
            if score["accepted_for_ranking"]:
                score["accepted_for_ranking"] = False
                score["rejection_reasons"].append("calibration gate not passed")
        return

    return


def selection_policy(scores: list[dict[str, Any]]) -> dict[str, Any]:
    shortlist = [
        score
        for score in scores
        if score.get("accepted_for_ranking")
        and score.get("verifier_score") is not None
        and score.get("prover_time_score") is not None
    ]
    shortlist.sort(
        key=lambda row: (int(row["verifier_score"]), float(row["prover_time_score"]))
    )
    return {
        "verifier_score_role": "filter_not_final_gas_comparator",
        "final_schedule_requires_native_tx_gas_measurement": True,
        "native_tx_gas_shortlist_size": NATIVE_TX_GAS_SHORTLIST_SIZE,
        "reason": (
            "Verifier score is ordinal and can rank-invert when transcript or folding bucket "
            "ratios differ by schedule shape. Use it to narrow the candidate set, then measure "
            "native transaction gas on the shortlist before selecting a Solidity verifier schedule."
        ),
        "recommended_native_tx_gas_shortlist": [
            {
                "label": row["label"],
                "verifier_score": row["verifier_score"],
                "prover_time_score": row["prover_time_score"],
                "estimated_prover_time_score": row.get("estimated_prover_time_score"),
                "bucket_scores": row.get("bucket_scores"),
            }
            for row in shortlist[:NATIVE_TX_GAS_SHORTLIST_SIZE]
        ],
    }


def extra_prover_training_scores(
    schedules: list[dict[str, Any] | None],
    rust_timings: dict[str, Any] | None,
    pow_seconds_per_unit: float,
    labels_already_scored: set[str],
) -> list[dict[str, Any]]:
    if rust_timings is None:
        return []

    extra_scores = []
    seen = set(labels_already_scored)
    for schedule in schedules:
        if schedule is None:
            continue
        for candidate in schedule.get("candidates", []):
            label = candidate.get("label")
            if not label or label in seen:
                continue
            measured = score_prover(candidate, rust_timings)
            if measured is None:
                continue
            seen.add(label)
            extra_scores.append(
                {
                    "_prover_training_source": "prover_calibration_schedule",
                    "label": label,
                    "folding_variant": candidate["folding_schedule"]["variant"],
                    "requested_pow_bits": candidate.get("requested_pow_bits"),
                    "folding_factor": candidate["folding_schedule"]["first_round"],
                    "folding_factor_rest": candidate["folding_schedule"]["rest"],
                    "starting_log_inv_rate": candidate["starting_log_inv_rate"],
                    "rs_domain_initial_reduction_factor": candidate[
                        "rs_domain_initial_reduction_factor"
                    ],
                    "pow_work_units": pow_work_units(candidate),
                    "pow_work_score": pow_work_score(candidate, pow_seconds_per_unit),
                    "prover_time_score": measured,
                    "prover_timed_out": prover_timeout(candidate, rust_timings),
                }
            )
    return extra_scores


def apply_prover_estimates(
    scores: list[dict[str, Any]],
    extra_training_scores: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Populate a plotting estimate for rows that have not been fully timed yet.

    `prover_time_score` remains the measured full commit+prove wall clock only.
    The estimate is for visualization: measured rows stay measured, while
    unmeasured rows use a calibrated log-ratio model fit to completed timings.
    """

    model = fit_log_ratio_prover_model(scores + list(extra_training_scores or []))
    for score in scores:
        measured = score.get("prover_time_score")
        prediction = prover_estimator_prediction(score, model)
        model_prediction = prediction.get("seconds") if prediction else None
        score["calibrated_prover_time_score"] = model_prediction
        if prediction:
            score["prover_nearest_training_distance"] = prediction.get(
                "nearest_training_distance"
            )
            score["prover_nearest_training_label"] = prediction.get(
                "nearest_training_label"
            )
            score["prover_estimator_extrapolation"] = prediction.get("extrapolation")

        if measured is not None and not score.get("prover_timed_out"):
            score["estimated_prover_time_score"] = float(measured)
            score["prover_time_estimate_kind"] = "measured"
            continue
        if score.get("prover_timed_out") and measured is not None:
            score["estimated_prover_time_score"] = float(measured)
            score["prover_time_estimate_kind"] = "timeout_cap"
            continue
        if model_prediction is not None:
            score["estimated_prover_time_score"] = model_prediction
            score["prover_time_estimate_kind"] = "estimated_calibrated_log_ratio"
            continue
        score["estimated_prover_time_score"] = None
        score["prover_time_estimate_kind"] = None

    return prover_estimator_report(model)


def fit_log_ratio_prover_model(scores: list[dict[str, Any]]) -> dict[str, Any] | None:
    training_rows = []
    timed_out_excluded = 0
    for score in scores:
        measured = score.get("prover_time_score")
        pow_score = score.get("pow_work_score")
        if score.get("prover_timed_out"):
            if measured is not None:
                timed_out_excluded += 1
            continue
        if measured is None or pow_score is None:
            continue
        measured = float(measured)
        pow_score = float(pow_score)
        if measured <= 0.0 or pow_score <= 0.0:
            continue
        features = prover_estimator_features(score)
        training_rows.append(
            {
                "label": score["label"],
                "source": score.get("_prover_training_source", "ranked_schedule"),
                "features": features,
                "target": math.log(measured / pow_score),
                "measured": measured,
                "pow_work_score": pow_score,
            }
        )

    if not training_rows:
        return None

    feature_scales = prover_feature_scales(training_rows)
    nearest_neighbor_distances = training_nearest_neighbor_distances(
        training_rows, feature_scales
    )
    extrapolation_threshold = percentile(
        nearest_neighbor_distances,
        PROVER_ESTIMATE_EXTRAPOLATION_PERCENTILE,
    )
    model = {
        "training_rows": training_rows,
        "feature_scales": feature_scales,
        "training_nearest_neighbor_distances": nearest_neighbor_distances,
        "extrapolation_threshold_z": extrapolation_threshold,
        "extrapolation_threshold_definition": "p95_training_nearest_neighbor_z_distance",
        "extrapolation_threshold_percentile": PROVER_ESTIMATE_EXTRAPOLATION_PERCENTILE,
        "timed_out_excluded_count": timed_out_excluded,
    }
    calibration_rows = leave_one_out_calibration_rows(model)
    errors = [
        abs(float(row["relative_error"]))
        for row in calibration_rows
        if row.get("relative_error") is not None
    ]
    holdout_rows = deterministic_holdout_rows(model, PROVER_ESTIMATE_HOLDOUT_COUNT)
    model["calibration_rows"] = calibration_rows
    model["max_relative_error"] = max(errors) if errors else None
    model["mean_relative_error"] = sum(errors) / len(errors) if errors else None
    model["rows_outside_10pct"] = [
        row
        for row in calibration_rows
        if row.get("relative_error") is not None
        and abs(float(row["relative_error"])) > PROVER_ESTIMATE_MAX_MEASURED_ERROR
    ]
    model["holdout_rows"] = holdout_rows
    holdout_errors = [
        abs(float(row["relative_error"]))
        for row in holdout_rows
        if row.get("relative_error") is not None
    ]
    model["holdout_max_relative_error"] = (
        max(holdout_errors) if holdout_errors else None
    )
    model["holdout_mean_relative_error"] = (
        sum(holdout_errors) / len(holdout_errors) if holdout_errors else None
    )
    model["holdout_rows_outside_10pct"] = [
        row
        for row in holdout_rows
        if row.get("relative_error") is not None
        and abs(float(row["relative_error"])) > PROVER_ESTIMATE_MAX_MEASURED_ERROR
    ]
    return model


def prover_estimator_features(score: dict[str, Any]) -> list[float]:
    pow_score = max(float(score.get("pow_work_score") or 1e-18), 1e-18)
    requested_pow = float(score.get("requested_pow_bits") or 0)
    ff = float(score.get("folding_factor") or 0)
    rest = float(score.get("folding_factor_rest") or ff)
    lir = float(score.get("starting_log_inv_rate") or 0)
    rsv = float(score.get("rs_domain_initial_reduction_factor") or 0)
    cfsr = 1.0 if score.get("folding_variant") == "ConstantFromSecondRound" else 0.0
    return [
        math.log(pow_score),
        requested_pow,
        ff,
        rest,
        lir,
        rsv,
        cfsr,
        lir * rsv,
        ff * rsv,
        ff * lir,
        rsv * rsv,
        1.0 if int(lir) == 4 and int(ff) == 5 else 0.0,
        1.0 if int(lir) == 4 and int(ff) == 6 else 0.0,
    ]


def prover_feature_scales(training_rows: list[dict[str, Any]]) -> list[float]:
    feature_count = len(PROVER_ESTIMATE_FEATURES)
    scales = []
    for index in range(feature_count):
        values = [float(row["features"][index]) for row in training_rows]
        mean = sum(values) / len(values)
        variance = sum((value - mean) ** 2 for value in values) / len(values)
        scales.append(math.sqrt(variance) or 1.0)
    return scales


def training_nearest_neighbor_distances(
    training_rows: list[dict[str, Any]],
    scales: list[float],
) -> list[float]:
    distances = []
    for i, lhs in enumerate(training_rows):
        nearest = None
        for j, rhs in enumerate(training_rows):
            if i == j:
                continue
            distance = normalized_feature_distance(
                lhs["features"], rhs["features"], scales
            )
            nearest = distance if nearest is None else min(nearest, distance)
        if nearest is not None:
            distances.append(nearest)
    distances.sort()
    return distances


def percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    if quantile <= 0.0:
        return values[0]
    if quantile >= 1.0:
        return values[-1]
    index = math.ceil(quantile * len(values)) - 1
    return values[max(0, min(index, len(values) - 1))]


def median(values: list[float]) -> float | None:
    if not values:
        return None
    values = sorted(values)
    midpoint = len(values) // 2
    if len(values) % 2:
        return values[midpoint]
    return (values[midpoint - 1] + values[midpoint]) / 2.0


def distance_summary(values: list[float]) -> dict[str, float | None]:
    distances = sorted(values)
    return {
        "min": distances[0] if distances else None,
        "median": median(distances),
        "p90": percentile(distances, 0.90),
        "p95": percentile(distances, 0.95),
        "max": distances[-1] if distances else None,
    }


def normalized_feature_distance(
    lhs: list[float],
    rhs: list[float],
    scales: list[float],
) -> float:
    total = 0.0
    for left, right, scale in zip(lhs, rhs, scales):
        total += ((left - right) / scale) ** 2
    return math.sqrt(total)


def prover_estimator_prediction(
    score: dict[str, Any], model: dict[str, Any] | None
) -> dict[str, Any] | None:
    pow_score = score.get("pow_work_score")
    if pow_score is None:
        return None
    pow_score = float(pow_score)
    if pow_score <= 0.0:
        return None
    if model is None:
        return {
            "seconds": pow_score,
            "nearest_training_distance": None,
            "nearest_training_label": None,
            "extrapolation": None,
        }
    return predict_calibrated_prover_time_from_features(
        prover_estimator_features(score),
        pow_score,
        model,
    )


def predict_calibrated_prover_time_from_features(
    features: list[float],
    pow_score: float,
    model: dict[str, Any],
) -> dict[str, Any]:
    training_rows = model["training_rows"]
    scales = model["feature_scales"]
    distances = [
        (
            normalized_feature_distance(features, row["features"], scales),
            row,
        )
        for row in training_rows
    ]
    if not distances:
        return {
            "seconds": pow_score,
            "nearest_training_distance": None,
            "nearest_training_label": None,
            "extrapolation": None,
        }
    distances.sort(key=lambda row: row[0])
    nearest_distance, nearest_row = distances[0]
    exact_targets = [
        float(row["target"])
        for distance, row in distances
        if distance <= PROVER_ESTIMATE_DISTANCE_EPSILON
    ]
    if exact_targets:
        log_ratio = sum(exact_targets) / len(exact_targets)
    else:
        nearest = distances[:PROVER_ESTIMATE_NEIGHBORS]
        weighted_sum = 0.0
        weight_total = 0.0
        for distance, row in nearest:
            weight = 1.0 / (distance * distance + PROVER_ESTIMATE_DISTANCE_EPSILON)
            weighted_sum += weight * float(row["target"])
            weight_total += weight
        log_ratio = weighted_sum / weight_total
    predicted = pow_score * math.exp(log_ratio)
    threshold = model.get("extrapolation_threshold_z")
    extrapolation = (
        nearest_distance > float(threshold) if threshold is not None else False
    )
    return {
        "seconds": max(predicted, PROVER_ESTIMATE_MIN_POW_FACTOR * pow_score),
        "nearest_training_distance": nearest_distance,
        "nearest_training_label": nearest_row["label"],
        "extrapolation": extrapolation,
    }


def model_with_training_rows(
    training_rows: list[dict[str, Any]],
) -> dict[str, Any] | None:
    if not training_rows:
        return None
    feature_scales = prover_feature_scales(training_rows)
    nearest_neighbor_distances = training_nearest_neighbor_distances(
        training_rows, feature_scales
    )
    return {
        "training_rows": training_rows,
        "feature_scales": feature_scales,
        "training_nearest_neighbor_distances": nearest_neighbor_distances,
        "extrapolation_threshold_z": percentile(
            nearest_neighbor_distances,
            PROVER_ESTIMATE_EXTRAPOLATION_PERCENTILE,
        ),
        "extrapolation_threshold_definition": "p95_training_nearest_neighbor_z_distance",
        "extrapolation_threshold_percentile": PROVER_ESTIMATE_EXTRAPOLATION_PERCENTILE,
    }


def predict_training_row_from_subset(
    row: dict[str, Any],
    training_rows: list[dict[str, Any]],
) -> dict[str, Any] | None:
    model = model_with_training_rows(training_rows)
    if model is None:
        return None
    return predict_calibrated_prover_time_from_features(
        row["features"], row["pow_work_score"], model
    )


def prediction_error_row(
    row: dict[str, Any],
    predicted: dict[str, Any] | None,
) -> dict[str, Any]:
    seconds = predicted.get("seconds") if predicted else None
    relative_error = (
        (float(seconds) - row["measured"]) / row["measured"]
        if seconds is not None
        else None
    )
    return {
        "label": row["label"],
        "source": row["source"],
        "measured": row["measured"],
        "predicted": seconds,
        "relative_error": relative_error,
        "nearest_training_distance": (
            predicted.get("nearest_training_distance") if predicted else None
        ),
        "nearest_training_label": (
            predicted.get("nearest_training_label") if predicted else None
        ),
        "extrapolation": predicted.get("extrapolation") if predicted else None,
    }


def leave_one_out_calibration_rows(model: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for row in model["training_rows"]:
        training_subset = [
            candidate
            for candidate in model["training_rows"]
            if candidate["label"] != row["label"]
        ]
        predicted = predict_training_row_from_subset(row, training_subset)
        rows.append(prediction_error_row(row, predicted))
    return rows


def deterministic_holdout_rows(
    model: dict[str, Any], count: int
) -> list[dict[str, Any]]:
    training_rows = sorted(model["training_rows"], key=lambda row: row["label"])
    if count <= 0 or len(training_rows) <= 1:
        return []
    count = min(count, len(training_rows) - 1)
    if count == 1:
        holdout = [training_rows[len(training_rows) // 2]]
    else:
        holdout = [
            training_rows[round(index * (len(training_rows) - 1) / (count - 1))]
            for index in range(count)
        ]
    holdout_labels = {row["label"] for row in holdout}
    training_subset = [
        row for row in model["training_rows"] if row["label"] not in holdout_labels
    ]
    return [
        prediction_error_row(
            row, predict_training_row_from_subset(row, training_subset)
        )
        for row in holdout
    ]


def prover_estimator_report(model: dict[str, Any] | None) -> dict[str, Any]:
    if model is None:
        return {
            "mode": "pow_only_no_measured_rows",
            "measured_sample_count": 0,
            "within_10pct": False,
            "note": (
                "estimated_prover_time_score is for plotting unmeasured candidates. "
                "prover_time_score remains the measured full commit+prove wall clock."
            ),
        }
    return {
        "mode": "measured_else_calibrated_log_ratio",
        "features": list(PROVER_ESTIMATE_FEATURES),
        "neighbors": PROVER_ESTIMATE_NEIGHBORS,
        "distance_epsilon": PROVER_ESTIMATE_DISTANCE_EPSILON,
        "min_pow_factor": PROVER_ESTIMATE_MIN_POW_FACTOR,
        "extrapolation_threshold_z": model["extrapolation_threshold_z"],
        "extrapolation_threshold_definition": model[
            "extrapolation_threshold_definition"
        ],
        "extrapolation_threshold_percentile": model[
            "extrapolation_threshold_percentile"
        ],
        "training_nearest_neighbor_distance_summary": distance_summary(
            model["training_nearest_neighbor_distances"]
        ),
        "feature_scales": model["feature_scales"],
        "measured_sample_count": len(model["training_rows"]),
        "ranked_schedule_measured_sample_count": sum(
            1 for row in model["training_rows"] if row["source"] == "ranked_schedule"
        ),
        "extra_measured_sample_count": sum(
            1 for row in model["training_rows"] if row["source"] != "ranked_schedule"
        ),
        "timed_out_excluded_count": model["timed_out_excluded_count"],
        "error_mode": "leave_one_out",
        "max_relative_error": model["max_relative_error"],
        "mean_relative_error": model["mean_relative_error"],
        "within_10pct": not model["rows_outside_10pct"],
        "rows_outside_10pct": model["rows_outside_10pct"],
        "calibration_rows": model["calibration_rows"],
        "holdout_count": len(model["holdout_rows"]),
        "holdout_max_relative_error": model["holdout_max_relative_error"],
        "holdout_mean_relative_error": model["holdout_mean_relative_error"],
        "holdout_within_10pct": not model["holdout_rows_outside_10pct"],
        "holdout_rows_outside_10pct": model["holdout_rows_outside_10pct"],
        "holdout_rows": model["holdout_rows"],
        "note": (
            "estimated_prover_time_score is for plotting unmeasured candidates. "
            "Measured rows use the measured full commit+prove wall clock; unmeasured rows use the "
            "calibrated log-ratio model. Reported error metrics are leave-one-out over measured anchors."
        ),
    }


def validate_quintic_kernel_bounds(gas: dict[str, int]) -> list[str]:
    warnings = []
    for quintic, octic in (
        ("ext5_mul", "ext8_mul"),
        ("ext5_square", "ext8_square"),
        ("ext5_inv", "ext8_inv"),
    ):
        if gas.get(quintic, 0) > gas.get(octic, math.inf):
            warnings.append(f"{quintic} exceeds {octic}")
    return warnings


def mark_implemented_scores(
    scores: list[dict[str, Any]], implemented_labels: list[str]
) -> None:
    implemented = set(implemented_labels)
    for score in scores:
        score["implemented"] = score.get("label") in implemented


def plot_axis_limits(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "x_max_fraction": args.plot_x_max_fraction,
        "y_max_fraction": args.plot_y_max_fraction,
        "row_work_x_max_fraction": args.plot_row_work_x_max_fraction,
        "row_work_y_max_fraction": args.plot_row_work_y_max_fraction,
        "verifier_x_max_fraction": args.plot_verifier_x_max_fraction,
        "verifier_y_max_fraction": args.plot_verifier_y_max_fraction,
        "mixed_measured_axis_multiple": args.plot_mixed_measured_axis_multiple,
        "max_derived_pow_bits": args.plot_max_derived_pow_bits,
    }


def write_plots(
    out_dir: Path,
    scores: list[dict[str, Any]],
    axis_limits: dict[str, Any] | None = None,
) -> None:
    for stale_plot in out_dir.glob("pareto_*.svg"):
        stale_plot.unlink()
    plot_specs = [
        (
            "pareto_verifier_vs_prover.svg",
            "verifier_score",
            "estimated_prover_time_score",
            True,
        ),
        (
            "pareto_verifier_vs_measured_prover.svg",
            "verifier_score",
            "prover_time_score",
            True,
        ),
        (
            "pareto_row_work_vs_prover.svg",
            "row_work_score",
            "estimated_prover_time_score",
            True,
        ),
        (
            "pareto_row_work_vs_measured_prover.svg",
            "row_work_score",
            "prover_time_score",
            True,
        ),
    ]
    for spec in plot_specs:
        filename, x_key, y_key = spec[:3]
        y_lower_is_better = bool(spec[3]) if len(spec) > 3 else True
        write_svg_plot(
            out_dir / filename,
            scores,
            x_key,
            y_key,
            y_lower_is_better,
            axis_limits_for_plot(x_key, y_key, axis_limits or {}),
        )


AXIS_LABELS = {
    "verifier_score": "quintic-calibrated verifier score (lower is better)",
    "row_work_score": "query rows * row values (lower is better)",
    "prover_time_score": "measured prover seconds",
    "estimated_prover_time_score": "prover seconds (measured where available; modeled otherwise)",
}


def axis_limits_for_plot(
    x_key: str,
    y_key: str,
    axis_limits: dict[str, Any],
) -> dict[str, Any]:
    if y_key != "estimated_prover_time_score":
        return {
            "x_max_fraction": None,
            "y_max_fraction": None,
            "measured_axis_multiple": None,
        }
    x_fraction = axis_limits.get("x_max_fraction")
    y_fraction = axis_limits.get("y_max_fraction")
    if x_key == "row_work_score":
        x_fraction = axis_limits.get("row_work_x_max_fraction") or x_fraction
        y_fraction = axis_limits.get("row_work_y_max_fraction") or y_fraction
    if x_key == "verifier_score":
        x_fraction = axis_limits.get("verifier_x_max_fraction") or x_fraction
        y_fraction = axis_limits.get("verifier_y_max_fraction") or y_fraction
    return {
        "x_max_fraction": x_fraction,
        "y_max_fraction": y_fraction,
        "measured_axis_multiple": axis_limits.get("mixed_measured_axis_multiple"),
    }


def write_svg_plot(
    path: Path,
    scores: list[dict[str, Any]],
    x_key: str,
    y_key: str,
    y_lower_is_better: bool,
    axis_limits: dict[str, Any],
) -> None:
    points = [
        score
        for score in scores
        if score.get(x_key) is not None
        and score.get(y_key) is not None
        and score.get("valid", True)
        and passes_plot_pow_filter(score, axis_limits)
    ]
    plot_width, plot_height = 900, 620
    detail_top = plot_height + 20
    width = plot_width
    height = detail_top + 112
    margin = 70
    if not points:
        path.write_text(
            '<svg xmlns="http://www.w3.org/2000/svg" width="900" height="620" />\n'
        )
        return

    xs = [float(p[x_key]) for p in points]
    ys = [float(p[y_key]) for p in points]
    min_x, max_x = min(xs), max(xs)
    min_y, max_y = min(ys), max(ys)
    max_x = apply_axis_fraction(min_x, max_x, axis_limits.get("x_max_fraction"))
    max_y = apply_axis_fraction(min_y, max_y, axis_limits.get("y_max_fraction"))
    max_x, max_y = apply_measured_axis_multiple(
        points,
        x_key,
        y_key,
        max_x,
        max_y,
        axis_limits.get("measured_axis_multiple"),
    )
    points = [
        point
        for point in points
        if float(point[x_key]) <= max_x and float(point[y_key]) <= max_y
    ]
    if not points:
        path.write_text(
            '<svg xmlns="http://www.w3.org/2000/svg" width="900" height="620" />\n'
        )
        return
    xs = [float(p[x_key]) for p in points]
    ys = [float(p[y_key]) for p in points]
    min_x, max_x = min(xs), max(xs)
    min_y, max_y = min(ys), max(ys)
    if min_x == max_x:
        max_x += 1
    if min_y == max_y:
        max_y += 1

    def sx(value: float) -> float:
        return margin + (value - min_x) / (max_x - min_x) * (plot_width - 2 * margin)

    def sy(value: float) -> float:
        return (
            plot_height
            - margin
            - (value - min_y) / (max_y - min_y) * (plot_height - 2 * margin)
        )

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">',
        plot_click_script(),
        '<rect width="100%" height="100%" fill="white"/>',
        f'<line x1="{margin}" y1="{plot_height-margin}" x2="{plot_width-margin}" y2="{plot_height-margin}" stroke="#333"/>',
        f'<line x1="{margin}" y1="{margin}" x2="{margin}" y2="{plot_height-margin}" stroke="#333"/>',
        f'<text x="{plot_width/2}" y="{plot_height-20}" text-anchor="middle" font-size="14">{axis_label(x_key)}</text>',
        f'<text x="18" y="{plot_height/2}" transform="rotate(-90 18 {plot_height/2})" text-anchor="middle" font-size="14">{axis_label(y_key)}</text>',
    ]
    estimated_frontier = pareto_frontier(
        [
            point
            for point in points
            if point.get("prover_time_estimate_kind") != "timeout_cap"
        ],
        x_key,
        y_key,
        y_lower_is_better,
    )
    if len(estimated_frontier) > 1:
        parts.append(
            frontier_polyline(
                estimated_frontier, x_key, y_key, sx, sy, "#777", "3 3", 0.5
            )
        )
    measured_frontier = pareto_frontier(
        [
            point
            for point in points
            if point.get("prover_time_estimate_kind") == "measured"
        ],
        x_key,
        y_key,
        y_lower_is_better,
    )
    if len(measured_frontier) > 1:
        parts.append(
            frontier_polyline(
                measured_frontier, x_key, y_key, sx, sy, "#1769aa", "", 0.8
            )
        )
    for index, point in enumerate(points):
        x = sx(float(point[x_key]))
        y = sy(float(point[y_key]))
        constant_from_second_round = (
            point.get("folding_variant") == "ConstantFromSecondRound"
        )
        implemented = bool(point.get("implemented"))
        color = marker_color(point)
        stroke = (
            "#7b2cbf"
            if implemented
            else ("#d17b00" if constant_from_second_round else "#333")
        )
        stroke_width = "2.6" if implemented else "1"
        title = (
            f"{point['label']}; {x_key}={point[x_key]}; {y_key}={point[y_key]}; "
            f"prover={point.get('prover_time_estimate_kind')}"
        )
        detail_text = point_detail_text(point, x_key, y_key)
        onclick = (
            f"selectPoint({index}, {escape_xml(json.dumps(detail_text))}); "
            "event.stopPropagation();"
        )
        if constant_from_second_round:
            parts.append(
                f'<g onclick="{onclick}" style="cursor:pointer"><path id="point-marker-{index}" data-stroke-width="{stroke_width}" d="M {x:.1f} {y-5:.1f} L {x+5:.1f} {y:.1f} L {x:.1f} {y+5:.1f} L {x-5:.1f} {y:.1f} Z" fill="{color}" stroke="{stroke}" stroke-width="{stroke_width}"/>'
                f"<title>{escape_xml(title)}</title></g>"
            )
        else:
            parts.append(
                f'<g onclick="{onclick}" style="cursor:pointer"><circle id="point-marker-{index}" data-stroke-width="{stroke_width}" cx="{x:.1f}" cy="{y:.1f}" r="4" fill="{color}" stroke="{stroke}" stroke-width="{stroke_width}"/>'
                f"<title>{escape_xml(title)}</title></g>"
            )
    parts.extend(plot_legend(width))
    parts.extend(plot_selected_detail_box(detail_top))
    parts.append("</svg>")
    path.write_text("\n".join(parts) + "\n")


def apply_axis_fraction(
    min_value: float, max_value: float, fraction: float | None
) -> float:
    if fraction is None:
        return max_value
    fraction = max(0.0, min(float(fraction), 1.0))
    return min_value + (max_value - min_value) * fraction


def apply_measured_axis_multiple(
    points: list[dict[str, Any]],
    x_key: str,
    y_key: str,
    max_x: float,
    max_y: float,
    multiple: float | None,
) -> tuple[float, float]:
    if multiple is None:
        return max_x, max_y
    measured = [
        point
        for point in points
        if point.get("prover_time_estimate_kind") == "measured"
        and point.get(x_key) is not None
        and point.get(y_key) is not None
    ]
    if not measured:
        return max_x, max_y
    multiple = max(0.0, float(multiple))
    measured_max_x = max(float(point[x_key]) for point in measured)
    measured_max_y = max(float(point[y_key]) for point in measured)
    return min(max_x, measured_max_x * multiple), min(max_y, measured_max_y * multiple)


def passes_plot_pow_filter(
    point: dict[str, Any],
    axis_limits: dict[str, Any],
) -> bool:
    max_pow = axis_limits.get("max_derived_pow_bits")
    if max_pow is None:
        return True
    derived = point.get("max_derived_pow_bits")
    return derived is not None and int(derived) <= int(max_pow)


def axis_label(key: str) -> str:
    return AXIS_LABELS.get(key, key)


def frontier_polyline(
    frontier: list[dict[str, Any]],
    x_key: str,
    y_key: str,
    sx: Any,
    sy: Any,
    stroke: str,
    dasharray: str,
    opacity: float,
) -> str:
    coords = " ".join(
        f"{sx(float(point[x_key])):.1f},{sy(float(point[y_key])):.1f}"
        for point in frontier
    )
    dash = f' stroke-dasharray="{dasharray}"' if dasharray else ""
    return (
        f'<polyline points="{coords}" fill="none" stroke="{stroke}" '
        f'stroke-width="1.5" opacity="{opacity}"{dash}/>'
    )


def marker_color(point: dict[str, Any]) -> str:
    kind = point.get("prover_time_estimate_kind")
    if kind == "measured":
        return "#1769aa"
    if kind == "timeout_cap":
        return "#b3261e"
    if kind == "estimated_calibrated_log_ratio":
        if point.get("prover_estimator_extrapolation"):
            return "#d17b00"
        return "#8a8a8a"
    return "#bbbbbb"


def pareto_frontier(
    points: list[dict[str, Any]],
    x_key: str,
    y_key: str,
    y_lower_is_better: bool,
) -> list[dict[str, Any]]:
    frontier = []
    best_y: float | None = None
    for point in sorted(
        points, key=lambda item: (float(item[x_key]), float(item[y_key]))
    ):
        y = float(point[y_key])
        if best_y is None:
            frontier.append(point)
            best_y = y
            continue
        improves = y < best_y if y_lower_is_better else y > best_y
        if improves:
            frontier.append(point)
            best_y = y
    return frontier


def plot_legend(width: int) -> list[str]:
    x = width - 330
    return [
        f'<g font-size="12">',
        f'<circle cx="{x}" cy="28" r="4" fill="#1769aa" stroke="#333"/>',
        f'<text x="{x + 12}" y="32">measured full prover timing</text>',
        f'<circle cx="{x}" cy="48" r="4" fill="#8a8a8a" stroke="#333"/>',
        f'<text x="{x + 12}" y="52">estimated by calibrated prover model</text>',
        f'<circle cx="{x}" cy="68" r="4" fill="#d17b00" stroke="#333"/>',
        f'<text x="{x + 12}" y="72">estimated outside measured neighborhood</text>',
        f'<circle cx="{x}" cy="88" r="4" fill="#b3261e" stroke="#333"/>',
        f'<text x="{x + 12}" y="92">timed out at cap</text>',
        f'<path d="M {x:.1f} 108 L {x+5:.1f} 113 L {x:.1f} 118 L {x-5:.1f} 113 Z" fill="#8a8a8a" stroke="#d17b00"/>',
        f'<text x="{x + 12}" y="117">ConstantFromSecondRound schedule</text>',
        f'<line x1="{x - 4}" y1="134" x2="{x + 8}" y2="134" stroke="#1769aa" stroke-width="1.5"/>',
        f'<text x="{x + 12}" y="138">measured frontier</text>',
        f'<line x1="{x - 4}" y1="154" x2="{x + 8}" y2="154" stroke="#777" stroke-width="1.5" stroke-dasharray="3 3"/>',
        f'<text x="{x + 12}" y="158">modeled frontier</text>',
        f'<circle cx="{x}" cy="178" r="4" fill="white" stroke="#7b2cbf" stroke-width="2.6"/>',
        f'<text x="{x + 12}" y="182">implemented verifier target</text>',
        f'<text x="{x - 8}" y="204" fill="#555">model is ordinal; see JSON for leave-one-out error</text>',
        f'<text x="{x - 8}" y="222" fill="#555">final gas choice needs native tx measurement</text>',
        "</g>",
    ]


def plot_click_script() -> str:
    return """<script><![CDATA[
let selectedPointIndex = null;
function selectPoint(index, detail) {
  const textarea = document.getElementById("selected-point-detail");
  if (textarea) {
    textarea.value = detail;
    textarea.focus();
    textarea.select();
  }
  if (selectedPointIndex !== null) {
    const oldMarker = document.getElementById("point-marker-" + selectedPointIndex);
    if (oldMarker) {
      oldMarker.setAttribute("stroke-width", oldMarker.getAttribute("data-stroke-width") || "1");
    }
  }
  selectedPointIndex = index;
  const marker = document.getElementById("point-marker-" + index);
  if (marker) {
    marker.setAttribute("stroke-width", "3");
  }
}
]]></script>"""


def plot_selected_detail_box(top: int) -> list[str]:
    return [
        f'<foreignObject x="60" y="{top}" width="790" height="92">',
        '<div xmlns="http://www.w3.org/1999/xhtml" style="font-family: system-ui, -apple-system, sans-serif; font-size: 12px;">',
        '<div style="font-weight: 600; margin-bottom: 4px;">Selected point</div>',
        '<textarea id="selected-point-detail" readonly="readonly" style="box-sizing: border-box; width: 100%; height: 62px; font: 11px monospace; border: 1px solid #aaa; border-radius: 4px; padding: 6px; resize: none;">Click a point to put copyable details here.</textarea>',
        "</div>",
        "</foreignObject>",
    ]


def point_detail_text(point: dict[str, Any], x_key: str, y_key: str) -> str:
    lines = [
        f"label={point['label']}",
        f"{x_key}={point.get(x_key)}",
        f"{y_key}={point.get(y_key)}",
        f"prover_time_estimate_kind={point.get('prover_time_estimate_kind')}",
    ]
    if point.get("prover_time_score") is not None:
        lines.append(f"measured_prover_time_score={point.get('prover_time_score')}")
    if point.get("prover_nearest_training_distance") is not None:
        lines.append(
            f"prover_nearest_training_distance={point.get('prover_nearest_training_distance')}"
        )
    if point.get("prover_nearest_training_label") is not None:
        lines.append(
            f"prover_nearest_training_label={point.get('prover_nearest_training_label')}"
        )
    if point.get("prover_estimator_extrapolation") is not None:
        lines.append(
            f"prover_estimator_extrapolation={point.get('prover_estimator_extrapolation')}"
        )
    if point.get("implemented"):
        lines.append("implemented=True")
    lines.extend(
        [
            f"folding_variant={point.get('folding_variant')}",
            f"requested_pow_bits={point.get('requested_pow_bits')}",
            f"folding_factor={point.get('folding_factor')}",
            f"folding_factor_rest={point.get('folding_factor_rest')}",
            f"starting_log_inv_rate={point.get('starting_log_inv_rate')}",
            f"rs_domain_initial_reduction_factor={point.get('rs_domain_initial_reduction_factor')}",
        ]
    )
    return "\n".join(lines)


def escape_xml(value: Any) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


if __name__ == "__main__":
    main()
