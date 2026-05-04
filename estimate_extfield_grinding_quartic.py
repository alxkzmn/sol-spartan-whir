#!/usr/bin/env python3
"""
Estimate gas for the quartic JohnsonBound extension-field grinding idea.

This is intentionally a thin wrapper around whir_param_sweep.py. It records the
ad hoc estimator used for the discussion about:

  - quartic extension
  - num_variables = 22
  - JohnsonBound 100-bit target
  - extension-field PoW witnesses
  - ConstantFromSecondRound(4,3), starting_log_inv_rate = 1,
    rs_domain_initial_reduction_factor = 3
  - max PoW budget = 46 bits

The script does not claim this is a deployable verifier. It relaxes the current
base-field PoW cap only for estimation, because the current protocol still
stores and checks PoW witnesses as base-field elements.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SWEEP_PATH = ROOT / "whir_param_sweep.py"

NUM_VARS = 22
SECURITY_LEVEL = 100
SOUNDNESS = "JohnsonBound"
FIELD_BITS_QUARTIC = 124
EXTENSION_DEGREE = 4

FF_0 = 4
FF_REST = 3
STARTING_LOG_INV_RATE = 1
RS_DOMAIN_INITIAL_REDUCTION_FACTOR = 3
MAX_POW_BITS_EXTENSION_GRINDING = 46

# Measured in test/WhirGasProfile_lir6_ff5_rsv1.t.sol:
# forge test --match-contract WhirGasProfileTest \
#   --match-test testProfileMicroBenchmarks -vv
OBSERVE_BASE_GAS = 340
OBSERVE_EXT4_GAS = 1835

# Native blob calldata approximation.
# Base PoW witness is 4 raw bytes; quartic extension witness is 16 raw bytes.
# The estimate assumes the extra bytes are nonzero to avoid understating cost.
BASE_WITNESS_BYTES = 4
EXT4_WITNESS_BYTES = 16
NONZERO_CALLDATA_GAS_PER_BYTE = 16

# The existing sweep script has an octic native blob calldata model, but not a
# fitted quartic native blob model for this unimplemented schedule. These
# per-item prices are the manual range used in the discussion: ext4 packed value
# calldata is scanned from optimistic raw-byte pricing toward ABI-slot pricing.
EXT4_BLOB_CALLDATA_GAS_RANGE = (250, 320)
BASE4_BLOB_CALLDATA_GAS = 64
DIGEST20_CALLDATA_GAS = 314
ROUGH_HEADER_CALLDATA_GAS = 2000
INTRINSIC_TX_GAS = 21_000


def load_sweep_module():
    spec = importlib.util.spec_from_file_location("whir_param_sweep", SWEEP_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load {SWEEP_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def native_blob_item_counts(sweep, cfg):
    """Mirror the octic native-blob count model, but count ext4 values."""

    decommitment_counts = [
        sweep.expected_merkle_decommitments(r.num_queries, r.depth)
        for r in cfg.round_parameters
    ]

    ext4_count = cfg.num_vars + 1  # statement point plus statement evaluation
    ext4_count += cfg.commitment_ood_samples
    ext4_count += cfg.ff_0 * 2  # initial sumcheck [c0, c2] per round

    base4_count = 0.0
    digest20_count = 1.0  # initial commitment

    for i, round_info in enumerate(cfg.round_parameters[:-1]):
        digest20_count += 1 + decommitment_counts[i]
        ext4_count += round_info.ood_samples

        if i + 1 < len(cfg.round_parameters) - 1:
            next_sumcheck_rounds = cfg.round_parameters[i + 1].folding_factor
        else:
            next_sumcheck_rounds = cfg.round_parameters[-1].folding_factor
        ext4_count += next_sumcheck_rounds * 2

        base4_count += 1  # round PoW witness
        row_values = round_info.num_queries * (2**round_info.folding_factor)
        if i == 0:
            base4_count += row_values
        else:
            ext4_count += row_values

    final_round = cfg.round_parameters[-1]
    digest20_count += decommitment_counts[-1]
    base4_count += 1  # final PoW witness
    ext4_count += 2**cfg.final_sumcheck_rounds  # final polynomial
    ext4_count += final_round.num_queries * (2**final_round.folding_factor)
    ext4_count += cfg.final_sumcheck_rounds * 2  # final sumcheck [c0, c2]

    return {
        "ext4_count": ext4_count,
        "base4_count": base4_count,
        "digest20_count": digest20_count,
        "decommitment_counts": decommitment_counts,
    }


def pow_witness_count(cfg) -> int:
    nonfinal_rounds = sum(
        1
        for round_info in cfg.round_parameters
        if isinstance(round_info.round_idx, int)
    )
    return (
        cfg.ff_0 + nonfinal_rounds * (1 + cfg.ff_rest) + 1 + cfg.final_sumcheck_rounds
    )


def calldata_range_from_counts(counts):
    low_ext4, high_ext4 = EXT4_BLOB_CALLDATA_GAS_RANGE
    values = []
    for ext4_price in (low_ext4, high_ext4):
        calldata = (
            counts["ext4_count"] * ext4_price
            + counts["base4_count"] * BASE4_BLOB_CALLDATA_GAS
            + counts["digest20_count"] * DIGEST20_CALLDATA_GAS
            + ROUGH_HEADER_CALLDATA_GAS
        )
        values.append(round(calldata))
    return min(values), max(values)


def main() -> None:
    sweep = load_sweep_module()

    # The existing script correctly guards current base-field grinding at 30
    # bits. Raise the module constant only for this extension-field thought
    # experiment, then pass max_pow = 46 into the derivation.
    sweep.MAX_POW_BITS = 60

    cfg = sweep.derive_config(
        NUM_VARS,
        FF_0,
        FF_REST,
        STARTING_LOG_INV_RATE,
        MAX_POW_BITS_EXTENSION_GRINDING,
        security_level=SECURITY_LEVEL,
        field_bits=FIELD_BITS_QUARTIC,
        soundness=SOUNDNESS,
        rs_domain_initial_reduction_factor=RS_DOMAIN_INITIAL_REDUCTION_FACTOR,
    )
    if not cfg.valid:
        raise RuntimeError(f"derived config is invalid: {cfg.invalid_reason}")

    execution = sweep.estimate_execution_gas(cfg, extension_degree=EXTENSION_DEGREE)
    execution_gas = sum(execution.__dict__.values())
    counts = native_blob_item_counts(sweep, cfg)
    calldata_low, calldata_high = calldata_range_from_counts(counts)

    witnesses = pow_witness_count(cfg)
    pow_extra_bytes = witnesses * (EXT4_WITNESS_BYTES - BASE_WITNESS_BYTES)
    pow_extra_calldata_gas = pow_extra_bytes * NONZERO_CALLDATA_GAS_PER_BYTE
    pow_extra_execution_gas = witnesses * (OBSERVE_EXT4_GAS - OBSERVE_BASE_GAS)

    print("Quartic extension-field grinding gas estimate")
    print("================================================")
    print(f"schedule: ConstantFromSecondRound({FF_0},{FF_REST})")
    print(f"starting_log_inv_rate: {STARTING_LOG_INV_RATE}")
    print(f"rs_domain_initial_reduction_factor: {RS_DOMAIN_INITIAL_REDUCTION_FACTOR}")
    print(f"max_pow_bits: {MAX_POW_BITS_EXTENSION_GRINDING}")
    print()
    print("Derived rounds:")
    for round_info in cfg.round_parameters:
        print(
            "  "
            f"round={round_info.round_idx}, "
            f"num_variables={round_info.num_variables}, "
            f"folding_factor={round_info.folding_factor}, "
            f"log_inv_rate={round_info.log_inv_rate}, "
            f"queries={round_info.num_queries}, "
            f"depth={round_info.depth}, "
            f"pow_bits={round_info.pow_bits}, "
            f"folding_pow_bits={round_info.folding_pow_bits}, "
            f"is_base={round_info.is_base}"
        )
    print(f"total_queries: {cfg.total_queries}")
    print()
    print("PoW witness delta:")
    print(f"  witness_count: {witnesses}")
    print(f"  extra_bytes_base_to_ext4: {pow_extra_bytes}")
    print(f"  extra_calldata_gas_worst_case: {pow_extra_calldata_gas}")
    print(f"  extra_execution_gas_from_observe_delta: {pow_extra_execution_gas}")
    print()
    print("Execution model:")
    print(f"  breakdown: {execution.__dict__}")
    print(f"  execution_gas: {execution_gas}")
    print()
    print("Native blob calldata model:")
    print(f"  counts: {counts}")
    print(f"  calldata_gas_range: {calldata_low}..{calldata_high}")
    print()
    print("Total tx gas estimate:")
    print(f"  low:  {INTRINSIC_TX_GAS + execution_gas + calldata_low}")
    print(f"  high: {INTRINSIC_TX_GAS + execution_gas + calldata_high}")


if __name__ == "__main__":
    main()
