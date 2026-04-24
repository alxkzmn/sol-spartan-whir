#!/usr/bin/env python3
"""
WHIR parameter sweep for EVM verifier gas estimation.

Models the WHIR parameter derivation from whir-p3 and estimates
execution gas + calldata gas for various configurations including:
  - Constant(folding_factor) folding
  - ConstantFromSecondRound(first_ff, rest_ff) folding
  - rs_domain_initial_reduction_factor
  - starting_log_inv_rate

Derived parameters mirror whir-p3/src/whir/parameters.rs and
whir-p3/src/parameters/errors.rs. Includes:
  - Per-round pow_bits, folding_pow_bits, OOD samples
  - Starting folding PoW bits, commitment OOD samples
  - Final pow_bits, final folding PoW bits
  - Validity check: all derived PoW ≤ max_pow_bits (mirrors check_pow_bits())

Calibration (five-point compromise):
  Point A: Constant(5)/lir=11/rs_v=3 on the alternate fixed verifier family
    measured=957,778  model=891,844  error=-6.9%
  Point B: Constant(4)/lir=6/rs_v=1 on old verifier (specialized constraint kernels)
    measured=996,074  model=1,064,610  error=+6.9%
  Point C: octic k22/jb100/lir=6/ff=4/rs_v=1 on the current native verifier family
    measured=7,865,125  model=7,865,125  error=+0.0%
  Point D: octic k22/jb100/lir=6/ff=4/rs_v=1 on a historical generic-native benchmark path
    measured=8,249,508  model=8,249,508  error=+0.0%
  Point E: octic k22/jb100/lir=6/CFSR(4,3)/rs_v=1 on a historical generic-native benchmark path
    measured=8,797,836  model=8,797,855  error=+0.0%
  Validation point F: octic k22/jb100/lir=5/ff=4/rs_v=1 on a historical generic-native benchmark path
    measured=9,164,323  model=9,239,822  error=+0.8%
  Current documented precision:
    - execution gas only, not total tx gas
    - both calibration points are within ±6.9% relative error
    - the current octic JohnsonBound production anchor matches the measured native verifier
    - the current octic generic schedule model matches both measured generic-native octic points
    - the current octic generic schedule model is within +0.8% on the measured lir=5 ff=4 validation point
    - this is the current measured calibration band, not a guarantee for every
      unbenchmarked schedule
  Constraint model uses iteration-aware decomposition:
    cost = (nq + ood_samples) × (PER_VAR × numVars + PER_ITER) per round,
    plus (1 + commitOodSamples) × (PER_VAR × numVars + PER_ITER) for initial.
  Per-unit constraint constants are set to ~50% of the micro-benchmark values
  (generic path) to split the difference between the generic and specialized
  verifier implementations. For octic schedules, the model now distinguishes:
    - the current hand-specialized production ff=4 family
    - unbenchmarked generic-native schedules that fall back to the generic
      STIR row/Merkle path when they miss the optimized rowLen=16, ff=4 kernels

Known constraints:
  - KoalaBear ORDER = 2^31 - 2^24 + 1 → max_pow_bits = 30 (hard assert in challenger)
  - BabyBear ORDER = 2^31 - 2^27 + 1 → max_pow_bits = 30 (same)
  - Mersenne31: TWO_ADICITY = 1, not viable for WHIR (requires TwoAdicField)
  - KoalaBear TWO_ADICITY = 24, BabyBear TWO_ADICITY = 27
  - Constraint: log_folded_domain_size = (num_vars + lir - ff_0) <= TWO_ADICITY
  - rs_domain_initial_reduction_factor (v) must be <= ff_0
  - Rust-level schedule validity is not the same thing as current stage4 Solidity
    compatibility. The script can rank broader schedules, but generated
    Solidity verifiers and end-to-end benchmarks only exist for the schedules
    that have been emitted into sol-spartan-whir/src.

Usage:
  python3 whir_param_sweep.py
  python3 whir_param_sweep.py --num-vars 20
  python3 whir_param_sweep.py --max-starting-log-inv-rate 11

Sweep controls and ranges:
  - num_vars is set by --num-vars (default: 16)
  - Constant(ff): ff in [1, num_vars]
  - ConstantFromSecondRound(ff_0, ff_rest): 1 <= ff_rest < ff_0 <= num_vars
  - starting_log_inv_rate: [1, min(--max-starting-log-inv-rate, TWO_ADICITY - num_vars + ff_0)]
  - rs_domain_initial_reduction_factor: [1, ff_0]
  - max_pow is fixed to MAX_POW_BITS (= 30), not swept
  - candidates that violate derive_config() assertions or derived-PoW validity are discarded
"""

import math
import argparse
from dataclasses import dataclass
from typing import List, Tuple

# === WHIR PARAMETER DERIVATION ===

FIELD_BITS_BY_EXTENSION = {4: 124, 8: 248}
DEFAULT_EXTENSION_DEGREE = 4
DEFAULT_FIELD_SIZE_BITS = FIELD_BITS_BY_EXTENSION[DEFAULT_EXTENSION_DEGREE]
DEFAULT_SOUNDNESS = "CapacityBound"
DEFAULT_SECURITY_LEVEL = 80
MAX_POW_BITS = 30  # hard limit: (1 << bits) < F::ORDER_U32 for 31-bit primes
TWO_ADICITY = 24  # KoalaBear (BabyBear = 27, irrelevant for num_vars <= 16)
MAX_SEND = 6  # MAX_NUM_VARIABLES_TO_SEND_COEFFS
MAX_STARTING_LOG_INV_RATE = 11  # sweep cap and current hard ceiling

CURRENT_LIR11 = (5, 5, 11, 3)
CURRENT_LIR6 = (4, 4, 6, 1)
CURRENT_QUARTIC_CONFIGS = (
    (CURRENT_LIR11, "WhirVerifier4_lir11_ff5_rsv3.sol"),
    (CURRENT_LIR6, "WhirVerifier4_lir6_ff5_rsv1.sol"),
)
CURRENT_CONFIG_LABELS = {
    params: label for params, label in CURRENT_QUARTIC_CONFIGS
}
OCTIC_REFERENCE = ((4, 4, 6, 1), "WhirBlobVerifierNative8_k22_jb100_lir6_ff4_rsv1.sol")


def log_eta(soundness: str, log_inv_rate: int) -> float:
    if soundness == "UniqueDecoding":
        return 0.0
    if soundness == "JohnsonBound":
        return -(0.5 * log_inv_rate + math.log2(10) + 1)
    if soundness == "CapacityBound":
        return -(log_inv_rate + math.log2(10) + 1)
    raise ValueError(f"unsupported soundness {soundness}")


def list_size_bits(soundness: str, log_degree: int, log_inv_rate: int) -> float:
    eta_log = log_eta(soundness, log_inv_rate)
    if soundness == "UniqueDecoding":
        return 0.0
    if soundness == "JohnsonBound":
        return 0.5 * log_inv_rate - (1 + eta_log)
    if soundness == "CapacityBound":
        return (log_degree + log_inv_rate) - eta_log
    raise ValueError(f"unsupported soundness {soundness}")


def log_1_delta(soundness: str, log_inv_rate: int) -> float:
    eta_log = log_eta(soundness, log_inv_rate)
    eta = 2 ** eta_log
    rate = 2 ** (-log_inv_rate)
    if soundness == "UniqueDecoding":
        delta = 0.5 * (1 - rate)
    elif soundness == "JohnsonBound":
        delta = 1 - math.sqrt(rate) - eta
    elif soundness == "CapacityBound":
        delta = 1 - rate - eta
    else:
        raise ValueError(f"unsupported soundness {soundness}")
    return math.log2(1 - delta)


def num_queries(soundness: str, protocol_security: float, log_inv_rate: int) -> int:
    return math.ceil(-protocol_security / log_1_delta(soundness, log_inv_rate))


def query_error(soundness: str, log_inv_rate: int, nq: int) -> float:
    return -nq * log_1_delta(soundness, log_inv_rate)


def ood_samples_fn(
    soundness: str,
    security_level: int,
    log_degree: int,
    log_inv_rate: int,
    field_bits: int,
) -> int:
    if soundness == "UniqueDecoding":
        return 0
    for s in range(1, 64):
        lsb = list_size_bits(soundness, log_degree, log_inv_rate)
        error = 2 * lsb + log_degree * s
        ood_err = s * field_bits + 1 - error
        if ood_err >= security_level:
            return s
    raise ValueError("Could not find appropriate number of OOD samples")


def prox_gaps_error(
    soundness: str,
    log_degree: int,
    log_inv_rate: int,
    field_bits: int,
    num_functions: int = 2,
) -> float:
    assert num_functions >= 2
    eta_log = log_eta(soundness, log_inv_rate)
    if soundness == "UniqueDecoding":
        error = log_degree + log_inv_rate
    elif soundness == "JohnsonBound":
        numerator = 2 * log_degree
        sqrt_rho_20 = 1 + math.log2(10) + 0.5 * log_inv_rate
        error = numerator + 7 * (min(sqrt_rho_20, -eta_log) - 1)
    elif soundness == "CapacityBound":
        error = (log_degree + 2 * log_inv_rate) - eta_log
    else:
        raise ValueError(f"unsupported soundness {soundness}")
    num_functions_1_log = math.log2(num_functions - 1)
    return field_bits - (error + num_functions_1_log)


def rbr_soundness_fold_sumcheck(
    soundness: str, field_bits: int, num_variables: int, log_inv_rate: int
) -> float:
    return field_bits - (list_size_bits(soundness, num_variables, log_inv_rate) + 1)


def folding_pow_bits_fn(
    soundness: str,
    security_level: int,
    field_bits: int,
    num_variables: int,
    log_inv_rate: int,
) -> float:
    pg = prox_gaps_error(soundness, num_variables, log_inv_rate, field_bits, 2)
    sc = rbr_soundness_fold_sumcheck(
        soundness, field_bits, num_variables, log_inv_rate
    )
    return max(0.0, security_level - min(pg, sc))


def rbr_soundness_queries_combination(
    soundness: str,
    field_bits: int,
    num_variables: int,
    log_inv_rate: int,
    ood_samples: int,
    nq: int,
) -> float:
    list_bits = list_size_bits(soundness, num_variables, log_inv_rate)
    log_combination = math.log2(ood_samples + nq)
    return field_bits - (log_combination + list_bits + 1)


@dataclass
class RoundInfo:
    round_idx: object  # int or "final"
    num_variables: int  # num_variables at this round (after the fold that created it)
    folding_factor: int  # folding factor for this round's leaf/fold width
    log_inv_rate: int  # log_inv_rate at this round (before fold)
    num_queries: int
    pow_bits: int
    folding_pow_bits: int
    depth: int  # Merkle tree depth (log2 of number of leaves)
    is_base: bool  # True for round 0 (base-field leaves)
    next_lir: int = 0
    ood_samples: int = 0


@dataclass
class WhirConfig:
    num_vars: int  # original number of variables in committed polynomial
    n_rounds: int  # number of non-final STIR rounds
    final_sumcheck_rounds: int
    round_parameters: List[RoundInfo]
    total_queries: int
    ff_0: int  # first-round folding factor
    ff_rest: int  # subsequent rounds folding factor
    rs_domain_initial_reduction_factor: int
    commitment_ood_samples: int
    starting_folding_pow_bits: int
    final_folding_pow_bits: int
    valid: bool  # True if all derived PoW <= max_pow_bits
    invalid_reason: str = ""  # reason if invalid


def compute_number_of_rounds(num_vars: int, ff_0: int, ff_rest: int) -> Tuple[int, int]:
    """
    Mirrors FoldingFactor::compute_number_of_rounds from Rust.
    Returns (n_rounds, final_sumcheck_rounds).
    n_rounds does NOT include the final round.
    """
    if ff_0 == ff_rest:
        # Constant case
        if num_vars <= MAX_SEND:
            return (0, num_vars - ff_0)
        n_rounds = math.ceil((num_vars - MAX_SEND) / ff_0)
        fsr = num_vars - n_rounds * ff_0
        return (n_rounds - 1, fsr)
    else:
        # ConstantFromSecondRound case
        nv_after_first = num_vars - ff_0
        if nv_after_first < MAX_SEND:
            return (0, nv_after_first)
        n_rounds = math.ceil((nv_after_first - MAX_SEND) / ff_rest)
        fsr = nv_after_first - n_rounds * ff_rest
        return (n_rounds, fsr)


def derive_config(
    num_vars: int,
    ff_0: int,
    ff_rest: int,
    starting_lir: int,
    max_pow: int,
    security_level: int = DEFAULT_SECURITY_LEVEL,
    field_bits: int = DEFAULT_FIELD_SIZE_BITS,
    soundness: str = DEFAULT_SOUNDNESS,
    rs_domain_initial_reduction_factor: int = 1,
) -> WhirConfig:
    """
    Derive full WHIR round schedule from parameters.

    Mirrors WhirConfig::new() from whir-p3/src/whir/parameters.rs.
    Derived PoW values are NOT clamped — they reflect what the protocol actually
    needs. The config is marked invalid (valid=False) if any derived PoW exceeds
    max_pow (mirrors check_pow_bits()).

    Args:
        num_vars: Number of variables in the committed polynomial
        ff_0: Folding factor for round 0
        ff_rest: Folding factor for subsequent rounds (same as ff_0 for Constant)
        starting_lir: Starting log inverse rate
        max_pow: Maximum PoW bits budget (used to compute protocol_security = sec - max_pow)
        rs_domain_initial_reduction_factor: rs_domain_initial_reduction_factor (must be <= ff_0, default 1)
    """
    if max_pow > MAX_POW_BITS:
        raise ValueError(
            f"max_pow ({max_pow}) exceeds field limit MAX_POW_BITS ({MAX_POW_BITS}). "
            f"Challenger will hard-assert: (1 << bits) < F::ORDER_U32"
        )
    assert (
        rs_domain_initial_reduction_factor <= ff_0
    ), f"rs_domain_initial_reduction_factor ({rs_domain_initial_reduction_factor}) must be <= ff_0 ({ff_0})"

    # Check TWO_ADICITY constraint
    log_folded = num_vars + starting_lir - ff_0
    assert (
        log_folded <= TWO_ADICITY
    ), f"log_folded_domain_size ({log_folded}) > TWO_ADICITY ({TWO_ADICITY})"

    n_rounds, final_sumcheck_rounds = compute_number_of_rounds(num_vars, ff_0, ff_rest)
    protocol_sec = security_level - max_pow

    # --- Commitment-level derivations (before any decrement) ---
    commitment_ood_samples = ood_samples_fn(
        soundness, security_level, num_vars, starting_lir, field_bits
    )
    starting_folding_pow_bits = folding_pow_bits_fn(
        soundness, security_level, field_bits, num_vars, starting_lir
    )

    rounds = []
    nv = num_vars
    lir = starting_lir
    log_domain = num_vars + starting_lir

    # Mirrors Rust: num_variables -= folding_factor.at_round(0) before the loop
    nv -= ff_0

    for i in range(n_rounds + 1):
        ff_this = ff_0 if i == 0 else ff_rest
        # Final round uses folding_factor.at_round(n_rounds):
        #   n_rounds==0 → at_round(0) → ff_0
        #   n_rounds>=1 → at_round(n_rounds) → ff_rest
        ff_final = ff_0 if n_rounds == 0 else ff_rest

        if i < n_rounds:
            # Non-final round
            v = rs_domain_initial_reduction_factor if i == 0 else 1
            next_lir = lir + (ff_this - v)

            nq = num_queries(soundness, protocol_sec, lir)
            ood_s = ood_samples_fn(soundness, security_level, nv, next_lir, field_bits)

            # pow_bits (uncapped) — mirrors Rust
            qe = query_error(soundness, lir, nq)
            ce = rbr_soundness_queries_combination(
                soundness, field_bits, nv, next_lir, ood_s, nq
            )
            pb = max(0.0, security_level - min(qe, ce))

            # folding_pow_bits (uncapped) — mirrors Rust
            fpow = folding_pow_bits_fn(
                soundness, security_level, field_bits, nv, next_lir
            )

            tree_depth = log_domain - ff_this

            rounds.append(
                RoundInfo(
                    round_idx=i,
                    num_variables=nv,
                    folding_factor=ff_this,
                    log_inv_rate=lir,
                    num_queries=nq,
                    pow_bits=int(pb),
                    folding_pow_bits=int(fpow),
                    depth=tree_depth,
                    is_base=(i == 0),
                    next_lir=next_lir,
                    ood_samples=ood_s,
                )
            )

            nv -= (ff_final if (i + 1 == n_rounds) else ff_rest) if n_rounds > 0 else 0
            lir = next_lir
            log_domain -= v  # domain_size >>= v
        else:
            # Final round — ff from folding_factor.at_round(n_rounds)
            nq = num_queries(soundness, protocol_sec, lir)
            tree_depth = log_domain - ff_final

            # final_pow_bits (uncapped)
            final_qe = query_error(soundness, lir, nq)
            pb = max(0.0, security_level - final_qe)

            rounds.append(
                RoundInfo(
                    round_idx="final",
                    num_variables=nv,
                    folding_factor=ff_final,
                    log_inv_rate=lir,
                    num_queries=nq,
                    pow_bits=int(pb),
                    folding_pow_bits=0,
                    depth=tree_depth,
                    is_base=(i == 0),
                )
            )

    # final_folding_pow_bits: max(0, security_level - (field_size_bits - 1))
    final_folding_pow_bits = max(0.0, security_level - (field_bits - 1))

    # --- Validity check (mirrors check_pow_bits()) ---
    all_pow_values = (
        [int(starting_folding_pow_bits), int(final_folding_pow_bits)]
        + [r.pow_bits for r in rounds]
        + [r.folding_pow_bits for r in rounds]
    )
    max_derived = max(all_pow_values)
    valid = max_derived <= max_pow
    invalid_reason = ""
    if not valid:
        invalid_reason = f"derived PoW {max_derived} > max_pow {max_pow}"

    return WhirConfig(
        num_vars=num_vars,
        n_rounds=n_rounds,
        final_sumcheck_rounds=final_sumcheck_rounds,
        round_parameters=rounds,
        total_queries=sum(r.num_queries for r in rounds),
        ff_0=ff_0,
        ff_rest=ff_rest,
        rs_domain_initial_reduction_factor=rs_domain_initial_reduction_factor,
        commitment_ood_samples=commitment_ood_samples,
        starting_folding_pow_bits=int(starting_folding_pow_bits),
        final_folding_pow_bits=int(final_folding_pow_bits),
        valid=valid,
        invalid_reason=invalid_reason,
    )


# === MERKLE MULTIPROOF DEDUP MODEL ===
#
# The WHIR verifier uses deduplicated batched Merkle proofs (MerkleMultiProof).
# At each tree level the verifier maintains a sorted "frontier" of nodes.
# In-frontier sibling pairs merge directly (no decommitment needed); unpaired
# nodes consume one decommitment each. This gives probabilistic savings that
# depend on query density at each level.
#
# Expected distinct nodes at level l for nq random queries in a tree of depth d:
#   F(l) = M * (1 - (1 - 1/M)^nq),  M = 2^(d-l)
#
# Expected compress calls = sum_{l=1}^{d} F(l)   (one compress per parent)
# Expected decommitments  = sum_{l=0}^{d-1} max(0, 2·F(l+1) - F(l))  (unpaired count)
#
# Verified against Rust tests (adjacent_queries_share_nodes, full_opening_has_no_decommitments)
# and Solidity MerkleVerifier assembly loop (same frontier-swap algorithm).


def _expected_f(nq: int, depth: int) -> list:
    """Expected distinct nodes at each level [0..depth]."""
    f = []
    for l in range(depth + 1):
        m = 1 << (depth - l)
        if m == 0:
            f.append(0.0)
        elif nq >= m:
            f.append(float(m))
        else:
            f.append(m * (1.0 - (1.0 - 1.0 / m) ** nq))
    return f


def expected_merkle_compresses(nq: int, depth: int) -> float:
    """Expected total keccak compress calls in a deduplicated Merkle multiproof."""
    f = _expected_f(nq, depth)
    return sum(f[1:])


def expected_merkle_decommitments(nq: int, depth: int) -> float:
    """Expected decommitment count (sibling hashes) in a deduplicated multiproof."""
    f = _expected_f(nq, depth)
    return sum(max(0.0, 2 * f[l + 1] - f[l]) for l in range(depth))


# === GAS COST MODEL ===
#
# Sub-cost constants calibrated to the stage4 quartic typed verifier
# (`WhirVerifier4.testGasWhirVerifyFixed()`).
#
# Calibration point (current):
#   Constant(5), starting_log_inv_rate=11, rs_v=3
#   -> model: 957,712 execution gas
#   -> live stage4 baseline: 957,712 execution gas
#
# Phase-level measurements from GasCalibration.t.sol (testMeasurePhases):
#   Setup (pattern+commit+eval):   33,032
#   Initial sumcheck (5r):         31,097
#   Round0 parse:                  16,873
#   Round0 STIR (5q d22 base):    167,902  (fold=66,405, non-fold=101,497)
#   Round0 sumcheck (5r pow=10):   31,310
#   Observe finalPoly (64 ext4):   46,081  -> 720/element
#   Final STIR (4q d19 ext4):     243,229  (fold=77,570, hornerBase~31k, rest~135k)
#   Final sumcheck (6r pow=0):     32,295
#   Constraint round0 (nv=11):    96,044
#   Constraint initial (nv=16):    43,430
#   Final value check (64coeff):   87,021
#   Sum of phases:                828,314
#
# Constant costs (same for all schedules with NUM_VARIABLES=16):
#   sumcheck verification: 94,702 (always 16 rounds total)
#   setup + initial constraint + test harness: ~208k
#
# Known model limitations:
#   - STIR per-round constants (MERKLE_PER_COMPRESS, LEAF_HASH_*, FOLD_*) were
#     calibrated from a Constant(4) schedule. For ff=5 with dim5 kernels, fold
#     costs are ~10% lower per-op than the model predicts; Merkle/leaf costs
#     shift because base vs ext4 leaf hashing differs by ~2x. These errors
#     partially cancel within each round and roughly offset across rounds.
#   - Constraint constants are set to 50% of the generic-path micro-benchmark
#     values to split the difference between generic and specialized verifier
#     implementations. The generic path (current verifier) is underpredicted by
#     6.9% on the lir11 calibration point; a verifier with hand-optimized
#     constraint kernels (like the old C4/lir6 verifier) is overpredicted by
#     6.9% on its calibration point.
#   - For ranking (relative comparison), the model is well-suited: the uniform
#     constraint scaling preserves relative ordering, and the dominant
#     schedule-dependent costs (observe_final, final_value_eval, hornerBase,
#     constraint iterations) are modeled with direct measurements.
MERKLE_PER_COMPRESS = 1283
SAMPLE_PER_QUERY = 1050
OVERHEAD_PER_QUERY = 741
LEAF_HASH_BASE_PER_VALUE = 145
LEAF_HASH_EXT4_PER_VALUE = 229
LEAF_HASH_EXT8_PER_VALUE = 458  # coarse: ext8 rows double the packed bytes of ext4
FOLD_EXT4_PER_OP = 675
# ext8 STIR fold calibration:
#   the remaining ext8 fold-rate shape is still derived from the
#   k22/jb100/lir=6/ff=4/rs_v=1 octic family.
#   The full octic model is then anchored to the native verifier with the
#   native fixed rebate below.
#   With the current non-fold constants this implies ~8.16k gas per ext8 fold op.
FOLD_EXT8_PER_OP = 8115
# ext8 ff=4 combined row-kernel rebate:
#   the current octic family combines leaf hashing and row evaluation for
#   rowLen=16, so the model subtracts a per-query rebate instead of inflating
#   unrelated arithmetic constants
COMBINED_HASH_EVAL_REBATE_EXT8_DIM4 = 4252
# ext8 packed-frontier rebate:
#   the current octic family now uses a packed 20-byte-digest frontier
#   for STIR Merkle reduction instead of the older 64-byte {index, hash} entry
#   format, plus a single calldatacopy for row hashing.
PACKED_FRONTIER_REBATE_EXT8_DIM4 = 1387
# ext8 fixed-tail rebate:
#   the current octic family now uses schedule-specific raw final-constraint
#   evaluation instead of the generic Constraint[] walker, reducing measured gas
#   by ~30.6k on the fixed k22/jb100/lir=6/ff=4/rs_v=1 verifier path
CONSTRAINT_FIXED_REBATE_EXT8 = 30645
# ext8 transcript rebate:
#   the current octic family now uses specialized ext8 pair/slice transcript
#   observation, removing ~203.1k gas from the fixed k22/jb100/lir=6/ff=4/rs_v=1
#   verifier family relative to the old generic observeBase loop path.
TRANSCRIPT_FIXED_REBATE_EXT8 = 203059
# octic generic/specialized schedule calibration:
#   The current deployable ff=4 family has a hand-specialized native top level.
#   Unbenchmarked octic schedules do not automatically inherit that shape.
#   Two historical measured octic generic-native benchmark points were added to separate:
#     - generic native rebate present even on the generic ff=4 path
#     - generic native top-level overhead on the ff=4 schedule
#     - extra cost when rounds fall back to the generic STIR row/Merkle path
#       because they miss the optimized rowLen=16, ff=4 kernels.
#
#   Structural ff=4 model (after transcript rebate only): 9,065,576 gas
#   Generic ff=4 native: 8,249,508 gas
#     -> generic native rebate = 816,068 gas
#   Specialized ff=4 native: 7,865,125 gas
#     -> extra specialization rebate = 384,383 gas
#   Generic ff=4 native:
#     8,249,508 - 7,865,125 = 384,383 gas above the production specialized path.
#   Generic CFSR(4,3) native:
#     needs an additional 1,736,881 gas over generic ff=4 to match measurement.
#     That schedule has 50 fallback STIR/final-STIR queries, so the fitted
#     penalty is 34,738 gas per fallback query.
OCTIC_GENERIC_NATIVE_REBATE = 816_068
OCTIC_FALLBACK_STIR_PENALTY_PER_QUERY = 34_738
OCTIC_CURRENT_REFERENCE_SPECIALIZATION_REBATE = 384_383
FOLD_BASE_PROMOTE_PER_OP = 307
EVAL_POINT_POW_PER_DEPTH_BIT = 116
EVAL_POINT_POW_BASE = 0
GRINDING_CHECK_PER_BIT = 20
GRINDING_CHECK_BASE = 0
OOD_EXEC_PER_SAMPLE = 1000  # sample + observe + decode per OOD answer
# ABI calldata cost per uint256 slot (32 bytes):
# Base field (31-bit): 4 nonzero data bytes + 28 zero-padding = 4×16 + 28×4 = 176 gas
# Ext4 packed (4×31-bit in top 16 bytes): ~16 nonzero + 16 zero = 16×16 + 16×4 = 320 gas
BASE_VALUE_CD = 176  # per uint256 slot holding one base field element
EXT4_VALUE_CD = 320  # per uint256 slot holding one packed ext4 element
EXT8_VALUE_CD = 512  # ext8 uses the full 32-byte slot
# Merkle decommitment: bytes32 = 32 bytes, ~20 nonzero digest + 12 zero padding
# 20×16 + 12×4 = 368 gas per node
DECOMMIT_CD = 368
# Native octic blob calldata model (fit from three measured blobs):
#   - Constant(4), lir=6
#   - Constant(4), lir=5
#   - CFSR(4,3), lir=6
# The native blob path uses raw 4-byte base values, raw 32-byte ext8 values,
# raw 20-byte digests, and a compact schedule header, not ABI slot padding.
#
# Solving for per-item costs on those three measured blobs gives:
#   ext8 ~= 504.21 gas
#   base4 ~= 71.65 gas
#   digest20 ~= 313.92 gas
# Using expected Merkle decommitment counts instead of actual counts still keeps
# all three measured octic blob schedules within about 0.5-0.8% calldata error.
OCTIC_BLOB_EXT8_CD = 504.20759089734696
OCTIC_BLOB_BASE4_CD = 71.6533283328791
OCTIC_BLOB_DIGEST20_CD = 313.9249718370198
# --- Constraint evaluation ---
# Each non-final round evaluates (nq + ood_samples) constraint iterations,
# each iterating over numVariables dimensions (select-poly or eq-poly eval).
# Initial constraint evaluates (statementCount + commitmentOodSamples)
# iterations over NUM_VARIABLES dimensions (eq-poly only).
# Micro-benchmark values (generic path): PER_VAR=666, PER_ITER=6487.
# Compromise at 50% to fit both generic (current) and specialized (old)
# verifier implementations within ±7% error.
CONSTRAINT_PER_VAR = 333  # per variable per constraint iteration (compromise)
CONSTRAINT_PER_ITER = 3244  # per constraint iteration (compromise)
# --- Observe final polynomial: 2^fsr ext4 coefficients into challenger ---
# Measured: 64 elements -> 46,081 gas = 720 gas/element.
# Includes validation, byte-swap encoding, buffer writes.
OBSERVE_EXT4_PER_ELEMENT = 720
OBSERVE_EXT8_PER_ELEMENT = 928  # scaled from ext8/ext4 pack-unpack measurements
# --- Final value evaluation: evaluate 2^fsr ext4 coefficients at fsr-point
#     challenge via evaluateExtensionRowAsExt4.
#     For fsr <= 5: dispatches to hand-optimized dim-specific kernel.
#     For fsr > 5: falls through to generic path (memory alloc + evaluate_hypercube).
# Generic path constants (measured from fsr=6, 64 coefficients):
#   evaluate_hypercube: 72,085 gas for 63 fold ops -> 1,144/op
#   Array alloc + calldata copy: 14,208 gas for 64 values -> 222/value
#   Wrapper (mul + require): 728 gas
GENERIC_EVAL_WRAPPER = 728
GENERIC_EVAL_COPY_PER_VALUE = 222
GENERIC_EVAL_FOLD_PER_OP = 1144
# ext8 final-value evaluation calibration:
#   evaluate_hypercube(dim=6) = 670,264 gas on the current kernel path
#   modelled as wrapper + 64-value copy + 63 fold ops
GENERIC_EVAL_COPY_PER_VALUE_EXT8 = 240
GENERIC_EVAL_FOLD_PER_OP_EXT8 = 10384
# --- HornerBase: final STIR evaluates finalPoly at each query point.
#     hornerBase(finalPoly, point) costs ~121 gas per coefficient per query.
#     Total for final round: nq × 2^fsr × HORNER_BASE_PER_COEFF.
#     This cost is ONLY in the final round (non-final rounds use hornerStep
#     for constraint combine instead).
HORNER_BASE_PER_COEFF = 121
# --- Fixed overhead: constant costs that don't vary with the schedule.
#     Includes: setup (observePattern + parseCommitment + initial combine),
#     sumcheck verification (always NUM_VARIABLES total rounds),
#     test harness overhead (_loadSuccessFixture + ABI encode).
#     Adjusted upward from 173,813 to compensate for the 50% constraint
#     scaling so both calibration points stay within ±7%.
FIXED_OVERHEAD = 182000


def _is_current_octic_reference_schedule(cfg: WhirConfig) -> bool:
    if cfg.num_vars != 22:
        return False
    if cfg.ff_0 != 4 or cfg.ff_rest != 4:
        return False
    if cfg.rs_domain_initial_reduction_factor != 1:
        return False
    if cfg.final_sumcheck_rounds != 6:
        return False
    if len(cfg.round_parameters) != 4:
        return False
    if cfg.round_parameters[0].log_inv_rate != 6:
        return False
    if cfg.total_queries != 62:
        return False
    return all(r.folding_factor == 4 for r in cfg.round_parameters)


def octic_fallback_query_count(cfg: WhirConfig) -> int:
    """Queries that miss the optimized rowLen=16, ff=4 STIR kernels."""
    return sum(r.num_queries for r in cfg.round_parameters if r.folding_factor != 4)


def leaf_hash_per_query(ff: int, is_base: bool, extension_degree: int) -> int:
    leaf_count = 2**ff
    if is_base:
        rate = LEAF_HASH_BASE_PER_VALUE
    else:
        rate = (
            LEAF_HASH_EXT4_PER_VALUE
            if extension_degree == 4
            else LEAF_HASH_EXT8_PER_VALUE
        )
    return int(rate * leaf_count)


def fold_per_query(ff: int, is_base: bool, extension_degree: int) -> int:
    n_folds = 2**ff - 1
    ext_fold_rate = FOLD_EXT4_PER_OP if extension_degree == 4 else FOLD_EXT8_PER_OP
    if is_base:
        base_layer = 2 ** (ff - 1)
        ext_folds = n_folds - base_layer
        return int(base_layer * FOLD_BASE_PROMOTE_PER_OP + ext_folds * ext_fold_rate)
    else:
        return int(n_folds * ext_fold_rate)


def evaluation_point_pow_gas(depth: int) -> int:
    if depth == 0:
        return 0
    return int(EVAL_POINT_POW_PER_DEPTH_BIT * depth + EVAL_POINT_POW_BASE)


def grinding_check_gas(pow_bits: int) -> int:
    if pow_bits == 0:
        return 0
    return int(GRINDING_CHECK_PER_BIT * pow_bits + GRINDING_CHECK_BASE)


@dataclass
class GasBreakdown:
    stir: int = 0
    constraint: int = 0
    observe_final: int = 0
    final_value_eval: int = 0
    fixed: int = 0

    @property
    def total(self) -> int:
        return (
            self.stir
            + self.constraint
            + self.observe_final
            + self.final_value_eval
            + self.fixed
        )


def final_value_eval_gas(fsr: int, extension_degree: int) -> int:
    """Cost of evaluating 2^fsr ext4 coefficients at fsr-point challenge.

    For fsr <= 5: dispatches to hand-optimized kernel.
    For fsr > 5: generic path (memory alloc + evaluate_hypercube loop).
    """
    if fsr == 0:
        return 0
    if extension_degree == 4 and fsr <= 5:
        # Kernel path: same fold cost model as STIR row evaluation
        return fold_per_query(fsr, False, extension_degree) + GENERIC_EVAL_WRAPPER
    else:
        # Generic path. For ext8 this is the only modeled path and is intentionally
        # coarse; ext8 evaluate_hypercube dominates this family and should be
        # re-profiled at the exact verifier dimensions before trusting totals.
        n_values = 2**fsr
        n_folds = n_values - 1
        copy_per_value = (
            GENERIC_EVAL_COPY_PER_VALUE
            if extension_degree == 4
            else GENERIC_EVAL_COPY_PER_VALUE_EXT8
        )
        fold_per_op = (
            GENERIC_EVAL_FOLD_PER_OP
            if extension_degree == 4
            else GENERIC_EVAL_FOLD_PER_OP_EXT8
        )
        return (
            GENERIC_EVAL_WRAPPER
            + n_values * copy_per_value
            + n_folds * fold_per_op
        )


def octic_blob_header_gas(round_count: int, decommitment_counts: List[float]) -> int:
    header = bytearray()
    header.extend(b"WHRB")
    header.extend((1).to_bytes(2, "big"))
    header.extend(bytes([20, 8, round_count, 0x03]))
    for count in decommitment_counts:
        header.extend(int(round(count)).to_bytes(2, "big"))
    return sum(4 if b == 0 else 16 for b in header)


def estimate_execution_gas(
    cfg: WhirConfig, extension_degree: int = DEFAULT_EXTENSION_DEGREE
) -> GasBreakdown:
    stir = 0
    for r in cfg.round_parameters:
        nq = r.num_queries
        depth = r.depth
        merkle = int(expected_merkle_compresses(nq, depth) * MERKLE_PER_COMPRESS)
        leaf = leaf_hash_per_query(r.folding_factor, r.is_base, extension_degree) * nq
        fold = fold_per_query(r.folding_factor, r.is_base, extension_degree) * nq
        combined_rebate = (
            COMBINED_HASH_EVAL_REBATE_EXT8_DIM4 * nq
            if extension_degree == 8 and r.folding_factor == 4
            else 0
        )
        packed_frontier_rebate = (
            PACKED_FRONTIER_REBATE_EXT8_DIM4 * nq
            if extension_degree == 8 and r.folding_factor == 4
            else 0
        )
        sample = SAMPLE_PER_QUERY * nq
        oh = OVERHEAD_PER_QUERY * nq
        eval_pow = nq * evaluation_point_pow_gas(depth)
        grinding = grinding_check_gas(r.pow_bits) + grinding_check_gas(
            r.folding_pow_bits
        )
        stir += (
            merkle + leaf + fold + sample + oh + eval_pow + grinding
            - combined_rebate - packed_frontier_rebate
        )

        # Final round: hornerBase evaluates finalPoly at each query point
        if r.round_idx == "final":
            stir += nq * (2**cfg.final_sumcheck_rounds) * HORNER_BASE_PER_COEFF

    # Starting folding PoW (before any round)
    stir += grinding_check_gas(cfg.starting_folding_pow_bits)
    # Final folding PoW (after all rounds)
    stir += grinding_check_gas(cfg.final_folding_pow_bits)
    # Initial commitment OOD: sample challenge + observe answer per sample
    stir += cfg.commitment_ood_samples * OOD_EXEC_PER_SAMPLE
    # Per-round OOD: same ops (sample + observe) for each non-final round's ood_answers
    for r in cfg.round_parameters:
        if isinstance(r.round_idx, int):
            stir += r.ood_samples * OOD_EXEC_PER_SAMPLE

    constraint = 0
    for r in cfg.round_parameters:
        if isinstance(r.round_idx, int):
            iterations = r.num_queries + r.ood_samples
            constraint += iterations * (
                CONSTRAINT_PER_VAR * r.num_variables + CONSTRAINT_PER_ITER
            )
    # Initial constraint: (1 statement + commitmentOodSamples) eq-poly evals
    # over the full polynomial dimension
    initial_iters = 1 + cfg.commitment_ood_samples
    constraint += initial_iters * (
        CONSTRAINT_PER_VAR * cfg.num_vars + CONSTRAINT_PER_ITER
    )
    if extension_degree == 8:
        constraint -= CONSTRAINT_FIXED_REBATE_EXT8

    # Observe final polynomial: 2^fsr ext4 coefficients into challenger
    observe_rate = (
        OBSERVE_EXT4_PER_ELEMENT
        if extension_degree == 4
        else OBSERVE_EXT8_PER_ELEMENT
    )
    observe_final = (2**cfg.final_sumcheck_rounds) * observe_rate

    # Final value evaluation: evaluate 2^fsr coefficients at challenge point
    fve = final_value_eval_gas(cfg.final_sumcheck_rounds, extension_degree)

    fixed = FIXED_OVERHEAD - (TRANSCRIPT_FIXED_REBATE_EXT8 if extension_degree == 8 else 0)
    if extension_degree == 8:
        fixed -= OCTIC_GENERIC_NATIVE_REBATE
        stir += octic_fallback_query_count(cfg) * OCTIC_FALLBACK_STIR_PENALTY_PER_QUERY
        if _is_current_octic_reference_schedule(cfg):
            fixed -= OCTIC_CURRENT_REFERENCE_SPECIALIZATION_REBATE

    return GasBreakdown(
        stir=stir,
        constraint=constraint,
        observe_final=observe_final,
        final_value_eval=fve,
        fixed=fixed,
    )


def estimate_calldata_gas(
    cfg: WhirConfig, extension_degree: int = DEFAULT_EXTENSION_DEGREE
) -> int:
    """Estimate calldata cost in gas (16 gas/nonzero byte, 4 gas/zero byte)."""
    if extension_degree == 8:
        decommitment_counts = [
            expected_merkle_decommitments(r.num_queries, r.depth)
            for r in cfg.round_parameters
        ]

        ext8_count = cfg.num_vars + 1  # statement point + statement eval
        ext8_count += cfg.commitment_ood_samples
        ext8_count += cfg.ff_0 * 2  # initial sumcheck [c0, c2] per round

        base4_count = 0.0
        digest20_count = 1.0  # initial commitment

        for i, r in enumerate(cfg.round_parameters[:-1]):
            digest20_count += 1 + decommitment_counts[i]
            ext8_count += r.ood_samples

            next_sumcheck_rounds = (
                cfg.round_parameters[i + 1].folding_factor
                if i + 1 < len(cfg.round_parameters) - 1
                else cfg.round_parameters[-1].folding_factor
            )
            ext8_count += next_sumcheck_rounds * 2

            base4_count += 1  # round pow witness
            row_values = r.num_queries * (2**r.folding_factor)
            if i == 0:
                base4_count += row_values
            else:
                ext8_count += row_values

        final_round = cfg.round_parameters[-1]
        digest20_count += decommitment_counts[-1]
        base4_count += 1  # final pow witness
        ext8_count += 2**cfg.final_sumcheck_rounds  # final polynomial
        ext8_count += final_round.num_queries * (2**final_round.folding_factor)
        ext8_count += cfg.final_sumcheck_rounds * 2  # final sumcheck [c0, c2]

        header_gas = octic_blob_header_gas(
            len(cfg.round_parameters) - 1, decommitment_counts
        )

        total = (
            header_gas
            + ext8_count * OCTIC_BLOB_EXT8_CD
            + base4_count * OCTIC_BLOB_BASE4_CD
            + digest20_count * OCTIC_BLOB_DIGEST20_CD
        )
        return int(round(total))

    leaf_cd = 0
    merkle_cd = 0
    ext_value_cd = EXT4_VALUE_CD if extension_degree == 4 else EXT8_VALUE_CD
    for r in cfg.round_parameters:
        nq = r.num_queries
        depth = r.depth
        leaf_count = 2**r.folding_factor
        if r.is_base:
            leaf_cd += nq * leaf_count * BASE_VALUE_CD
        else:
            leaf_cd += nq * leaf_count * ext_value_cd
        merkle_cd += int(expected_merkle_decommitments(nq, depth) * DECOMMIT_CD)

    # OOD answers in calldata: initial + per-round, each packed ext4 → uint256
    ood_cd = cfg.commitment_ood_samples * ext_value_cd
    for r in cfg.round_parameters:
        if isinstance(r.round_idx, int):
            ood_cd += r.ood_samples * ext_value_cd

    # --- Schedule-dependent proof components ---
    # Initial sumcheck: ff_0 rounds, each sends [c0, c2] (2 ext4) + powWitness (1 base)
    sc_cd = cfg.ff_0 * 2 * ext_value_cd + cfg.ff_0 * BASE_VALUE_CD
    # Per non-final round: commitment (bytes32) + powWitness (base) + sumcheck
    # Sumcheck rounds = folding_factor.at_round(round+1), which is always ff_rest
    for r in cfg.round_parameters:
        if isinstance(r.round_idx, int):
            sc_cd += DECOMMIT_CD  # commitment bytes32
            sc_cd += BASE_VALUE_CD  # powWitness uint256
            sc_cd += cfg.ff_rest * 2 * ext_value_cd  # sumcheck polynomialEvals
            sc_cd += cfg.ff_rest * BASE_VALUE_CD  # sumcheck powWitnesses
    # Final poly: 2^final_sumcheck_rounds ext4 coefficients
    sc_cd += (2**cfg.final_sumcheck_rounds) * ext_value_cd
    # Final pow witness
    sc_cd += BASE_VALUE_CD
    # Final sumcheck (if final_sumcheck_rounds > 0): fsr rounds × (2 ext4 evals + 1 base pow)
    if cfg.final_sumcheck_rounds > 0:
        sc_cd += (
            cfg.final_sumcheck_rounds * 2 * ext_value_cd
            + cfg.final_sumcheck_rounds * BASE_VALUE_CD
        )
    # Initial commitment (bytes32)
    sc_cd += DECOMMIT_CD

    # Fixed ABI overhead: array-length words, struct offsets, booleans,
    # function selector, base tx cost (21000). Empirically ~25,000 gas.
    fixed_cd = 25000

    return leaf_cd + merkle_cd + ood_cd + sc_cd + fixed_cd


def _short_name(name: str, current_label: str = "") -> str:
    """Shorten config name for table display."""
    s = name.replace("ConstantFromSecondRound", "CFSR")
    s = s.replace(",starting_log_inv_rate=", ", lir=")
    s = s.replace(",rs_domain_initial_reduction_factor=", ", rs_v=")
    return s + (f" ◀ {current_label}" if current_label else "")


_CFG_W = 44  # config name column width


def _table_header(ranked: bool = True) -> str:
    """Return markdown-style table header + separator."""
    if ranked:
        h = (
            f"| {'#':>3} | {'Config':<{_CFG_W}} "
            f"| {'Rnds':>4} | {'Queries':>7} "
            f"| {'Exec':>9} | {'Calldata':>8} "
            f"| {'Total':>10} | {'Δ Total':>9} |"
        )
        s = f"|{'-' * 5}|{'-' * (_CFG_W + 2)}|{'-' * 6}|{'-' * 9}|{'-' * 11}|{'-' * 10}|{'-' * 12}|{'-' * 11}|"
    else:
        h = (
            f"| {'Config':<{_CFG_W}} "
            f"| {'Rnds':>4} | {'Queries':>7} "
            f"| {'Exec':>9} | {'Calldata':>8} "
            f"| {'Total':>10} | {'Δ Total':>9} |"
        )
        s = f"|{'-' * (_CFG_W + 2)}|{'-' * 6}|{'-' * 9}|{'-' * 11}|{'-' * 10}|{'-' * 12}|{'-' * 11}|"
    return h + "\n" + s


def _table_row(r: "SweepResult", base_total: int, rank: int = None) -> str:
    """Format one markdown-style table row."""
    d_total = r.total - base_total
    n_rnds = r.cfg.n_rounds + 1
    sn = _short_name(r.name, r.current_label)
    if rank is not None:
        return (
            f"| {rank:>3} | {sn:<{_CFG_W}} "
            f"| {n_rnds:>4} | {r.cfg.total_queries:>7} "
            f"| {r.ex.total:>9,} | {r.cd:>8,} "
            f"| {r.total:>10,} | {d_total:>+9,} |"
        )
    return (
        f"| {sn:<{_CFG_W}} "
        f"| {n_rnds:>4} | {r.cfg.total_queries:>7} "
        f"| {r.ex.total:>9,} | {r.cd:>8,} "
        f"| {r.total:>10,} | {d_total:>+9,} |"
    )


def _table_ellipsis_row() -> str:
    return (
        f"| {'...':>3} | {'...':<{_CFG_W}} "
        f"| {'...':>4} | {'...':>7} "
        f"| {'...':>9} | {'...':>8} "
        f"| {'...':>10} | {'...':>9} |"
    )


def make_config_name(
    ff_0: int, ff_rest: int, lir: int, rs_v: int
) -> str:
    """Build config name string from parameters."""
    if ff_0 == ff_rest:
        name = f"Constant({ff_0})"
    else:
        name = f"ConstantFromSecondRound({ff_0},{ff_rest})"
    name += f",starting_log_inv_rate={lir}"
    if rs_v != 1:
        name += f",rs_domain_initial_reduction_factor={rs_v}"
    return name


@dataclass
class SweepResult:
    name: str
    cfg: WhirConfig
    ex: GasBreakdown
    cd: int
    total: int
    group: str  # "Constant(4)", "Constant(5)", "ConstantFromSecondRound(...,4)", etc.
    params: Tuple[int, int, int, int]
    current_label: str = ""


def max_starting_log_inv_rate(
    num_vars: int, ff_0: int, sweep_cap: int = MAX_STARTING_LOG_INV_RATE
) -> int:
    """Largest starting_log_inv_rate allowed by validity and the chosen sweep cap."""
    return min(sweep_cap, TWO_ADICITY - num_vars + ff_0)


def print_sweep(
    num_vars: int = 16,
    security_level: int = DEFAULT_SECURITY_LEVEL,
    soundness: str = DEFAULT_SOUNDNESS,
    extension_degree: int = DEFAULT_EXTENSION_DEGREE,
    max_starting_log_inv_rate_cap: int = MAX_STARTING_LOG_INV_RATE,
):
    field_bits = FIELD_BITS_BY_EXTENSION[extension_degree]
    labeled_configs = []
    if (
        num_vars == 16
        and security_level == 80
        and soundness == "CapacityBound"
        and extension_degree == 4
    ):
        labeled_configs.extend(CURRENT_QUARTIC_CONFIGS)
    if (
        num_vars == 22
        and security_level == 100
        and soundness == "JohnsonBound"
        and extension_degree == 8
    ):
        labeled_configs.append(OCTIC_REFERENCE)
    mode_labels = {params: label for params, label in labeled_configs}

    print(
        f"WHIR Parameter Sweep — {num_vars} variables, {security_level}-bit security, "
        f"{soundness}, extension degree {extension_degree} ({field_bits}-bit)"
    )
    print(
        f"Max PoW: {MAX_POW_BITS} bits (31-bit prime field), "
        f"TWO_ADICITY: {TWO_ADICITY}"
    )
    print(
        "Note: rows below are Rust-valid schedule candidates. The model is calibrated "
        "on the quartic CapacityBound verifier families plus three historical octic "
        "JohnsonBound benchmark points: the current specialized production ff=4 verifier, "
        "a generic ff=4 native benchmark path, and a generic CFSR(4,3) native benchmark path. "
        "Treat the current octic reference row as exact for the current deployable "
        "verifier; treat other octic rows as generic-native estimates that include "
        "a penalty when rounds miss the optimized rowLen=16, ff=4 STIR kernels."
    )

    # --- Sweep parameter ranges ---
    # Sweep the full validity space instead of a curated subset.
    #
    # The full search space is:
    #   - num_vars = CLI/runtime input (default 16), not swept internally
    #   - Constant(ff): ff in [1, num_vars]
    #   - ConstantFromSecondRound(ff_0, ff_rest): 1 <= ff_rest < ff_0 <= num_vars
    #   - starting_log_inv_rate in [1, min(cap, TWO_ADICITY - num_vars + ff_0)]
    #     where cap defaults to 11 (the current hard sweep ceiling)
    #   - rs_domain_initial_reduction_factor (rs_v) in [1, ff_0]
    #
    # Additional filtering happens in derive_config():
    #   - log_folded_domain_size = num_vars + starting_log_inv_rate - ff_0 <= TWO_ADICITY
    #   - rs_domain_initial_reduction_factor <= ff_0
    #   - all derived PoW values must be <= MAX_POW_BITS
    MAX_POW = MAX_POW_BITS

    results: List[SweepResult] = []

    def try_config(ff_0: int, ff_rest: int, lir: int, rs_v: int, group: str):
        try:
            cfg = derive_config(
                num_vars,
                ff_0,
                ff_rest,
                lir,
                MAX_POW,
                security_level=security_level,
                field_bits=field_bits,
                soundness=soundness,
                rs_domain_initial_reduction_factor=rs_v,
            )
        except (AssertionError, ValueError):
            return
        if not cfg.valid:
            return
        params = (ff_0, ff_rest, lir, rs_v)
        current_label = mode_labels.get(params, "")
        name = make_config_name(ff_0, ff_rest, lir, rs_v)
        ex = estimate_execution_gas(cfg, extension_degree=extension_degree)
        cd = estimate_calldata_gas(cfg, extension_degree=extension_degree)
        total = ex.total + cd
        results.append(
            SweepResult(
                name=name,
                cfg=cfg,
                ex=ex,
                cd=cd,
                total=total,
                group=group,
                params=params,
                current_label=current_label,
            )
        )

    # 1. Constant(ff) — ff_0 == ff_rest
    for ff in range(1, num_vars + 1):
        group = f"Constant({ff})"
        max_lir = max_starting_log_inv_rate(num_vars, ff, max_starting_log_inv_rate_cap)
        if max_lir < 1:
            continue
        for lir in range(1, max_lir + 1):
            for rs_v in range(1, ff + 1):
                try_config(ff, ff, lir, rs_v, group)

    # 2. ConstantFromSecondRound(first_ff, rest_ff) — ff_0 > ff_rest
    for ff_rest in range(1, num_vars):
        for ff_0 in range(ff_rest + 1, num_vars + 1):
            group = f"ConstantFromSecondRound(*,{ff_rest})"
            max_lir = max_starting_log_inv_rate(
                num_vars, ff_0, max_starting_log_inv_rate_cap
            )
            if max_lir < 1:
                continue
            for lir in range(1, max_lir + 1):
                for rs_v in range(1, ff_0 + 1):
                    try_config(ff_0, ff_rest, lir, rs_v, group)

    if not results:
        print("\nNo valid configs found for this sweep.")
        return

    results.sort(key=lambda r: r.total)
    baseline_params = labeled_configs[0][0] if labeled_configs else results[0].params
    baseline_result = next(
        (r for r in results if r.params == baseline_params),
        results[0],
    )
    base_total = baseline_result.total

    # --- Print results grouped, sorted by total within each group ---
    seen_groups = []
    for r in results:
        if r.group not in seen_groups:
            seen_groups.append(r.group)

    for group in seen_groups:
        group_results = [r for r in results if r.group == group]
        group_results.sort(key=lambda r: r.total)

        print(f"\n### {group} ({len(group_results)} configs)\n")
        print(_table_header(ranked=True))
        for i, r in enumerate(group_results, 1):
            print(_table_row(r, base_total, rank=i))

    # --- Top-N overall ---
    top_n = 10
    print(f"\n### TOP {top_n} OVERALL (out of {len(results)} valid)\n")
    print(_table_header(ranked=True))
    for i, r in enumerate(results[:top_n], 1):
        print(_table_row(r, base_total, rank=i))

    pinned_current_rows = []
    for current_params, _label in labeled_configs:
        current_index = next(
            (i for i, r in enumerate(results, 1) if r.params == current_params), None
        )
        if current_index is not None and current_index > top_n:
            pinned_current_rows.append((current_index, results[current_index - 1]))

    if pinned_current_rows:
        print(_table_ellipsis_row())
        for current_index, current_result in pinned_current_rows:
            print(_table_row(current_result, base_total, rank=current_index))

    # Summary
    print(f"\n{'=' * 80}")
    print("NOTES:")
    print(f"{'=' * 80}")
    print(f"  • {len(results)} valid configs out of full sweep")
    print(
        f"  • soundness = {soundness}, extension degree = {extension_degree}, field bits = {field_bits}"
    )
    print(
        f"  • PoW budget = {MAX_POW_BITS} bits (31-bit prime field hard limit in challenger)"
    )
    print(f"  • Configs with derived PoW > {MAX_POW_BITS} are excluded (invalid)")
    print(
        f"  • starting_log_inv_rate is capped at {max_starting_log_inv_rate_cap} for this sweep"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="WHIR parameter sweep for EVM verifier gas"
    )
    parser.add_argument(
        "--num-vars", type=int, default=16, help="Number of variables (default: 16)"
    )
    parser.add_argument(
        "--security-level",
        type=int,
        default=DEFAULT_SECURITY_LEVEL,
        help=f"Security level in bits (default: {DEFAULT_SECURITY_LEVEL})",
    )
    parser.add_argument(
        "--soundness",
        choices=("UniqueDecoding", "JohnsonBound", "CapacityBound"),
        default=DEFAULT_SOUNDNESS,
        help=f"Soundness assumption (default: {DEFAULT_SOUNDNESS})",
    )
    parser.add_argument(
        "--extension-degree",
        type=int,
        choices=sorted(FIELD_BITS_BY_EXTENSION),
        default=DEFAULT_EXTENSION_DEGREE,
        help=f"Extension degree (default: {DEFAULT_EXTENSION_DEGREE})",
    )
    parser.add_argument(
        "--max-starting-log-inv-rate",
        type=int,
        default=MAX_STARTING_LOG_INV_RATE,
        help=(
            "starting_log_inv_rate sweep cap "
            f"(default: {MAX_STARTING_LOG_INV_RATE}, hard ceiling: "
            f"{MAX_STARTING_LOG_INV_RATE})"
        ),
    )
    args = parser.parse_args()
    print_sweep(
        args.num_vars,
        args.security_level,
        args.soundness,
        args.extension_degree,
        args.max_starting_log_inv_rate,
    )
