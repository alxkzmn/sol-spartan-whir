#!/usr/bin/env python3
"""Independent bounds and differential checks for packed quintic dot products.

Run with Python 3. The schoolbook oracle uses generic descending polynomial
reduction over Python integers. The candidate uses three integer MULMOD images
per element, followed by delayed coefficient reconstruction.
"""

import argparse
import json
import random

T = 1 << 16
B = 1 << 51
LANE_MASK = B - 1
K = 1 << 42
BIAS_WORD = K * sum(B**i for i in range(5))
WORD_MOD = 1 << 256


def pack(coeffs):
    return sum(x * B**i for i, x in enumerate(coeffs))


def split(value):
    lo = [x % T for x in value]
    hi = [x // T for x in value]
    return pack(lo), pack(hi), pack([a + b for a, b in zip(lo, hi)])


def reference_product(a, b, polynomial):
    coeffs = [0] * 9
    for i in range(5):
        for j in range(5):
            coeffs[i + j] += a[i] * b[j]
    for degree in range(8, 4, -1):
        top = coeffs[degree]
        for j in range(5):
            coeffs[degree - 5 + j] -= top * polynomial[j]
        coeffs[degree] = 0
    return coeffs[:5]


def reference_dot(left, right, p, polynomial):
    result = [0] * 5
    for a, b in zip(left, right):
        for i, value in enumerate(reference_product(a, b, polynomial)):
            result[i] += value
    return [value % p for value in result]


def candidate(left, right, p, baby):
    integer_modulus = B**5 - 2 if baby else B**5 + B**2 - 1
    accum = [0, 0, 0]
    for a, b in zip(left, right):
        aa, bb = split(a), split(b)
        for channel in range(3):
            product = (aa[channel] * bb[channel]) % integer_modulus
            if baby:
                accum[channel] += product
                assert accum[channel] < WORD_MOD
            else:
                # ADDMOD is needed here: a negative coefficient polynomial
                # has an integer residue close to the 255-bit modulus.
                accum[channel] = (accum[channel] + product) % integer_modulus
    if not baby:
        accum = [(value + BIAS_WORD) % integer_modulus for value in accum]
    result = []
    for i in range(5):
        lo, hi, summed = [(value >> (51 * i)) & LANE_MASK for value in accum]
        if baby:
            assert summed >= lo + hi
            value = lo + T * (summed - lo - hi) + T*T * hi
        else:
            # This positive expression can be evaluated without uint256
            # underflow. Its constant includes a multiple of the base prime.
            correction = (p << 64) + K * (T - 1 - T*T)
            positive = correction + lo + T * summed + T*T * hi
            subtraction = T * (lo + hi)
            assert 0 <= subtraction <= positive < WORD_MOD
            value = positive - subtraction
        result.append(value % p)
    assert all(0 <= x < p for x in result)
    return result


def check_bounds(p, baby):
    hi_max = (p - 1) // T
    low_max = T - 1
    sum_max = hi_max + low_max
    reduction_weight = 9 if baby else 6
    per_product = reduction_weight * sum_max**2
    per_batch = 16 * per_product
    assert per_product < B
    assert per_batch < B
    assert per_batch * sum(B**i for i in range(5)) < WORD_MOD
    if not baby:
        assert per_batch < K
        assert K + per_batch < B
        assert (K + per_batch) * sum(B**i for i in range(5)) < B**5 + B**2 - 1
    final_bound = 16 * reduction_weight * (p - 1)**2
    assert final_bound < 1 << 69
    return {
        "prime": p,
        "low_limb_max": low_max,
        "high_limb_max": hi_max,
        "sum_limb_max": sum_max,
        "per_product_coefficient_abs_bound": per_product,
        "batch_coefficient_abs_bound": per_batch,
        "reconstructed_coefficient_abs_bound": final_bound,
        "radix_bits": 51,
        "integer_modulus": hex(B**5 - 2 if baby else B**5 + B**2 - 1),
    }


def run_field(p, baby, random_cases, seed):
    polynomial = [-2, 0, 0, 0, 0, 1] if baby else [-1, 0, 1, 0, 0, 1]
    bounds = check_bounds(p, baby)
    cases = 0

    def check(left, right):
        nonlocal cases
        assert len(left) == len(right) <= 16
        assert all(0 <= x < p for rows in (left, right) for row in rows for x in row)
        expected = reference_dot(left, right, p, polynomial)
        actual = candidate(left, right, p, baby)
        assert actual == expected, (p, left, right, actual, expected)
        cases += 1

    boundaries = sorted(set(x for x in (
        0, 1, T-1, T, T+1, (1 << 30)-1, 1 << 30,
        ((p-1)//T-1)*T+T-1, p-2, p-1,
    ) if 0 <= x < p))
    # Includes all 25 basis-product pairs at unit and maximal scales, and
    # combinations exercising both high and low 16-bit split boundaries.
    for i in range(5):
        for j in range(5):
            for x in boundaries:
                for y in (1, T-1, p-1):
                    a, b = [0]*5, [0]*5
                    a[i], b[j] = x, y
                    check([a]*16, [b]*16)
    for x in boundaries:
        for y in boundaries:
            check([[x]*5]*16, [[y]*5]*16)
    for count in (1, 2, 4, 8, 15, 16):
        check([[p-1]*5]*count, [[p-1]*5]*count)
        check([[0, p-1, 0, p-1, 0]]*count, [[p-1, 0, p-1, 0, p-1]]*count)
    rng = random.Random(seed)
    for _ in range(random_cases):
        check([[rng.randrange(p) for _ in range(5)] for _ in range(16)],
              [[rng.randrange(p) for _ in range(5)] for _ in range(16)])
    return {"field": "BabyBear" if baby else "KoalaBear", "cases": cases,
            "random_16_term_cases": random_cases, "bounds": bounds}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--random-cases", type=int, default=1000)
    args = parser.parse_args()
    print(json.dumps({"status": "PASS", "seed": 20260905,
                      "results": [run_field(0x78000001, True, args.random_cases, 20260905),
                                  run_field(0x7f000001, False, args.random_cases, 20260906)]}, indent=2))
