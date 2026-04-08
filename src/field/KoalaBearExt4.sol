// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {KoalaBear} from "./KoalaBear.sol";
import {KoalaBear} from "./KoalaBear.sol";

library KoalaBearExt4 {
    uint256 internal constant DEGREE = 4;
    uint256 internal constant COEFF_MASK = 0xffffffff;
    uint256 internal constant PACKED_MODULUS =
        (uint256(KoalaBear.MODULUS) << 224) |
            (uint256(KoalaBear.MODULUS) << 192) |
            (uint256(KoalaBear.MODULUS) << 160) |
            (uint256(KoalaBear.MODULUS) << 128);
    uint256 internal constant ONE = uint256(1) << 224;
    uint256 internal constant TWO = uint256(2) << 224;
    uint256 internal constant INV_TWO = 1_065_353_217;
    uint256 internal constant DTH_ROOT = 2_113_994_754;

    error BaseScalarOutOfRange(uint256 value);

    function pack(
        uint256[4] memory coeffs
    ) internal pure returns (uint256 packed) {
        unchecked {
            packed =
                (coeffs[0] << 224) |
                (coeffs[1] << 192) |
                (coeffs[2] << 160) |
                (coeffs[3] << 128);
        }
    }

    // TODO: Enforce `packed & ((1 << 128) - 1) == 0` for all externally supplied
    // quartic words at the ABI/validation boundary so non-canonical encodings are
    // rejected before they reach arithmetic helpers.
    function unpack(
        uint256 packed
    ) internal pure returns (uint256[4] memory coeffs) {
        require(packed & ((1 << 128) - 1) == 0, "LOW_BITS");
        coeffs[0] = packed >> 224;
        coeffs[1] = (packed >> 192) & COEFF_MASK;
        coeffs[2] = (packed >> 160) & COEFF_MASK;
        coeffs[3] = (packed >> 128) & COEFF_MASK;
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256 out) {
        assembly ("memory-safe") {
            let modulus := 0x7f000001
            let mask := 0xffffffff
            let sum := add(a, b)

            // Each lane sum ∈ [0, 2M-2]; mod gives the canonical reduction.
            out := or(
                or(
                    shl(224, mod(shr(224, sum), modulus)),
                    shl(192, mod(and(shr(192, sum), mask), modulus))
                ),
                or(
                    shl(160, mod(and(shr(160, sum), mask), modulus)),
                    shl(128, mod(and(shr(128, sum), mask), modulus))
                )
            )
        }
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256 out) {
        assembly ("memory-safe") {
            let modulus := 0x7f000001
            let mask := 0xffffffff
            let tmp := sub(
                add(
                    a,
                    0x7f0000017f0000017f0000017f00000100000000000000000000000000000000
                ),
                b
            )

            // Each lane ∈ [1, 2M-1]; mod gives the canonical reduction.
            out := or(
                or(
                    shl(224, mod(shr(224, tmp), modulus)),
                    shl(192, mod(and(shr(192, tmp), mask), modulus))
                ),
                or(
                    shl(160, mod(and(shr(160, tmp), mask), modulus)),
                    shl(128, mod(and(shr(128, tmp), mask), modulus))
                )
            )
        }
    }

    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        return _mul_packed(a, b);
    }

    function square(uint256 a) internal pure returns (uint256) {
        return _square_packed(a);
    }

    function fromBase(uint256 value) internal pure returns (uint256) {
        if (value >= KoalaBear.MODULUS) {
            revert BaseScalarOutOfRange(value);
        }
        return value << 224;
    }

    function mulBase(
        uint256 a,
        uint256 scalar
    ) internal pure returns (uint256) {
        if (scalar >= KoalaBear.MODULUS) {
            revert BaseScalarOutOfRange(scalar);
        }
        return _scalar_mul(a, scalar);
    }

    function inv(uint256 a) internal pure returns (uint256) {
        require(a != 0, "ZERO_INV");

        uint256 prodConj = _frobenius(a);
        for (uint256 i = 2; i < DEGREE; ++i) {
            prodConj = _frobenius(mul(prodConj, a));
        }

        uint256[4] memory lhs = unpack(a);
        uint256[4] memory rhs = unpack(prodConj);
        uint256 norm = _norm(lhs, rhs);

        return _scalar_mul(prodConj, KoalaBear.inv(norm));
    }

    function mul_by_w(uint256 a) internal pure returns (uint256) {
        return _scalar_mul(a, KoalaBear.W);
    }

    function extrapolate_012(
        uint256 e0,
        uint256 e1,
        uint256 e2,
        uint256 r
    ) internal pure returns (uint256) {
        return _extrapolate_012_fast(e0, e1, e2, r);
    }

    function extrapolate_012_reference(
        uint256 e0,
        uint256 e1,
        uint256 e2,
        uint256 r
    ) internal pure returns (uint256) {
        uint256 l0 = _scalar_mul(mul(sub(r, ONE), sub(r, TWO)), INV_TWO);
        uint256 l1 = mul(r, sub(TWO, r));
        uint256 l2 = _scalar_mul(mul(r, sub(r, ONE)), INV_TWO);
        return add(add(mul(e0, l0), mul(e1, l1)), mul(e2, l2));
    }

    function eq_poly_eval(
        uint256[] memory p,
        uint256[] memory q
    ) internal pure returns (uint256 acc) {
        require(p.length == q.length, "LEN");
        acc = ONE;

        unchecked {
            for (uint256 i = 0; i < p.length; ++i) {
                uint256 term = add(
                    ONE,
                    sub(sub(_scalar_mul(mul(p[i], q[i]), 2), p[i]), q[i])
                );
                acc = mul(acc, term);
            }
        }
    }

    function evaluate_hypercube(
        uint256[] memory evals,
        uint256[] memory point
    ) internal pure returns (uint256) {
        uint256 size = evals.length;
        require(size != 0 && _is_power_of_two(size), "BAD_EVALS");
        require(size == (uint256(1) << point.length), "DIM");

        if (point.length == 0) {
            return evals[0];
        }
        if (point.length == 1) {
            return _fold_once(evals[0], evals[1], point[0]);
        }
        if (point.length == 2) {
            uint256 l0 = _fold_once(evals[0], evals[2], point[0]);
            uint256 l1 = _fold_once(evals[1], evals[3], point[0]);
            return _fold_once(l0, l1, point[1]);
        }
        if (point.length == 3) {
            uint256 l0 = _fold_once(evals[0], evals[4], point[0]);
            uint256 l1 = _fold_once(evals[1], evals[5], point[0]);
            uint256 l2 = _fold_once(evals[2], evals[6], point[0]);
            uint256 l3 = _fold_once(evals[3], evals[7], point[0]);
            uint256 m0 = _fold_once(l0, l2, point[1]);
            uint256 m1 = _fold_once(l1, l3, point[1]);
            return _fold_once(m0, m1, point[2]);
        }
        if (point.length == 4) {
            uint256 l0 = _fold_once(evals[0], evals[8], point[0]);
            uint256 l1 = _fold_once(evals[1], evals[9], point[0]);
            uint256 l2 = _fold_once(evals[2], evals[10], point[0]);
            uint256 l3 = _fold_once(evals[3], evals[11], point[0]);
            uint256 l4 = _fold_once(evals[4], evals[12], point[0]);
            uint256 l5 = _fold_once(evals[5], evals[13], point[0]);
            uint256 l6 = _fold_once(evals[6], evals[14], point[0]);
            uint256 l7 = _fold_once(evals[7], evals[15], point[0]);
            uint256 m0 = _fold_once(l0, l4, point[1]);
            uint256 m1 = _fold_once(l1, l5, point[1]);
            uint256 m2 = _fold_once(l2, l6, point[1]);
            uint256 m3 = _fold_once(l3, l7, point[1]);
            uint256 n0 = _fold_once(m0, m2, point[2]);
            uint256 n1 = _fold_once(m1, m3, point[2]);
            return _fold_once(n0, n1, point[3]);
        }

        unchecked {
            for (uint256 i = 0; i < point.length; ++i) {
                size >>= 1;
                for (uint256 j = 0; j < size; ++j) {
                    evals[j] = _fold_once(evals[j], evals[j + size], point[i]);
                }
            }
        }

        return evals[0];
    }

    function _fold_once(
        uint256 a0,
        uint256 a1,
        uint256 r
    ) internal pure returns (uint256) {
        return add(a0, mul(r, sub(a1, a0)));
    }

    function _scalar_mul(
        uint256 a,
        uint256 scalar
    ) internal pure returns (uint256) {
        uint256[4] memory coeffs = unpack(a);

        unchecked {
            for (uint256 i = 0; i < DEGREE; ++i) {
                coeffs[i] = KoalaBear.mul(coeffs[i], scalar);
            }
        }

        return pack(coeffs);
    }

    function _frobenius(uint256 a) internal pure returns (uint256) {
        return _repeated_frobenius(a, 1);
    }

    function _repeated_frobenius(
        uint256 a,
        uint256 count
    ) internal pure returns (uint256) {
        uint256 power = count % DEGREE;
        if (power == 0) {
            return a;
        }

        uint256 z = KoalaBear.pow(DTH_ROOT, power);
        uint256 running = 1;
        uint256[4] memory coeffs = unpack(a);

        unchecked {
            for (uint256 i = 0; i < DEGREE; ++i) {
                coeffs[i] = KoalaBear.mul(coeffs[i], running);
                running = KoalaBear.mul(running, z);
            }
        }

        return pack(coeffs);
    }

    function _norm(
        uint256[4] memory a,
        uint256[4] memory b
    ) internal pure returns (uint256) {
        uint256 wCoeff;

        unchecked {
            for (uint256 i = 1; i < DEGREE; ++i) {
                wCoeff = KoalaBear.add(
                    wCoeff,
                    KoalaBear.mul(a[i], b[DEGREE - i])
                );
            }
        }

        return
            KoalaBear.add(
                KoalaBear.mul(a[0], b[0]),
                KoalaBear.mul(KoalaBear.W, wCoeff)
            );
    }

    function mul_reference(
        uint256 a,
        uint256 b
    ) internal pure returns (uint256) {
        return pack(_mul_coeffs_reference(unpack(a), unpack(b)));
    }

    function _mul_packed(
        uint256 a,
        uint256 b
    ) internal pure returns (uint256 out) {
        uint256 a0 = a >> 224;
        uint256 a1 = (a >> 192) & COEFF_MASK;
        uint256 a2 = (a >> 160) & COEFF_MASK;
        uint256 a3 = (a >> 128) & COEFF_MASK;
        uint256 b0 = b >> 224;
        uint256 b1 = (b >> 192) & COEFF_MASK;
        uint256 b2 = (b >> 160) & COEFF_MASK;
        uint256 b3 = (b >> 128) & COEFF_MASK;

        unchecked {
            uint256 c0 = a0 * b0 + KoalaBear.W * (a1 * b3 + a2 * b2 + a3 * b1);
            uint256 c1 = a0 * b1 + a1 * b0 + KoalaBear.W * (a2 * b3 + a3 * b2);
            uint256 c2 = a0 * b2 + a1 * b1 + a2 * b0 + KoalaBear.W * (a3 * b3);
            uint256 c3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0;

            c0 %= KoalaBear.MODULUS;
            c1 %= KoalaBear.MODULUS;
            c2 %= KoalaBear.MODULUS;
            c3 %= KoalaBear.MODULUS;

            out = (c0 << 224) | (c1 << 192) | (c2 << 160) | (c3 << 128);
        }
    }

    function _square_packed(uint256 a) internal pure returns (uint256 out) {
        uint256 a0 = a >> 224;
        uint256 a1 = (a >> 192) & COEFF_MASK;
        uint256 a2 = (a >> 160) & COEFF_MASK;
        uint256 a3 = (a >> 128) & COEFF_MASK;

        unchecked {
            uint256 a0a0 = a0 * a0;
            uint256 a0a1 = a0 * a1;
            uint256 a0a2 = a0 * a2;
            uint256 a0a3 = a0 * a3;
            uint256 a1a1 = a1 * a1;
            uint256 a1a2 = a1 * a2;
            uint256 a1a3 = a1 * a3;
            uint256 a2a2 = a2 * a2;
            uint256 a2a3 = a2 * a3;
            uint256 a3a3 = a3 * a3;

            uint256 c0 = a0a0 + KoalaBear.W * (a2a2 + (2 * a1a3));
            uint256 c1 = (2 * a0a1) + KoalaBear.W * (2 * a2a3);
            uint256 c2 = (2 * a0a2) + a1a1 + KoalaBear.W * a3a3;
            uint256 c3 = (2 * a0a3) + (2 * a1a2);

            c0 %= KoalaBear.MODULUS;
            c1 %= KoalaBear.MODULUS;
            c2 %= KoalaBear.MODULUS;
            c3 %= KoalaBear.MODULUS;

            out = (c0 << 224) | (c1 << 192) | (c2 << 160) | (c3 << 128);
        }
    }

    function _mul_coeffs_reference(
        uint256[4] memory a,
        uint256[4] memory b
    ) internal pure returns (uint256[4] memory out) {
        unchecked {
            for (uint256 i = 0; i < DEGREE; ++i) {
                for (uint256 j = 0; j < DEGREE; ++j) {
                    uint256 term = KoalaBear.mul(a[i], b[j]);
                    uint256 idx = i + j;
                    if (idx >= DEGREE) {
                        out[idx - DEGREE] = KoalaBear.add(
                            out[idx - DEGREE],
                            KoalaBear.mul(term, KoalaBear.W)
                        );
                    } else {
                        out[idx] = KoalaBear.add(out[idx], term);
                    }
                }
            }
        }
    }

    function _extrapolate_012_fast(
        uint256 e0,
        uint256 e1,
        uint256 e2,
        uint256 r
    ) internal pure returns (uint256) {
        uint256 q1Packed;
        uint256 q2Packed;

        // Branchless q1/q2 computation using constant biases.
        // q2 = (c0 + c2 - 2*c1) / 2 mod M  →  mulmod(c0+c2+2M - 2*c1, invTwo, M)
        // q1 = (4*c1 - c2 - 3*c0) / 2 mod M →  mulmod(4*c1+4M - c2 - 3*c0, invTwo, M)
        // The constant biases (2M, 4M) prevent underflow:
        //   q2 arg ∈ [2, 4M-2], q1 arg ∈ [4, 8M-4]. mulmod handles these.
        assembly ("memory-safe") {
            let M := 0x7f000001
            let mask := 0xffffffff
            let invTwo := 1065353217
            let twoM := 0xfe000002 // 2 * M
            let fourM := 0x1fc000004 // 4 * M

            // --- Lane 0 (bits 224-255) ---
            let c0 := shr(224, e0)
            let c1 := shr(224, e1)
            let c2 := shr(224, e2)

            q2Packed := shl(
                224,
                mulmod(sub(add(add(c0, c2), twoM), add(c1, c1)), invTwo, M)
            )
            q1Packed := shl(
                224,
                mulmod(
                    sub(add(shl(2, c1), fourM), add(c2, mul(c0, 3))),
                    invTwo,
                    M
                )
            )

            // --- Lane 1 (bits 192-223) ---
            c0 := and(shr(192, e0), mask)
            c1 := and(shr(192, e1), mask)
            c2 := and(shr(192, e2), mask)

            q2Packed := or(
                q2Packed,
                shl(
                    192,
                    mulmod(sub(add(add(c0, c2), twoM), add(c1, c1)), invTwo, M)
                )
            )
            q1Packed := or(
                q1Packed,
                shl(
                    192,
                    mulmod(
                        sub(add(shl(2, c1), fourM), add(c2, mul(c0, 3))),
                        invTwo,
                        M
                    )
                )
            )

            // --- Lane 2 (bits 160-191) ---
            c0 := and(shr(160, e0), mask)
            c1 := and(shr(160, e1), mask)
            c2 := and(shr(160, e2), mask)

            q2Packed := or(
                q2Packed,
                shl(
                    160,
                    mulmod(sub(add(add(c0, c2), twoM), add(c1, c1)), invTwo, M)
                )
            )
            q1Packed := or(
                q1Packed,
                shl(
                    160,
                    mulmod(
                        sub(add(shl(2, c1), fourM), add(c2, mul(c0, 3))),
                        invTwo,
                        M
                    )
                )
            )

            // --- Lane 3 (bits 128-159) ---
            c0 := and(shr(128, e0), mask)
            c1 := and(shr(128, e1), mask)
            c2 := and(shr(128, e2), mask)

            q2Packed := or(
                q2Packed,
                shl(
                    128,
                    mulmod(sub(add(add(c0, c2), twoM), add(c1, c1)), invTwo, M)
                )
            )
            q1Packed := or(
                q1Packed,
                shl(
                    128,
                    mulmod(
                        sub(add(shl(2, c1), fourM), add(c2, mul(c0, 3))),
                        invTwo,
                        M
                    )
                )
            )
        }

        return add(e0, mul(r, add(q1Packed, mul(r, q2Packed))));
    }

    function _is_power_of_two(uint256 x) internal pure returns (bool) {
        return x & (x - 1) == 0;
    }
}
