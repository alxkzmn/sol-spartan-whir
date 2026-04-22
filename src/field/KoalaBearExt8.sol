// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { KoalaBear } from "./KoalaBear.sol";

library KoalaBearExt8 {
    uint256 internal constant DEGREE = 8;
    uint256 internal constant COEFF_MASK = 0xffffffff;
    uint256 internal constant ONE = uint256(1) << 224;
    uint256 internal constant TWO = uint256(2) << 224;
    uint256 internal constant INV_TWO = 1_065_353_217;
    uint256 internal constant DTH_ROOT = 1_748_172_362;

    error BaseScalarOutOfRange(uint256 value);

    function pack(uint256[8] memory coeffs) internal pure returns (uint256 packed) {
        unchecked {
            packed = (coeffs[0] << 224) | (coeffs[1] << 192) | (coeffs[2] << 160)
                | (coeffs[3] << 128) | (coeffs[4] << 96) | (coeffs[5] << 64) | (coeffs[6] << 32)
                | coeffs[7];
        }
    }

    function unpack(uint256 packed) internal pure returns (uint256[8] memory coeffs) {
        coeffs[0] = packed >> 224;
        coeffs[1] = (packed >> 192) & COEFF_MASK;
        coeffs[2] = (packed >> 160) & COEFF_MASK;
        coeffs[3] = (packed >> 128) & COEFF_MASK;
        coeffs[4] = (packed >> 96) & COEFF_MASK;
        coeffs[5] = (packed >> 64) & COEFF_MASK;
        coeffs[6] = (packed >> 32) & COEFF_MASK;
        coeffs[7] = packed & COEFF_MASK;
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256 out) {
        assembly ("memory-safe") {
            let modulus := 0x7f000001
            let mask := 0xffffffff
            let sum := add(a, b)

            out := or(
                or(
                    or(
                        shl(224, mod(shr(224, sum), modulus)),
                        shl(192, mod(and(shr(192, sum), mask), modulus))
                    ),
                    or(
                        shl(160, mod(and(shr(160, sum), mask), modulus)),
                        shl(128, mod(and(shr(128, sum), mask), modulus))
                    )
                ),
                or(
                    or(
                        shl(96, mod(and(shr(96, sum), mask), modulus)),
                        shl(64, mod(and(shr(64, sum), mask), modulus))
                    ),
                    or(shl(32, mod(and(shr(32, sum), mask), modulus)), mod(and(sum, mask), modulus))
                )
            )
        }
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256 out) {
        assembly ("memory-safe") {
            let modulus := 0x7f000001
            let mask := 0xffffffff
            let tmp :=
                sub(add(a, 0x7f0000017f0000017f0000017f0000017f0000017f0000017f0000017f000001), b)

            out := or(
                or(
                    or(
                        shl(224, mod(shr(224, tmp), modulus)),
                        shl(192, mod(and(shr(192, tmp), mask), modulus))
                    ),
                    or(
                        shl(160, mod(and(shr(160, tmp), mask), modulus)),
                        shl(128, mod(and(shr(128, tmp), mask), modulus))
                    )
                ),
                or(
                    or(
                        shl(96, mod(and(shr(96, tmp), mask), modulus)),
                        shl(64, mod(and(shr(64, tmp), mask), modulus))
                    ),
                    or(shl(32, mod(and(shr(32, tmp), mask), modulus)), mod(and(tmp, mask), modulus))
                )
            )
        }
    }

    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        return _mulPacked(a, b);
    }

    function mulReference(uint256 a, uint256 b) internal pure returns (uint256) {
        return pack(_mulCoeffsReference(unpack(a), unpack(b)));
    }

    function square(uint256 a) internal pure returns (uint256) {
        return _squarePacked(a);
    }

    function fromBase(uint256 value) internal pure returns (uint256) {
        if (value >= KoalaBear.MODULUS) {
            revert BaseScalarOutOfRange(value);
        }
        return value << 224;
    }

    function mulBase(uint256 a, uint256 scalar) internal pure returns (uint256) {
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

        uint256[8] memory lhs = unpack(a);
        uint256[8] memory rhs = unpack(prodConj);
        uint256 norm = _norm(lhs, rhs);

        return _scalar_mul(prodConj, KoalaBear.inv(norm));
    }

    function mul_by_w(uint256 a) internal pure returns (uint256) {
        return _scalar_mul(a, KoalaBear.W);
    }

    function extrapolate_012(uint256 e0, uint256 e1, uint256 e2, uint256 r)
        internal
        pure
        returns (uint256)
    {
        return _extrapolate012Fast(e0, e1, e2, r);
    }

    function extrapolate_012_from_sumcheck(uint256 c0, uint256 claimedEval, uint256 c2, uint256 r)
        internal
        pure
        returns (uint256)
    {
        return _extrapolate012FromSumcheckFast(c0, claimedEval, c2, r);
    }

    function extrapolate_012_reference(uint256 e0, uint256 e1, uint256 e2, uint256 r)
        internal
        pure
        returns (uint256)
    {
        uint256 l0 = _scalar_mul(mul(sub(r, ONE), sub(r, TWO)), INV_TWO);
        uint256 l1 = mul(r, sub(TWO, r));
        uint256 l2 = _scalar_mul(mul(r, sub(r, ONE)), INV_TWO);
        return add(add(mul(e0, l0), mul(e1, l1)), mul(e2, l2));
    }

    function eq_poly_eval(uint256[] memory p, uint256[] memory q)
        internal
        pure
        returns (uint256 acc)
    {
        require(p.length == q.length, "LEN");
        acc = ONE;

        unchecked {
            for (uint256 i = 0; i < p.length; ++i) {
                uint256 term = add(ONE, sub(sub(_scalar_mul(mul(p[i], q[i]), 2), p[i]), q[i]));
                acc = mul(acc, term);
            }
        }
    }

    function evaluate_hypercube(uint256[] memory evals, uint256[] memory point)
        internal
        pure
        returns (uint256)
    {
        uint256 size = evals.length;
        require(size != 0 && _isPowerOfTwo(size), "BAD_EVALS");
        require(size == (uint256(1) << point.length), "DIM");

        if (point.length == 0) {
            return evals[0];
        }
        if (point.length == 1) {
            evals[0] = _fold_once(evals[0], evals[1], point[0]);
            return evals[0];
        }
        if (point.length == 2) {
            uint256 r0 = point[0];
            evals[0] = _fold_once(evals[0], evals[2], r0);
            evals[1] = _fold_once(evals[1], evals[3], r0);
            evals[0] = _fold_once(evals[0], evals[1], point[1]);
            return evals[0];
        }
        if (point.length == 3) {
            uint256 r0 = point[0];
            for (uint256 i = 0; i < 4; ++i) {
                evals[i] = _fold_once(evals[i], evals[i + 4], r0);
            }
            uint256 r1 = point[1];
            for (uint256 i = 0; i < 2; ++i) {
                evals[i] = _fold_once(evals[i], evals[i + 2], r1);
            }
            evals[0] = _fold_once(evals[0], evals[1], point[2]);
            return evals[0];
        }
        if (point.length == 4) {
            uint256 r0 = point[0];
            for (uint256 i = 0; i < 8; ++i) {
                evals[i] = _fold_once(evals[i], evals[i + 8], r0);
            }
            uint256 r1 = point[1];
            for (uint256 i = 0; i < 4; ++i) {
                evals[i] = _fold_once(evals[i], evals[i + 4], r1);
            }
            uint256 r2 = point[2];
            for (uint256 i = 0; i < 2; ++i) {
                evals[i] = _fold_once(evals[i], evals[i + 2], r2);
            }
            evals[0] = _fold_once(evals[0], evals[1], point[3]);
            return evals[0];
        }
        if (point.length == 5) {
            uint256 r0 = point[0];
            for (uint256 i = 0; i < 16; ++i) {
                evals[i] = _fold_once(evals[i], evals[i + 16], r0);
            }
            uint256 r1 = point[1];
            for (uint256 i = 0; i < 8; ++i) {
                evals[i] = _fold_once(evals[i], evals[i + 8], r1);
            }
            uint256 r2 = point[2];
            for (uint256 i = 0; i < 4; ++i) {
                evals[i] = _fold_once(evals[i], evals[i + 4], r2);
            }
            uint256 r3 = point[3];
            for (uint256 i = 0; i < 2; ++i) {
                evals[i] = _fold_once(evals[i], evals[i + 2], r3);
            }
            evals[0] = _fold_once(evals[0], evals[1], point[4]);
            return evals[0];
        }
        if (point.length == 6) {
            uint256 r0 = point[0];
            for (uint256 i = 0; i < 32; ++i) {
                evals[i] = _fold_once(evals[i], evals[i + 32], r0);
            }
            uint256 r1 = point[1];
            for (uint256 i = 0; i < 16; ++i) {
                evals[i] = _fold_once(evals[i], evals[i + 16], r1);
            }
            uint256 r2 = point[2];
            for (uint256 i = 0; i < 8; ++i) {
                evals[i] = _fold_once(evals[i], evals[i + 8], r2);
            }
            uint256 r3 = point[3];
            for (uint256 i = 0; i < 4; ++i) {
                evals[i] = _fold_once(evals[i], evals[i + 4], r3);
            }
            uint256 r4 = point[4];
            for (uint256 i = 0; i < 2; ++i) {
                evals[i] = _fold_once(evals[i], evals[i + 2], r4);
            }
            evals[0] = _fold_once(evals[0], evals[1], point[5]);
            return evals[0];
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

    function _fold_once(uint256 a0, uint256 a1, uint256 r) internal pure returns (uint256 out) {
        assembly ("memory-safe") {
            let M := 0x7f000001
            let m := 0xffffffff

            let r0 := shr(224, r)
            let r1 := and(shr(192, r), m)
            let r2 := and(shr(160, r), m)
            let r3 := and(shr(128, r), m)
            let r4 := and(shr(96, r), m)
            let r5 := and(shr(64, r), m)
            let r6 := and(shr(32, r), m)
            let r7 := and(r, m)

            let a00 := shr(224, a0)
            let a01 := and(shr(192, a0), m)
            let a02 := and(shr(160, a0), m)
            let a03 := and(shr(128, a0), m)
            let a04 := and(shr(96, a0), m)
            let a05 := and(shr(64, a0), m)
            let a06 := and(shr(32, a0), m)
            let a07 := and(a0, m)

            let d0 := sub(add(shr(224, a1), M), a00)
            let d1 := sub(add(and(shr(192, a1), m), M), a01)
            let d2 := sub(add(and(shr(160, a1), m), M), a02)
            let d3 := sub(add(and(shr(128, a1), m), M), a03)
            let d4 := sub(add(and(shr(96, a1), m), M), a04)
            let d5 := sub(add(and(shr(64, a1), m), M), a05)
            let d6 := sub(add(and(shr(32, a1), m), M), a06)
            let d7 := sub(add(and(a1, m), M), a07)

            let s0 :=
                add(
                    add(add(mul(r1, d7), mul(r2, d6)), add(mul(r3, d5), mul(r4, d4))),
                    add(add(mul(r5, d3), mul(r6, d2)), mul(r7, d1))
                )
            let s1 :=
                add(
                    add(add(mul(r2, d7), mul(r3, d6)), add(mul(r4, d5), mul(r5, d4))),
                    add(mul(r6, d3), mul(r7, d2))
                )
            let s2 :=
                add(add(add(mul(r3, d7), mul(r4, d6)), add(mul(r5, d5), mul(r6, d4))), mul(r7, d3))
            let s3 := add(add(add(mul(r4, d7), mul(r5, d6)), mul(r6, d5)), mul(r7, d4))
            let s4 := add(add(mul(r5, d7), mul(r6, d6)), mul(r7, d5))
            let s5 := add(mul(r6, d7), mul(r7, d6))
            let s6 := mul(r7, d7)

            let c0 := mod(add(a00, add(mul(r0, d0), mul(3, s0))), M)
            let c1 := mod(add(a01, add(add(mul(r0, d1), mul(r1, d0)), mul(3, s1))), M)
            let c2 :=
                mod(add(a02, add(add(add(mul(r0, d2), mul(r1, d1)), mul(r2, d0)), mul(3, s2))), M)
            let c3 :=
                mod(
                    add(
                        a03,
                        add(
                            add(add(add(mul(r0, d3), mul(r1, d2)), mul(r2, d1)), mul(r3, d0)),
                            mul(3, s3)
                        )
                    ),
                    M
                )
            let c4 :=
                mod(
                    add(
                        a04,
                        add(
                            add(
                                add(add(add(mul(r0, d4), mul(r1, d3)), mul(r2, d2)), mul(r3, d1)),
                                mul(r4, d0)
                            ),
                            mul(3, s4)
                        )
                    ),
                    M
                )
            let c5 :=
                mod(
                    add(
                        a05,
                        add(
                            add(
                                add(
                                    add(
                                        add(add(mul(r0, d5), mul(r1, d4)), mul(r2, d3)),
                                        mul(r3, d2)
                                    ),
                                    mul(r4, d1)
                                ),
                                mul(r5, d0)
                            ),
                            mul(3, s5)
                        )
                    ),
                    M
                )
            let c6 :=
                mod(
                    add(
                        a06,
                        add(
                            add(
                                add(
                                    add(
                                        add(
                                            add(add(mul(r0, d6), mul(r1, d5)), mul(r2, d4)),
                                            mul(r3, d3)
                                        ),
                                        mul(r4, d2)
                                    ),
                                    mul(r5, d1)
                                ),
                                mul(r6, d0)
                            ),
                            mul(3, s6)
                        )
                    ),
                    M
                )
            let c7 :=
                mod(
                    add(
                        a07,
                        add(
                            add(
                                add(
                                    add(
                                        add(
                                            add(add(mul(r0, d7), mul(r1, d6)), mul(r2, d5)),
                                            mul(r3, d4)
                                        ),
                                        mul(r4, d3)
                                    ),
                                    mul(r5, d2)
                                ),
                                mul(r6, d1)
                            ),
                            mul(r7, d0)
                        )
                    ),
                    M
                )

            out := or(
                or(or(shl(224, c0), shl(192, c1)), or(shl(160, c2), shl(128, c3))),
                or(or(shl(96, c4), shl(64, c5)), or(shl(32, c6), c7))
            )
        }
    }

    function _scalar_mul(uint256 a, uint256 scalar) internal pure returns (uint256 out) {
        assembly ("memory-safe") {
            let modulus := 0x7f000001
            let mask := 0xffffffff

            out := or(
                or(
                    or(
                        shl(224, mulmod(shr(224, a), scalar, modulus)),
                        shl(192, mulmod(and(shr(192, a), mask), scalar, modulus))
                    ),
                    or(
                        shl(160, mulmod(and(shr(160, a), mask), scalar, modulus)),
                        shl(128, mulmod(and(shr(128, a), mask), scalar, modulus))
                    )
                ),
                or(
                    or(
                        shl(96, mulmod(and(shr(96, a), mask), scalar, modulus)),
                        shl(64, mulmod(and(shr(64, a), mask), scalar, modulus))
                    ),
                    or(
                        shl(32, mulmod(and(shr(32, a), mask), scalar, modulus)),
                        mulmod(and(a, mask), scalar, modulus)
                    )
                )
            )
        }
    }

    function _frobenius(uint256 a) internal pure returns (uint256) {
        return _repeated_frobenius(a, 1);
    }

    function _repeated_frobenius(uint256 a, uint256 count) internal pure returns (uint256) {
        uint256 power = count % DEGREE;
        if (power == 0) {
            return a;
        }

        uint256 z = KoalaBear.pow(DTH_ROOT, power);
        uint256 running = 1;
        uint256[8] memory coeffs = unpack(a);

        unchecked {
            for (uint256 i = 0; i < DEGREE; ++i) {
                coeffs[i] = KoalaBear.mul(coeffs[i], running);
                running = KoalaBear.mul(running, z);
            }
        }

        return pack(coeffs);
    }

    function _norm(uint256[8] memory a, uint256[8] memory b) internal pure returns (uint256) {
        uint256 wCoeff;

        unchecked {
            for (uint256 i = 1; i < DEGREE; ++i) {
                wCoeff = KoalaBear.add(wCoeff, KoalaBear.mul(a[i], b[DEGREE - i]));
            }
        }

        return KoalaBear.add(KoalaBear.mul(a[0], b[0]), KoalaBear.mul(KoalaBear.W, wCoeff));
    }

    function _mulPacked(uint256 a, uint256 b) internal pure returns (uint256 out) {
        uint256 a0 = a >> 224;
        uint256 a1 = (a >> 192) & COEFF_MASK;
        uint256 a2 = (a >> 160) & COEFF_MASK;
        uint256 a3 = (a >> 128) & COEFF_MASK;
        uint256 a4 = (a >> 96) & COEFF_MASK;
        uint256 a5 = (a >> 64) & COEFF_MASK;
        uint256 a6 = (a >> 32) & COEFF_MASK;
        uint256 a7 = a & COEFF_MASK;
        uint256 b0 = b >> 224;
        uint256 b1 = (b >> 192) & COEFF_MASK;
        uint256 b2 = (b >> 160) & COEFF_MASK;
        uint256 b3 = (b >> 128) & COEFF_MASK;
        uint256 b4 = (b >> 96) & COEFF_MASK;
        uint256 b5 = (b >> 64) & COEFF_MASK;
        uint256 b6 = (b >> 32) & COEFF_MASK;
        uint256 b7 = b & COEFF_MASK;

        unchecked {
            uint256 c0 =
                a0 * b0 + 3 * (a1 * b7 + a2 * b6 + a3 * b5 + a4 * b4 + a5 * b3 + a6 * b2 + a7 * b1);
            uint256 c1 =
                a0 * b1 + a1 * b0 + 3 * (a2 * b7 + a3 * b6 + a4 * b5 + a5 * b4 + a6 * b3 + a7 * b2);
            uint256 c2 =
                a0 * b2 + a1 * b1 + a2 * b0 + 3 * (a3 * b7 + a4 * b6 + a5 * b5 + a6 * b4 + a7 * b3);
            uint256 c3 =
                a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + 3 * (a4 * b7 + a5 * b6 + a6 * b5 + a7 * b4);
            uint256 c4 =
                a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0 + 3 * (a5 * b7 + a6 * b6 + a7 * b5);
            uint256 c5 =
                a0 * b5 + a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1 + a5 * b0 + 3 * (a6 * b7 + a7 * b6);
            uint256 c6 =
                a0 * b6 + a1 * b5 + a2 * b4 + a3 * b3 + a4 * b2 + a5 * b1 + a6 * b0 + 3 * (a7 * b7);
            uint256 c7 =
                a0 * b7 + a1 * b6 + a2 * b5 + a3 * b4 + a4 * b3 + a5 * b2 + a6 * b1 + a7 * b0;

            c0 %= KoalaBear.MODULUS;
            c1 %= KoalaBear.MODULUS;
            c2 %= KoalaBear.MODULUS;
            c3 %= KoalaBear.MODULUS;
            c4 %= KoalaBear.MODULUS;
            c5 %= KoalaBear.MODULUS;
            c6 %= KoalaBear.MODULUS;
            c7 %= KoalaBear.MODULUS;

            out = (c0 << 224) | (c1 << 192) | (c2 << 160) | (c3 << 128) | (c4 << 96) | (c5 << 64)
                | (c6 << 32) | c7;
        }
    }

    function _squarePacked(uint256 a) internal pure returns (uint256 out) {
        uint256 a0 = a >> 224;
        uint256 a1 = (a >> 192) & COEFF_MASK;
        uint256 a2 = (a >> 160) & COEFF_MASK;
        uint256 a3 = (a >> 128) & COEFF_MASK;
        uint256 a4 = (a >> 96) & COEFF_MASK;
        uint256 a5 = (a >> 64) & COEFF_MASK;
        uint256 a6 = (a >> 32) & COEFF_MASK;
        uint256 a7 = a & COEFF_MASK;

        unchecked {
            uint256 a0a0 = a0 * a0;
            uint256 a0a1 = a0 * a1;
            uint256 a0a2 = a0 * a2;
            uint256 a0a3 = a0 * a3;
            uint256 a0a4 = a0 * a4;
            uint256 a0a5 = a0 * a5;
            uint256 a0a6 = a0 * a6;
            uint256 a0a7 = a0 * a7;
            uint256 a1a1 = a1 * a1;
            uint256 a1a2 = a1 * a2;
            uint256 a1a3 = a1 * a3;
            uint256 a1a4 = a1 * a4;
            uint256 a1a5 = a1 * a5;
            uint256 a1a6 = a1 * a6;
            uint256 a1a7 = a1 * a7;
            uint256 a2a2 = a2 * a2;
            uint256 a2a3 = a2 * a3;
            uint256 a2a4 = a2 * a4;
            uint256 a2a5 = a2 * a5;
            uint256 a2a6 = a2 * a6;
            uint256 a2a7 = a2 * a7;
            uint256 a3a3 = a3 * a3;
            uint256 a3a4 = a3 * a4;
            uint256 a3a5 = a3 * a5;
            uint256 a3a6 = a3 * a6;
            uint256 a3a7 = a3 * a7;
            uint256 a4a4 = a4 * a4;
            uint256 a4a5 = a4 * a5;
            uint256 a4a6 = a4 * a6;
            uint256 a4a7 = a4 * a7;
            uint256 a5a5 = a5 * a5;
            uint256 a5a6 = a5 * a6;
            uint256 a5a7 = a5 * a7;
            uint256 a6a6 = a6 * a6;
            uint256 a6a7 = a6 * a7;
            uint256 a7a7 = a7 * a7;

            uint256 c0 = a0a0 + 3 * ((2 * a1a7) + (2 * a2a6) + (2 * a3a5) + a4a4);
            uint256 c1 = (2 * a0a1) + 3 * ((2 * a2a7) + (2 * a3a6) + (2 * a4a5));
            uint256 c2 = (2 * a0a2) + a1a1 + 3 * ((2 * a3a7) + (2 * a4a6) + a5a5);
            uint256 c3 = (2 * a0a3) + (2 * a1a2) + 3 * ((2 * a4a7) + (2 * a5a6));
            uint256 c4 = (2 * a0a4) + (2 * a1a3) + a2a2 + 3 * ((2 * a5a7) + a6a6);
            uint256 c5 = (2 * a0a5) + (2 * a1a4) + (2 * a2a3) + 3 * (2 * a6a7);
            uint256 c6 = (2 * a0a6) + (2 * a1a5) + (2 * a2a4) + a3a3 + 3 * a7a7;
            uint256 c7 = (2 * a0a7) + (2 * a1a6) + (2 * a2a5) + (2 * a3a4);

            c0 %= KoalaBear.MODULUS;
            c1 %= KoalaBear.MODULUS;
            c2 %= KoalaBear.MODULUS;
            c3 %= KoalaBear.MODULUS;
            c4 %= KoalaBear.MODULUS;
            c5 %= KoalaBear.MODULUS;
            c6 %= KoalaBear.MODULUS;
            c7 %= KoalaBear.MODULUS;

            out = (c0 << 224) | (c1 << 192) | (c2 << 160) | (c3 << 128) | (c4 << 96) | (c5 << 64)
                | (c6 << 32) | c7;
        }
    }

    function _mulCoeffsReference(uint256[8] memory a, uint256[8] memory b)
        internal
        pure
        returns (uint256[8] memory out)
    {
        unchecked {
            for (uint256 i = 0; i < DEGREE; ++i) {
                for (uint256 j = 0; j < DEGREE; ++j) {
                    uint256 term = KoalaBear.mul(a[i], b[j]);
                    uint256 idx = i + j;
                    if (idx >= DEGREE) {
                        out[idx - DEGREE] =
                            KoalaBear.add(out[idx - DEGREE], KoalaBear.mul(term, KoalaBear.W));
                    } else {
                        out[idx] = KoalaBear.add(out[idx], term);
                    }
                }
            }
        }
    }

    function _extrapolate012Fast(uint256 e0, uint256 e1, uint256 e2, uint256 r)
        internal
        pure
        returns (uint256)
    {
        uint256 q1Packed;
        uint256 q2Packed;

        assembly ("memory-safe") {
            let M := 0x7f000001
            let mask := 0xffffffff
            let invTwo := 1065353217
            let twoM := 0xfe000002
            let fourM := 0x1fc000004

            let c0 := shr(224, e0)
            let c1 := shr(224, e1)
            let c2 := shr(224, e2)
            q2Packed := shl(224, mulmod(sub(add(add(c0, c2), twoM), add(c1, c1)), invTwo, M))
            q1Packed := shl(
                224,
                mulmod(sub(add(shl(2, c1), fourM), add(c2, mul(c0, 3))), invTwo, M)
            )

            c0 := and(shr(192, e0), mask)
            c1 := and(shr(192, e1), mask)
            c2 := and(shr(192, e2), mask)
            q2Packed := or(
                q2Packed,
                shl(192, mulmod(sub(add(add(c0, c2), twoM), add(c1, c1)), invTwo, M))
            )
            q1Packed := or(
                q1Packed,
                shl(192, mulmod(sub(add(shl(2, c1), fourM), add(c2, mul(c0, 3))), invTwo, M))
            )

            c0 := and(shr(160, e0), mask)
            c1 := and(shr(160, e1), mask)
            c2 := and(shr(160, e2), mask)
            q2Packed := or(
                q2Packed,
                shl(160, mulmod(sub(add(add(c0, c2), twoM), add(c1, c1)), invTwo, M))
            )
            q1Packed := or(
                q1Packed,
                shl(160, mulmod(sub(add(shl(2, c1), fourM), add(c2, mul(c0, 3))), invTwo, M))
            )

            c0 := and(shr(128, e0), mask)
            c1 := and(shr(128, e1), mask)
            c2 := and(shr(128, e2), mask)
            q2Packed := or(
                q2Packed,
                shl(128, mulmod(sub(add(add(c0, c2), twoM), add(c1, c1)), invTwo, M))
            )
            q1Packed := or(
                q1Packed,
                shl(128, mulmod(sub(add(shl(2, c1), fourM), add(c2, mul(c0, 3))), invTwo, M))
            )

            c0 := and(shr(96, e0), mask)
            c1 := and(shr(96, e1), mask)
            c2 := and(shr(96, e2), mask)
            q2Packed := or(
                q2Packed,
                shl(96, mulmod(sub(add(add(c0, c2), twoM), add(c1, c1)), invTwo, M))
            )
            q1Packed := or(
                q1Packed,
                shl(96, mulmod(sub(add(shl(2, c1), fourM), add(c2, mul(c0, 3))), invTwo, M))
            )

            c0 := and(shr(64, e0), mask)
            c1 := and(shr(64, e1), mask)
            c2 := and(shr(64, e2), mask)
            q2Packed := or(
                q2Packed,
                shl(64, mulmod(sub(add(add(c0, c2), twoM), add(c1, c1)), invTwo, M))
            )
            q1Packed := or(
                q1Packed,
                shl(64, mulmod(sub(add(shl(2, c1), fourM), add(c2, mul(c0, 3))), invTwo, M))
            )

            c0 := and(shr(32, e0), mask)
            c1 := and(shr(32, e1), mask)
            c2 := and(shr(32, e2), mask)
            q2Packed := or(
                q2Packed,
                shl(32, mulmod(sub(add(add(c0, c2), twoM), add(c1, c1)), invTwo, M))
            )
            q1Packed := or(
                q1Packed,
                shl(32, mulmod(sub(add(shl(2, c1), fourM), add(c2, mul(c0, 3))), invTwo, M))
            )

            c0 := and(e0, mask)
            c1 := and(e1, mask)
            c2 := and(e2, mask)
            q2Packed := or(q2Packed, mulmod(sub(add(add(c0, c2), twoM), add(c1, c1)), invTwo, M))
            q1Packed := or(
                q1Packed,
                mulmod(sub(add(shl(2, c1), fourM), add(c2, mul(c0, 3))), invTwo, M)
            )
        }

        return add(e0, mul(r, add(q1Packed, mul(r, q2Packed))));
    }

    function _extrapolate012FromSumcheckFast(
        uint256 c0Packed,
        uint256 claimedPacked,
        uint256 c2Packed,
        uint256 r
    ) internal pure returns (uint256) {
        uint256 q1Packed;
        uint256 q2Packed;

        assembly ("memory-safe") {
            let M := 0x7f000001
            let mask := 0xffffffff
            let invTwo := 1065353217
            let twoM := 0xfe000002
            let eightM := 0x3f8000008

            let c0 := shr(224, c0Packed)
            let claim := shr(224, claimedPacked)
            let c2 := shr(224, c2Packed)
            q2Packed := shl(
                224,
                mulmod(sub(add(add(mul(c0, 3), c2), twoM), shl(1, claim)), invTwo, M)
            )
            q1Packed := shl(
                224,
                mulmod(sub(add(shl(2, claim), eightM), add(mul(c0, 7), c2)), invTwo, M)
            )

            c0 := and(shr(192, c0Packed), mask)
            claim := and(shr(192, claimedPacked), mask)
            c2 := and(shr(192, c2Packed), mask)
            q2Packed := or(
                q2Packed,
                shl(192, mulmod(sub(add(add(mul(c0, 3), c2), twoM), shl(1, claim)), invTwo, M))
            )
            q1Packed := or(
                q1Packed,
                shl(192, mulmod(sub(add(shl(2, claim), eightM), add(mul(c0, 7), c2)), invTwo, M))
            )

            c0 := and(shr(160, c0Packed), mask)
            claim := and(shr(160, claimedPacked), mask)
            c2 := and(shr(160, c2Packed), mask)
            q2Packed := or(
                q2Packed,
                shl(160, mulmod(sub(add(add(mul(c0, 3), c2), twoM), shl(1, claim)), invTwo, M))
            )
            q1Packed := or(
                q1Packed,
                shl(160, mulmod(sub(add(shl(2, claim), eightM), add(mul(c0, 7), c2)), invTwo, M))
            )

            c0 := and(shr(128, c0Packed), mask)
            claim := and(shr(128, claimedPacked), mask)
            c2 := and(shr(128, c2Packed), mask)
            q2Packed := or(
                q2Packed,
                shl(128, mulmod(sub(add(add(mul(c0, 3), c2), twoM), shl(1, claim)), invTwo, M))
            )
            q1Packed := or(
                q1Packed,
                shl(128, mulmod(sub(add(shl(2, claim), eightM), add(mul(c0, 7), c2)), invTwo, M))
            )

            c0 := and(shr(96, c0Packed), mask)
            claim := and(shr(96, claimedPacked), mask)
            c2 := and(shr(96, c2Packed), mask)
            q2Packed := or(
                q2Packed,
                shl(96, mulmod(sub(add(add(mul(c0, 3), c2), twoM), shl(1, claim)), invTwo, M))
            )
            q1Packed := or(
                q1Packed,
                shl(96, mulmod(sub(add(shl(2, claim), eightM), add(mul(c0, 7), c2)), invTwo, M))
            )

            c0 := and(shr(64, c0Packed), mask)
            claim := and(shr(64, claimedPacked), mask)
            c2 := and(shr(64, c2Packed), mask)
            q2Packed := or(
                q2Packed,
                shl(64, mulmod(sub(add(add(mul(c0, 3), c2), twoM), shl(1, claim)), invTwo, M))
            )
            q1Packed := or(
                q1Packed,
                shl(64, mulmod(sub(add(shl(2, claim), eightM), add(mul(c0, 7), c2)), invTwo, M))
            )

            c0 := and(shr(32, c0Packed), mask)
            claim := and(shr(32, claimedPacked), mask)
            c2 := and(shr(32, c2Packed), mask)
            q2Packed := or(
                q2Packed,
                shl(32, mulmod(sub(add(add(mul(c0, 3), c2), twoM), shl(1, claim)), invTwo, M))
            )
            q1Packed := or(
                q1Packed,
                shl(32, mulmod(sub(add(shl(2, claim), eightM), add(mul(c0, 7), c2)), invTwo, M))
            )

            c0 := and(c0Packed, mask)
            claim := and(claimedPacked, mask)
            c2 := and(c2Packed, mask)
            q2Packed := or(
                q2Packed,
                mulmod(sub(add(add(mul(c0, 3), c2), twoM), shl(1, claim)), invTwo, M)
            )
            q1Packed := or(
                q1Packed,
                mulmod(sub(add(shl(2, claim), eightM), add(mul(c0, 7), c2)), invTwo, M)
            )
        }

        return add(c0Packed, mul(r, add(q1Packed, mul(r, q2Packed))));
    }

    function _isPowerOfTwo(uint256 x) internal pure returns (bool) {
        return x & (x - 1) == 0;
    }
}
