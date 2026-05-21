// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { KoalaBear } from "./KoalaBear.sol";

library KoalaBearExt5 {
    uint256 internal constant DEGREE = 5;
    uint256 internal constant COEFF_MASK = 0xffffffff;
    uint256 internal constant ONE = uint256(1) << 224;
    uint256 internal constant TWO = uint256(2) << 224;
    uint256 internal constant INV_TWO = 1_065_353_217;
    uint256 internal constant LOW_96_MASK = (uint256(1) << 96) - 1;
    uint256 internal constant PACKED_HIGH_BIT = uint256(0x80000000) << 224
        | (uint256(0x80000000) << 192) | (uint256(0x80000000) << 160) | (uint256(0x80000000) << 128)
        | (uint256(0x80000000) << 96);
    uint256 internal constant PACKED_LOW_31 = uint256(0x7fffffff) << 224
        | (uint256(0x7fffffff) << 192) | (uint256(0x7fffffff) << 160) | (uint256(0x7fffffff) << 128)
        | (uint256(0x7fffffff) << 96);
    uint256 internal constant PACKED_CANONICAL_BIAS = uint256(0x00ffffff) << 224
        | (uint256(0x00ffffff) << 192) | (uint256(0x00ffffff) << 160) | (uint256(0x00ffffff) << 128)
        | (uint256(0x00ffffff) << 96);

    error BaseScalarOutOfRange(uint256 value);
    error PackedExtensionElementOutOfRange(uint256 value);

    function pack(uint256[5] memory coeffs) internal pure returns (uint256 packed) {
        unchecked {
            packed = (coeffs[0] << 224) | (coeffs[1] << 192) | (coeffs[2] << 160)
                | (coeffs[3] << 128) | (coeffs[4] << 96);
        }
    }

    function unpack(uint256 packed) internal pure returns (uint256[5] memory coeffs) {
        coeffs[0] = packed >> 224;
        coeffs[1] = (packed >> 192) & COEFF_MASK;
        coeffs[2] = (packed >> 160) & COEFF_MASK;
        coeffs[3] = (packed >> 128) & COEFF_MASK;
        coeffs[4] = (packed >> 96) & COEFF_MASK;
    }

    function validatePacked(uint256 packed) internal pure {
        unchecked {
            uint256 invalidHighBits = packed & PACKED_HIGH_BIT;
            uint256 invalidLow31 =
                ((packed & PACKED_LOW_31) + PACKED_CANONICAL_BIAS) & PACKED_HIGH_BIT;
            if (((packed & LOW_96_MASK) | invalidHighBits | invalidLow31) == 0) {
                return;
            }
            revert PackedExtensionElementOutOfRange(packed);
        }
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256 out) {
        assembly ("memory-safe") {
            let modulus := 0x7f000001
            let sum := add(a, b)
            let highBits :=
                and(
                    add(sum, 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000),
                    0x8000000080000000800000008000000080000000000000000000000000000000
                )
            out := and(
                sub(sum, mul(shr(31, highBits), modulus)),
                0xffffffffffffffffffffffffffffffffffffffff000000000000000000000000
            )
        }
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256 out) {
        assembly ("memory-safe") {
            let modulus := 0x7f000001
            let tmp :=
                sub(add(a, 0x7f0000017f0000017f0000017f0000017f000001000000000000000000000000), b)
            let highBits :=
                and(
                    add(tmp, 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000),
                    0x8000000080000000800000008000000080000000000000000000000000000000
                )
            out := and(
                sub(tmp, mul(shr(31, highBits), modulus)),
                0xffffffffffffffffffffffffffffffffffffffff000000000000000000000000
            )
        }
    }

    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        return _mulPacked(a, b);
    }

    function mulReference(uint256 a, uint256 b) internal pure returns (uint256) {
        return pack(_mulCoeffs(unpack(a), unpack(b)));
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
        return _scalarMul(a, scalar);
    }

    /// @dev Gaussian-elimination fallback. Keep this out of verifier hot paths unless re-profiled.
    function inv(uint256 a) internal pure returns (uint256) {
        require(a != 0, "ZERO_INV");
        uint256[5] memory coeffs = unpack(a);
        uint256[5][5] memory mat;
        uint256[5] memory rhs;
        rhs[0] = 1;

        unchecked {
            for (uint256 col = 0; col < DEGREE; ++col) {
                uint256[5] memory basis;
                basis[col] = 1;
                uint256[5] memory product = _mulCoeffs(coeffs, basis);
                for (uint256 row = 0; row < DEGREE; ++row) {
                    mat[row][col] = product[row];
                }
            }

            for (uint256 pivot = 0; pivot < DEGREE; ++pivot) {
                uint256 pivotRow = pivot;
                while (pivotRow < DEGREE && mat[pivotRow][pivot] == 0) {
                    ++pivotRow;
                }
                require(pivotRow < DEGREE, "SINGULAR");

                if (pivotRow != pivot) {
                    for (uint256 col = pivot; col < DEGREE; ++col) {
                        (mat[pivot][col], mat[pivotRow][col]) =
                        (mat[pivotRow][col], mat[pivot][col]);
                    }
                    (rhs[pivot], rhs[pivotRow]) = (rhs[pivotRow], rhs[pivot]);
                }

                uint256 invPivot = KoalaBear.inv(mat[pivot][pivot]);
                for (uint256 col = pivot; col < DEGREE; ++col) {
                    mat[pivot][col] = KoalaBear.mul(mat[pivot][col], invPivot);
                }
                rhs[pivot] = KoalaBear.mul(rhs[pivot], invPivot);

                for (uint256 row = 0; row < DEGREE; ++row) {
                    if (row == pivot) {
                        continue;
                    }
                    uint256 factor = mat[row][pivot];
                    if (factor == 0) {
                        continue;
                    }
                    for (uint256 col = pivot; col < DEGREE; ++col) {
                        mat[row][col] =
                            KoalaBear.sub(mat[row][col], KoalaBear.mul(factor, mat[pivot][col]));
                    }
                    rhs[row] = KoalaBear.sub(rhs[row], KoalaBear.mul(factor, rhs[pivot]));
                }
            }
        }

        return pack(rhs);
    }

    function extrapolate_012(uint256 e0, uint256 e1, uint256 e2, uint256 r)
        internal
        pure
        returns (uint256)
    {
        return _extrapolate012Fast(e0, e1, e2, r);
    }

    function extrapolate_012_reference(uint256 e0, uint256 e1, uint256 e2, uint256 r)
        internal
        pure
        returns (uint256)
    {
        uint256 l0 = _scalarMul(mul(sub(r, ONE), sub(r, TWO)), INV_TWO);
        uint256 l1 = mul(r, sub(TWO, r));
        uint256 l2 = _scalarMul(mul(r, sub(r, ONE)), INV_TWO);
        return add(add(mul(e0, l0), mul(e1, l1)), mul(e2, l2));
    }

    function extrapolate_012_from_sumcheck(uint256 c0, uint256 claimedEval, uint256 c2, uint256 r)
        internal
        pure
        returns (uint256)
    {
        return extrapolate_012(c0, sub(claimedEval, c0), c2, r);
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
                uint256 term = add(ONE, sub(sub(_scalarMul(mul(p[i], q[i]), 2), p[i]), q[i]));
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
        require(size != 0 && (size & (size - 1)) == 0, "BAD_EVALS");
        require(size == (uint256(1) << point.length), "DIM");

        unchecked {
            for (uint256 i = 0; i < point.length; ++i) {
                size >>= 1;
                for (uint256 j = 0; j < size; ++j) {
                    evals[j] = _foldOnce(evals[j], evals[j + size], point[i]);
                }
            }
        }

        return evals[0];
    }

    function _foldOnce(uint256 a0, uint256 a1, uint256 r) internal pure returns (uint256) {
        return add(a0, mul(r, sub(a1, a0)));
    }

    function _scalarMul(uint256 a, uint256 scalar) private pure returns (uint256) {
        uint256 out;
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
                shl(96, mulmod(and(shr(96, a), mask), scalar, modulus))
            )
        }
        return out;
    }

    function _mulPacked(uint256 a, uint256 b) private pure returns (uint256 out) {
        assembly ("memory-safe") {
            let M := 0x7f000001
            let mask := 0xffffffff

            let a0 := shr(224, a)
            let a1 := and(shr(192, a), mask)
            let a2 := and(shr(160, a), mask)
            let a3 := and(shr(128, a), mask)
            let a4 := and(shr(96, a), mask)

            let b0 := shr(224, b)
            let b1 := and(shr(192, b), mask)
            let b2 := and(shr(160, b), mask)
            let b3 := and(shr(128, b), mask)
            let b4 := and(shr(96, b), mask)

            let c0 := mul(a0, b0)
            let c1 := add(mul(a0, b1), mul(a1, b0))
            let c2 := add(add(mul(a0, b2), mul(a1, b1)), mul(a2, b0))
            let c3 := add(add(add(mul(a0, b3), mul(a1, b2)), mul(a2, b1)), mul(a3, b0))
            let c4 :=
                add(add(add(add(mul(a0, b4), mul(a1, b3)), mul(a2, b2)), mul(a3, b1)), mul(a4, b0))
            let c5 := add(add(add(mul(a1, b4), mul(a2, b3)), mul(a3, b2)), mul(a4, b1))
            let c6 := add(add(mul(a2, b4), mul(a3, b3)), mul(a4, b2))
            let c7 := add(mul(a3, b4), mul(a4, b3))
            let c8 := mul(a4, b4)
            let bias := shl(35, M)

            out := or(
                or(
                    or(
                        shl(224, mod(add(add(c0, c5), sub(bias, c8)), M)),
                        shl(192, mod(add(c1, c6), M))
                    ),
                    or(
                        shl(160, mod(add(add(add(c2, sub(bias, c5)), c7), c8), M)),
                        shl(128, mod(add(add(c3, sub(bias, c6)), c8), M))
                    )
                ),
                shl(96, mod(add(c4, sub(bias, c7)), M))
            )
        }
    }

    function _squarePacked(uint256 a) private pure returns (uint256 out) {
        assembly ("memory-safe") {
            let M := 0x7f000001
            let mask := 0xffffffff

            let a0 := shr(224, a)
            let a1 := and(shr(192, a), mask)
            let a2 := and(shr(160, a), mask)
            let a3 := and(shr(128, a), mask)
            let a4 := and(shr(96, a), mask)

            let a0a0 := mul(a0, a0)
            let a0a1 := mul(a0, a1)
            let a0a2 := mul(a0, a2)
            let a0a3 := mul(a0, a3)
            let a0a4 := mul(a0, a4)
            let a1a1 := mul(a1, a1)
            let a1a2 := mul(a1, a2)
            let a1a3 := mul(a1, a3)
            let a1a4 := mul(a1, a4)
            let a2a2 := mul(a2, a2)
            let a2a3 := mul(a2, a3)
            let a2a4 := mul(a2, a4)
            let a3a3 := mul(a3, a3)
            let a3a4 := mul(a3, a4)
            let a4a4 := mul(a4, a4)

            let c0 := a0a0
            let c1 := shl(1, a0a1)
            let c2 := add(shl(1, a0a2), a1a1)
            let c3 := add(shl(1, a0a3), shl(1, a1a2))
            let c4 := add(add(shl(1, a0a4), shl(1, a1a3)), a2a2)
            let c5 := add(shl(1, a1a4), shl(1, a2a3))
            let c6 := add(shl(1, a2a4), a3a3)
            let c7 := shl(1, a3a4)
            let c8 := a4a4
            let bias := shl(35, M)

            out := or(
                or(
                    or(
                        shl(224, mod(add(add(c0, c5), sub(bias, c8)), M)),
                        shl(192, mod(add(c1, c6), M))
                    ),
                    or(
                        shl(160, mod(add(add(add(c2, sub(bias, c5)), c7), c8), M)),
                        shl(128, mod(add(add(c3, sub(bias, c6)), c8), M))
                    )
                ),
                shl(96, mod(add(c4, sub(bias, c7)), M))
            )
        }
    }

    function _extrapolate012Fast(uint256 e0, uint256 e1, uint256 e2, uint256 r)
        private
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
        }

        return add(e0, mul(r, add(q1Packed, mul(r, q2Packed))));
    }

    function _mulCoeffs(uint256[5] memory a, uint256[5] memory b)
        private
        pure
        returns (uint256[5] memory out)
    {
        uint256 c0 = KoalaBear.mul(a[0], b[0]);
        uint256 c1 = _sum2(a[0], b[1], a[1], b[0]);
        uint256 c2 = _sum3(a[0], b[2], a[1], b[1], a[2], b[0]);
        uint256 c3 = _sum4(a[0], b[3], a[1], b[2], a[2], b[1], a[3], b[0]);
        uint256 c4 = _sum5(a[0], b[4], a[1], b[3], a[2], b[2], a[3], b[1], a[4], b[0]);
        uint256 c5 = _sum4(a[1], b[4], a[2], b[3], a[3], b[2], a[4], b[1]);
        uint256 c6 = _sum3(a[2], b[4], a[3], b[3], a[4], b[2]);
        uint256 c7 = _sum2(a[3], b[4], a[4], b[3]);
        uint256 c8 = KoalaBear.mul(a[4], b[4]);
        uint256 c5MinusC8 = KoalaBear.sub(c5, c8);

        out[0] = KoalaBear.add(c0, c5MinusC8);
        out[1] = KoalaBear.add(c1, c6);
        out[2] = KoalaBear.add(KoalaBear.sub(c2, c5MinusC8), c7);
        out[3] = KoalaBear.add(KoalaBear.sub(c3, c6), c8);
        out[4] = KoalaBear.sub(c4, c7);
    }

    function _sum2(uint256 a0, uint256 b0, uint256 a1, uint256 b1) private pure returns (uint256) {
        return KoalaBear.add(KoalaBear.mul(a0, b0), KoalaBear.mul(a1, b1));
    }

    function _sum3(uint256 a0, uint256 b0, uint256 a1, uint256 b1, uint256 a2, uint256 b2)
        private
        pure
        returns (uint256)
    {
        return KoalaBear.add(_sum2(a0, b0, a1, b1), KoalaBear.mul(a2, b2));
    }

    function _sum4(
        uint256 a0,
        uint256 b0,
        uint256 a1,
        uint256 b1,
        uint256 a2,
        uint256 b2,
        uint256 a3,
        uint256 b3
    ) private pure returns (uint256) {
        return KoalaBear.add(_sum2(a0, b0, a1, b1), _sum2(a2, b2, a3, b3));
    }

    function _sum5(
        uint256 a0,
        uint256 b0,
        uint256 a1,
        uint256 b1,
        uint256 a2,
        uint256 b2,
        uint256 a3,
        uint256 b3,
        uint256 a4,
        uint256 b4
    ) private pure returns (uint256) {
        return KoalaBear.add(_sum4(a0, b0, a1, b1, a2, b2, a3, b3), KoalaBear.mul(a4, b4));
    }
}
