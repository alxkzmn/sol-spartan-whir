// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {LibSort} from "solady/utils/LibSort.sol";

import {KoalaBear} from "../field/KoalaBear.sol";
import {KoalaBearExt4} from "../field/KoalaBearExt4.sol";
import {KeccakChallenger} from "../transcript/KeccakChallenger.sol";

library WhirVerifierUtils4 {
    using KeccakChallenger for KeccakChallenger.State;

    error BaseFieldElementOutOfRange(uint256 value);
    error PackedExtensionElementOutOfRange(uint256 value);
    error NotPowerOfTwo(uint256 value);

    function observePattern(
        KeccakChallenger.State memory challenger,
        uint256[] calldata pattern
    ) internal pure {
        unchecked {
            for (uint256 i = 0; i < pattern.length; ++i) {
                uint256 value = pattern[i];
                if (value >= KoalaBear.MODULUS) {
                    revert BaseFieldElementOutOfRange(value);
                }
                challenger.observeBase(value);
            }
        }
    }

    function observeValidatedExt4(
        KeccakChallenger.State memory challenger,
        uint256 packed
    ) internal pure {
        challenger.observeValidatedPackedExt4(packed);
    }

    function sampleExt4(
        KeccakChallenger.State memory challenger
    ) internal pure returns (uint256) {
        unchecked {
            return
                (challenger.sampleBase() << 224) |
                (challenger.sampleBase() << 192) |
                (challenger.sampleBase() << 160) |
                (challenger.sampleBase() << 128);
        }
    }

    function validateBaseCalldata(uint256[] calldata values) internal pure {
        unchecked {
            for (uint256 i = 0; i < values.length; ++i) {
                if (values[i] >= KoalaBear.MODULUS) {
                    revert BaseFieldElementOutOfRange(values[i]);
                }
            }
        }
    }

    function validatePackedExt4Calldata(
        uint256[] calldata values
    ) internal pure {
        unchecked {
            for (uint256 i = 0; i < values.length; ++i) {
                validatePackedExt4(values[i]);
            }
        }
    }

    function validatePackedExt4(uint256 packed) internal pure {
        unchecked {
            if (
                (packed & ((1 << 128) - 1)) != 0 ||
                (packed >> 224) >= KoalaBear.MODULUS ||
                ((packed >> 192) & 0xffffffff) >= KoalaBear.MODULUS ||
                ((packed >> 160) & 0xffffffff) >= KoalaBear.MODULUS ||
                ((packed >> 128) & 0xffffffff) >= KoalaBear.MODULUS
            ) {
                revert PackedExtensionElementOutOfRange(packed);
            }
        }
    }

    function expandFromUnivariateExt(
        uint256 value,
        uint256 numVariables
    ) internal pure returns (uint256[] memory point) {
        point = new uint256[](numVariables);
        uint256 current = value;

        for (uint256 i = numVariables; i > 0; --i) {
            point[i - 1] = current;
            current = KoalaBearExt4.square(current);
        }
    }

    function hornerBase(
        uint256[] calldata coeffs,
        uint256 var_
    ) internal pure returns (uint256 acc) {
        assembly ("memory-safe") {
            let modulus := 0x7f000001
            let mask := 0xffffffff

            let src := add(coeffs.offset, shl(5, coeffs.length))
            let end := coeffs.offset

            for {

            } gt(src, end) {

            } {
                src := sub(src, 0x20)
                let packed := calldataload(src)

                let a0 := shr(224, acc)
                let a1 := and(shr(192, acc), mask)
                let a2 := and(shr(160, acc), mask)
                let a3 := and(shr(128, acc), mask)

                let c0 := shr(224, packed)
                let c1 := and(shr(192, packed), mask)
                let c2 := and(shr(160, packed), mask)
                let c3 := and(shr(128, packed), mask)

                // mulmod ∈ [0,M-1], + c ∈ [0,M-1] → sum ∈ [0,2M-2]. mod reduces.
                let r0 := mod(add(mulmod(a0, var_, modulus), c0), modulus)
                let r1 := mod(add(mulmod(a1, var_, modulus), c1), modulus)
                let r2 := mod(add(mulmod(a2, var_, modulus), c2), modulus)
                let r3 := mod(add(mulmod(a3, var_, modulus), c3), modulus)

                acc := or(
                    or(shl(224, r0), shl(192, r1)),
                    or(shl(160, r2), shl(128, r3))
                )
            }
        }
    }

    function sampleStirQueries(
        KeccakChallenger.State memory challenger,
        uint256 domainSize,
        uint256 foldingFactor,
        uint256 numQueries
    ) internal pure returns (uint256[] memory queries) {
        uint256 foldedDomainSize = domainSize >> foldingFactor;
        uint256 domainBits = log2Strict(foldedDomainSize);
        uint256 maxBitsPerCall = 20;
        uint256 totalBitsNeeded = numQueries * domainBits;

        queries = new uint256[](numQueries);

        if (totalBitsNeeded <= maxBitsPerCall) {
            uint256 allBits = challenger.sampleBitsUnchecked(totalBitsNeeded);
            uint256 mask = domainBits == 0
                ? 0
                : ((uint256(1) << domainBits) - 1);
            unchecked {
                for (uint256 i = 0; i < numQueries; ++i) {
                    queries[i] = (allBits & mask) % foldedDomainSize;
                    allBits >>= domainBits;
                }
            }
        } else {
            uint256 queriesPerBatch = maxBitsPerCall / domainBits;
            if (queriesPerBatch >= 2) {
                uint256 remaining = numQueries;
                uint256 cursor = 0;
                uint256 mask = (uint256(1) << domainBits) - 1;
                while (remaining > 0) {
                    uint256 batchSize = remaining < queriesPerBatch
                        ? remaining
                        : queriesPerBatch;
                    uint256 batchBits = batchSize * domainBits;
                    uint256 allBits = challenger.sampleBitsUnchecked(batchBits);

                    unchecked {
                        for (uint256 i = 0; i < batchSize; ++i) {
                            queries[cursor] =
                                (allBits & mask) %
                                foldedDomainSize;
                            allBits >>= domainBits;
                            cursor += 1;
                        }
                    }

                    remaining -= batchSize;
                }
            } else {
                unchecked {
                    for (uint256 i = 0; i < numQueries; ++i) {
                        queries[i] = challenger.sampleBitsUnchecked(domainBits);
                    }
                }
            }
        }

        if (queries.length > 1) {
            LibSort.sort(queries);
            LibSort.uniquifySorted(queries);
        }
    }

    function evaluateBaseRowAsExt4(
        uint256[] calldata flatValues,
        uint256 start,
        uint256 rowLen,
        uint256[] memory point
    ) internal pure returns (uint256) {
        if (point.length == 0) {
            return _loadBaseAsExt4Unchecked(flatValues, start);
        }
        if (point.length == 1) {
            return
                _foldOnce(
                    _loadBaseAsExt4Unchecked(flatValues, start),
                    _loadBaseAsExt4Unchecked(flatValues, start + 1),
                    point[0]
                );
        }
        if (point.length == 2) {
            uint256 l0 = _foldOnce(
                _loadBaseAsExt4Unchecked(flatValues, start),
                _loadBaseAsExt4Unchecked(flatValues, start + 2),
                point[0]
            );
            uint256 l1 = _foldOnce(
                _loadBaseAsExt4Unchecked(flatValues, start + 1),
                _loadBaseAsExt4Unchecked(flatValues, start + 3),
                point[0]
            );
            return _foldOnce(l0, l1, point[1]);
        }
        if (point.length == 3) {
            return _evaluateBaseRowDim3(flatValues, start, point);
        }
        if (point.length == 4) {
            return _evaluateBaseRowDim4(flatValues, start, point);
        }

        uint256[] memory evals = new uint256[](rowLen);
        unchecked {
            for (uint256 i = 0; i < rowLen; ++i) {
                evals[i] = _loadBaseAsExt4Unchecked(flatValues, start + i);
            }
        }
        return KoalaBearExt4.evaluate_hypercube(evals, point);
    }

    function evaluateExtensionRowAsExt4(
        uint256[] calldata flatValues,
        uint256 start,
        uint256 rowLen,
        uint256[] memory point
    ) internal pure returns (uint256) {
        if (point.length == 0) {
            return _loadPackedExt4Unchecked(flatValues, start);
        }
        if (point.length == 1) {
            return
                _foldOnce(
                    _loadPackedExt4Unchecked(flatValues, start),
                    _loadPackedExt4Unchecked(flatValues, start + 1),
                    point[0]
                );
        }
        if (point.length == 2) {
            uint256 l0 = _foldOnce(
                _loadPackedExt4Unchecked(flatValues, start),
                _loadPackedExt4Unchecked(flatValues, start + 2),
                point[0]
            );
            uint256 l1 = _foldOnce(
                _loadPackedExt4Unchecked(flatValues, start + 1),
                _loadPackedExt4Unchecked(flatValues, start + 3),
                point[0]
            );
            return _foldOnce(l0, l1, point[1]);
        }
        if (point.length == 3) {
            return _evaluateExtensionRowDim3(flatValues, start, point);
        }
        if (point.length == 4) {
            return _evaluateExtensionRowDim4(flatValues, start, point);
        }

        uint256[] memory evals = new uint256[](rowLen);
        unchecked {
            for (uint256 i = 0; i < rowLen; ++i) {
                evals[i] = _loadPackedExt4Unchecked(flatValues, start + i);
            }
        }
        return KoalaBearExt4.evaluate_hypercube(evals, point);
    }

    function _evaluateBaseRowDim3(
        uint256[] calldata flatValues,
        uint256 start,
        uint256[] memory point
    ) private pure returns (uint256) {
        uint256 l0 = _foldOnce(
            _loadBaseAsExt4Unchecked(flatValues, start),
            _loadBaseAsExt4Unchecked(flatValues, start + 4),
            point[0]
        );
        uint256 l1 = _foldOnce(
            _loadBaseAsExt4Unchecked(flatValues, start + 1),
            _loadBaseAsExt4Unchecked(flatValues, start + 5),
            point[0]
        );
        uint256 l2 = _foldOnce(
            _loadBaseAsExt4Unchecked(flatValues, start + 2),
            _loadBaseAsExt4Unchecked(flatValues, start + 6),
            point[0]
        );
        uint256 l3 = _foldOnce(
            _loadBaseAsExt4Unchecked(flatValues, start + 3),
            _loadBaseAsExt4Unchecked(flatValues, start + 7),
            point[0]
        );
        uint256 m0 = _foldOnce(l0, l2, point[1]);
        uint256 m1 = _foldOnce(l1, l3, point[1]);
        return _foldOnce(m0, m1, point[2]);
    }

    function _evaluateBaseRowDim4(
        uint256[] calldata flatValues,
        uint256 start,
        uint256[] memory point
    ) internal pure returns (uint256) {
        uint256 src;
        assembly ("memory-safe") {
            src := add(flatValues.offset, shl(5, start))
        }
        uint256 v0;
        uint256 v1;
        uint256 v2;
        uint256 v3;
        uint256 v4;
        uint256 v5;
        uint256 v6;
        uint256 v7;
        uint256 v8;
        uint256 v9;
        uint256 v10;
        uint256 v11;
        uint256 v12;
        uint256 v13;
        uint256 v14;
        uint256 v15;
        assembly ("memory-safe") {
            v0 := calldataload(src)
            v1 := calldataload(add(src, 0x20))
            v2 := calldataload(add(src, 0x40))
            v3 := calldataload(add(src, 0x60))
            v4 := calldataload(add(src, 0x80))
            v5 := calldataload(add(src, 0xa0))
            v6 := calldataload(add(src, 0xc0))
            v7 := calldataload(add(src, 0xe0))
            v8 := calldataload(add(src, 0x100))
            v9 := calldataload(add(src, 0x120))
            v10 := calldataload(add(src, 0x140))
            v11 := calldataload(add(src, 0x160))
            v12 := calldataload(add(src, 0x180))
            v13 := calldataload(add(src, 0x1a0))
            v14 := calldataload(add(src, 0x1c0))
            v15 := calldataload(add(src, 0x1e0))
        }
        (uint256 r00, uint256 r01, uint256 r02, uint256 r03) = _unpackCoeffs(
            point[0]
        );
        (uint256 r10, uint256 r11, uint256 r12, uint256 r13) = _unpackCoeffs(
            point[1]
        );
        (uint256 r20, uint256 r21, uint256 r22, uint256 r23) = _unpackCoeffs(
            point[2]
        );
        (uint256 r30, uint256 r31, uint256 r32, uint256 r33) = _unpackCoeffs(
            point[3]
        );

        // Layer 1: fold base-field pairs → ext4. Both inputs have only lane 0
        // nonzero, so d = (d0, 0, 0, 0) and r * d simplifies to 4 muls.
        uint256 l0 = _foldOnceBase(v0, v8, r00, r01, r02, r03);
        uint256 l1 = _foldOnceBase(v1, v9, r00, r01, r02, r03);
        uint256 l2 = _foldOnceBase(v2, v10, r00, r01, r02, r03);
        uint256 l3 = _foldOnceBase(v3, v11, r00, r01, r02, r03);
        uint256 l4 = _foldOnceBase(v4, v12, r00, r01, r02, r03);
        uint256 l5 = _foldOnceBase(v5, v13, r00, r01, r02, r03);
        uint256 l6 = _foldOnceBase(v6, v14, r00, r01, r02, r03);
        uint256 l7 = _foldOnceBase(v7, v15, r00, r01, r02, r03);
        // Layers 2-4: ext4 → ext4 (full schoolbook)
        uint256 m0 = _foldOnceWithCoeffs(l0, l4, r10, r11, r12, r13);
        uint256 m1 = _foldOnceWithCoeffs(l1, l5, r10, r11, r12, r13);
        uint256 m2 = _foldOnceWithCoeffs(l2, l6, r10, r11, r12, r13);
        uint256 m3 = _foldOnceWithCoeffs(l3, l7, r10, r11, r12, r13);
        uint256 n0 = _foldOnceWithCoeffs(m0, m2, r20, r21, r22, r23);
        uint256 n1 = _foldOnceWithCoeffs(m1, m3, r20, r21, r22, r23);
        return _foldOnceWithCoeffs(n0, n1, r30, r31, r32, r33);
    }

    function _evaluateExtensionRowDim3(
        uint256[] calldata flatValues,
        uint256 start,
        uint256[] memory point
    ) private pure returns (uint256) {
        uint256 l0 = _foldOnce(
            _loadPackedExt4Unchecked(flatValues, start),
            _loadPackedExt4Unchecked(flatValues, start + 4),
            point[0]
        );
        uint256 l1 = _foldOnce(
            _loadPackedExt4Unchecked(flatValues, start + 1),
            _loadPackedExt4Unchecked(flatValues, start + 5),
            point[0]
        );
        uint256 l2 = _foldOnce(
            _loadPackedExt4Unchecked(flatValues, start + 2),
            _loadPackedExt4Unchecked(flatValues, start + 6),
            point[0]
        );
        uint256 l3 = _foldOnce(
            _loadPackedExt4Unchecked(flatValues, start + 3),
            _loadPackedExt4Unchecked(flatValues, start + 7),
            point[0]
        );
        uint256 m0 = _foldOnce(l0, l2, point[1]);
        uint256 m1 = _foldOnce(l1, l3, point[1]);
        return _foldOnce(m0, m1, point[2]);
    }

    function _evaluateExtensionRowDim4(
        uint256[] calldata flatValues,
        uint256 start,
        uint256[] memory point
    ) internal pure returns (uint256) {
        uint256 src;
        assembly ("memory-safe") {
            src := add(flatValues.offset, shl(5, start))
        }
        uint256 v0;
        uint256 v1;
        uint256 v2;
        uint256 v3;
        uint256 v4;
        uint256 v5;
        uint256 v6;
        uint256 v7;
        uint256 v8;
        uint256 v9;
        uint256 v10;
        uint256 v11;
        uint256 v12;
        uint256 v13;
        uint256 v14;
        uint256 v15;
        assembly ("memory-safe") {
            v0 := calldataload(src)
            v1 := calldataload(add(src, 0x20))
            v2 := calldataload(add(src, 0x40))
            v3 := calldataload(add(src, 0x60))
            v4 := calldataload(add(src, 0x80))
            v5 := calldataload(add(src, 0xa0))
            v6 := calldataload(add(src, 0xc0))
            v7 := calldataload(add(src, 0xe0))
            v8 := calldataload(add(src, 0x100))
            v9 := calldataload(add(src, 0x120))
            v10 := calldataload(add(src, 0x140))
            v11 := calldataload(add(src, 0x160))
            v12 := calldataload(add(src, 0x180))
            v13 := calldataload(add(src, 0x1a0))
            v14 := calldataload(add(src, 0x1c0))
            v15 := calldataload(add(src, 0x1e0))
        }
        (uint256 r00, uint256 r01, uint256 r02, uint256 r03) = _unpackCoeffs(
            point[0]
        );
        (uint256 r10, uint256 r11, uint256 r12, uint256 r13) = _unpackCoeffs(
            point[1]
        );
        (uint256 r20, uint256 r21, uint256 r22, uint256 r23) = _unpackCoeffs(
            point[2]
        );
        (uint256 r30, uint256 r31, uint256 r32, uint256 r33) = _unpackCoeffs(
            point[3]
        );

        uint256 l0 = _foldOnceWithCoeffs(v0, v8, r00, r01, r02, r03);
        uint256 l1 = _foldOnceWithCoeffs(v1, v9, r00, r01, r02, r03);
        uint256 l2 = _foldOnceWithCoeffs(v2, v10, r00, r01, r02, r03);
        uint256 l3 = _foldOnceWithCoeffs(v3, v11, r00, r01, r02, r03);
        uint256 l4 = _foldOnceWithCoeffs(v4, v12, r00, r01, r02, r03);
        uint256 l5 = _foldOnceWithCoeffs(v5, v13, r00, r01, r02, r03);
        uint256 l6 = _foldOnceWithCoeffs(v6, v14, r00, r01, r02, r03);
        uint256 l7 = _foldOnceWithCoeffs(v7, v15, r00, r01, r02, r03);
        uint256 m0 = _foldOnceWithCoeffs(l0, l4, r10, r11, r12, r13);
        uint256 m1 = _foldOnceWithCoeffs(l1, l5, r10, r11, r12, r13);
        uint256 m2 = _foldOnceWithCoeffs(l2, l6, r10, r11, r12, r13);
        uint256 m3 = _foldOnceWithCoeffs(l3, l7, r10, r11, r12, r13);
        uint256 n0 = _foldOnceWithCoeffs(m0, m2, r20, r21, r22, r23);
        uint256 n1 = _foldOnceWithCoeffs(m1, m3, r20, r21, r22, r23);
        return _foldOnceWithCoeffs(n0, n1, r30, r31, r32, r33);
    }

    function _loadBaseAsExt4Unchecked(
        uint256[] calldata flatValues,
        uint256 index
    ) private pure returns (uint256) {
        return flatValues[index] << 224;
    }

    function _loadPackedExt4Unchecked(
        uint256[] calldata flatValues,
        uint256 index
    ) private pure returns (uint256 value) {
        value = flatValues[index];
    }

    /// @dev Fold two base-field values using pre-unpacked ext4 coefficients.
    /// Both inputs are raw base-field elements (not packed ext4), so
    /// d = (a1 - a0, 0, 0, 0) and the schoolbook r*d reduces from 16 to 4 muls.
    function _foldOnceBase(
        uint256 a0,
        uint256 a1,
        uint256 r0,
        uint256 r1,
        uint256 r2,
        uint256 r3
    ) private pure returns (uint256 out) {
        assembly {
            let M := 0x7f000001
            let d := mod(sub(add(a1, M), a0), M)
            out := or(
                or(
                    shl(224, mod(add(a0, mul(r0, d)), M)),
                    shl(192, mod(mul(r1, d), M))
                ),
                or(shl(160, mod(mul(r2, d), M)), shl(128, mod(mul(r3, d), M)))
            )
        }
    }

    function _foldOnce(
        uint256 a0,
        uint256 a1,
        uint256 r
    ) private pure returns (uint256 out) {
        assembly {
            let M := 0x7f000001
            let m := 0xffffffff

            let a00 := shr(224, a0)
            let a01 := and(shr(192, a0), m)
            let a02 := and(shr(160, a0), m)
            a0 := and(shr(128, a0), m) // a03

            // d = a1 - a0 (per lane, mod M)
            let d0 := mod(sub(add(shr(224, a1), M), a00), M)
            let d1 := mod(sub(add(and(shr(192, a1), m), M), a01), M)
            let d2 := mod(sub(add(and(shr(160, a1), m), M), a02), M)
            let d3 := mod(sub(add(and(shr(128, a1), m), M), a0), M)

            // Unpack r
            let r0 := shr(224, r)
            let r1 := and(shr(192, r), m)
            let r2 := and(shr(160, r), m)
            r := and(shr(128, r), m) // r3

            // c = a0 + r * d (schoolbook over X^4 - 3, r is now r3)
            out := shl(
                224,
                mod(
                    add(
                        a00,
                        add(
                            mul(r0, d0),
                            mul(
                                3,
                                add(add(mul(r1, d3), mul(r2, d2)), mul(r, d1))
                            )
                        )
                    ),
                    M
                )
            )
            out := or(
                out,
                shl(
                    192,
                    mod(
                        add(
                            a01,
                            add(
                                add(mul(r0, d1), mul(r1, d0)),
                                mul(3, add(mul(r2, d3), mul(r, d2)))
                            )
                        ),
                        M
                    )
                )
            )
            out := or(
                out,
                shl(
                    160,
                    mod(
                        add(
                            a02,
                            add(
                                add(add(mul(r0, d2), mul(r1, d1)), mul(r2, d0)),
                                mul(3, mul(r, d3))
                            )
                        ),
                        M
                    )
                )
            )
            out := or(
                out,
                shl(
                    128,
                    mod(
                        add(
                            a0,
                            add(
                                add(add(mul(r0, d3), mul(r1, d2)), mul(r2, d1)),
                                mul(r, d0)
                            )
                        ),
                        M
                    )
                )
            )
        }
    }

    function _foldOnceWithCoeffs(
        uint256 a0,
        uint256 a1,
        uint256 r0,
        uint256 r1,
        uint256 r2,
        uint256 r3
    ) private pure returns (uint256 out) {
        assembly {
            let M := 0x7f000001
            let m := 0xffffffff

            let a00 := shr(224, a0)
            let a01 := and(shr(192, a0), m)
            let a02 := and(shr(160, a0), m)
            a0 := and(shr(128, a0), m) // a03

            // d = a1 - a0 (per lane, mod M)
            let d0 := mod(sub(add(shr(224, a1), M), a00), M)
            let d1 := mod(sub(add(and(shr(192, a1), m), M), a01), M)
            let d2 := mod(sub(add(and(shr(160, a1), m), M), a02), M)
            let d3 := mod(sub(add(and(shr(128, a1), m), M), a0), M)

            // c = a0 + r * d (schoolbook over X^4 - 3)
            out := shl(
                224,
                mod(
                    add(
                        a00,
                        add(
                            mul(r0, d0),
                            mul(
                                3,
                                add(add(mul(r1, d3), mul(r2, d2)), mul(r3, d1))
                            )
                        )
                    ),
                    M
                )
            )
            out := or(
                out,
                shl(
                    192,
                    mod(
                        add(
                            a01,
                            add(
                                add(mul(r0, d1), mul(r1, d0)),
                                mul(3, add(mul(r2, d3), mul(r3, d2)))
                            )
                        ),
                        M
                    )
                )
            )
            out := or(
                out,
                shl(
                    160,
                    mod(
                        add(
                            a02,
                            add(
                                add(add(mul(r0, d2), mul(r1, d1)), mul(r2, d0)),
                                mul(3, mul(r3, d3))
                            )
                        ),
                        M
                    )
                )
            )
            out := or(
                out,
                shl(
                    128,
                    mod(
                        add(
                            a0,
                            add(
                                add(add(mul(r0, d3), mul(r1, d2)), mul(r2, d1)),
                                mul(r3, d0)
                            )
                        ),
                        M
                    )
                )
            )
        }
    }

    function _unpackCoeffs(
        uint256 packed
    ) private pure returns (uint256 c0, uint256 c1, uint256 c2, uint256 c3) {
        c0 = packed >> 224;
        c1 = (packed >> 192) & 0xffffffff;
        c2 = (packed >> 160) & 0xffffffff;
        c3 = (packed >> 128) & 0xffffffff;
    }

    function log2Strict(uint256 x) internal pure returns (uint256 result) {
        if (x == 0 || (x & (x - 1)) != 0) {
            revert NotPowerOfTwo(x);
        }

        while (x > 1) {
            x >>= 1;
            result += 1;
        }
    }
}
