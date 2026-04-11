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

    function expandFromUnivariateExtInto(
        uint256[] memory dst,
        uint256 dstOffset,
        uint256 value,
        uint256 numVariables
    ) internal pure {
        uint256 current = value;

        for (uint256 i = numVariables; i > 0; --i) {
            dst[dstOffset + i - 1] = current;
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

    function hornerBaseMemory(
        uint256[] memory coeffs,
        uint256 var_
    ) internal pure returns (uint256 acc) {
        assembly ("memory-safe") {
            let modulus := 0x7f000001
            let mask := 0xffffffff

            let src := add(add(coeffs, 0x20), shl(5, mload(coeffs)))
            let end := add(coeffs, 0x20)

            for {

            } gt(src, end) {

            } {
                src := sub(src, 0x20)
                let packed := mload(src)

                let a0 := shr(224, acc)
                let a1 := and(shr(192, acc), mask)
                let a2 := and(shr(160, acc), mask)
                let a3 := and(shr(128, acc), mask)

                let c0 := shr(224, packed)
                let c1 := and(shr(192, packed), mask)
                let c2 := and(shr(160, packed), mask)
                let c3 := and(shr(128, packed), mask)

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

    function hornerBaseBlob(
        bytes calldata blob,
        uint256 offset,
        uint256 coeffCount,
        uint256 var_
    ) internal pure returns (uint256 acc) {
        assembly ("memory-safe") {
            let modulus := 0x7f000001
            let mask := 0xffffffff

            let src := add(add(blob.offset, offset), shl(4, coeffCount))
            let end := add(blob.offset, offset)

            for {

            } gt(src, end) {

            } {
                src := sub(src, 0x10)
                let packed := and(calldataload(src), not(sub(shl(128, 1), 1)))

                let a0 := shr(224, acc)
                let a1 := and(shr(192, acc), mask)
                let a2 := and(shr(160, acc), mask)
                let a3 := and(shr(128, acc), mask)

                let c0 := shr(224, packed)
                let c1 := and(shr(192, packed), mask)
                let c2 := and(shr(160, packed), mask)
                let c3 := and(shr(128, packed), mask)

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

    function checkHornerBaseBlob16Matches(
        bytes calldata blob,
        uint256 offset,
        uint256[] memory vars,
        uint256[] memory rowEvals
    ) internal pure returns (uint256 mismatchPlusOne) {
        assembly ("memory-safe") {
            let modulus := 0x7f000001
            let mask := 0xffffffff
            let highMask := not(sub(shl(128, 1), 1))

            let varBase := add(vars, 0x20)
            let evalBase := add(rowEvals, 0x20)

            let v0 := mload(varBase)
            let v1 := mload(add(varBase, 0x20))
            let v2 := mload(add(varBase, 0x40))
            let v3 := mload(add(varBase, 0x60))
            let v4 := mload(add(varBase, 0x80))

            let a00 := 0
            let a01 := 0
            let a02 := 0
            let a03 := 0
            let a10 := 0
            let a11 := 0
            let a12 := 0
            let a13 := 0
            let a20 := 0
            let a21 := 0
            let a22 := 0
            let a23 := 0
            let a30 := 0
            let a31 := 0
            let a32 := 0
            let a33 := 0
            let a40 := 0
            let a41 := 0
            let a42 := 0
            let a43 := 0

            let src := add(add(blob.offset, offset), 0x100)
            let end := add(blob.offset, offset)

            for {

            } gt(src, end) {

            } {
                src := sub(src, 0x10)
                let packed := and(calldataload(src), highMask)

                let c0 := shr(224, packed)
                let c1 := and(shr(192, packed), mask)
                let c2 := and(shr(160, packed), mask)
                let c3 := and(shr(128, packed), mask)

                a00 := mod(add(mulmod(a00, v0, modulus), c0), modulus)
                a01 := mod(add(mulmod(a01, v0, modulus), c1), modulus)
                a02 := mod(add(mulmod(a02, v0, modulus), c2), modulus)
                a03 := mod(add(mulmod(a03, v0, modulus), c3), modulus)

                a10 := mod(add(mulmod(a10, v1, modulus), c0), modulus)
                a11 := mod(add(mulmod(a11, v1, modulus), c1), modulus)
                a12 := mod(add(mulmod(a12, v1, modulus), c2), modulus)
                a13 := mod(add(mulmod(a13, v1, modulus), c3), modulus)

                a20 := mod(add(mulmod(a20, v2, modulus), c0), modulus)
                a21 := mod(add(mulmod(a21, v2, modulus), c1), modulus)
                a22 := mod(add(mulmod(a22, v2, modulus), c2), modulus)
                a23 := mod(add(mulmod(a23, v2, modulus), c3), modulus)

                a30 := mod(add(mulmod(a30, v3, modulus), c0), modulus)
                a31 := mod(add(mulmod(a31, v3, modulus), c1), modulus)
                a32 := mod(add(mulmod(a32, v3, modulus), c2), modulus)
                a33 := mod(add(mulmod(a33, v3, modulus), c3), modulus)

                a40 := mod(add(mulmod(a40, v4, modulus), c0), modulus)
                a41 := mod(add(mulmod(a41, v4, modulus), c1), modulus)
                a42 := mod(add(mulmod(a42, v4, modulus), c2), modulus)
                a43 := mod(add(mulmod(a43, v4, modulus), c3), modulus)
            }

            let out0 := or(
                or(shl(224, a00), shl(192, a01)),
                or(shl(160, a02), shl(128, a03))
            )
            let out1 := or(
                or(shl(224, a10), shl(192, a11)),
                or(shl(160, a12), shl(128, a13))
            )
            let out2 := or(
                or(shl(224, a20), shl(192, a21)),
                or(shl(160, a22), shl(128, a23))
            )
            let out3 := or(
                or(shl(224, a30), shl(192, a31)),
                or(shl(160, a32), shl(128, a33))
            )
            let out4 := or(
                or(shl(224, a40), shl(192, a41)),
                or(shl(160, a42), shl(128, a43))
            )

            if and(iszero(mismatchPlusOne), iszero(eq(out0, mload(evalBase)))) {
                mismatchPlusOne := 1
            }
            if and(
                iszero(mismatchPlusOne),
                iszero(eq(out1, mload(add(evalBase, 0x20))))
            ) {
                mismatchPlusOne := 2
            }
            if and(
                iszero(mismatchPlusOne),
                iszero(eq(out2, mload(add(evalBase, 0x40))))
            ) {
                mismatchPlusOne := 3
            }
            if and(
                iszero(mismatchPlusOne),
                iszero(eq(out3, mload(add(evalBase, 0x60))))
            ) {
                mismatchPlusOne := 4
            }
            if and(
                iszero(mismatchPlusOne),
                iszero(eq(out4, mload(add(evalBase, 0x80))))
            ) {
                mismatchPlusOne := 5
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
        return sampleStirQueriesPow2(challenger, domainBits, numQueries);
    }

    function sampleStirQueriesPow2(
        KeccakChallenger.State memory challenger,
        uint256 domainBits,
        uint256 numQueries
    ) internal pure returns (uint256[] memory queries) {
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
                    queries[i] = allBits & mask;
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
                            queries[cursor] = allBits & mask;
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

    function _evaluateBaseRowDim4BlobWindow(
        bytes calldata blob,
        uint256 offset,
        uint256[] memory point,
        uint256 pointOffset
    ) internal pure returns (uint256) {
        uint256 pointBase;
        assembly ("memory-safe") {
            pointBase := add(add(point, 0x20), shl(5, pointOffset))
        }
        uint256 p0;
        uint256 p1;
        uint256 p2;
        uint256 p3;
        assembly ("memory-safe") {
            p0 := mload(pointBase)
            p1 := mload(add(pointBase, 0x20))
            p2 := mload(add(pointBase, 0x40))
            p3 := mload(add(pointBase, 0x60))
        }

        return
            _evaluateBaseRowDim4BlobPackedPoints(blob, offset, p0, p1, p2, p3);
    }

    function _evaluateBaseRowDim4BlobPackedPoints(
        bytes calldata blob,
        uint256 offset,
        uint256 p0,
        uint256 p1,
        uint256 p2,
        uint256 p3
    ) internal pure returns (uint256) {
        uint256 src;
        assembly ("memory-safe") {
            src := add(blob.offset, offset)
        }
        uint256 w0;
        uint256 w1;
        assembly ("memory-safe") {
            w0 := calldataload(src)
            w1 := calldataload(add(src, 0x20))
        }

        return _evaluateBaseRowDim4FromBlobWords(w0, w1, p0, p1, p2, p3);
    }

    function _hashAndEvaluateBaseRowDim4BlobPackedPoints(
        bytes calldata blob,
        uint256 offset,
        uint256 p0,
        uint256 p1,
        uint256 p2,
        uint256 p3
    ) internal pure returns (bytes32 digest, uint256 evalValue) {
        uint256 src;
        assembly ("memory-safe") {
            src := add(blob.offset, offset)
        }
        uint256 w0;
        uint256 w1;
        assembly ("memory-safe") {
            function revertField(x) {
                mstore(
                    0x00,
                    0xf512b67800000000000000000000000000000000000000000000000000000000
                )
                mstore(0x04, x)
                revert(0x00, 0x24)
            }

            let ptr := mload(0x40)
            let modulus := 0x7f000001
            w0 := calldataload(src)
            w1 := calldataload(add(src, 0x20))

            {
                let v0 := shr(224, w0)
                let v1 := and(shr(192, w0), 0xffffffff)
                let v2 := and(shr(160, w0), 0xffffffff)
                let v3 := and(shr(128, w0), 0xffffffff)
                let v4 := and(shr(96, w0), 0xffffffff)
                let v5 := and(shr(64, w0), 0xffffffff)
                let v6 := and(shr(32, w0), 0xffffffff)
                let v7 := and(w0, 0xffffffff)
                if or(
                    or(
                        or(iszero(lt(v0, modulus)), iszero(lt(v1, modulus))),
                        or(iszero(lt(v2, modulus)), iszero(lt(v3, modulus)))
                    ),
                    or(
                        or(iszero(lt(v4, modulus)), iszero(lt(v5, modulus))),
                        or(iszero(lt(v6, modulus)), iszero(lt(v7, modulus)))
                    )
                ) {
                    revertField(w0)
                }
            }

            {
                let v8 := shr(224, w1)
                let v9 := and(shr(192, w1), 0xffffffff)
                let v10 := and(shr(160, w1), 0xffffffff)
                let v11 := and(shr(128, w1), 0xffffffff)
                let v12 := and(shr(96, w1), 0xffffffff)
                let v13 := and(shr(64, w1), 0xffffffff)
                let v14 := and(shr(32, w1), 0xffffffff)
                let v15 := and(w1, 0xffffffff)
                if or(
                    or(
                        or(iszero(lt(v8, modulus)), iszero(lt(v9, modulus))),
                        or(iszero(lt(v10, modulus)), iszero(lt(v11, modulus)))
                    ),
                    or(
                        or(iszero(lt(v12, modulus)), iszero(lt(v13, modulus))),
                        or(iszero(lt(v14, modulus)), iszero(lt(v15, modulus)))
                    )
                ) {
                    revertField(w1)
                }
            }

            mstore8(ptr, 0x00)
            mstore(add(ptr, 0x01), w0)
            mstore(add(ptr, 0x21), w1)
            digest := and(keccak256(ptr, 65), not(sub(shl(96, 1), 1)))
        }

        evalValue = _evaluateBaseRowDim4FromBlobWords(w0, w1, p0, p1, p2, p3);
    }

    function _evaluateBaseRowDim4FromBlobWords(
        uint256 w0,
        uint256 w1,
        uint256 p0,
        uint256 p1,
        uint256 p2,
        uint256 p3
    ) private pure returns (uint256) {
        uint256 mask = 0xffffffff;

        uint256 v0 = w0 >> 224;
        uint256 v1 = (w0 >> 192) & mask;
        uint256 v2 = (w0 >> 160) & mask;
        uint256 v3 = (w0 >> 128) & mask;
        uint256 v4 = (w0 >> 96) & mask;
        uint256 v5 = (w0 >> 64) & mask;
        uint256 v6 = (w0 >> 32) & mask;
        uint256 v7 = w0 & mask;
        uint256 v8 = w1 >> 224;
        uint256 v9 = (w1 >> 192) & mask;
        uint256 v10 = (w1 >> 160) & mask;
        uint256 v11 = (w1 >> 128) & mask;
        uint256 v12 = (w1 >> 96) & mask;
        uint256 v13 = (w1 >> 64) & mask;
        uint256 v14 = (w1 >> 32) & mask;
        uint256 v15 = w1 & mask;

        (uint256 r00, uint256 r01, uint256 r02, uint256 r03) = _unpackCoeffs(
            p0
        );
        (uint256 r10, uint256 r11, uint256 r12, uint256 r13) = _unpackCoeffs(
            p1
        );
        (uint256 r20, uint256 r21, uint256 r22, uint256 r23) = _unpackCoeffs(
            p2
        );
        (uint256 r30, uint256 r31, uint256 r32, uint256 r33) = _unpackCoeffs(
            p3
        );

        uint256 l0 = _foldOnceBase(v0, v8, r00, r01, r02, r03);
        uint256 l1 = _foldOnceBase(v1, v9, r00, r01, r02, r03);
        uint256 l2 = _foldOnceBase(v2, v10, r00, r01, r02, r03);
        uint256 l3 = _foldOnceBase(v3, v11, r00, r01, r02, r03);
        uint256 l4 = _foldOnceBase(v4, v12, r00, r01, r02, r03);
        uint256 l5 = _foldOnceBase(v5, v13, r00, r01, r02, r03);
        uint256 l6 = _foldOnceBase(v6, v14, r00, r01, r02, r03);
        uint256 l7 = _foldOnceBase(v7, v15, r00, r01, r02, r03);
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

    function _evaluateExtensionRowDim4BlobWindow(
        bytes calldata blob,
        uint256 offset,
        uint256[] memory point,
        uint256 pointOffset
    ) internal pure returns (uint256) {
        uint256 pointBase;
        assembly ("memory-safe") {
            pointBase := add(add(point, 0x20), shl(5, pointOffset))
        }
        uint256 p0;
        uint256 p1;
        uint256 p2;
        uint256 p3;
        assembly ("memory-safe") {
            p0 := mload(pointBase)
            p1 := mload(add(pointBase, 0x20))
            p2 := mload(add(pointBase, 0x40))
            p3 := mload(add(pointBase, 0x60))
        }

        return
            _evaluateExtensionRowDim4BlobPackedPoints(
                blob,
                offset,
                p0,
                p1,
                p2,
                p3
            );
    }

    function _evaluateExtensionRowDim4BlobPackedPoints(
        bytes calldata blob,
        uint256 offset,
        uint256 p0,
        uint256 p1,
        uint256 p2,
        uint256 p3
    ) internal pure returns (uint256) {
        uint256 src;
        assembly ("memory-safe") {
            src := add(blob.offset, offset)
        }

        uint256 w0;
        uint256 w1;
        uint256 w2;
        uint256 w3;
        uint256 w4;
        uint256 w5;
        uint256 w6;
        uint256 w7;
        assembly ("memory-safe") {
            w0 := calldataload(src)
            w1 := calldataload(add(src, 0x20))
            w2 := calldataload(add(src, 0x40))
            w3 := calldataload(add(src, 0x60))
            w4 := calldataload(add(src, 0x80))
            w5 := calldataload(add(src, 0xa0))
            w6 := calldataload(add(src, 0xc0))
            w7 := calldataload(add(src, 0xe0))
        }

        return
            _evaluateExtensionRowDim4FromBlobWords(
                w0,
                w1,
                w2,
                w3,
                w4,
                w5,
                w6,
                w7,
                p0,
                p1,
                p2,
                p3
            );
    }

    function _hashAndEvaluateExtensionRowDim4BlobPackedPoints(
        bytes calldata blob,
        uint256 offset,
        uint256 p0,
        uint256 p1,
        uint256 p2,
        uint256 p3
    ) internal pure returns (bytes32 digest, uint256 evalValue) {
        uint256 src;
        assembly ("memory-safe") {
            src := add(blob.offset, offset)
        }

        uint256 w0;
        uint256 w1;
        uint256 w2;
        uint256 w3;
        uint256 w4;
        uint256 w5;
        uint256 w6;
        uint256 w7;
        assembly ("memory-safe") {
            function revertPacked(x) {
                mstore(
                    0x00,
                    0xf512b67800000000000000000000000000000000000000000000000000000000
                )
                mstore(0x04, x)
                revert(0x00, 0x24)
            }

            function validateWord(word, modulus, coeffMask, lowMask) {
                let hi := and(word, not(lowMask))
                let hi0 := shr(224, hi)
                let hi1 := and(shr(192, hi), coeffMask)
                let hi2 := and(shr(160, hi), coeffMask)
                let hi3 := and(shr(128, hi), coeffMask)
                if or(
                    or(iszero(lt(hi0, modulus)), iszero(lt(hi1, modulus))),
                    or(iszero(lt(hi2, modulus)), iszero(lt(hi3, modulus)))
                ) {
                    revertPacked(hi)
                }

                let lo := and(word, lowMask)
                let lo0 := shr(96, lo)
                let lo1 := and(shr(64, lo), coeffMask)
                let lo2 := and(shr(32, lo), coeffMask)
                let lo3 := and(lo, coeffMask)
                if or(
                    or(iszero(lt(lo0, modulus)), iszero(lt(lo1, modulus))),
                    or(iszero(lt(lo2, modulus)), iszero(lt(lo3, modulus)))
                ) {
                    revertPacked(shl(128, lo))
                }
            }

            let ptr := mload(0x40)
            let modulus := 0x7f000001
            let coeffMask := 0xffffffff
            let lowMask := sub(shl(128, 1), 1)

            w0 := calldataload(src)
            w1 := calldataload(add(src, 0x20))
            w2 := calldataload(add(src, 0x40))
            w3 := calldataload(add(src, 0x60))
            w4 := calldataload(add(src, 0x80))
            w5 := calldataload(add(src, 0xa0))
            w6 := calldataload(add(src, 0xc0))
            w7 := calldataload(add(src, 0xe0))

            validateWord(w0, modulus, coeffMask, lowMask)
            validateWord(w1, modulus, coeffMask, lowMask)
            validateWord(w2, modulus, coeffMask, lowMask)
            validateWord(w3, modulus, coeffMask, lowMask)
            validateWord(w4, modulus, coeffMask, lowMask)
            validateWord(w5, modulus, coeffMask, lowMask)
            validateWord(w6, modulus, coeffMask, lowMask)
            validateWord(w7, modulus, coeffMask, lowMask)

            mstore8(ptr, 0x00)
            mstore(add(ptr, 0x01), w0)
            mstore(add(ptr, 0x21), w1)
            mstore(add(ptr, 0x41), w2)
            mstore(add(ptr, 0x61), w3)
            mstore(add(ptr, 0x81), w4)
            mstore(add(ptr, 0xa1), w5)
            mstore(add(ptr, 0xc1), w6)
            mstore(add(ptr, 0xe1), w7)
            digest := and(keccak256(ptr, 257), not(sub(shl(96, 1), 1)))
        }

        evalValue = _evaluateExtensionRowDim4FromBlobWords(
            w0,
            w1,
            w2,
            w3,
            w4,
            w5,
            w6,
            w7,
            p0,
            p1,
            p2,
            p3
        );
    }

    function _evaluateExtensionRowDim4FromBlobWords(
        uint256 w0,
        uint256 w1,
        uint256 w2,
        uint256 w3,
        uint256 w4,
        uint256 w5,
        uint256 w6,
        uint256 w7,
        uint256 p0,
        uint256 p1,
        uint256 p2,
        uint256 p3
    ) private pure returns (uint256) {
        uint256 lowMask = (uint256(1) << 128) - 1;

        uint256 v0 = w0 & ~lowMask;
        uint256 v1 = (w0 & lowMask) << 128;
        uint256 v2 = w1 & ~lowMask;
        uint256 v3 = (w1 & lowMask) << 128;
        uint256 v4 = w2 & ~lowMask;
        uint256 v5 = (w2 & lowMask) << 128;
        uint256 v6 = w3 & ~lowMask;
        uint256 v7 = (w3 & lowMask) << 128;
        uint256 v8 = w4 & ~lowMask;
        uint256 v9 = (w4 & lowMask) << 128;
        uint256 v10 = w5 & ~lowMask;
        uint256 v11 = (w5 & lowMask) << 128;
        uint256 v12 = w6 & ~lowMask;
        uint256 v13 = (w6 & lowMask) << 128;
        uint256 v14 = w7 & ~lowMask;
        uint256 v15 = (w7 & lowMask) << 128;

        (uint256 r00, uint256 r01, uint256 r02, uint256 r03) = _unpackCoeffs(
            p0
        );
        (uint256 r10, uint256 r11, uint256 r12, uint256 r13) = _unpackCoeffs(
            p1
        );
        (uint256 r20, uint256 r21, uint256 r22, uint256 r23) = _unpackCoeffs(
            p2
        );
        (uint256 r30, uint256 r31, uint256 r32, uint256 r33) = _unpackCoeffs(
            p3
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
            let d := sub(add(a1, M), a0)
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

            // d = a1 - a0 (per lane, unreduced: d_i in [1, 2P-1])
            let d0 := sub(add(shr(224, a1), M), a00)
            let d1 := sub(add(and(shr(192, a1), m), M), a01)
            let d2 := sub(add(and(shr(160, a1), m), M), a02)
            let d3 := sub(add(and(shr(128, a1), m), M), a0)

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

            // d = a1 - a0 (per lane, unreduced: d_i in [1, 2P-1])
            let d0 := sub(add(shr(224, a1), M), a00)
            let d1 := sub(add(and(shr(192, a1), m), M), a01)
            let d2 := sub(add(and(shr(160, a1), m), M), a02)
            let d3 := sub(add(and(shr(128, a1), m), M), a0)

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
