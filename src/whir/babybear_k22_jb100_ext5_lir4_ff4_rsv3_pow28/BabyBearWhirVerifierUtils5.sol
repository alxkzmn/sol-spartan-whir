// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { LibSort } from "solady/utils/LibSort.sol";

import { BabyBear } from "../../field/BabyBear.sol";
import { BabyBearExt5 } from "../../field/BabyBearExt5.sol";
import { BabyBearKeccakChallenger } from "../../transcript/BabyBearKeccakChallenger.sol";

library BabyBearWhirVerifierUtils5 {
    using BabyBearKeccakChallenger for BabyBearKeccakChallenger.State;

    error BaseFieldElementOutOfRange(uint256 value);
    error PackedExtensionElementOutOfRange(uint256 value);
    error NotPowerOfTwo(uint256 value);

    function observeValidatedExt5(BabyBearKeccakChallenger.State memory challenger, uint256 packed)
        internal
        pure
    {
        challenger.observeValidatedPackedExt5(packed);
    }

    function sampleExt5(BabyBearKeccakChallenger.State memory challenger)
        internal
        pure
        returns (uint256)
    {
        unchecked {
            return (challenger.sampleBase() << 224) | (challenger.sampleBase() << 192)
                | (challenger.sampleBase() << 160) | (challenger.sampleBase() << 128)
                | (challenger.sampleBase() << 96);
        }
    }

    function _computeDim4EqWeights(uint256 p0, uint256 p1, uint256 p2, uint256 p3)
        internal
        pure
        returns (uint256 weightsPtr)
    {
        uint256 a11 = BabyBearExt5.mul(p0, p1);
        uint256 a10 = BabyBearExt5.sub(p0, a11);
        uint256 a01 = BabyBearExt5.sub(p1, a11);
        uint256 a00 = BabyBearExt5.sub(BabyBearExt5.sub(BabyBearExt5.ONE, p0), a01);
        uint256 b001 = BabyBearExt5.mul(a00, p2);
        uint256 b000 = BabyBearExt5.sub(a00, b001);
        uint256 b011 = BabyBearExt5.mul(a01, p2);
        uint256 b010 = BabyBearExt5.sub(a01, b011);
        uint256 b101 = BabyBearExt5.mul(a10, p2);
        uint256 b100 = BabyBearExt5.sub(a10, b101);
        uint256 b111 = BabyBearExt5.mul(a11, p2);
        uint256 b110 = BabyBearExt5.sub(a11, b111);

        assembly ("memory-safe") {
            weightsPtr := mload(0x40)
            mstore(0x40, add(weightsPtr, 0x200))
        }

        _storeDim4EqWeightPair(weightsPtr, 0x000, b000, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x040, b001, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x080, b010, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x0c0, b011, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x100, b100, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x140, b101, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x180, b110, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x1c0, b111, p3);
    }

    function _storeDim4EqWeightPair(uint256 weightsPtr, uint256 offset, uint256 prefix, uint256 p3)
        private
        pure
    {
        uint256 w1 = BabyBearExt5.mul(prefix, p3);
        uint256 w0 = BabyBearExt5.sub(prefix, w1);
        assembly ("memory-safe") {
            mstore(add(weightsPtr, offset), w0)
            mstore(add(add(weightsPtr, offset), 0x20), w1)
        }
    }

    function _computeDim4EqWeightsUnpacked(uint256 p0, uint256 p1, uint256 p2, uint256 p3)
        internal
        pure
        returns (uint256)
    {
        return _prepareRowWeights(_computeDim4EqWeights(p0, p1, p2, p3));
    }

    function validateBase(uint256 value) internal pure {
        if (value >= BabyBear.MODULUS) {
            revert BaseFieldElementOutOfRange(value);
        }
    }

    function validatePackedExt5Calldata(uint256[] calldata values) internal pure {
        unchecked {
            for (uint256 i = 0; i < values.length; ++i) {
                validatePackedExt5(values[i]);
            }
        }
    }

    function validatePackedExt5(uint256 packed) internal pure {
        BabyBearExt5.validatePacked(packed);
    }

    function expandFromUnivariateExtInto(
        uint256[] memory dst,
        uint256 dstOffset,
        uint256 value,
        uint256 numVariables
    ) internal pure {
        uint256 current = value;

        unchecked {
            for (uint256 i = numVariables; i > 0; --i) {
                dst[dstOffset + i - 1] = current;
                current = BabyBearExt5.square(current);
            }
        }
    }

    function sampleStirQueries(
        BabyBearKeccakChallenger.State memory challenger,
        uint256 domainSize,
        uint256 foldingFactor,
        uint256 numQueries
    ) internal pure returns (uint256[] memory queries) {
        uint256 foldedDomainSize = domainSize >> foldingFactor;
        uint256 domainBits = log2Strict(foldedDomainSize);
        return sampleStirQueriesPow2(challenger, domainBits, numQueries);
    }

    function sampleStirQueriesPow2(
        BabyBearKeccakChallenger.State memory challenger,
        uint256 domainBits,
        uint256 numQueries
    ) internal pure returns (uint256[] memory queries) {
        uint256 maxBitsPerCall = 20;
        uint256 totalBitsNeeded = numQueries * domainBits;

        queries = new uint256[](numQueries);

        if (totalBitsNeeded <= maxBitsPerCall) {
            uint256 allBits = challenger.sampleBitsUnchecked(totalBitsNeeded);
            uint256 mask = domainBits == 0 ? 0 : ((uint256(1) << domainBits) - 1);
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
                    uint256 batchSize = remaining < queriesPerBatch ? remaining : queriesPerBatch;
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

    function log2Strict(uint256 value) internal pure returns (uint256 exponent) {
        if (value == 0 || (value & (value - 1)) != 0) {
            revert NotPowerOfTwo(value);
        }

        while (value > 1) {
            value >>= 1;
            exponent += 1;
        }
    }

    function hornerBase(uint256[] calldata coeffs, uint256 var_)
        internal
        pure
        returns (uint256 acc)
    {
        assembly ("memory-safe") {
            let modulus := 0x78000001
            let mask := 0xffffffff
            let src := add(coeffs.offset, shl(5, coeffs.length))
            let end := coeffs.offset

            for { } gt(src, end) { } {
                src := sub(src, 0x20)
                let packed := calldataload(src)

                let a0 := shr(224, acc)
                let a1 := and(shr(192, acc), mask)
                let a2 := and(shr(160, acc), mask)
                let a3 := and(shr(128, acc), mask)
                let a4 := and(shr(96, acc), mask)

                let c0 := shr(224, packed)
                let c1 := and(shr(192, packed), mask)
                let c2 := and(shr(160, packed), mask)
                let c3 := and(shr(128, packed), mask)
                let c4 := and(shr(96, packed), mask)

                let r0 := mod(add(mulmod(a0, var_, modulus), c0), modulus)
                let r1 := mod(add(mulmod(a1, var_, modulus), c1), modulus)
                let r2 := mod(add(mulmod(a2, var_, modulus), c2), modulus)
                let r3 := mod(add(mulmod(a3, var_, modulus), c3), modulus)
                let r4 := mod(add(mulmod(a4, var_, modulus), c4), modulus)

                acc := or(
                    or(or(shl(224, r0), shl(192, r1)), or(shl(160, r2), shl(128, r3))),
                    shl(96, r4)
                )
            }
        }
    }

    function hornerBaseBlob(bytes calldata blob, uint256 offset, uint256 coeffCount, uint256 var_)
        internal
        pure
        returns (uint256 acc)
    {
        assembly ("memory-safe") {
            let modulus := 0x78000001
            let mask := 0xffffffff
            let low96Mask := sub(shl(96, 1), 1)

            let src := add(add(blob.offset, offset), mul(20, coeffCount))
            let end := add(blob.offset, offset)

            for { } gt(src, end) { } {
                src := sub(src, 20)
                let packed := and(calldataload(src), not(low96Mask))

                let a0 := shr(224, acc)
                let a1 := and(shr(192, acc), mask)
                let a2 := and(shr(160, acc), mask)
                let a3 := and(shr(128, acc), mask)
                let a4 := and(shr(96, acc), mask)

                let c0 := shr(224, packed)
                let c1 := and(shr(192, packed), mask)
                let c2 := and(shr(160, packed), mask)
                let c3 := and(shr(128, packed), mask)
                let c4 := and(shr(96, packed), mask)

                let r0 := mod(add(mulmod(a0, var_, modulus), c0), modulus)
                let r1 := mod(add(mulmod(a1, var_, modulus), c1), modulus)
                let r2 := mod(add(mulmod(a2, var_, modulus), c2), modulus)
                let r3 := mod(add(mulmod(a3, var_, modulus), c3), modulus)
                let r4 := mod(add(mulmod(a4, var_, modulus), c4), modulus)

                acc := or(
                    or(or(shl(224, r0), shl(192, r1)), or(shl(160, r2), shl(128, r3))),
                    shl(96, r4)
                )
            }
        }
    }

    function selectPolyEval(
        uint256 var_,
        uint256[] memory fullPoint,
        uint256 pointOffset,
        uint256 numVariables
    ) internal pure returns (uint256 acc) {
        acc = BabyBearExt5.ONE;
        uint256[] memory expanded = new uint256[](numVariables);
        uint256 current = var_;

        unchecked {
            for (uint256 i = numVariables; i > 0; --i) {
                expanded[i - 1] = current;
                current = BabyBear.mul(current, current);
            }
            for (uint256 i = 0; i < numVariables; ++i) {
                uint256 value = expanded[i];
                uint256 scalar = value == 0 ? BabyBear.MODULUS - 1 : value - 1;
                uint256 term = BabyBearExt5.add(
                    BabyBearExt5.ONE, BabyBearExt5.mulBase(fullPoint[pointOffset + i], scalar)
                );
                acc = BabyBearExt5.mul(acc, term);
            }
        }
    }

    function evaluateBaseRowAsExt5(
        uint256[] calldata flatValues,
        uint256 start,
        uint256 rowLen,
        uint256[] memory point
    ) internal pure returns (uint256) {
        if (point.length == 4 && rowLen == 16) {
            return _evaluateBaseRowDim4(flatValues, start, point);
        }

        uint256[] memory evals = new uint256[](rowLen);
        unchecked {
            for (uint256 i = 0; i < rowLen; ++i) {
                uint256 value = flatValues[start + i];
                validateBase(value);
                evals[i] = BabyBearExt5.fromBase(value);
            }
        }
        if (point.length == 0) {
            return evals[0];
        }
        return evaluateHypercubeMemory(evals, point);
    }

    function evaluateExtensionRowAsExt5(
        uint256[] calldata flatValues,
        uint256 start,
        uint256 rowLen,
        uint256[] memory point
    ) internal pure returns (uint256) {
        if (point.length == 4 && rowLen == 16) {
            return _evaluateExtensionRowDim4(flatValues, start, point);
        }

        uint256[] memory evals = new uint256[](rowLen);
        unchecked {
            for (uint256 i = 0; i < rowLen; ++i) {
                uint256 value = flatValues[start + i];
                validatePackedExt5(value);
                evals[i] = value;
            }
        }
        if (point.length == 0) {
            return evals[0];
        }
        return evaluateHypercubeMemory(evals, point);
    }

    function evaluateExtensionRowAsExt5Blob(
        bytes calldata blob,
        uint256 offset,
        uint256 rowLen,
        uint256[] memory fullPoint,
        uint256 pointOffset,
        uint256 pointLen
    ) internal pure returns (uint256) {
        if (pointLen == 4 && rowLen == 16) {
            return _evaluateExtensionRowDim4BlobWindow(blob, offset, fullPoint, pointOffset);
        }

        uint256[] memory evals = new uint256[](rowLen);
        uint256[] memory point = _slicePoint(fullPoint, pointOffset, pointLen);

        unchecked {
            for (uint256 i = 0; i < rowLen; ++i) {
                uint256 value;
                assembly ("memory-safe") {
                    value := and(
                        calldataload(add(add(blob.offset, offset), mul(20, i))),
                        not(sub(shl(96, 1), 1))
                    )
                }
                validatePackedExt5(value);
                evals[i] = value;
            }
        }

        if (point.length == 0) {
            return evals[0];
        }
        return evaluateHypercubeMemory(evals, point);
    }

    function evaluateFinalValueBlob64Dim6(
        bytes calldata blob,
        uint256 offset,
        uint256[] memory fullPoint,
        uint256 pointOffset
    ) internal pure returns (uint256) {
        uint256 weights = _computeDim4EqWeightsUnpacked(
            fullPoint[pointOffset + 2],
            fullPoint[pointOffset + 3],
            fullPoint[pointOffset + 4],
            fullPoint[pointOffset + 5]
        );
        uint256 a = _evaluateFinalRow16(blob, offset, weights);
        uint256 b = _evaluateFinalRow16(blob, offset + 320, weights);
        uint256 d = _evaluateFinalRow16(blob, offset + 640, weights);
        uint256 e = _evaluateFinalRow16(blob, offset + 960, weights);
        uint256 p1 = fullPoint[pointOffset + 1];
        uint256 left = BabyBearExt5.add(a, BabyBearExt5.mul(BabyBearExt5.sub(b, a), p1));
        uint256 right = BabyBearExt5.add(d, BabyBearExt5.mul(BabyBearExt5.sub(e, d), p1));
        return BabyBearExt5.add(
            left, BabyBearExt5.mul(BabyBearExt5.sub(right, left), fullPoint[pointOffset])
        );
    }

    function evaluateHypercubeMemory(uint256[] memory evals, uint256[] memory point)
        internal
        pure
        returns (uint256)
    {
        return BabyBearExt5.evaluate_hypercube(evals, point);
    }

    function _slicePoint(uint256[] memory fullPoint, uint256 pointOffset, uint256 pointLen)
        private
        pure
        returns (uint256[] memory point)
    {
        point = new uint256[](pointLen);
        unchecked {
            for (uint256 i = 0; i < pointLen; ++i) {
                point[i] = fullPoint[pointOffset + i];
            }
        }
    }

    function _evaluateBaseRowDim4(
        uint256[] calldata flatValues,
        uint256 start,
        uint256[] memory point
    ) private pure returns (uint256) {
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

        validateBase(v0);
        validateBase(v1);
        validateBase(v2);
        validateBase(v3);
        validateBase(v4);
        validateBase(v5);
        validateBase(v6);
        validateBase(v7);
        validateBase(v8);
        validateBase(v9);
        validateBase(v10);
        validateBase(v11);
        validateBase(v12);
        validateBase(v13);
        validateBase(v14);
        validateBase(v15);

        (uint256 r00, uint256 r01, uint256 r02, uint256 r03, uint256 r04) = _unpackCoeffs(point[0]);
        (uint256 r10, uint256 r11, uint256 r12, uint256 r13, uint256 r14) = _unpackCoeffs(point[1]);
        (uint256 r20, uint256 r21, uint256 r22, uint256 r23, uint256 r24) = _unpackCoeffs(point[2]);
        (uint256 r30, uint256 r31, uint256 r32, uint256 r33, uint256 r34) = _unpackCoeffs(point[3]);

        uint256 l0 = _foldOnceBase(v0, v8, r00, r01, r02, r03, r04);
        uint256 l1 = _foldOnceBase(v1, v9, r00, r01, r02, r03, r04);
        uint256 l2 = _foldOnceBase(v2, v10, r00, r01, r02, r03, r04);
        uint256 l3 = _foldOnceBase(v3, v11, r00, r01, r02, r03, r04);
        uint256 l4 = _foldOnceBase(v4, v12, r00, r01, r02, r03, r04);
        uint256 l5 = _foldOnceBase(v5, v13, r00, r01, r02, r03, r04);
        uint256 l6 = _foldOnceBase(v6, v14, r00, r01, r02, r03, r04);
        uint256 l7 = _foldOnceBase(v7, v15, r00, r01, r02, r03, r04);
        uint256 m0 = _foldOnceWithCoeffs(l0, l4, r10, r11, r12, r13, r14);
        uint256 m1 = _foldOnceWithCoeffs(l1, l5, r10, r11, r12, r13, r14);
        uint256 m2 = _foldOnceWithCoeffs(l2, l6, r10, r11, r12, r13, r14);
        uint256 m3 = _foldOnceWithCoeffs(l3, l7, r10, r11, r12, r13, r14);
        uint256 n0 = _foldOnceWithCoeffs(m0, m2, r20, r21, r22, r23, r24);
        uint256 n1 = _foldOnceWithCoeffs(m1, m3, r20, r21, r22, r23, r24);
        return _foldOnceWithCoeffs(n0, n1, r30, r31, r32, r33, r34);
    }

    function _hashAndEvaluateBaseRowDim4PackedPoints(
        uint256[] calldata flatValues,
        uint256 start,
        uint256 p0,
        uint256 p1,
        uint256 p2,
        uint256 p3
    ) internal pure returns (bytes32 digest, uint256 evalValue) {
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

        validateBase(v0);
        validateBase(v1);
        validateBase(v2);
        validateBase(v3);
        validateBase(v4);
        validateBase(v5);
        validateBase(v6);
        validateBase(v7);
        validateBase(v8);
        validateBase(v9);
        validateBase(v10);
        validateBase(v11);
        validateBase(v12);
        validateBase(v13);
        validateBase(v14);
        validateBase(v15);

        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore8(ptr, 0x00)
            mstore(add(ptr, 0x01), shl(224, v0))
            mstore(add(ptr, 0x05), shl(224, v1))
            mstore(add(ptr, 0x09), shl(224, v2))
            mstore(add(ptr, 0x0d), shl(224, v3))
            mstore(add(ptr, 0x11), shl(224, v4))
            mstore(add(ptr, 0x15), shl(224, v5))
            mstore(add(ptr, 0x19), shl(224, v6))
            mstore(add(ptr, 0x1d), shl(224, v7))
            mstore(add(ptr, 0x21), shl(224, v8))
            mstore(add(ptr, 0x25), shl(224, v9))
            mstore(add(ptr, 0x29), shl(224, v10))
            mstore(add(ptr, 0x2d), shl(224, v11))
            mstore(add(ptr, 0x31), shl(224, v12))
            mstore(add(ptr, 0x35), shl(224, v13))
            mstore(add(ptr, 0x39), shl(224, v14))
            mstore(add(ptr, 0x3d), shl(224, v15))
            digest := and(keccak256(ptr, 65), not(sub(shl(96, 1), 1)))
        }

        (uint256 r00, uint256 r01, uint256 r02, uint256 r03, uint256 r04) = _unpackCoeffs(p0);
        (uint256 r10, uint256 r11, uint256 r12, uint256 r13, uint256 r14) = _unpackCoeffs(p1);
        (uint256 r20, uint256 r21, uint256 r22, uint256 r23, uint256 r24) = _unpackCoeffs(p2);
        (uint256 r30, uint256 r31, uint256 r32, uint256 r33, uint256 r34) = _unpackCoeffs(p3);

        uint256 l0 = _foldOnceBase(v0, v8, r00, r01, r02, r03, r04);
        uint256 l1 = _foldOnceBase(v1, v9, r00, r01, r02, r03, r04);
        uint256 l2 = _foldOnceBase(v2, v10, r00, r01, r02, r03, r04);
        uint256 l3 = _foldOnceBase(v3, v11, r00, r01, r02, r03, r04);
        uint256 l4 = _foldOnceBase(v4, v12, r00, r01, r02, r03, r04);
        uint256 l5 = _foldOnceBase(v5, v13, r00, r01, r02, r03, r04);
        uint256 l6 = _foldOnceBase(v6, v14, r00, r01, r02, r03, r04);
        uint256 l7 = _foldOnceBase(v7, v15, r00, r01, r02, r03, r04);
        uint256 m0 = _foldOnceWithCoeffs(l0, l4, r10, r11, r12, r13, r14);
        uint256 m1 = _foldOnceWithCoeffs(l1, l5, r10, r11, r12, r13, r14);
        uint256 m2 = _foldOnceWithCoeffs(l2, l6, r10, r11, r12, r13, r14);
        uint256 m3 = _foldOnceWithCoeffs(l3, l7, r10, r11, r12, r13, r14);
        uint256 n0 = _foldOnceWithCoeffs(m0, m2, r20, r21, r22, r23, r24);
        uint256 n1 = _foldOnceWithCoeffs(m1, m3, r20, r21, r22, r23, r24);
        evalValue = _foldOnceWithCoeffs(n0, n1, r30, r31, r32, r33, r34);
    }

    function _evaluateExtensionRowDim4(
        uint256[] calldata flatValues,
        uint256 start,
        uint256[] memory point
    ) private pure returns (uint256) {
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

            function validateExt5(packed) {
                let highBitMask :=
                    0x8000000080000000800000008000000080000000000000000000000000000000
                let low31Mask := 0x7fffffff7fffffff7fffffff7fffffff7fffffff000000000000000000000000
                let bias := 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000
                if or(
                    or(and(packed, sub(shl(96, 1), 1)), and(packed, highBitMask)),
                    and(add(and(packed, low31Mask), bias), highBitMask)
                ) {
                    mstore(0x00, 0xd53cfe5c00000000000000000000000000000000000000000000000000000000)
                    mstore(0x04, packed)
                    revert(0x00, 0x24)
                }
            }

            validateExt5(v0)
            validateExt5(v1)
            validateExt5(v2)
            validateExt5(v3)
            validateExt5(v4)
            validateExt5(v5)
            validateExt5(v6)
            validateExt5(v7)
            validateExt5(v8)
            validateExt5(v9)
            validateExt5(v10)
            validateExt5(v11)
            validateExt5(v12)
            validateExt5(v13)
            validateExt5(v14)
            validateExt5(v15)
        }

        (uint256 r00, uint256 r01, uint256 r02, uint256 r03, uint256 r04) = _unpackCoeffs(point[0]);
        (uint256 r10, uint256 r11, uint256 r12, uint256 r13, uint256 r14) = _unpackCoeffs(point[1]);
        (uint256 r20, uint256 r21, uint256 r22, uint256 r23, uint256 r24) = _unpackCoeffs(point[2]);
        (uint256 r30, uint256 r31, uint256 r32, uint256 r33, uint256 r34) = _unpackCoeffs(point[3]);

        uint256 l0 = _foldOnceWithCoeffs(v0, v8, r00, r01, r02, r03, r04);
        uint256 l1 = _foldOnceWithCoeffs(v1, v9, r00, r01, r02, r03, r04);
        uint256 l2 = _foldOnceWithCoeffs(v2, v10, r00, r01, r02, r03, r04);
        uint256 l3 = _foldOnceWithCoeffs(v3, v11, r00, r01, r02, r03, r04);
        uint256 l4 = _foldOnceWithCoeffs(v4, v12, r00, r01, r02, r03, r04);
        uint256 l5 = _foldOnceWithCoeffs(v5, v13, r00, r01, r02, r03, r04);
        uint256 l6 = _foldOnceWithCoeffs(v6, v14, r00, r01, r02, r03, r04);
        uint256 l7 = _foldOnceWithCoeffs(v7, v15, r00, r01, r02, r03, r04);
        uint256 m0 = _foldOnceWithCoeffs(l0, l4, r10, r11, r12, r13, r14);
        uint256 m1 = _foldOnceWithCoeffs(l1, l5, r10, r11, r12, r13, r14);
        uint256 m2 = _foldOnceWithCoeffs(l2, l6, r10, r11, r12, r13, r14);
        uint256 m3 = _foldOnceWithCoeffs(l3, l7, r10, r11, r12, r13, r14);
        uint256 n0 = _foldOnceWithCoeffs(m0, m2, r20, r21, r22, r23, r24);
        uint256 n1 = _foldOnceWithCoeffs(m1, m3, r20, r21, r22, r23, r24);
        return _foldOnceWithCoeffs(n0, n1, r30, r31, r32, r33, r34);
    }

    function _hashAndEvaluateBaseRowDim4BlobUnpacked(
        bytes calldata blob,
        uint256 offset,
        uint256 weightsPtr,
        uint256 r00,
        uint256 r01,
        uint256 r02,
        uint256 r03,
        uint256 r04,
        uint256 r10,
        uint256 r11,
        uint256 r12,
        uint256 r13,
        uint256 r14,
        uint256 r20,
        uint256 r21,
        uint256 r22,
        uint256 r23,
        uint256 r24,
        uint256 r30,
        uint256 r31,
        uint256 r32,
        uint256 r33,
        uint256 r34
    ) internal pure returns (bytes32 digest, uint256 evalValue) {
        uint256 src;
        assembly ("memory-safe") {
            src := add(blob.offset, offset)
        }

        uint256 w0;
        uint256 w1;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            function revertField(x) {
                mstore(0x00, 0xf512b67800000000000000000000000000000000000000000000000000000000)
                mstore(0x04, x)
                revert(0x00, 0x24)
            }

            let modulus := 0x78000001
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
            calldatacopy(add(ptr, 0x01), src, 0x40)
            digest := and(keccak256(ptr, 65), not(sub(shl(96, 1), 1)))
        }

        r00;
        r01;
        r02;
        r03;
        r04;
        r10;
        r11;
        r12;
        r13;
        r14;
        r20;
        r21;
        r22;
        r23;
        r24;
        r30;
        r31;
        r32;
        r33;
        r34;

        evalValue = _dotBaseRadix80(weightsPtr, w0, w1);
    }

    function _evaluateExtensionRowDim4BlobWindow(
        bytes calldata blob,
        uint256 offset,
        uint256[] memory fullPoint,
        uint256 pointOffset
    ) private pure returns (uint256) {
        uint256 p0;
        uint256 p1;
        uint256 p2;
        uint256 p3;
        assembly ("memory-safe") {
            let pointBase := add(add(fullPoint, 0x20), shl(5, pointOffset))
            p0 := mload(pointBase)
            p1 := mload(add(pointBase, 0x20))
            p2 := mload(add(pointBase, 0x40))
            p3 := mload(add(pointBase, 0x60))
        }

        return _evaluateExtensionRowDim4BlobPackedPoints(blob, offset, p0, p1, p2, p3);
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

            function validateExt5(packed) {
                let highBitMask :=
                    0x8000000080000000800000008000000080000000000000000000000000000000
                let low31Mask := 0x7fffffff7fffffff7fffffff7fffffff7fffffff000000000000000000000000
                let bias := 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000
                if or(
                    or(and(packed, sub(shl(96, 1), 1)), and(packed, highBitMask)),
                    and(add(and(packed, low31Mask), bias), highBitMask)
                ) {
                    mstore(0x00, 0xd53cfe5c00000000000000000000000000000000000000000000000000000000)
                    mstore(0x04, packed)
                    revert(0x00, 0x24)
                }
            }

            validateExt5(v0)
            validateExt5(v1)
            validateExt5(v2)
            validateExt5(v3)
            validateExt5(v4)
            validateExt5(v5)
            validateExt5(v6)
            validateExt5(v7)
            validateExt5(v8)
            validateExt5(v9)
            validateExt5(v10)
            validateExt5(v11)
            validateExt5(v12)
            validateExt5(v13)
            validateExt5(v14)
            validateExt5(v15)
        }

        (uint256 r00, uint256 r01, uint256 r02, uint256 r03, uint256 r04) = _unpackCoeffs(p0);
        (uint256 r10, uint256 r11, uint256 r12, uint256 r13, uint256 r14) = _unpackCoeffs(p1);
        (uint256 r20, uint256 r21, uint256 r22, uint256 r23, uint256 r24) = _unpackCoeffs(p2);
        (uint256 r30, uint256 r31, uint256 r32, uint256 r33, uint256 r34) = _unpackCoeffs(p3);

        uint256 l0 = _foldOnceWithCoeffs(v0, v8, r00, r01, r02, r03, r04);
        uint256 l1 = _foldOnceWithCoeffs(v1, v9, r00, r01, r02, r03, r04);
        uint256 l2 = _foldOnceWithCoeffs(v2, v10, r00, r01, r02, r03, r04);
        uint256 l3 = _foldOnceWithCoeffs(v3, v11, r00, r01, r02, r03, r04);
        uint256 l4 = _foldOnceWithCoeffs(v4, v12, r00, r01, r02, r03, r04);
        uint256 l5 = _foldOnceWithCoeffs(v5, v13, r00, r01, r02, r03, r04);
        uint256 l6 = _foldOnceWithCoeffs(v6, v14, r00, r01, r02, r03, r04);
        uint256 l7 = _foldOnceWithCoeffs(v7, v15, r00, r01, r02, r03, r04);
        uint256 m0 = _foldOnceWithCoeffs(l0, l4, r10, r11, r12, r13, r14);
        uint256 m1 = _foldOnceWithCoeffs(l1, l5, r10, r11, r12, r13, r14);
        uint256 m2 = _foldOnceWithCoeffs(l2, l6, r10, r11, r12, r13, r14);
        uint256 m3 = _foldOnceWithCoeffs(l3, l7, r10, r11, r12, r13, r14);
        uint256 n0 = _foldOnceWithCoeffs(m0, m2, r20, r21, r22, r23, r24);
        uint256 n1 = _foldOnceWithCoeffs(m1, m3, r20, r21, r22, r23, r24);
        return _foldOnceWithCoeffs(n0, n1, r30, r31, r32, r33, r34);
    }

    function _hashAndEvaluateExtension5RowDim4BlobUnpacked(
        bytes calldata blob,
        uint256 offset,
        uint256 weightsPtr,
        uint256 r00,
        uint256 r01,
        uint256 r02,
        uint256 r03,
        uint256 r04,
        uint256 r10,
        uint256 r11,
        uint256 r12,
        uint256 r13,
        uint256 r14,
        uint256 r20,
        uint256 r21,
        uint256 r22,
        uint256 r23,
        uint256 r24,
        uint256 r30,
        uint256 r31,
        uint256 r32,
        uint256 r33,
        uint256 r34
    ) internal pure returns (bytes32 digest, uint256 evalValue) {
        uint256 src;
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
            src := add(blob.offset, offset)
            let lowMask := not(sub(shl(96, 1), 1))
            let ptr := mload(0x40)
            v0 := and(calldataload(src), lowMask)
            v1 := and(calldataload(add(src, 20)), lowMask)
            v2 := and(calldataload(add(src, 40)), lowMask)
            v3 := and(calldataload(add(src, 60)), lowMask)
            v4 := and(calldataload(add(src, 80)), lowMask)
            v5 := and(calldataload(add(src, 100)), lowMask)
            v6 := and(calldataload(add(src, 120)), lowMask)
            v7 := and(calldataload(add(src, 140)), lowMask)
            v8 := and(calldataload(add(src, 160)), lowMask)
            v9 := and(calldataload(add(src, 180)), lowMask)
            v10 := and(calldataload(add(src, 200)), lowMask)
            v11 := and(calldataload(add(src, 220)), lowMask)
            v12 := and(calldataload(add(src, 240)), lowMask)
            v13 := and(calldataload(add(src, 260)), lowMask)
            v14 := and(calldataload(add(src, 280)), lowMask)
            v15 := and(calldataload(add(src, 300)), lowMask)

            function validateExt5(packed) {
                let highBitMask :=
                    0x8000000080000000800000008000000080000000000000000000000000000000
                let low31Mask := 0x7fffffff7fffffff7fffffff7fffffff7fffffff000000000000000000000000
                let bias := 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000
                if or(
                    and(packed, highBitMask),
                    and(add(and(packed, low31Mask), bias), highBitMask)
                ) {
                    mstore(0x00, 0xd53cfe5c00000000000000000000000000000000000000000000000000000000)
                    mstore(0x04, packed)
                    revert(0x00, 0x24)
                }
            }

            let invalidBits := 0
            invalidBits := or(
                invalidBits,
                or(v0, add(v0, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000))
            )
            invalidBits := or(
                invalidBits,
                or(v1, add(v1, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000))
            )
            invalidBits := or(
                invalidBits,
                or(v2, add(v2, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000))
            )
            invalidBits := or(
                invalidBits,
                or(v3, add(v3, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000))
            )
            invalidBits := or(
                invalidBits,
                or(v4, add(v4, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000))
            )
            invalidBits := or(
                invalidBits,
                or(v5, add(v5, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000))
            )
            invalidBits := or(
                invalidBits,
                or(v6, add(v6, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000))
            )
            invalidBits := or(
                invalidBits,
                or(v7, add(v7, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000))
            )
            invalidBits := or(
                invalidBits,
                or(v8, add(v8, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000))
            )
            invalidBits := or(
                invalidBits,
                or(v9, add(v9, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000))
            )
            invalidBits := or(
                invalidBits,
                or(
                    v10,
                    add(v10, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000)
                )
            )
            invalidBits := or(
                invalidBits,
                or(
                    v11,
                    add(v11, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000)
                )
            )
            invalidBits := or(
                invalidBits,
                or(
                    v12,
                    add(v12, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000)
                )
            )
            invalidBits := or(
                invalidBits,
                or(
                    v13,
                    add(v13, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000)
                )
            )
            invalidBits := or(
                invalidBits,
                or(
                    v14,
                    add(v14, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000)
                )
            )
            invalidBits := or(
                invalidBits,
                or(
                    v15,
                    add(v15, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000)
                )
            )
            if and(
                invalidBits,
                0x8000000080000000800000008000000080000000000000000000000000000000
            ) {
                validateExt5(v0)
                validateExt5(v1)
                validateExt5(v2)
                validateExt5(v3)
                validateExt5(v4)
                validateExt5(v5)
                validateExt5(v6)
                validateExt5(v7)
                validateExt5(v8)
                validateExt5(v9)
                validateExt5(v10)
                validateExt5(v11)
                validateExt5(v12)
                validateExt5(v13)
                validateExt5(v14)
                validateExt5(v15)
            }

            mstore8(ptr, 0x00)
            calldatacopy(add(ptr, 0x01), src, 320)
            digest := and(keccak256(ptr, 321), lowMask)
        }

        r00;
        r01;
        r02;
        r03;
        r04;
        r10;
        r11;
        r12;
        r13;
        r14;
        r20;
        r21;
        r22;
        r23;
        r24;
        r30;
        r31;
        r32;
        r33;
        r34;

        evalValue = _dotExt5Weights16Unpacked(
            weightsPtr, v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15
        );
    }

    function _dotExt5Weights16Unpacked(
        uint256 weightsPtr,
        uint256 v0,
        uint256 v1,
        uint256 v2,
        uint256 v3,
        uint256 v4,
        uint256 v5,
        uint256 v6,
        uint256 v7,
        uint256 v8,
        uint256 v9,
        uint256 v10,
        uint256 v11,
        uint256 v12,
        uint256 v13,
        uint256 v14,
        uint256 v15
    ) internal pure returns (uint256 out) {
        assembly ("memory-safe") {
            let M := 0x78000001
            let c0 := 0
            let c1 := 0
            let c2 := 0
            function accumulate(a, w, d0, d1, d2) -> e0, e1, e2 {
                let u :=
                    or(
                        and(shr(224, a), 0xffffffff),
                        or(
                            shl(51, and(shr(192, a), 0xffffffff)),
                            or(
                                shl(102, and(shr(160, a), 0xffffffff)),
                                or(
                                    shl(153, and(shr(128, a), 0xffffffff)),
                                    shl(204, and(shr(96, a), 0xffffffff))
                                )
                            )
                        )
                    )
                let low := and(u, 0xffff000000001fffe000000003fffc000000007fff800000000ffff)
                let high :=
                    and(shr(16, u), 0xffff000000001fffe000000003fffc000000007fff800000000ffff)
                e0 := add(
                    d0,
                    mulmod(
                        low,
                        mload(w),
                        0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe
                    )
                )
                e1 := add(
                    d1,
                    mulmod(
                        high,
                        mload(add(w, 32)),
                        0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe
                    )
                )
                e2 := add(
                    d2,
                    mulmod(
                        add(low, high),
                        mload(add(w, 64)),
                        0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe
                    )
                )
            }
            c0, c1, c2 := accumulate(v0, add(weightsPtr, 0), c0, c1, c2)
            c0, c1, c2 := accumulate(v1, add(weightsPtr, 96), c0, c1, c2)
            c0, c1, c2 := accumulate(v2, add(weightsPtr, 192), c0, c1, c2)
            c0, c1, c2 := accumulate(v3, add(weightsPtr, 288), c0, c1, c2)
            c0, c1, c2 := accumulate(v4, add(weightsPtr, 384), c0, c1, c2)
            c0, c1, c2 := accumulate(v5, add(weightsPtr, 480), c0, c1, c2)
            c0, c1, c2 := accumulate(v6, add(weightsPtr, 576), c0, c1, c2)
            c0, c1, c2 := accumulate(v7, add(weightsPtr, 672), c0, c1, c2)
            c0, c1, c2 := accumulate(v8, add(weightsPtr, 768), c0, c1, c2)
            c0, c1, c2 := accumulate(v9, add(weightsPtr, 864), c0, c1, c2)
            c0, c1, c2 := accumulate(v10, add(weightsPtr, 960), c0, c1, c2)
            c0, c1, c2 := accumulate(v11, add(weightsPtr, 1056), c0, c1, c2)
            c0, c1, c2 := accumulate(v12, add(weightsPtr, 1152), c0, c1, c2)
            c0, c1, c2 := accumulate(v13, add(weightsPtr, 1248), c0, c1, c2)
            c0, c1, c2 := accumulate(v14, add(weightsPtr, 1344), c0, c1, c2)
            c0, c1, c2 := accumulate(v15, add(weightsPtr, 1440), c0, c1, c2)
            let cross := sub(sub(c2, c0), c1)
            let r0 :=
                mod(
                    add(
                        add(
                            and(shr(0, c0), 0x7ffffffffffff),
                            shl(16, and(shr(0, cross), 0x7ffffffffffff))
                        ),
                        shl(32, and(shr(0, c1), 0x7ffffffffffff))
                    ),
                    M
                )
            let r1 :=
                mod(
                    add(
                        add(
                            and(shr(51, c0), 0x7ffffffffffff),
                            shl(16, and(shr(51, cross), 0x7ffffffffffff))
                        ),
                        shl(32, and(shr(51, c1), 0x7ffffffffffff))
                    ),
                    M
                )
            let r2 :=
                mod(
                    add(
                        add(
                            and(shr(102, c0), 0x7ffffffffffff),
                            shl(16, and(shr(102, cross), 0x7ffffffffffff))
                        ),
                        shl(32, and(shr(102, c1), 0x7ffffffffffff))
                    ),
                    M
                )
            let r3 :=
                mod(
                    add(
                        add(
                            and(shr(153, c0), 0x7ffffffffffff),
                            shl(16, and(shr(153, cross), 0x7ffffffffffff))
                        ),
                        shl(32, and(shr(153, c1), 0x7ffffffffffff))
                    ),
                    M
                )
            let r4 :=
                mod(
                    add(
                        add(
                            and(shr(204, c0), 0x7ffffffffffff),
                            shl(16, and(shr(204, cross), 0x7ffffffffffff))
                        ),
                        shl(32, and(shr(204, c1), 0x7ffffffffffff))
                    ),
                    M
                )
            out := or(
                shl(224, r0),
                or(shl(192, r1), or(shl(160, r2), or(shl(128, r3), shl(96, r4))))
            )
        }
    }

    function _dotBaseRowWeights16Packed(uint256 weightsPtr, uint256 w0, uint256 w1)
        private
        pure
        returns (uint256 out)
    {
        assembly ("memory-safe") {
            let M := 0x78000001
            let mask := 0xffffffff
            function accumulate(scalar, weight, c0, c1, c2, c3, c4) -> d0, d1, d2, d3, d4 {
                d0 := add(c0, mul(scalar, shr(224, weight)))
                d1 := add(c1, mul(scalar, and(shr(192, weight), 0xffffffff)))
                d2 := add(c2, mul(scalar, and(shr(160, weight), 0xffffffff)))
                d3 := add(c3, mul(scalar, and(shr(128, weight), 0xffffffff)))
                d4 := add(c4, mul(scalar, and(shr(96, weight), 0xffffffff)))
            }

            let c0 := 0
            let c1 := 0
            let c2 := 0
            let c3 := 0
            let c4 := 0

            c0, c1, c2, c3, c4 := accumulate(shr(224, w0), mload(weightsPtr), c0, c1, c2, c3, c4)
            c0, c1, c2, c3, c4 :=
                accumulate(
                and(shr(192, w0), mask),
                mload(add(weightsPtr, 0x020)),
                c0,
                c1,
                c2,
                c3,
                c4
            )
            c0, c1, c2, c3, c4 :=
                accumulate(
                and(shr(160, w0), mask),
                mload(add(weightsPtr, 0x040)),
                c0,
                c1,
                c2,
                c3,
                c4
            )
            c0, c1, c2, c3, c4 :=
                accumulate(
                and(shr(128, w0), mask),
                mload(add(weightsPtr, 0x060)),
                c0,
                c1,
                c2,
                c3,
                c4
            )
            c0, c1, c2, c3, c4 :=
                accumulate(
                and(shr(96, w0), mask),
                mload(add(weightsPtr, 0x080)),
                c0,
                c1,
                c2,
                c3,
                c4
            )
            c0, c1, c2, c3, c4 :=
                accumulate(
                and(shr(64, w0), mask),
                mload(add(weightsPtr, 0x0a0)),
                c0,
                c1,
                c2,
                c3,
                c4
            )
            c0, c1, c2, c3, c4 :=
                accumulate(
                and(shr(32, w0), mask),
                mload(add(weightsPtr, 0x0c0)),
                c0,
                c1,
                c2,
                c3,
                c4
            )
            c0, c1, c2, c3, c4 :=
                accumulate(and(w0, mask), mload(add(weightsPtr, 0x0e0)), c0, c1, c2, c3, c4)
            c0, c1, c2, c3, c4 :=
                accumulate(shr(224, w1), mload(add(weightsPtr, 0x100)), c0, c1, c2, c3, c4)
            c0, c1, c2, c3, c4 :=
                accumulate(
                and(shr(192, w1), mask),
                mload(add(weightsPtr, 0x120)),
                c0,
                c1,
                c2,
                c3,
                c4
            )
            c0, c1, c2, c3, c4 :=
                accumulate(
                and(shr(160, w1), mask),
                mload(add(weightsPtr, 0x140)),
                c0,
                c1,
                c2,
                c3,
                c4
            )
            c0, c1, c2, c3, c4 :=
                accumulate(
                and(shr(128, w1), mask),
                mload(add(weightsPtr, 0x160)),
                c0,
                c1,
                c2,
                c3,
                c4
            )
            c0, c1, c2, c3, c4 :=
                accumulate(
                and(shr(96, w1), mask),
                mload(add(weightsPtr, 0x180)),
                c0,
                c1,
                c2,
                c3,
                c4
            )
            c0, c1, c2, c3, c4 :=
                accumulate(
                and(shr(64, w1), mask),
                mload(add(weightsPtr, 0x1a0)),
                c0,
                c1,
                c2,
                c3,
                c4
            )
            c0, c1, c2, c3, c4 :=
                accumulate(
                and(shr(32, w1), mask),
                mload(add(weightsPtr, 0x1c0)),
                c0,
                c1,
                c2,
                c3,
                c4
            )
            c0, c1, c2, c3, c4 :=
                accumulate(and(w1, mask), mload(add(weightsPtr, 0x1e0)), c0, c1, c2, c3, c4)

            out := or(
                or(or(shl(224, mod(c0, M)), shl(192, mod(c1, M))), shl(160, mod(c2, M))),
                or(shl(128, mod(c3, M)), shl(96, mod(c4, M)))
            )
        }
    }

    function _foldOnceBase(
        uint256 a0,
        uint256 a1,
        uint256 r0,
        uint256 r1,
        uint256 r2,
        uint256 r3,
        uint256 r4
    ) private pure returns (uint256 out) {
        assembly ("memory-safe") {
            let M := 0x78000001
            let d := sub(add(a1, M), a0)
            let c0 := mod(add(a0, mul(r0, d)), M)
            let c1 := mod(mul(r1, d), M)
            let c2 := mod(mul(r2, d), M)
            let c3 := mod(mul(r3, d), M)
            let c4 := mod(mul(r4, d), M)
            out := or(
                or(or(shl(224, c0), shl(192, c1)), or(shl(160, c2), shl(128, c3))),
                shl(96, c4)
            )
        }
    }

    function _foldOnceWithCoeffs(
        uint256 a0,
        uint256 a1,
        uint256 r0,
        uint256 r1,
        uint256 r2,
        uint256 r3,
        uint256 r4
    ) private pure returns (uint256 out) {
        unchecked {
            uint256 a00 = a0 >> 224;
            uint256 a01 = (a0 >> 192) & 0xffffffff;
            uint256 a02 = (a0 >> 160) & 0xffffffff;
            uint256 a03 = (a0 >> 128) & 0xffffffff;
            uint256 a04 = (a0 >> 96) & 0xffffffff;

            uint256 d0 = (a1 >> 224) + BabyBear.MODULUS - a00;
            uint256 d1 = ((a1 >> 192) & 0xffffffff) + BabyBear.MODULUS - a01;
            uint256 d2 = ((a1 >> 160) & 0xffffffff) + BabyBear.MODULUS - a02;
            uint256 d3 = ((a1 >> 128) & 0xffffffff) + BabyBear.MODULUS - a03;
            uint256 d4 = ((a1 >> 96) & 0xffffffff) + BabyBear.MODULUS - a04;

            uint256 c0 = r0 * d0;
            uint256 c1 = r0 * d1 + r1 * d0;
            uint256 c2 = r0 * d2 + r1 * d1 + r2 * d0;
            uint256 c3 = r0 * d3 + r1 * d2 + r2 * d1 + r3 * d0;
            uint256 c4 = r0 * d4 + r1 * d3 + r2 * d2 + r3 * d1 + r4 * d0;
            uint256 c5 = r1 * d4 + r2 * d3 + r3 * d2 + r4 * d1;
            uint256 c6 = r2 * d4 + r3 * d3 + r4 * d2;
            uint256 c7 = r3 * d4 + r4 * d3;
            uint256 c8 = r4 * d4;
            uint256 rOut0 = (a00 + c0 + 2 * c5) % BabyBear.MODULUS;
            uint256 rOut1 = (a01 + c1 + 2 * c6) % BabyBear.MODULUS;
            uint256 rOut2 = (a02 + c2 + 2 * c7) % BabyBear.MODULUS;
            uint256 rOut3 = (a03 + c3 + 2 * c8) % BabyBear.MODULUS;
            uint256 rOut4 = (a04 + c4) % BabyBear.MODULUS;

            out = (rOut0 << 224) | (rOut1 << 192) | (rOut2 << 160) | (rOut3 << 128) | (rOut4 << 96);
        }
    }

    function _unpackCoeffs(uint256 packed)
        internal
        pure
        returns (uint256 c0, uint256 c1, uint256 c2, uint256 c3, uint256 c4)
    {
        c0 = packed >> 224;
        c1 = (packed >> 192) & 0xffffffff;
        c2 = (packed >> 160) & 0xffffffff;
        c3 = (packed >> 128) & 0xffffffff;
        c4 = (packed >> 96) & 0xffffffff;
    }

    function _prepareRowWeights(uint256 packedPtr) internal pure returns (uint256 ptr) {
        assembly ("memory-safe") {
            ptr := mload(0x40)
            mstore(0x40, add(ptr, 1536))
            for { let i := 0 } lt(i, 16) { i := add(i, 1) } {
                let a := mload(add(packedPtr, shl(5, i)))
                let dst := add(ptr, mul(i, 96))
                let u :=
                    or(
                        and(shr(224, a), 0xffffffff),
                        or(
                            shl(51, and(shr(192, a), 0xffffffff)),
                            or(
                                shl(102, and(shr(160, a), 0xffffffff)),
                                or(
                                    shl(153, and(shr(128, a), 0xffffffff)),
                                    shl(204, and(shr(96, a), 0xffffffff))
                                )
                            )
                        )
                    )
                let low := and(u, 0xffff000000001fffe000000003fffc000000007fff800000000ffff)
                let high :=
                    and(shr(16, u), 0xffff000000001fffe000000003fffc000000007fff800000000ffff)
                mstore(dst, low)
                mstore(add(dst, 32), high)
                mstore(add(dst, 64), add(low, high))
            }
        }
    }

    function _prepareBaseRadix80(uint256 packedPtr) internal pure returns (uint256 ptr) {
        assembly ("memory-safe") {
            ptr := mload(0x40)
            mstore(0x40, add(ptr, 0x400))
            for { let i := 0 } lt(i, 16) { i := add(i, 1) } {
                let w := mload(add(packedPtr, shl(5, i)))
                let dst := add(ptr, shl(6, i))
                mstore(
                    dst,
                    or(
                        or(shr(224, w), shl(80, and(shr(192, w), 0xffffffff))),
                        shl(160, and(shr(160, w), 0xffffffff))
                    )
                )
                mstore(
                    add(dst, 32),
                    or(and(shr(128, w), 0xffffffff), shl(80, and(shr(96, w), 0xffffffff)))
                )
            }
        }
    }

    function _dotBaseRadix80(uint256 weightsPtr, uint256 w0, uint256 w1)
        internal
        pure
        returns (uint256 out)
    {
        assembly ("memory-safe") {
            let a := 0
            let b := 0
            function accumulate(s, w, ca, cb) -> aa, bb {
                aa := add(ca, mul(s, mload(w)))
                bb := add(cb, mul(s, mload(add(w, 32))))
            }
            a, b := accumulate(and(shr(224, w0), 0xffffffff), add(weightsPtr, 0), a, b)
            a, b := accumulate(and(shr(192, w0), 0xffffffff), add(weightsPtr, 64), a, b)
            a, b := accumulate(and(shr(160, w0), 0xffffffff), add(weightsPtr, 128), a, b)
            a, b := accumulate(and(shr(128, w0), 0xffffffff), add(weightsPtr, 192), a, b)
            a, b := accumulate(and(shr(96, w0), 0xffffffff), add(weightsPtr, 256), a, b)
            a, b := accumulate(and(shr(64, w0), 0xffffffff), add(weightsPtr, 320), a, b)
            a, b := accumulate(and(shr(32, w0), 0xffffffff), add(weightsPtr, 384), a, b)
            a, b := accumulate(and(shr(0, w0), 0xffffffff), add(weightsPtr, 448), a, b)
            a, b := accumulate(and(shr(224, w1), 0xffffffff), add(weightsPtr, 512), a, b)
            a, b := accumulate(and(shr(192, w1), 0xffffffff), add(weightsPtr, 576), a, b)
            a, b := accumulate(and(shr(160, w1), 0xffffffff), add(weightsPtr, 640), a, b)
            a, b := accumulate(and(shr(128, w1), 0xffffffff), add(weightsPtr, 704), a, b)
            a, b := accumulate(and(shr(96, w1), 0xffffffff), add(weightsPtr, 768), a, b)
            a, b := accumulate(and(shr(64, w1), 0xffffffff), add(weightsPtr, 832), a, b)
            a, b := accumulate(and(shr(32, w1), 0xffffffff), add(weightsPtr, 896), a, b)
            a, b := accumulate(and(shr(0, w1), 0xffffffff), add(weightsPtr, 960), a, b)
            let M := 0x78000001
            let mask := sub(shl(80, 1), 1)
            out := or(
                or(
                    or(shl(224, mod(and(a, mask), M)), shl(192, mod(and(shr(80, a), mask), M))),
                    shl(160, mod(shr(160, a), M))
                ),
                or(shl(128, mod(and(b, mask), M)), shl(96, mod(shr(80, b), M)))
            )
        }
    }

    function _evaluateFinalRow16(bytes calldata blob, uint256 offset, uint256 weightsPtr)
        private
        pure
        returns (uint256 out)
    {
        assembly ("memory-safe") {
            let src := add(blob.offset, offset)
            let M := 0x78000001
            let c0 := 0
            let c1 := 0
            let c2 := 0
            function accumulate(a, w, d0, d1, d2) -> e0, e1, e2 {
                let u :=
                    or(
                        and(shr(224, a), 0xffffffff),
                        or(
                            shl(51, and(shr(192, a), 0xffffffff)),
                            or(
                                shl(102, and(shr(160, a), 0xffffffff)),
                                or(
                                    shl(153, and(shr(128, a), 0xffffffff)),
                                    shl(204, and(shr(96, a), 0xffffffff))
                                )
                            )
                        )
                    )
                let low := and(u, 0xffff000000001fffe000000003fffc000000007fff800000000ffff)
                let high :=
                    and(shr(16, u), 0xffff000000001fffe000000003fffc000000007fff800000000ffff)
                e0 := add(
                    d0,
                    mulmod(
                        low,
                        mload(w),
                        0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe
                    )
                )
                e1 := add(
                    d1,
                    mulmod(
                        high,
                        mload(add(w, 32)),
                        0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe
                    )
                )
                e2 := add(
                    d2,
                    mulmod(
                        add(low, high),
                        mload(add(w, 64)),
                        0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe
                    )
                )
            }
            c0, c1, c2 :=
                accumulate(
                and(calldataload(add(src, 0)), not(sub(shl(96, 1), 1))),
                add(weightsPtr, 0),
                c0,
                c1,
                c2
            )
            c0, c1, c2 :=
                accumulate(
                and(calldataload(add(src, 20)), not(sub(shl(96, 1), 1))),
                add(weightsPtr, 96),
                c0,
                c1,
                c2
            )
            c0, c1, c2 :=
                accumulate(
                and(calldataload(add(src, 40)), not(sub(shl(96, 1), 1))),
                add(weightsPtr, 192),
                c0,
                c1,
                c2
            )
            c0, c1, c2 :=
                accumulate(
                and(calldataload(add(src, 60)), not(sub(shl(96, 1), 1))),
                add(weightsPtr, 288),
                c0,
                c1,
                c2
            )
            c0, c1, c2 :=
                accumulate(
                and(calldataload(add(src, 80)), not(sub(shl(96, 1), 1))),
                add(weightsPtr, 384),
                c0,
                c1,
                c2
            )
            c0, c1, c2 :=
                accumulate(
                and(calldataload(add(src, 100)), not(sub(shl(96, 1), 1))),
                add(weightsPtr, 480),
                c0,
                c1,
                c2
            )
            c0, c1, c2 :=
                accumulate(
                and(calldataload(add(src, 120)), not(sub(shl(96, 1), 1))),
                add(weightsPtr, 576),
                c0,
                c1,
                c2
            )
            c0, c1, c2 :=
                accumulate(
                and(calldataload(add(src, 140)), not(sub(shl(96, 1), 1))),
                add(weightsPtr, 672),
                c0,
                c1,
                c2
            )
            c0, c1, c2 :=
                accumulate(
                and(calldataload(add(src, 160)), not(sub(shl(96, 1), 1))),
                add(weightsPtr, 768),
                c0,
                c1,
                c2
            )
            c0, c1, c2 :=
                accumulate(
                and(calldataload(add(src, 180)), not(sub(shl(96, 1), 1))),
                add(weightsPtr, 864),
                c0,
                c1,
                c2
            )
            c0, c1, c2 :=
                accumulate(
                and(calldataload(add(src, 200)), not(sub(shl(96, 1), 1))),
                add(weightsPtr, 960),
                c0,
                c1,
                c2
            )
            c0, c1, c2 :=
                accumulate(
                and(calldataload(add(src, 220)), not(sub(shl(96, 1), 1))),
                add(weightsPtr, 1056),
                c0,
                c1,
                c2
            )
            c0, c1, c2 :=
                accumulate(
                and(calldataload(add(src, 240)), not(sub(shl(96, 1), 1))),
                add(weightsPtr, 1152),
                c0,
                c1,
                c2
            )
            c0, c1, c2 :=
                accumulate(
                and(calldataload(add(src, 260)), not(sub(shl(96, 1), 1))),
                add(weightsPtr, 1248),
                c0,
                c1,
                c2
            )
            c0, c1, c2 :=
                accumulate(
                and(calldataload(add(src, 280)), not(sub(shl(96, 1), 1))),
                add(weightsPtr, 1344),
                c0,
                c1,
                c2
            )
            c0, c1, c2 :=
                accumulate(
                and(calldataload(add(src, 300)), not(sub(shl(96, 1), 1))),
                add(weightsPtr, 1440),
                c0,
                c1,
                c2
            )
            let cross := sub(sub(c2, c0), c1)
            let r0 :=
                mod(
                    add(
                        add(
                            and(shr(0, c0), 0x7ffffffffffff),
                            shl(16, and(shr(0, cross), 0x7ffffffffffff))
                        ),
                        shl(32, and(shr(0, c1), 0x7ffffffffffff))
                    ),
                    M
                )
            let r1 :=
                mod(
                    add(
                        add(
                            and(shr(51, c0), 0x7ffffffffffff),
                            shl(16, and(shr(51, cross), 0x7ffffffffffff))
                        ),
                        shl(32, and(shr(51, c1), 0x7ffffffffffff))
                    ),
                    M
                )
            let r2 :=
                mod(
                    add(
                        add(
                            and(shr(102, c0), 0x7ffffffffffff),
                            shl(16, and(shr(102, cross), 0x7ffffffffffff))
                        ),
                        shl(32, and(shr(102, c1), 0x7ffffffffffff))
                    ),
                    M
                )
            let r3 :=
                mod(
                    add(
                        add(
                            and(shr(153, c0), 0x7ffffffffffff),
                            shl(16, and(shr(153, cross), 0x7ffffffffffff))
                        ),
                        shl(32, and(shr(153, c1), 0x7ffffffffffff))
                    ),
                    M
                )
            let r4 :=
                mod(
                    add(
                        add(
                            and(shr(204, c0), 0x7ffffffffffff),
                            shl(16, and(shr(204, cross), 0x7ffffffffffff))
                        ),
                        shl(32, and(shr(204, c1), 0x7ffffffffffff))
                    ),
                    M
                )
            out := or(
                shl(224, r0),
                or(shl(192, r1), or(shl(160, r2), or(shl(128, r3), shl(96, r4))))
            )
        }
    }

    function _prepareHornerRadix64(bytes calldata blob, uint256 offset)
        internal
        pure
        returns (uint256 ptr)
    {
        assembly ("memory-safe") {
            ptr := mload(0x40)
            mstore(0x40, add(ptr, 4096))
            let src := add(blob.offset, offset)
            for { let i := 0 } lt(i, 64) { i := add(i, 1) } {
                let w := calldataload(add(src, mul(i, 20)))
                let dst := add(ptr, shl(6, i))
                mstore(
                    dst,
                    or(
                        or(shr(224, w), shl(64, and(shr(192, w), 0xffffffff))),
                        or(
                            shl(128, and(shr(160, w), 0xffffffff)),
                            shl(192, and(shr(128, w), 0xffffffff))
                        )
                    )
                )
                mstore(add(dst, 32), and(shr(96, w), 0xffffffff))
            }
        }
    }

    function _hornerRadix64(uint256 ptr, uint256 x) internal pure returns (uint256 out) {
        assembly ("memory-safe") {
            let M := 0x78000001
            let mask := 0xffffffffffffffff
            let a := 0
            let b := 0
            let x2 := mulmod(x, x, M)
            let x3 := mulmod(x2, x, M)
            let x4 := mulmod(x2, x2, M)
            for { let src := add(ptr, 4096) } gt(src, ptr) { } {
                src := sub(src, 256)
                let v :=
                    add(
                        add(
                            add(
                                add(mul(a, x4), mul(mload(add(src, 192)), x3)),
                                mul(mload(add(src, 128)), x2)
                            ),
                            mul(mload(add(src, 64)), x)
                        ),
                        mload(src)
                    )
                b := mod(
                    add(
                        add(
                            add(
                                add(mul(b, x4), mul(mload(add(src, 224)), x3)),
                                mul(mload(add(src, 160)), x2)
                            ),
                            mul(mload(add(src, 96)), x)
                        ),
                        mload(add(src, 32))
                    ),
                    M
                )
                a := or(
                    or(mod(and(v, mask), M), shl(64, mod(and(shr(64, v), mask), M))),
                    or(shl(128, mod(and(shr(128, v), mask), M)), shl(192, mod(shr(192, v), M)))
                )
            }
            out := or(
                or(
                    or(shl(224, and(a, 0xffffffff)), shl(192, and(shr(64, a), 0xffffffff))),
                    or(shl(160, and(shr(128, a), 0xffffffff)), shl(128, shr(192, a)))
                ),
                shl(96, b)
            )
        }
    }

    function _checkHornerRadix64(
        uint256 ptr,
        uint256 v0,
        uint256 v1,
        uint256 v2,
        uint256 v3,
        uint256 v4,
        uint256 rowEvalsBase,
        uint256 rowOffset
    ) internal pure returns (uint256 mismatchPlusOne) {
        uint256 expected0;
        uint256 expected1;
        uint256 expected2;
        uint256 expected3;
        uint256 expected4;
        assembly ("memory-safe") {
            let evalBase := add(rowEvalsBase, shl(5, rowOffset))
            expected0 := mload(evalBase)
            expected1 := mload(add(evalBase, 0x20))
            expected2 := mload(add(evalBase, 0x40))
            expected3 := mload(add(evalBase, 0x60))
            expected4 := mload(add(evalBase, 0x80))
        }
        if (_hornerRadix64(ptr, v0) != expected0) return 1;
        if (_hornerRadix64(ptr, v1) != expected1) return 2;
        if (_hornerRadix64(ptr, v2) != expected2) return 3;
        if (_hornerRadix64(ptr, v3) != expected3) return 4;
        if (_hornerRadix64(ptr, v4) != expected4) return 5;
    }

    function _hashAndFoldExtensionRow(
        bytes calldata blob,
        uint256 offset,
        uint256 weightsPtr,
        uint256 claim,
        uint256 challengePtr
    ) internal pure returns (bytes32 digest, uint256 evalValue) {
        uint256 src;
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
            src := add(blob.offset, offset)
            let lowMask := not(sub(shl(96, 1), 1))
            let ptr := mload(0x40)
            v0 := and(calldataload(src), lowMask)
            v1 := and(calldataload(add(src, 20)), lowMask)
            v2 := and(calldataload(add(src, 40)), lowMask)
            v3 := and(calldataload(add(src, 60)), lowMask)
            v4 := and(calldataload(add(src, 80)), lowMask)
            v5 := and(calldataload(add(src, 100)), lowMask)
            v6 := and(calldataload(add(src, 120)), lowMask)
            v7 := and(calldataload(add(src, 140)), lowMask)
            v8 := and(calldataload(add(src, 160)), lowMask)
            v9 := and(calldataload(add(src, 180)), lowMask)
            v10 := and(calldataload(add(src, 200)), lowMask)
            v11 := and(calldataload(add(src, 220)), lowMask)
            v12 := and(calldataload(add(src, 240)), lowMask)
            v13 := and(calldataload(add(src, 260)), lowMask)
            v14 := and(calldataload(add(src, 280)), lowMask)
            v15 := and(calldataload(add(src, 300)), lowMask)

            function validateExt5(packed) {
                let highBitMask :=
                    0x8000000080000000800000008000000080000000000000000000000000000000
                let low31Mask := 0x7fffffff7fffffff7fffffff7fffffff7fffffff000000000000000000000000
                let bias := 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000
                if or(
                    and(packed, highBitMask),
                    and(add(and(packed, low31Mask), bias), highBitMask)
                ) {
                    mstore(0x00, 0xd53cfe5c00000000000000000000000000000000000000000000000000000000)
                    mstore(0x04, packed)
                    revert(0x00, 0x24)
                }
            }

            let invalidBits := 0
            invalidBits := or(
                invalidBits,
                or(v0, add(v0, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000))
            )
            invalidBits := or(
                invalidBits,
                or(v1, add(v1, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000))
            )
            invalidBits := or(
                invalidBits,
                or(v2, add(v2, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000))
            )
            invalidBits := or(
                invalidBits,
                or(v3, add(v3, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000))
            )
            invalidBits := or(
                invalidBits,
                or(v4, add(v4, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000))
            )
            invalidBits := or(
                invalidBits,
                or(v5, add(v5, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000))
            )
            invalidBits := or(
                invalidBits,
                or(v6, add(v6, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000))
            )
            invalidBits := or(
                invalidBits,
                or(v7, add(v7, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000))
            )
            invalidBits := or(
                invalidBits,
                or(v8, add(v8, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000))
            )
            invalidBits := or(
                invalidBits,
                or(v9, add(v9, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000))
            )
            invalidBits := or(
                invalidBits,
                or(
                    v10,
                    add(v10, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000)
                )
            )
            invalidBits := or(
                invalidBits,
                or(
                    v11,
                    add(v11, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000)
                )
            )
            invalidBits := or(
                invalidBits,
                or(
                    v12,
                    add(v12, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000)
                )
            )
            invalidBits := or(
                invalidBits,
                or(
                    v13,
                    add(v13, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000)
                )
            )
            invalidBits := or(
                invalidBits,
                or(
                    v14,
                    add(v14, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000)
                )
            )
            invalidBits := or(
                invalidBits,
                or(
                    v15,
                    add(v15, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000)
                )
            )
            if and(
                invalidBits,
                0x8000000080000000800000008000000080000000000000000000000000000000
            ) {
                validateExt5(v0)
                validateExt5(v1)
                validateExt5(v2)
                validateExt5(v3)
                validateExt5(v4)
                validateExt5(v5)
                validateExt5(v6)
                validateExt5(v7)
                validateExt5(v8)
                validateExt5(v9)
                validateExt5(v10)
                validateExt5(v11)
                validateExt5(v12)
                validateExt5(v13)
                validateExt5(v14)
                validateExt5(v15)
            }

            mstore8(ptr, 0x00)
            calldatacopy(add(ptr, 0x01), src, 320)
            digest := and(keccak256(ptr, 321), lowMask)
        }

        evalValue = _dotExt5Weights17Unpacked(
            weightsPtr,
            v0,
            v1,
            v2,
            v3,
            v4,
            v5,
            v6,
            v7,
            v8,
            v9,
            v10,
            v11,
            v12,
            v13,
            v14,
            v15,
            claim,
            challengePtr
        );
    }

    function _dotExt5Weights17Unpacked(
        uint256 weightsPtr,
        uint256 v0,
        uint256 v1,
        uint256 v2,
        uint256 v3,
        uint256 v4,
        uint256 v5,
        uint256 v6,
        uint256 v7,
        uint256 v8,
        uint256 v9,
        uint256 v10,
        uint256 v11,
        uint256 v12,
        uint256 v13,
        uint256 v14,
        uint256 v15,
        uint256 claim,
        uint256 challengePtr
    ) internal pure returns (uint256 out) {
        assembly ("memory-safe") {
            let M := 0x78000001
            let c0 := 0
            let c1 := 0
            let c2 := 0
            function accumulate(a, w, d0, d1, d2) -> e0, e1, e2 {
                let u :=
                    or(
                        and(shr(224, a), 0xffffffff),
                        or(
                            shl(51, and(shr(192, a), 0xffffffff)),
                            or(
                                shl(102, and(shr(160, a), 0xffffffff)),
                                or(
                                    shl(153, and(shr(128, a), 0xffffffff)),
                                    shl(204, and(shr(96, a), 0xffffffff))
                                )
                            )
                        )
                    )
                let low := and(u, 0xffff000000001fffe000000003fffc000000007fff800000000ffff)
                let high :=
                    and(shr(16, u), 0xffff000000001fffe000000003fffc000000007fff800000000ffff)
                e0 := add(
                    d0,
                    mulmod(
                        low,
                        mload(w),
                        0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe
                    )
                )
                e1 := add(
                    d1,
                    mulmod(
                        high,
                        mload(add(w, 32)),
                        0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe
                    )
                )
                e2 := add(
                    d2,
                    mulmod(
                        add(low, high),
                        mload(add(w, 64)),
                        0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe
                    )
                )
            }
            c0, c1, c2 := accumulate(claim, challengePtr, c0, c1, c2)
            c0, c1, c2 := accumulate(v0, add(weightsPtr, 0), c0, c1, c2)
            c0, c1, c2 := accumulate(v1, add(weightsPtr, 96), c0, c1, c2)
            c0, c1, c2 := accumulate(v2, add(weightsPtr, 192), c0, c1, c2)
            c0, c1, c2 := accumulate(v3, add(weightsPtr, 288), c0, c1, c2)
            c0, c1, c2 := accumulate(v4, add(weightsPtr, 384), c0, c1, c2)
            c0, c1, c2 := accumulate(v5, add(weightsPtr, 480), c0, c1, c2)
            c0, c1, c2 := accumulate(v6, add(weightsPtr, 576), c0, c1, c2)
            c0, c1, c2 := accumulate(v7, add(weightsPtr, 672), c0, c1, c2)
            c0, c1, c2 := accumulate(v8, add(weightsPtr, 768), c0, c1, c2)
            c0, c1, c2 := accumulate(v9, add(weightsPtr, 864), c0, c1, c2)
            c0, c1, c2 := accumulate(v10, add(weightsPtr, 960), c0, c1, c2)
            c0, c1, c2 := accumulate(v11, add(weightsPtr, 1056), c0, c1, c2)
            c0, c1, c2 := accumulate(v12, add(weightsPtr, 1152), c0, c1, c2)
            c0, c1, c2 := accumulate(v13, add(weightsPtr, 1248), c0, c1, c2)
            c0, c1, c2 := accumulate(v14, add(weightsPtr, 1344), c0, c1, c2)
            c0, c1, c2 := accumulate(v15, add(weightsPtr, 1440), c0, c1, c2)
            let cross := sub(sub(c2, c0), c1)
            let r0 :=
                mod(
                    add(
                        add(
                            and(shr(0, c0), 0x7ffffffffffff),
                            shl(16, and(shr(0, cross), 0x7ffffffffffff))
                        ),
                        shl(32, and(shr(0, c1), 0x7ffffffffffff))
                    ),
                    M
                )
            let r1 :=
                mod(
                    add(
                        add(
                            and(shr(51, c0), 0x7ffffffffffff),
                            shl(16, and(shr(51, cross), 0x7ffffffffffff))
                        ),
                        shl(32, and(shr(51, c1), 0x7ffffffffffff))
                    ),
                    M
                )
            let r2 :=
                mod(
                    add(
                        add(
                            and(shr(102, c0), 0x7ffffffffffff),
                            shl(16, and(shr(102, cross), 0x7ffffffffffff))
                        ),
                        shl(32, and(shr(102, c1), 0x7ffffffffffff))
                    ),
                    M
                )
            let r3 :=
                mod(
                    add(
                        add(
                            and(shr(153, c0), 0x7ffffffffffff),
                            shl(16, and(shr(153, cross), 0x7ffffffffffff))
                        ),
                        shl(32, and(shr(153, c1), 0x7ffffffffffff))
                    ),
                    M
                )
            let r4 :=
                mod(
                    add(
                        add(
                            and(shr(204, c0), 0x7ffffffffffff),
                            shl(16, and(shr(204, cross), 0x7ffffffffffff))
                        ),
                        shl(32, and(shr(204, c1), 0x7ffffffffffff))
                    ),
                    M
                )
            out := or(
                shl(224, r0),
                or(shl(192, r1), or(shl(160, r2), or(shl(128, r3), shl(96, r4))))
            )
        }
    }

    function _prepareRowChallenge(uint256 a) internal pure returns (uint256 ptr) {
        assembly ("memory-safe") {
            ptr := mload(0x40)
            mstore(0x40, add(ptr, 96))
            let u :=
                or(
                    and(shr(224, a), 0xffffffff),
                    or(
                        shl(51, and(shr(192, a), 0xffffffff)),
                        or(
                            shl(102, and(shr(160, a), 0xffffffff)),
                            or(
                                shl(153, and(shr(128, a), 0xffffffff)),
                                shl(204, and(shr(96, a), 0xffffffff))
                            )
                        )
                    )
                )
            let low := and(u, 0xffff000000001fffe000000003fffc000000007fff800000000ffff)
            let high := and(shr(16, u), 0xffff000000001fffe000000003fffc000000007fff800000000ffff)
            mstore(ptr, low)
            mstore(add(ptr, 32), high)
            mstore(add(ptr, 64), add(low, high))
        }
    }
}
