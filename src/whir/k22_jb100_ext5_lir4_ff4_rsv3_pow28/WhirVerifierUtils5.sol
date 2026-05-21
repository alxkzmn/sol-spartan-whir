// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { LibSort } from "solady/utils/LibSort.sol";

import { KoalaBear } from "../../field/KoalaBear.sol";
import { KoalaBearExt5 } from "../../field/KoalaBearExt5.sol";
import { KeccakChallenger } from "../../transcript/KeccakChallenger.sol";

library WhirVerifierUtils5 {
    using KeccakChallenger for KeccakChallenger.State;

    error BaseFieldElementOutOfRange(uint256 value);
    error PackedExtensionElementOutOfRange(uint256 value);
    error NotPowerOfTwo(uint256 value);

    function observeValidatedExt5(KeccakChallenger.State memory challenger, uint256 packed)
        internal
        pure
    {
        challenger.observeValidatedPackedExt5(packed);
    }

    function sampleExt5(KeccakChallenger.State memory challenger) internal pure returns (uint256) {
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
        uint256 q0 = KoalaBearExt5.sub(KoalaBearExt5.ONE, p0);
        uint256 q1 = KoalaBearExt5.sub(KoalaBearExt5.ONE, p1);
        uint256 q2 = KoalaBearExt5.sub(KoalaBearExt5.ONE, p2);
        uint256 q3 = KoalaBearExt5.sub(KoalaBearExt5.ONE, p3);

        uint256 a00 = KoalaBearExt5.mul(q0, q1);
        uint256 a01 = KoalaBearExt5.mul(q0, p1);
        uint256 a10 = KoalaBearExt5.mul(p0, q1);
        uint256 a11 = KoalaBearExt5.mul(p0, p1);

        uint256 b000 = KoalaBearExt5.mul(a00, q2);
        uint256 b001 = KoalaBearExt5.mul(a00, p2);
        uint256 b010 = KoalaBearExt5.mul(a01, q2);
        uint256 b011 = KoalaBearExt5.mul(a01, p2);
        uint256 b100 = KoalaBearExt5.mul(a10, q2);
        uint256 b101 = KoalaBearExt5.mul(a10, p2);
        uint256 b110 = KoalaBearExt5.mul(a11, q2);
        uint256 b111 = KoalaBearExt5.mul(a11, p2);

        assembly ("memory-safe") {
            weightsPtr := mload(0x40)
            mstore(0x40, add(weightsPtr, 0x200))
        }

        _storeDim4EqWeightPair(weightsPtr, 0x000, b000, q3, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x040, b001, q3, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x080, b010, q3, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x0c0, b011, q3, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x100, b100, q3, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x140, b101, q3, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x180, b110, q3, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x1c0, b111, q3, p3);
    }

    function _storeDim4EqWeightPair(
        uint256 weightsPtr,
        uint256 offset,
        uint256 prefix,
        uint256 q3,
        uint256 p3
    ) private pure {
        uint256 w0 = KoalaBearExt5.mul(prefix, q3);
        uint256 w1 = KoalaBearExt5.mul(prefix, p3);
        assembly ("memory-safe") {
            mstore(add(weightsPtr, offset), w0)
            mstore(add(add(weightsPtr, offset), 0x20), w1)
        }
    }

    function _computeDim4EqWeightsUnpacked(uint256 p0, uint256 p1, uint256 p2, uint256 p3)
        internal
        pure
        returns (uint256 unpackedPtr)
    {
        uint256 packedPtr = _computeDim4EqWeights(p0, p1, p2, p3);
        assembly ("memory-safe") {
            unpackedPtr := mload(0x40)
            mstore(0x40, add(unpackedPtr, 0xa00))

            for {
                let src := packedPtr
                let dst := unpackedPtr
            } lt(src, add(packedPtr, 0x200)) {
                src := add(src, 0x20)
                dst := add(dst, 0xa0)
            } {
                let packed := mload(src)
                mstore(dst, shr(224, packed))
                mstore(add(dst, 0x20), and(shr(192, packed), 0xffffffff))
                mstore(add(dst, 0x40), and(shr(160, packed), 0xffffffff))
                mstore(add(dst, 0x60), and(shr(128, packed), 0xffffffff))
                mstore(add(dst, 0x80), and(shr(96, packed), 0xffffffff))
            }
        }
    }

    function validateBase(uint256 value) internal pure {
        if (value >= KoalaBear.MODULUS) {
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
        KoalaBearExt5.validatePacked(packed);
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
                current = KoalaBearExt5.square(current);
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
            let modulus := 0x7f000001
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
            let modulus := 0x7f000001
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

    function hornerBaseBlob64Pairwise(bytes calldata blob, uint256 offset, uint256 var_)
        internal
        pure
        returns (uint256 acc)
    {
        assembly ("memory-safe") {
            let modulus := 0x7f000001
            let mask := 0xffffffff
            let low96Mask := sub(shl(96, 1), 1)
            let var2 := mulmod(var_, var_, modulus)

            let src := add(add(blob.offset, offset), 1280)
            let end := add(blob.offset, offset)

            for { } gt(src, end) { } {
                src := sub(src, 20)
                let hi := and(calldataload(src), not(low96Mask))
                src := sub(src, 20)
                let lo := and(calldataload(src), not(low96Mask))

                let a0 := shr(224, acc)
                let a1 := and(shr(192, acc), mask)
                let a2 := and(shr(160, acc), mask)
                let a3 := and(shr(128, acc), mask)
                let a4 := and(shr(96, acc), mask)

                let h0 := shr(224, hi)
                let h1 := and(shr(192, hi), mask)
                let h2 := and(shr(160, hi), mask)
                let h3 := and(shr(128, hi), mask)
                let h4 := and(shr(96, hi), mask)

                let l0 := shr(224, lo)
                let l1 := and(shr(192, lo), mask)
                let l2 := and(shr(160, lo), mask)
                let l3 := and(shr(128, lo), mask)
                let l4 := and(shr(96, lo), mask)

                let r0 :=
                    mod(add(add(mulmod(a0, var2, modulus), mulmod(h0, var_, modulus)), l0), modulus)
                let r1 :=
                    mod(add(add(mulmod(a1, var2, modulus), mulmod(h1, var_, modulus)), l1), modulus)
                let r2 :=
                    mod(add(add(mulmod(a2, var2, modulus), mulmod(h2, var_, modulus)), l2), modulus)
                let r3 :=
                    mod(add(add(mulmod(a3, var2, modulus), mulmod(h3, var_, modulus)), l3), modulus)
                let r4 :=
                    mod(add(add(mulmod(a4, var2, modulus), mulmod(h4, var_, modulus)), l4), modulus)

                acc := or(
                    or(or(shl(224, r0), shl(192, r1)), or(shl(160, r2), shl(128, r3))),
                    shl(96, r4)
                )
            }
        }
    }

    function checkHornerBaseBlob64Matches5Raw(
        bytes calldata blob,
        uint256 offset,
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
        if (hornerBaseBlob64Pairwise(blob, offset, v0) != expected0) return 1;
        if (hornerBaseBlob64Pairwise(blob, offset, v1) != expected1) return 2;
        if (hornerBaseBlob64Pairwise(blob, offset, v2) != expected2) return 3;
        if (hornerBaseBlob64Pairwise(blob, offset, v3) != expected3) return 4;
        if (hornerBaseBlob64Pairwise(blob, offset, v4) != expected4) return 5;
    }

    function selectPolyEval(
        uint256 var_,
        uint256[] memory fullPoint,
        uint256 pointOffset,
        uint256 numVariables
    ) internal pure returns (uint256 acc) {
        acc = KoalaBearExt5.ONE;
        uint256[] memory expanded = new uint256[](numVariables);
        uint256 current = var_;

        unchecked {
            for (uint256 i = numVariables; i > 0; --i) {
                expanded[i - 1] = current;
                current = KoalaBear.mul(current, current);
            }
            for (uint256 i = 0; i < numVariables; ++i) {
                uint256 value = expanded[i];
                uint256 scalar = value == 0 ? KoalaBear.MODULUS - 1 : value - 1;
                uint256 term = KoalaBearExt5.add(
                    KoalaBearExt5.ONE, KoalaBearExt5.mulBase(fullPoint[pointOffset + i], scalar)
                );
                acc = KoalaBearExt5.mul(acc, term);
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
                evals[i] = KoalaBearExt5.fromBase(value);
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
        uint256 pointBase;
        assembly ("memory-safe") {
            pointBase := add(add(fullPoint, 0x20), shl(5, pointOffset))
        }

        uint256 p0;
        uint256 p1;
        uint256 p2;
        uint256 p3;
        uint256 p4;
        uint256 p5;
        assembly ("memory-safe") {
            p0 := mload(pointBase)
            p1 := mload(add(pointBase, 0x20))
            p2 := mload(add(pointBase, 0x40))
            p3 := mload(add(pointBase, 0x60))
            p4 := mload(add(pointBase, 0x80))
            p5 := mload(add(pointBase, 0xa0))
        }

        (uint256 r00, uint256 r01, uint256 r02, uint256 r03, uint256 r04) = _unpackCoeffs(p0);
        (uint256 r10, uint256 r11, uint256 r12, uint256 r13, uint256 r14) = _unpackCoeffs(p1);
        (uint256 r20, uint256 r21, uint256 r22, uint256 r23, uint256 r24) = _unpackCoeffs(p2);
        (uint256 r30, uint256 r31, uint256 r32, uint256 r33, uint256 r34) = _unpackCoeffs(p3);
        (uint256 r40, uint256 r41, uint256 r42, uint256 r43, uint256 r44) = _unpackCoeffs(p4);
        (uint256 r50, uint256 r51, uint256 r52, uint256 r53, uint256 r54) = _unpackCoeffs(p5);

        uint256 evalsBase;
        uint256 src;
        assembly ("memory-safe") {
            evalsBase := mload(0x40)
            mstore(0x40, add(evalsBase, 0x100))
            src := add(blob.offset, offset)
        }

        unchecked {
            for (uint256 i = 0; i < 8; ++i) {
                uint256 v0;
                uint256 v8;
                uint256 v16;
                uint256 v24;
                uint256 v32;
                uint256 v40;
                uint256 v48;
                uint256 v56;
                assembly ("memory-safe") {
                    let low96Mask := sub(shl(96, 1), 1)
                    v0 := and(calldataload(add(src, mul(20, i))), not(low96Mask))
                    v8 := and(calldataload(add(src, mul(20, add(i, 8)))), not(low96Mask))
                    v16 := and(calldataload(add(src, mul(20, add(i, 16)))), not(low96Mask))
                    v24 := and(calldataload(add(src, mul(20, add(i, 24)))), not(low96Mask))
                    v32 := and(calldataload(add(src, mul(20, add(i, 32)))), not(low96Mask))
                    v40 := and(calldataload(add(src, mul(20, add(i, 40)))), not(low96Mask))
                    v48 := and(calldataload(add(src, mul(20, add(i, 48)))), not(low96Mask))
                    v56 := and(calldataload(add(src, mul(20, add(i, 56)))), not(low96Mask))
                }

                uint256 a0 = _foldOnceWithCoeffs(v0, v32, r00, r01, r02, r03, r04);
                uint256 a1 = _foldOnceWithCoeffs(v16, v48, r00, r01, r02, r03, r04);
                uint256 b0 = _foldOnceWithCoeffs(a0, a1, r10, r11, r12, r13, r14);
                uint256 a2 = _foldOnceWithCoeffs(v8, v40, r00, r01, r02, r03, r04);
                uint256 a3 = _foldOnceWithCoeffs(v24, v56, r00, r01, r02, r03, r04);
                uint256 b1 = _foldOnceWithCoeffs(a2, a3, r10, r11, r12, r13, r14);
                uint256 evalValue = _foldOnceWithCoeffs(b0, b1, r20, r21, r22, r23, r24);
                assembly ("memory-safe") {
                    mstore(add(evalsBase, shl(5, i)), evalValue)
                }
            }
            for (uint256 i = 0; i < 4; ++i) {
                uint256 base;
                uint256 left;
                uint256 right;
                assembly ("memory-safe") {
                    base := add(evalsBase, shl(5, i))
                    left := mload(base)
                    right := mload(add(base, 0x80))
                }
                uint256 evalValue = _foldOnceWithCoeffs(left, right, r30, r31, r32, r33, r34);
                assembly ("memory-safe") {
                    mstore(base, evalValue)
                }
            }
            for (uint256 i = 0; i < 2; ++i) {
                uint256 base;
                uint256 left;
                uint256 right;
                assembly ("memory-safe") {
                    base := add(evalsBase, shl(5, i))
                    left := mload(base)
                    right := mload(add(base, 0x40))
                }
                uint256 evalValue = _foldOnceWithCoeffs(left, right, r40, r41, r42, r43, r44);
                assembly ("memory-safe") {
                    mstore(base, evalValue)
                }
            }
        }

        uint256 eval0;
        uint256 eval1;
        assembly ("memory-safe") {
            eval0 := mload(evalsBase)
            eval1 := mload(add(evalsBase, 0x20))
        }
        return _foldOnceWithCoeffs(eval0, eval1, r50, r51, r52, r53, r54);
    }

    function evaluateHypercubeMemory(uint256[] memory evals, uint256[] memory point)
        internal
        pure
        returns (uint256)
    {
        return KoalaBearExt5.evaluate_hypercube(evals, point);
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
                let bias := 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000
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

        evalValue = _dotBaseRowWeights16Packed(weightsPtr, w0, w1);
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
                let bias := 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000
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
                let bias := 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000
                if or(
                    and(packed, highBitMask),
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
    ) private pure returns (uint256 out) {
        assembly ("memory-safe") {
            let M := 0x7f000001
            let mask := 0xffffffff

            let c0 := 0
            let c1 := 0
            let c2 := 0
            let c3 := 0
            let c4 := 0
            let c5 := 0
            let c6 := 0
            let c7 := 0
            let c8 := 0

            function accumulate(a, w, d0, d1, d2, d3, d4, d5, d6, d7, d8) ->
                e0,
                e1,
                e2,
                e3,
                e4,
                e5,
                e6,
                e7,
                e8
            {
                let a0 := shr(224, a)
                let a1 := and(shr(192, a), 0xffffffff)
                let a2 := and(shr(160, a), 0xffffffff)
                let a3 := and(shr(128, a), 0xffffffff)
                let a4 := and(shr(96, a), 0xffffffff)

                let b0 := mload(w)
                let b1 := mload(add(w, 0x20))
                let b2 := mload(add(w, 0x40))
                let b3 := mload(add(w, 0x60))
                let b4 := mload(add(w, 0x80))

                e0 := add(d0, mul(a0, b0))
                e1 := add(d1, add(mul(a0, b1), mul(a1, b0)))
                e2 := add(d2, add(add(mul(a0, b2), mul(a1, b1)), mul(a2, b0)))
                e3 := add(d3, add(add(add(mul(a0, b3), mul(a1, b2)), mul(a2, b1)), mul(a3, b0)))
                e4 := add(
                    d4,
                    add(
                        add(add(add(mul(a0, b4), mul(a1, b3)), mul(a2, b2)), mul(a3, b1)),
                        mul(a4, b0)
                    )
                )
                e5 := add(d5, add(add(add(mul(a1, b4), mul(a2, b3)), mul(a3, b2)), mul(a4, b1)))
                e6 := add(d6, add(add(mul(a2, b4), mul(a3, b3)), mul(a4, b2)))
                e7 := add(d7, add(mul(a3, b4), mul(a4, b3)))
                e8 := add(d8, mul(a4, b4))
            }

            c0, c1, c2, c3, c4, c5, c6, c7, c8 :=
                accumulate(v0, weightsPtr, c0, c1, c2, c3, c4, c5, c6, c7, c8)
            c0, c1, c2, c3, c4, c5, c6, c7, c8 :=
                accumulate(v1, add(weightsPtr, 0x0a0), c0, c1, c2, c3, c4, c5, c6, c7, c8)
            c0, c1, c2, c3, c4, c5, c6, c7, c8 :=
                accumulate(v2, add(weightsPtr, 0x140), c0, c1, c2, c3, c4, c5, c6, c7, c8)
            c0, c1, c2, c3, c4, c5, c6, c7, c8 :=
                accumulate(v3, add(weightsPtr, 0x1e0), c0, c1, c2, c3, c4, c5, c6, c7, c8)
            c0, c1, c2, c3, c4, c5, c6, c7, c8 :=
                accumulate(v4, add(weightsPtr, 0x280), c0, c1, c2, c3, c4, c5, c6, c7, c8)
            c0, c1, c2, c3, c4, c5, c6, c7, c8 :=
                accumulate(v5, add(weightsPtr, 0x320), c0, c1, c2, c3, c4, c5, c6, c7, c8)
            c0, c1, c2, c3, c4, c5, c6, c7, c8 :=
                accumulate(v6, add(weightsPtr, 0x3c0), c0, c1, c2, c3, c4, c5, c6, c7, c8)
            c0, c1, c2, c3, c4, c5, c6, c7, c8 :=
                accumulate(v7, add(weightsPtr, 0x460), c0, c1, c2, c3, c4, c5, c6, c7, c8)
            c0, c1, c2, c3, c4, c5, c6, c7, c8 :=
                accumulate(v8, add(weightsPtr, 0x500), c0, c1, c2, c3, c4, c5, c6, c7, c8)
            c0, c1, c2, c3, c4, c5, c6, c7, c8 :=
                accumulate(v9, add(weightsPtr, 0x5a0), c0, c1, c2, c3, c4, c5, c6, c7, c8)
            c0, c1, c2, c3, c4, c5, c6, c7, c8 :=
                accumulate(v10, add(weightsPtr, 0x640), c0, c1, c2, c3, c4, c5, c6, c7, c8)
            c0, c1, c2, c3, c4, c5, c6, c7, c8 :=
                accumulate(v11, add(weightsPtr, 0x6e0), c0, c1, c2, c3, c4, c5, c6, c7, c8)
            c0, c1, c2, c3, c4, c5, c6, c7, c8 :=
                accumulate(v12, add(weightsPtr, 0x780), c0, c1, c2, c3, c4, c5, c6, c7, c8)
            c0, c1, c2, c3, c4, c5, c6, c7, c8 :=
                accumulate(v13, add(weightsPtr, 0x820), c0, c1, c2, c3, c4, c5, c6, c7, c8)
            c0, c1, c2, c3, c4, c5, c6, c7, c8 :=
                accumulate(v14, add(weightsPtr, 0x8c0), c0, c1, c2, c3, c4, c5, c6, c7, c8)
            c0, c1, c2, c3, c4, c5, c6, c7, c8 :=
                accumulate(v15, add(weightsPtr, 0x960), c0, c1, c2, c3, c4, c5, c6, c7, c8)

            let bias := shl(80, M)
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

    function _dotBaseRowWeights16Packed(uint256 weightsPtr, uint256 w0, uint256 w1)
        private
        pure
        returns (uint256 out)
    {
        assembly ("memory-safe") {
            let M := 0x7f000001
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
            let M := 0x7f000001
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
        assembly ("memory-safe") {
            let M := 0x7f000001
            let m := 0xffffffff

            let a00 := shr(224, a0)
            let a01 := and(shr(192, a0), m)
            let a02 := and(shr(160, a0), m)
            let a03 := and(shr(128, a0), m)
            let a04 := and(shr(96, a0), m)

            let d0 := sub(add(shr(224, a1), M), a00)
            let d1 := sub(add(and(shr(192, a1), m), M), a01)
            let d2 := sub(add(and(shr(160, a1), m), M), a02)
            let d3 := sub(add(and(shr(128, a1), m), M), a03)
            let d4 := sub(add(and(shr(96, a1), m), M), a04)

            let c0 := mul(r0, d0)
            let c1 := add(mul(r0, d1), mul(r1, d0))
            let c2 := add(add(mul(r0, d2), mul(r1, d1)), mul(r2, d0))
            let c3 := add(add(add(mul(r0, d3), mul(r1, d2)), mul(r2, d1)), mul(r3, d0))
            let c4 :=
                add(add(add(add(mul(r0, d4), mul(r1, d3)), mul(r2, d2)), mul(r3, d1)), mul(r4, d0))
            let c5 := add(add(add(mul(r1, d4), mul(r2, d3)), mul(r3, d2)), mul(r4, d1))
            let c6 := add(add(mul(r2, d4), mul(r3, d3)), mul(r4, d2))
            let c7 := add(mul(r3, d4), mul(r4, d3))
            let c8 := mul(r4, d4)

            let bias := shl(35, M)

            let rOut0 := mod(add(add(add(a00, c0), c5), sub(bias, c8)), M)
            let rOut1 := mod(add(add(a01, c1), c6), M)
            let rOut2 := mod(add(add(add(add(a02, c2), sub(bias, c5)), c7), c8), M)
            let rOut3 := mod(add(add(add(a03, c3), sub(bias, c6)), c8), M)
            let rOut4 := mod(add(add(a04, c4), sub(bias, c7)), M)

            out := or(
                or(or(shl(224, rOut0), shl(192, rOut1)), or(shl(160, rOut2), shl(128, rOut3))),
                shl(96, rOut4)
            )
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
}
