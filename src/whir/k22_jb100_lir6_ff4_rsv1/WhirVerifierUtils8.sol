// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { LibSort } from "solady/utils/LibSort.sol";

import { KoalaBear } from "../../field/KoalaBear.sol";
import { KoalaBearExt8 } from "../../field/KoalaBearExt8.sol";
import { KeccakChallenger } from "../../transcript/KeccakChallenger.sol";

library WhirVerifierUtils8 {
    using KeccakChallenger for KeccakChallenger.State;

    error BaseFieldElementOutOfRange(uint256 value);
    error PackedExtensionElementOutOfRange(uint256 value);
    error NotPowerOfTwo(uint256 value);

    function observeValidatedExt8(KeccakChallenger.State memory challenger, uint256 packed)
        internal
        pure
    {
        challenger.observeValidatedPackedExt8(packed);
    }

    function sampleExt8(KeccakChallenger.State memory challenger) internal pure returns (uint256) {
        unchecked {
            return (challenger.sampleBase() << 224) | (challenger.sampleBase() << 192)
                | (challenger.sampleBase() << 160) | (challenger.sampleBase() << 128)
                | (challenger.sampleBase() << 96) | (challenger.sampleBase() << 64)
                | (challenger.sampleBase() << 32) | challenger.sampleBase();
        }
    }

    function validateBase(uint256 value) internal pure {
        if (value >= KoalaBear.MODULUS) {
            revert BaseFieldElementOutOfRange(value);
        }
    }

    function validateBaseCalldata(uint256[] calldata values) internal pure {
        unchecked {
            for (uint256 i = 0; i < values.length; ++i) {
                validateBase(values[i]);
            }
        }
    }

    function validatePackedExt8Calldata(uint256[] calldata values) internal pure {
        unchecked {
            for (uint256 i = 0; i < values.length; ++i) {
                validatePackedExt8(values[i]);
            }
        }
    }

    function validatePackedExt8(uint256 packed) internal pure {
        unchecked {
            if (
                (packed >> 224) >= KoalaBear.MODULUS
                    || ((packed >> 192) & 0xffffffff) >= KoalaBear.MODULUS
                    || ((packed >> 160) & 0xffffffff) >= KoalaBear.MODULUS
                    || ((packed >> 128) & 0xffffffff) >= KoalaBear.MODULUS
                    || ((packed >> 96) & 0xffffffff) >= KoalaBear.MODULUS
                    || ((packed >> 64) & 0xffffffff) >= KoalaBear.MODULUS
                    || ((packed >> 32) & 0xffffffff) >= KoalaBear.MODULUS
                    || (packed & 0xffffffff) >= KoalaBear.MODULUS
            ) {
                revert PackedExtensionElementOutOfRange(packed);
            }
        }
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
                current = KoalaBearExt8.square(current);
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
                let a5 := and(shr(64, acc), mask)
                let a6 := and(shr(32, acc), mask)
                let a7 := and(acc, mask)

                let c0 := shr(224, packed)
                let c1 := and(shr(192, packed), mask)
                let c2 := and(shr(160, packed), mask)
                let c3 := and(shr(128, packed), mask)
                let c4 := and(shr(96, packed), mask)
                let c5 := and(shr(64, packed), mask)
                let c6 := and(shr(32, packed), mask)
                let c7 := and(packed, mask)

                let r0 := mod(add(mulmod(a0, var_, modulus), c0), modulus)
                let r1 := mod(add(mulmod(a1, var_, modulus), c1), modulus)
                let r2 := mod(add(mulmod(a2, var_, modulus), c2), modulus)
                let r3 := mod(add(mulmod(a3, var_, modulus), c3), modulus)
                let r4 := mod(add(mulmod(a4, var_, modulus), c4), modulus)
                let r5 := mod(add(mulmod(a5, var_, modulus), c5), modulus)
                let r6 := mod(add(mulmod(a6, var_, modulus), c6), modulus)
                let r7 := mod(add(mulmod(a7, var_, modulus), c7), modulus)

                acc := or(
                    or(or(shl(224, r0), shl(192, r1)), or(shl(160, r2), shl(128, r3))),
                    or(or(shl(96, r4), shl(64, r5)), or(shl(32, r6), r7))
                )
            }
        }
    }

    function hornerBaseMemory(uint256[] memory coeffs, uint256 var_)
        internal
        pure
        returns (uint256 acc)
    {
        assembly ("memory-safe") {
            let modulus := 0x7f000001
            let mask := 0xffffffff

            let src := add(add(coeffs, 0x20), shl(5, mload(coeffs)))
            let end := add(coeffs, 0x20)

            for { } gt(src, end) { } {
                src := sub(src, 0x20)
                let packed := mload(src)

                let a0 := shr(224, acc)
                let a1 := and(shr(192, acc), mask)
                let a2 := and(shr(160, acc), mask)
                let a3 := and(shr(128, acc), mask)
                let a4 := and(shr(96, acc), mask)
                let a5 := and(shr(64, acc), mask)
                let a6 := and(shr(32, acc), mask)
                let a7 := and(acc, mask)

                let c0 := shr(224, packed)
                let c1 := and(shr(192, packed), mask)
                let c2 := and(shr(160, packed), mask)
                let c3 := and(shr(128, packed), mask)
                let c4 := and(shr(96, packed), mask)
                let c5 := and(shr(64, packed), mask)
                let c6 := and(shr(32, packed), mask)
                let c7 := and(packed, mask)

                let r0 := mod(add(mulmod(a0, var_, modulus), c0), modulus)
                let r1 := mod(add(mulmod(a1, var_, modulus), c1), modulus)
                let r2 := mod(add(mulmod(a2, var_, modulus), c2), modulus)
                let r3 := mod(add(mulmod(a3, var_, modulus), c3), modulus)
                let r4 := mod(add(mulmod(a4, var_, modulus), c4), modulus)
                let r5 := mod(add(mulmod(a5, var_, modulus), c5), modulus)
                let r6 := mod(add(mulmod(a6, var_, modulus), c6), modulus)
                let r7 := mod(add(mulmod(a7, var_, modulus), c7), modulus)

                acc := or(
                    or(or(shl(224, r0), shl(192, r1)), or(shl(160, r2), shl(128, r3))),
                    or(or(shl(96, r4), shl(64, r5)), or(shl(32, r6), r7))
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

            let src := add(add(blob.offset, offset), shl(5, coeffCount))
            let end := add(blob.offset, offset)

            for { } gt(src, end) { } {
                src := sub(src, 0x20)
                let packed := calldataload(src)

                let a0 := shr(224, acc)
                let a1 := and(shr(192, acc), mask)
                let a2 := and(shr(160, acc), mask)
                let a3 := and(shr(128, acc), mask)
                let a4 := and(shr(96, acc), mask)
                let a5 := and(shr(64, acc), mask)
                let a6 := and(shr(32, acc), mask)
                let a7 := and(acc, mask)

                let c0 := shr(224, packed)
                let c1 := and(shr(192, packed), mask)
                let c2 := and(shr(160, packed), mask)
                let c3 := and(shr(128, packed), mask)
                let c4 := and(shr(96, packed), mask)
                let c5 := and(shr(64, packed), mask)
                let c6 := and(shr(32, packed), mask)
                let c7 := and(packed, mask)

                let r0 := mod(add(mulmod(a0, var_, modulus), c0), modulus)
                let r1 := mod(add(mulmod(a1, var_, modulus), c1), modulus)
                let r2 := mod(add(mulmod(a2, var_, modulus), c2), modulus)
                let r3 := mod(add(mulmod(a3, var_, modulus), c3), modulus)
                let r4 := mod(add(mulmod(a4, var_, modulus), c4), modulus)
                let r5 := mod(add(mulmod(a5, var_, modulus), c5), modulus)
                let r6 := mod(add(mulmod(a6, var_, modulus), c6), modulus)
                let r7 := mod(add(mulmod(a7, var_, modulus), c7), modulus)

                acc := or(
                    or(or(shl(224, r0), shl(192, r1)), or(shl(160, r2), shl(128, r3))),
                    or(or(shl(96, r4), shl(64, r5)), or(shl(32, r6), r7))
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
        assembly ("memory-safe") {
            let modulus := 0x7f000001
            let mask := 0xffffffff

            let evalBase := add(rowEvalsBase, shl(5, rowOffset))

            let a00 := 0
            let a01 := 0
            let a02 := 0
            let a03 := 0
            let a04 := 0
            let a05 := 0
            let a06 := 0
            let a07 := 0
            let a10 := 0
            let a11 := 0
            let a12 := 0
            let a13 := 0
            let a14 := 0
            let a15 := 0
            let a16 := 0
            let a17 := 0
            let a20 := 0
            let a21 := 0
            let a22 := 0
            let a23 := 0
            let a24 := 0
            let a25 := 0
            let a26 := 0
            let a27 := 0
            let a30 := 0
            let a31 := 0
            let a32 := 0
            let a33 := 0
            let a34 := 0
            let a35 := 0
            let a36 := 0
            let a37 := 0
            let a40 := 0
            let a41 := 0
            let a42 := 0
            let a43 := 0
            let a44 := 0
            let a45 := 0
            let a46 := 0
            let a47 := 0

            let src := add(add(blob.offset, offset), 0x800)
            let end := add(blob.offset, offset)

            for { } gt(src, end) { } {
                src := sub(src, 0x20)
                let packed := calldataload(src)

                let c0 := shr(224, packed)
                let c1 := and(shr(192, packed), mask)
                let c2 := and(shr(160, packed), mask)
                let c3 := and(shr(128, packed), mask)
                let c4 := and(shr(96, packed), mask)
                let c5 := and(shr(64, packed), mask)
                let c6 := and(shr(32, packed), mask)
                let c7 := and(packed, mask)

                a00 := mod(add(mulmod(a00, v0, modulus), c0), modulus)
                a01 := mod(add(mulmod(a01, v0, modulus), c1), modulus)
                a02 := mod(add(mulmod(a02, v0, modulus), c2), modulus)
                a03 := mod(add(mulmod(a03, v0, modulus), c3), modulus)
                a04 := mod(add(mulmod(a04, v0, modulus), c4), modulus)
                a05 := mod(add(mulmod(a05, v0, modulus), c5), modulus)
                a06 := mod(add(mulmod(a06, v0, modulus), c6), modulus)
                a07 := mod(add(mulmod(a07, v0, modulus), c7), modulus)

                a10 := mod(add(mulmod(a10, v1, modulus), c0), modulus)
                a11 := mod(add(mulmod(a11, v1, modulus), c1), modulus)
                a12 := mod(add(mulmod(a12, v1, modulus), c2), modulus)
                a13 := mod(add(mulmod(a13, v1, modulus), c3), modulus)
                a14 := mod(add(mulmod(a14, v1, modulus), c4), modulus)
                a15 := mod(add(mulmod(a15, v1, modulus), c5), modulus)
                a16 := mod(add(mulmod(a16, v1, modulus), c6), modulus)
                a17 := mod(add(mulmod(a17, v1, modulus), c7), modulus)

                a20 := mod(add(mulmod(a20, v2, modulus), c0), modulus)
                a21 := mod(add(mulmod(a21, v2, modulus), c1), modulus)
                a22 := mod(add(mulmod(a22, v2, modulus), c2), modulus)
                a23 := mod(add(mulmod(a23, v2, modulus), c3), modulus)
                a24 := mod(add(mulmod(a24, v2, modulus), c4), modulus)
                a25 := mod(add(mulmod(a25, v2, modulus), c5), modulus)
                a26 := mod(add(mulmod(a26, v2, modulus), c6), modulus)
                a27 := mod(add(mulmod(a27, v2, modulus), c7), modulus)

                a30 := mod(add(mulmod(a30, v3, modulus), c0), modulus)
                a31 := mod(add(mulmod(a31, v3, modulus), c1), modulus)
                a32 := mod(add(mulmod(a32, v3, modulus), c2), modulus)
                a33 := mod(add(mulmod(a33, v3, modulus), c3), modulus)
                a34 := mod(add(mulmod(a34, v3, modulus), c4), modulus)
                a35 := mod(add(mulmod(a35, v3, modulus), c5), modulus)
                a36 := mod(add(mulmod(a36, v3, modulus), c6), modulus)
                a37 := mod(add(mulmod(a37, v3, modulus), c7), modulus)

                a40 := mod(add(mulmod(a40, v4, modulus), c0), modulus)
                a41 := mod(add(mulmod(a41, v4, modulus), c1), modulus)
                a42 := mod(add(mulmod(a42, v4, modulus), c2), modulus)
                a43 := mod(add(mulmod(a43, v4, modulus), c3), modulus)
                a44 := mod(add(mulmod(a44, v4, modulus), c4), modulus)
                a45 := mod(add(mulmod(a45, v4, modulus), c5), modulus)
                a46 := mod(add(mulmod(a46, v4, modulus), c6), modulus)
                a47 := mod(add(mulmod(a47, v4, modulus), c7), modulus)
            }

            let out0 :=
                or(
                    or(or(shl(224, a00), shl(192, a01)), or(shl(160, a02), shl(128, a03))),
                    or(or(shl(96, a04), shl(64, a05)), or(shl(32, a06), a07))
                )
            let out1 :=
                or(
                    or(or(shl(224, a10), shl(192, a11)), or(shl(160, a12), shl(128, a13))),
                    or(or(shl(96, a14), shl(64, a15)), or(shl(32, a16), a17))
                )
            let out2 :=
                or(
                    or(or(shl(224, a20), shl(192, a21)), or(shl(160, a22), shl(128, a23))),
                    or(or(shl(96, a24), shl(64, a25)), or(shl(32, a26), a27))
                )
            let out3 :=
                or(
                    or(or(shl(224, a30), shl(192, a31)), or(shl(160, a32), shl(128, a33))),
                    or(or(shl(96, a34), shl(64, a35)), or(shl(32, a36), a37))
                )
            let out4 :=
                or(
                    or(or(shl(224, a40), shl(192, a41)), or(shl(160, a42), shl(128, a43))),
                    or(or(shl(96, a44), shl(64, a45)), or(shl(32, a46), a47))
                )

            if and(iszero(mismatchPlusOne), iszero(eq(out0, mload(evalBase)))) {
                mismatchPlusOne := 1
            }
            if and(iszero(mismatchPlusOne), iszero(eq(out1, mload(add(evalBase, 0x20))))) {
                mismatchPlusOne := 2
            }
            if and(iszero(mismatchPlusOne), iszero(eq(out2, mload(add(evalBase, 0x40))))) {
                mismatchPlusOne := 3
            }
            if and(iszero(mismatchPlusOne), iszero(eq(out3, mload(add(evalBase, 0x60))))) {
                mismatchPlusOne := 4
            }
            if and(iszero(mismatchPlusOne), iszero(eq(out4, mload(add(evalBase, 0x80))))) {
                mismatchPlusOne := 5
            }
        }
    }

    function checkHornerBaseBlob64Matches5(
        bytes calldata blob,
        uint256 offset,
        uint256[] memory indices,
        uint256 indicesOffset,
        uint256 foldedDomainGen,
        uint256[] memory rowEvals,
        uint256 rowOffset
    ) internal pure returns (uint256 mismatchPlusOne) {
        uint256 v0 = KoalaBear.pow(foldedDomainGen, indices[indicesOffset]);
        uint256 v1 = KoalaBear.pow(foldedDomainGen, indices[indicesOffset + 1]);
        uint256 v2 = KoalaBear.pow(foldedDomainGen, indices[indicesOffset + 2]);
        uint256 v3 = KoalaBear.pow(foldedDomainGen, indices[indicesOffset + 3]);
        uint256 v4 = KoalaBear.pow(foldedDomainGen, indices[indicesOffset + 4]);
        uint256 rowEvalsBase;
        assembly ("memory-safe") {
            rowEvalsBase := add(rowEvals, 0x20)
        }
        return checkHornerBaseBlob64Matches5Raw(
            blob, offset, v0, v1, v2, v3, v4, rowEvalsBase, rowOffset
        );
    }

    function selectPolyEval(
        uint256 var_,
        uint256[] memory fullPoint,
        uint256 pointOffset,
        uint256 numVariables
    ) internal pure returns (uint256 acc) {
        acc = KoalaBearExt8.ONE;
        uint256 current = var_;

        unchecked {
            for (uint256 i = numVariables; i > 0; --i) {
                uint256 scalar = current == 0 ? KoalaBear.MODULUS - 1 : current - 1;
                uint256 term = KoalaBearExt8.add(
                    KoalaBearExt8.ONE, KoalaBearExt8.mulBase(fullPoint[pointOffset + i - 1], scalar)
                );
                acc = KoalaBearExt8.mul(acc, term);
                current = KoalaBear.mul(current, current);
            }
        }
    }

    function evaluateBaseRowAsExt8(
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
                evals[i] = KoalaBearExt8.fromBase(value);
            }
        }
        if (point.length == 0) {
            return evals[0];
        }
        return evaluateHypercubeMemory(evals, point);
    }

    function evaluateExtensionRowAsExt8(
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
                validatePackedExt8(value);
                evals[i] = value;
            }
        }
        if (point.length == 0) {
            return evals[0];
        }
        return evaluateHypercubeMemory(evals, point);
    }

    function evaluateBaseRowAsExt8Blob(
        bytes calldata blob,
        uint256 offset,
        uint256 rowLen,
        uint256[] memory fullPoint,
        uint256 pointOffset,
        uint256 pointLen
    ) internal pure returns (uint256) {
        if (pointLen == 4 && rowLen == 16) {
            return _evaluateBaseRowDim4BlobWindow(blob, offset, fullPoint, pointOffset);
        }

        uint256[] memory evals = new uint256[](rowLen);
        uint256[] memory point = _slicePoint(fullPoint, pointOffset, pointLen);

        unchecked {
            for (uint256 i = 0; i < rowLen; ++i) {
                uint256 value;
                assembly ("memory-safe") {
                    value := shr(224, calldataload(add(add(blob.offset, offset), shl(2, i))))
                }
                validateBase(value);
                evals[i] = KoalaBearExt8.fromBase(value);
            }
        }

        if (point.length == 0) {
            return evals[0];
        }
        return evaluateHypercubeMemory(evals, point);
    }

    function evaluateExtensionRowAsExt8Blob(
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
                    value := calldataload(add(add(blob.offset, offset), shl(5, i)))
                }
                validatePackedExt8(value);
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

        (
            uint256 r00,
            uint256 r01,
            uint256 r02,
            uint256 r03,
            uint256 r04,
            uint256 r05,
            uint256 r06,
            uint256 r07
        ) = _unpackCoeffs(p0);
        (
            uint256 r10,
            uint256 r11,
            uint256 r12,
            uint256 r13,
            uint256 r14,
            uint256 r15,
            uint256 r16,
            uint256 r17
        ) = _unpackCoeffs(p1);
        (
            uint256 r20,
            uint256 r21,
            uint256 r22,
            uint256 r23,
            uint256 r24,
            uint256 r25,
            uint256 r26,
            uint256 r27
        ) = _unpackCoeffs(p2);
        (
            uint256 r30,
            uint256 r31,
            uint256 r32,
            uint256 r33,
            uint256 r34,
            uint256 r35,
            uint256 r36,
            uint256 r37
        ) = _unpackCoeffs(p3);
        (
            uint256 r40,
            uint256 r41,
            uint256 r42,
            uint256 r43,
            uint256 r44,
            uint256 r45,
            uint256 r46,
            uint256 r47
        ) = _unpackCoeffs(p4);
        (
            uint256 r50,
            uint256 r51,
            uint256 r52,
            uint256 r53,
            uint256 r54,
            uint256 r55,
            uint256 r56,
            uint256 r57
        ) = _unpackCoeffs(p5);

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
                    v0 := calldataload(add(src, shl(5, i)))
                    v8 := calldataload(add(src, shl(5, add(i, 8))))
                    v16 := calldataload(add(src, shl(5, add(i, 16))))
                    v24 := calldataload(add(src, shl(5, add(i, 24))))
                    v32 := calldataload(add(src, shl(5, add(i, 32))))
                    v40 := calldataload(add(src, shl(5, add(i, 40))))
                    v48 := calldataload(add(src, shl(5, add(i, 48))))
                    v56 := calldataload(add(src, shl(5, add(i, 56))))
                }

                uint256 a0 = _foldOnceWithCoeffs(v0, v32, r00, r01, r02, r03, r04, r05, r06, r07);
                uint256 a1 = _foldOnceWithCoeffs(v16, v48, r00, r01, r02, r03, r04, r05, r06, r07);
                uint256 b0 = _foldOnceWithCoeffs(a0, a1, r10, r11, r12, r13, r14, r15, r16, r17);
                uint256 a2 = _foldOnceWithCoeffs(v8, v40, r00, r01, r02, r03, r04, r05, r06, r07);
                uint256 a3 = _foldOnceWithCoeffs(v24, v56, r00, r01, r02, r03, r04, r05, r06, r07);
                uint256 b1 = _foldOnceWithCoeffs(a2, a3, r10, r11, r12, r13, r14, r15, r16, r17);
                uint256 evalValue =
                    _foldOnceWithCoeffs(b0, b1, r20, r21, r22, r23, r24, r25, r26, r27);
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
                uint256 evalValue =
                    _foldOnceWithCoeffs(left, right, r30, r31, r32, r33, r34, r35, r36, r37);
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
                uint256 evalValue =
                    _foldOnceWithCoeffs(left, right, r40, r41, r42, r43, r44, r45, r46, r47);
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
        return _foldOnceWithCoeffs(eval0, eval1, r50, r51, r52, r53, r54, r55, r56, r57);
    }

    function evaluateHypercubeMemory(uint256[] memory evals, uint256[] memory point)
        internal
        pure
        returns (uint256)
    {
        uint256 size = evals.length;

        unchecked {
            for (uint256 i = 0; i < point.length; ++i) {
                (
                    uint256 r0,
                    uint256 r1,
                    uint256 r2,
                    uint256 r3,
                    uint256 r4,
                    uint256 r5,
                    uint256 r6,
                    uint256 r7
                ) = _unpackCoeffs(point[i]);
                size >>= 1;
                for (uint256 j = 0; j < size; ++j) {
                    evals[j] = _foldOnceWithCoeffs(
                        evals[j], evals[j + size], r0, r1, r2, r3, r4, r5, r6, r7
                    );
                }
            }
        }

        return evals[0];
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

        (
            uint256 r00,
            uint256 r01,
            uint256 r02,
            uint256 r03,
            uint256 r04,
            uint256 r05,
            uint256 r06,
            uint256 r07
        ) = _unpackCoeffs(point[0]);
        (
            uint256 r10,
            uint256 r11,
            uint256 r12,
            uint256 r13,
            uint256 r14,
            uint256 r15,
            uint256 r16,
            uint256 r17
        ) = _unpackCoeffs(point[1]);
        (
            uint256 r20,
            uint256 r21,
            uint256 r22,
            uint256 r23,
            uint256 r24,
            uint256 r25,
            uint256 r26,
            uint256 r27
        ) = _unpackCoeffs(point[2]);
        (
            uint256 r30,
            uint256 r31,
            uint256 r32,
            uint256 r33,
            uint256 r34,
            uint256 r35,
            uint256 r36,
            uint256 r37
        ) = _unpackCoeffs(point[3]);

        uint256 l0 = _foldOnceBase(v0, v8, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l1 = _foldOnceBase(v1, v9, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l2 = _foldOnceBase(v2, v10, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l3 = _foldOnceBase(v3, v11, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l4 = _foldOnceBase(v4, v12, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l5 = _foldOnceBase(v5, v13, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l6 = _foldOnceBase(v6, v14, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l7 = _foldOnceBase(v7, v15, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 m0 = _foldOnceWithCoeffs(l0, l4, r10, r11, r12, r13, r14, r15, r16, r17);
        uint256 m1 = _foldOnceWithCoeffs(l1, l5, r10, r11, r12, r13, r14, r15, r16, r17);
        uint256 m2 = _foldOnceWithCoeffs(l2, l6, r10, r11, r12, r13, r14, r15, r16, r17);
        uint256 m3 = _foldOnceWithCoeffs(l3, l7, r10, r11, r12, r13, r14, r15, r16, r17);
        uint256 n0 = _foldOnceWithCoeffs(m0, m2, r20, r21, r22, r23, r24, r25, r26, r27);
        uint256 n1 = _foldOnceWithCoeffs(m1, m3, r20, r21, r22, r23, r24, r25, r26, r27);
        return _foldOnceWithCoeffs(n0, n1, r30, r31, r32, r33, r34, r35, r36, r37);
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

        (
            uint256 r00,
            uint256 r01,
            uint256 r02,
            uint256 r03,
            uint256 r04,
            uint256 r05,
            uint256 r06,
            uint256 r07
        ) = _unpackCoeffs(p0);
        (
            uint256 r10,
            uint256 r11,
            uint256 r12,
            uint256 r13,
            uint256 r14,
            uint256 r15,
            uint256 r16,
            uint256 r17
        ) = _unpackCoeffs(p1);
        (
            uint256 r20,
            uint256 r21,
            uint256 r22,
            uint256 r23,
            uint256 r24,
            uint256 r25,
            uint256 r26,
            uint256 r27
        ) = _unpackCoeffs(p2);
        (
            uint256 r30,
            uint256 r31,
            uint256 r32,
            uint256 r33,
            uint256 r34,
            uint256 r35,
            uint256 r36,
            uint256 r37
        ) = _unpackCoeffs(p3);

        uint256 l0 = _foldOnceBase(v0, v8, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l1 = _foldOnceBase(v1, v9, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l2 = _foldOnceBase(v2, v10, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l3 = _foldOnceBase(v3, v11, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l4 = _foldOnceBase(v4, v12, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l5 = _foldOnceBase(v5, v13, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l6 = _foldOnceBase(v6, v14, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l7 = _foldOnceBase(v7, v15, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 m0 = _foldOnceWithCoeffs(l0, l4, r10, r11, r12, r13, r14, r15, r16, r17);
        uint256 m1 = _foldOnceWithCoeffs(l1, l5, r10, r11, r12, r13, r14, r15, r16, r17);
        uint256 m2 = _foldOnceWithCoeffs(l2, l6, r10, r11, r12, r13, r14, r15, r16, r17);
        uint256 m3 = _foldOnceWithCoeffs(l3, l7, r10, r11, r12, r13, r14, r15, r16, r17);
        uint256 n0 = _foldOnceWithCoeffs(m0, m2, r20, r21, r22, r23, r24, r25, r26, r27);
        uint256 n1 = _foldOnceWithCoeffs(m1, m3, r20, r21, r22, r23, r24, r25, r26, r27);
        evalValue = _foldOnceWithCoeffs(n0, n1, r30, r31, r32, r33, r34, r35, r36, r37);
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

            function validateExt8(packed) {
                let modulus := 0x7f000001
                let mask := 0xffffffff
                if or(
                    or(
                        or(
                            iszero(lt(shr(224, packed), modulus)),
                            iszero(lt(and(shr(192, packed), mask), modulus))
                        ),
                        or(
                            iszero(lt(and(shr(160, packed), mask), modulus)),
                            iszero(lt(and(shr(128, packed), mask), modulus))
                        )
                    ),
                    or(
                        or(
                            iszero(lt(and(shr(96, packed), mask), modulus)),
                            iszero(lt(and(shr(64, packed), mask), modulus))
                        ),
                        or(
                            iszero(lt(and(shr(32, packed), mask), modulus)),
                            iszero(lt(and(packed, mask), modulus))
                        )
                    )
                ) {
                    mstore(0x00, 0xd53cfe5c00000000000000000000000000000000000000000000000000000000)
                    mstore(0x04, packed)
                    revert(0x00, 0x24)
                }
            }

            validateExt8(v0)
            validateExt8(v1)
            validateExt8(v2)
            validateExt8(v3)
            validateExt8(v4)
            validateExt8(v5)
            validateExt8(v6)
            validateExt8(v7)
            validateExt8(v8)
            validateExt8(v9)
            validateExt8(v10)
            validateExt8(v11)
            validateExt8(v12)
            validateExt8(v13)
            validateExt8(v14)
            validateExt8(v15)
        }

        (
            uint256 r00,
            uint256 r01,
            uint256 r02,
            uint256 r03,
            uint256 r04,
            uint256 r05,
            uint256 r06,
            uint256 r07
        ) = _unpackCoeffs(point[0]);
        (
            uint256 r10,
            uint256 r11,
            uint256 r12,
            uint256 r13,
            uint256 r14,
            uint256 r15,
            uint256 r16,
            uint256 r17
        ) = _unpackCoeffs(point[1]);
        (
            uint256 r20,
            uint256 r21,
            uint256 r22,
            uint256 r23,
            uint256 r24,
            uint256 r25,
            uint256 r26,
            uint256 r27
        ) = _unpackCoeffs(point[2]);
        (
            uint256 r30,
            uint256 r31,
            uint256 r32,
            uint256 r33,
            uint256 r34,
            uint256 r35,
            uint256 r36,
            uint256 r37
        ) = _unpackCoeffs(point[3]);

        uint256 l0 = _foldOnceWithCoeffs(v0, v8, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l1 = _foldOnceWithCoeffs(v1, v9, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l2 = _foldOnceWithCoeffs(v2, v10, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l3 = _foldOnceWithCoeffs(v3, v11, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l4 = _foldOnceWithCoeffs(v4, v12, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l5 = _foldOnceWithCoeffs(v5, v13, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l6 = _foldOnceWithCoeffs(v6, v14, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l7 = _foldOnceWithCoeffs(v7, v15, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 m0 = _foldOnceWithCoeffs(l0, l4, r10, r11, r12, r13, r14, r15, r16, r17);
        uint256 m1 = _foldOnceWithCoeffs(l1, l5, r10, r11, r12, r13, r14, r15, r16, r17);
        uint256 m2 = _foldOnceWithCoeffs(l2, l6, r10, r11, r12, r13, r14, r15, r16, r17);
        uint256 m3 = _foldOnceWithCoeffs(l3, l7, r10, r11, r12, r13, r14, r15, r16, r17);
        uint256 n0 = _foldOnceWithCoeffs(m0, m2, r20, r21, r22, r23, r24, r25, r26, r27);
        uint256 n1 = _foldOnceWithCoeffs(m1, m3, r20, r21, r22, r23, r24, r25, r26, r27);
        return _foldOnceWithCoeffs(n0, n1, r30, r31, r32, r33, r34, r35, r36, r37);
    }

    function _hashAndEvaluateExtensionRowDim4PackedPoints(
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

            function validateExt8(packed) {
                let modulus := 0x7f000001
                let mask := 0xffffffff
                if or(
                    or(
                        or(
                            iszero(lt(shr(224, packed), modulus)),
                            iszero(lt(and(shr(192, packed), mask), modulus))
                        ),
                        or(
                            iszero(lt(and(shr(160, packed), mask), modulus)),
                            iszero(lt(and(shr(128, packed), mask), modulus))
                        )
                    ),
                    or(
                        or(
                            iszero(lt(and(shr(96, packed), mask), modulus)),
                            iszero(lt(and(shr(64, packed), mask), modulus))
                        ),
                        or(
                            iszero(lt(and(shr(32, packed), mask), modulus)),
                            iszero(lt(and(packed, mask), modulus))
                        )
                    )
                ) {
                    mstore(0x00, 0xd53cfe5c00000000000000000000000000000000000000000000000000000000)
                    mstore(0x04, packed)
                    revert(0x00, 0x24)
                }
            }

            validateExt8(v0)
            validateExt8(v1)
            validateExt8(v2)
            validateExt8(v3)
            validateExt8(v4)
            validateExt8(v5)
            validateExt8(v6)
            validateExt8(v7)
            validateExt8(v8)
            validateExt8(v9)
            validateExt8(v10)
            validateExt8(v11)
            validateExt8(v12)
            validateExt8(v13)
            validateExt8(v14)
            validateExt8(v15)
        }

        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore8(ptr, 0x00)
            mstore(add(ptr, 0x01), v0)
            mstore(add(ptr, 0x21), v1)
            mstore(add(ptr, 0x41), v2)
            mstore(add(ptr, 0x61), v3)
            mstore(add(ptr, 0x81), v4)
            mstore(add(ptr, 0xa1), v5)
            mstore(add(ptr, 0xc1), v6)
            mstore(add(ptr, 0xe1), v7)
            mstore(add(ptr, 0x101), v8)
            mstore(add(ptr, 0x121), v9)
            mstore(add(ptr, 0x141), v10)
            mstore(add(ptr, 0x161), v11)
            mstore(add(ptr, 0x181), v12)
            mstore(add(ptr, 0x1a1), v13)
            mstore(add(ptr, 0x1c1), v14)
            mstore(add(ptr, 0x1e1), v15)
            digest := and(keccak256(ptr, 513), not(sub(shl(96, 1), 1)))
        }

        (
            uint256 r00,
            uint256 r01,
            uint256 r02,
            uint256 r03,
            uint256 r04,
            uint256 r05,
            uint256 r06,
            uint256 r07
        ) = _unpackCoeffs(p0);
        (
            uint256 r10,
            uint256 r11,
            uint256 r12,
            uint256 r13,
            uint256 r14,
            uint256 r15,
            uint256 r16,
            uint256 r17
        ) = _unpackCoeffs(p1);
        (
            uint256 r20,
            uint256 r21,
            uint256 r22,
            uint256 r23,
            uint256 r24,
            uint256 r25,
            uint256 r26,
            uint256 r27
        ) = _unpackCoeffs(p2);
        (
            uint256 r30,
            uint256 r31,
            uint256 r32,
            uint256 r33,
            uint256 r34,
            uint256 r35,
            uint256 r36,
            uint256 r37
        ) = _unpackCoeffs(p3);

        uint256 l0 = _foldOnceWithCoeffs(v0, v8, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l1 = _foldOnceWithCoeffs(v1, v9, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l2 = _foldOnceWithCoeffs(v2, v10, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l3 = _foldOnceWithCoeffs(v3, v11, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l4 = _foldOnceWithCoeffs(v4, v12, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l5 = _foldOnceWithCoeffs(v5, v13, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l6 = _foldOnceWithCoeffs(v6, v14, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l7 = _foldOnceWithCoeffs(v7, v15, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 m0 = _foldOnceWithCoeffs(l0, l4, r10, r11, r12, r13, r14, r15, r16, r17);
        uint256 m1 = _foldOnceWithCoeffs(l1, l5, r10, r11, r12, r13, r14, r15, r16, r17);
        uint256 m2 = _foldOnceWithCoeffs(l2, l6, r10, r11, r12, r13, r14, r15, r16, r17);
        uint256 m3 = _foldOnceWithCoeffs(l3, l7, r10, r11, r12, r13, r14, r15, r16, r17);
        uint256 n0 = _foldOnceWithCoeffs(m0, m2, r20, r21, r22, r23, r24, r25, r26, r27);
        uint256 n1 = _foldOnceWithCoeffs(m1, m3, r20, r21, r22, r23, r24, r25, r26, r27);
        evalValue = _foldOnceWithCoeffs(n0, n1, r30, r31, r32, r33, r34, r35, r36, r37);
    }

    function _evaluateBaseRowDim4BlobWindow(
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

        return _evaluateBaseRowDim4BlobPackedPoints(blob, offset, p0, p1, p2, p3);
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

        evalValue = _evaluateBaseRowDim4FromBlobWords(w0, w1, p0, p1, p2, p3);
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

            function validateExt8(packed) {
                let modulus := 0x7f000001
                let mask := 0xffffffff
                if or(
                    or(
                        or(
                            iszero(lt(shr(224, packed), modulus)),
                            iszero(lt(and(shr(192, packed), mask), modulus))
                        ),
                        or(
                            iszero(lt(and(shr(160, packed), mask), modulus)),
                            iszero(lt(and(shr(128, packed), mask), modulus))
                        )
                    ),
                    or(
                        or(
                            iszero(lt(and(shr(96, packed), mask), modulus)),
                            iszero(lt(and(shr(64, packed), mask), modulus))
                        ),
                        or(
                            iszero(lt(and(shr(32, packed), mask), modulus)),
                            iszero(lt(and(packed, mask), modulus))
                        )
                    )
                ) {
                    mstore(0x00, 0xd53cfe5c00000000000000000000000000000000000000000000000000000000)
                    mstore(0x04, packed)
                    revert(0x00, 0x24)
                }
            }

            validateExt8(v0)
            validateExt8(v1)
            validateExt8(v2)
            validateExt8(v3)
            validateExt8(v4)
            validateExt8(v5)
            validateExt8(v6)
            validateExt8(v7)
            validateExt8(v8)
            validateExt8(v9)
            validateExt8(v10)
            validateExt8(v11)
            validateExt8(v12)
            validateExt8(v13)
            validateExt8(v14)
            validateExt8(v15)
        }

        (
            uint256 r00,
            uint256 r01,
            uint256 r02,
            uint256 r03,
            uint256 r04,
            uint256 r05,
            uint256 r06,
            uint256 r07
        ) = _unpackCoeffs(p0);
        (
            uint256 r10,
            uint256 r11,
            uint256 r12,
            uint256 r13,
            uint256 r14,
            uint256 r15,
            uint256 r16,
            uint256 r17
        ) = _unpackCoeffs(p1);
        (
            uint256 r20,
            uint256 r21,
            uint256 r22,
            uint256 r23,
            uint256 r24,
            uint256 r25,
            uint256 r26,
            uint256 r27
        ) = _unpackCoeffs(p2);
        (
            uint256 r30,
            uint256 r31,
            uint256 r32,
            uint256 r33,
            uint256 r34,
            uint256 r35,
            uint256 r36,
            uint256 r37
        ) = _unpackCoeffs(p3);

        uint256 l0 = _foldOnceWithCoeffs(v0, v8, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l1 = _foldOnceWithCoeffs(v1, v9, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l2 = _foldOnceWithCoeffs(v2, v10, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l3 = _foldOnceWithCoeffs(v3, v11, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l4 = _foldOnceWithCoeffs(v4, v12, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l5 = _foldOnceWithCoeffs(v5, v13, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l6 = _foldOnceWithCoeffs(v6, v14, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l7 = _foldOnceWithCoeffs(v7, v15, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 m0 = _foldOnceWithCoeffs(l0, l4, r10, r11, r12, r13, r14, r15, r16, r17);
        uint256 m1 = _foldOnceWithCoeffs(l1, l5, r10, r11, r12, r13, r14, r15, r16, r17);
        uint256 m2 = _foldOnceWithCoeffs(l2, l6, r10, r11, r12, r13, r14, r15, r16, r17);
        uint256 m3 = _foldOnceWithCoeffs(l3, l7, r10, r11, r12, r13, r14, r15, r16, r17);
        uint256 n0 = _foldOnceWithCoeffs(m0, m2, r20, r21, r22, r23, r24, r25, r26, r27);
        uint256 n1 = _foldOnceWithCoeffs(m1, m3, r20, r21, r22, r23, r24, r25, r26, r27);
        return _foldOnceWithCoeffs(n0, n1, r30, r31, r32, r33, r34, r35, r36, r37);
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
            let ptr := mload(0x40)
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

            function validateExt8(packed) {
                let modulus := 0x7f000001
                let mask := 0xffffffff
                if or(
                    or(
                        or(
                            iszero(lt(shr(224, packed), modulus)),
                            iszero(lt(and(shr(192, packed), mask), modulus))
                        ),
                        or(
                            iszero(lt(and(shr(160, packed), mask), modulus)),
                            iszero(lt(and(shr(128, packed), mask), modulus))
                        )
                    ),
                    or(
                        or(
                            iszero(lt(and(shr(96, packed), mask), modulus)),
                            iszero(lt(and(shr(64, packed), mask), modulus))
                        ),
                        or(
                            iszero(lt(and(shr(32, packed), mask), modulus)),
                            iszero(lt(and(packed, mask), modulus))
                        )
                    )
                ) {
                    mstore(0x00, 0xd53cfe5c00000000000000000000000000000000000000000000000000000000)
                    mstore(0x04, packed)
                    revert(0x00, 0x24)
                }
            }

            validateExt8(v0)
            validateExt8(v1)
            validateExt8(v2)
            validateExt8(v3)
            validateExt8(v4)
            validateExt8(v5)
            validateExt8(v6)
            validateExt8(v7)
            validateExt8(v8)
            validateExt8(v9)
            validateExt8(v10)
            validateExt8(v11)
            validateExt8(v12)
            validateExt8(v13)
            validateExt8(v14)
            validateExt8(v15)

            mstore8(ptr, 0x00)
            calldatacopy(add(ptr, 0x01), src, 0x200)
            digest := and(keccak256(ptr, 513), not(sub(shl(96, 1), 1)))
        }

        (
            uint256 r00,
            uint256 r01,
            uint256 r02,
            uint256 r03,
            uint256 r04,
            uint256 r05,
            uint256 r06,
            uint256 r07
        ) = _unpackCoeffs(p0);
        (
            uint256 r10,
            uint256 r11,
            uint256 r12,
            uint256 r13,
            uint256 r14,
            uint256 r15,
            uint256 r16,
            uint256 r17
        ) = _unpackCoeffs(p1);
        (
            uint256 r20,
            uint256 r21,
            uint256 r22,
            uint256 r23,
            uint256 r24,
            uint256 r25,
            uint256 r26,
            uint256 r27
        ) = _unpackCoeffs(p2);
        (
            uint256 r30,
            uint256 r31,
            uint256 r32,
            uint256 r33,
            uint256 r34,
            uint256 r35,
            uint256 r36,
            uint256 r37
        ) = _unpackCoeffs(p3);

        uint256 l0 = _foldOnceWithCoeffs(v0, v8, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l1 = _foldOnceWithCoeffs(v1, v9, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l2 = _foldOnceWithCoeffs(v2, v10, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l3 = _foldOnceWithCoeffs(v3, v11, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l4 = _foldOnceWithCoeffs(v4, v12, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l5 = _foldOnceWithCoeffs(v5, v13, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l6 = _foldOnceWithCoeffs(v6, v14, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l7 = _foldOnceWithCoeffs(v7, v15, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 m0 = _foldOnceWithCoeffs(l0, l4, r10, r11, r12, r13, r14, r15, r16, r17);
        uint256 m1 = _foldOnceWithCoeffs(l1, l5, r10, r11, r12, r13, r14, r15, r16, r17);
        uint256 m2 = _foldOnceWithCoeffs(l2, l6, r10, r11, r12, r13, r14, r15, r16, r17);
        uint256 m3 = _foldOnceWithCoeffs(l3, l7, r10, r11, r12, r13, r14, r15, r16, r17);
        uint256 n0 = _foldOnceWithCoeffs(m0, m2, r20, r21, r22, r23, r24, r25, r26, r27);
        uint256 n1 = _foldOnceWithCoeffs(m1, m3, r20, r21, r22, r23, r24, r25, r26, r27);
        evalValue = _foldOnceWithCoeffs(n0, n1, r30, r31, r32, r33, r34, r35, r36, r37);
    }

    /// @notice Like _hashAndEvaluateExtensionRowDim4BlobPackedPoints but takes folding
    /// coefficients already unpacked (32 scalars instead of 4 packed ext8 points).
    /// Callers should unpack p0..p3 once before a query loop and call this variant
    /// per row to avoid repeating the unpack on every row.
    function _hashAndEvaluateExtensionRowDim4BlobUnpacked(
        bytes calldata blob,
        uint256 offset,
        uint256 r00,
        uint256 r01,
        uint256 r02,
        uint256 r03,
        uint256 r04,
        uint256 r05,
        uint256 r06,
        uint256 r07,
        uint256 r10,
        uint256 r11,
        uint256 r12,
        uint256 r13,
        uint256 r14,
        uint256 r15,
        uint256 r16,
        uint256 r17,
        uint256 r20,
        uint256 r21,
        uint256 r22,
        uint256 r23,
        uint256 r24,
        uint256 r25,
        uint256 r26,
        uint256 r27,
        uint256 r30,
        uint256 r31,
        uint256 r32,
        uint256 r33,
        uint256 r34,
        uint256 r35,
        uint256 r36,
        uint256 r37
    ) internal pure returns (bytes32 digest, uint256 evalValue) {
        assembly ("memory-safe") {
            let src := add(blob.offset, offset)
            let ptr := mload(0x40)
            let rowPtr := add(ptr, 0x20)
            calldatacopy(rowPtr, src, 0x200)
            mstore8(sub(rowPtr, 1), 0x00)

            function revertPacked(packed) {
                mstore(0x00, 0xd53cfe5c00000000000000000000000000000000000000000000000000000000)
                mstore(0x04, packed)
                revert(0x00, 0x24)
            }

            function fold(a0, a1, rr0, rr1, rr2, rr3, rr4, rr5, rr6, rr7, validateInputs) -> out {
                let M := 0x7f000001
                let m := 0xffffffff

                function mul2(a0_, a1_, b0_, b1_) -> p0_, p1_, p2_ {
                    p0_ := mul(a0_, b0_)
                    p1_ := add(mul(a0_, b1_), mul(a1_, b0_))
                    p2_ := mul(a1_, b1_)
                }

                function mul4(a0_, a1_, a2_, a3_, b0_, b1_, b2_, b3_) ->
                    p0_,
                    p1_,
                    p2_,
                    p3_,
                    p4_,
                    p5_,
                    p6_
                {
                    let l0_, l1_, l2_ := mul2(a0_, a1_, b0_, b1_)
                    let h0_, h1_, h2_ := mul2(a2_, a3_, b2_, b3_)
                    let m0_, m1_, m2_ :=
                        mul2(add(a0_, a2_), add(a1_, a3_), add(b0_, b2_), add(b1_, b3_))

                    let x0_ := sub(sub(m0_, l0_), h0_)
                    let x1_ := sub(sub(m1_, l1_), h1_)
                    let x2_ := sub(sub(m2_, l2_), h2_)

                    p0_ := l0_
                    p1_ := l1_
                    p2_ := add(l2_, x0_)
                    p3_ := x1_
                    p4_ := add(x2_, h0_)
                    p5_ := h1_
                    p6_ := h2_
                }

                let a00 := shr(224, a0)
                let a01 := and(shr(192, a0), m)
                let a02 := and(shr(160, a0), m)
                let a03 := and(shr(128, a0), m)
                let a04 := and(shr(96, a0), m)
                let a05 := and(shr(64, a0), m)
                let a06 := and(shr(32, a0), m)
                let a07 := and(a0, m)

                let b00 := shr(224, a1)
                let b01 := and(shr(192, a1), m)
                let b02 := and(shr(160, a1), m)
                let b03 := and(shr(128, a1), m)
                let b04 := and(shr(96, a1), m)
                let b05 := and(shr(64, a1), m)
                let b06 := and(shr(32, a1), m)
                let b07 := and(a1, m)

                if validateInputs {
                    if or(
                        or(
                            or(iszero(lt(a00, M)), iszero(lt(a01, M))),
                            or(iszero(lt(a02, M)), iszero(lt(a03, M)))
                        ),
                        or(
                            or(iszero(lt(a04, M)), iszero(lt(a05, M))),
                            or(iszero(lt(a06, M)), iszero(lt(a07, M)))
                        )
                    ) {
                        revertPacked(a0)
                    }
                    if or(
                        or(
                            or(iszero(lt(b00, M)), iszero(lt(b01, M))),
                            or(iszero(lt(b02, M)), iszero(lt(b03, M)))
                        ),
                        or(
                            or(iszero(lt(b04, M)), iszero(lt(b05, M))),
                            or(iszero(lt(b06, M)), iszero(lt(b07, M)))
                        )
                    ) {
                        revertPacked(a1)
                    }
                }

                let d0 := sub(add(b00, M), a00)
                let d1 := sub(add(b01, M), a01)
                let d2 := sub(add(b02, M), a02)
                let d3 := sub(add(b03, M), a03)
                let d4 := sub(add(b04, M), a04)
                let d5 := sub(add(b05, M), a05)
                let d6 := sub(add(b06, M), a06)
                let d7 := sub(add(b07, M), a07)

                let scratch := add(mload(0x40), 0x220)

                {
                    let p00, p01, p02, p03, p04, p05, p06 :=
                        mul4(d0, d1, d2, d3, rr0, rr1, rr2, rr3)
                    mstore(scratch, p00)
                    mstore(add(scratch, 0x20), p01)
                    mstore(add(scratch, 0x40), p02)
                    mstore(add(scratch, 0x60), p03)
                    mstore(add(scratch, 0x80), p04)
                    mstore(add(scratch, 0xa0), p05)
                    mstore(add(scratch, 0xc0), p06)
                }

                {
                    let p20, p21, p22, p23, p24, p25, p26 :=
                        mul4(d4, d5, d6, d7, rr4, rr5, rr6, rr7)
                    let hiBase := add(scratch, 0xe0)
                    mstore(hiBase, p20)
                    mstore(add(hiBase, 0x20), p21)
                    mstore(add(hiBase, 0x40), p22)
                    mstore(add(hiBase, 0x60), p23)
                    mstore(add(hiBase, 0x80), p24)
                    mstore(add(hiBase, 0xa0), p25)
                    mstore(add(hiBase, 0xc0), p26)
                }

                let q0, q1, q2, q3, q4, q5, q6 :=
                    mul4(
                        add(d0, d4),
                        add(d1, d5),
                        add(d2, d6),
                        add(d3, d7),
                        add(rr0, rr4),
                        add(rr1, rr5),
                        add(rr2, rr6),
                        add(rr3, rr7)
                    )

                let hiBase := add(scratch, 0xe0)

                let l0 := mload(scratch)
                let h0 := mload(hiBase)
                let l4 := mload(add(scratch, 0x80))
                let h4 := mload(add(hiBase, 0x80))
                let x0 := sub(sub(q0, l0), h0)
                let x4 := sub(sub(q4, l4), h4)
                let c0 := mod(add(a00, add(l0, mul(3, add(h0, x4)))), M)
                let c4 := mod(add(a04, add(add(l4, mul(3, h4)), x0)), M)

                let l1 := mload(add(scratch, 0x20))
                let h1 := mload(add(hiBase, 0x20))
                let l5 := mload(add(scratch, 0xa0))
                let h5 := mload(add(hiBase, 0xa0))
                let x1 := sub(sub(q1, l1), h1)
                let x5 := sub(sub(q5, l5), h5)
                let c1 := mod(add(a01, add(l1, mul(3, add(h1, x5)))), M)
                let c5 := mod(add(a05, add(add(l5, mul(3, h5)), x1)), M)

                let l2 := mload(add(scratch, 0x40))
                let h2 := mload(add(hiBase, 0x40))
                let l6 := mload(add(scratch, 0xc0))
                let h6 := mload(add(hiBase, 0xc0))
                let x2 := sub(sub(q2, l2), h2)
                let x6 := sub(sub(q6, l6), h6)
                let c2 := mod(add(a02, add(l2, mul(3, add(h2, x6)))), M)
                let c6 := mod(add(a06, add(add(l6, mul(3, h6)), x2)), M)

                let l3 := mload(add(scratch, 0x60))
                let h3 := mload(add(hiBase, 0x60))
                let c3 := mod(add(a03, add(l3, mul(3, h3))), M)
                let c7 := mod(add(a07, sub(sub(q3, l3), h3)), M)

                out := or(
                    or(or(shl(224, c0), shl(192, c1)), or(shl(160, c2), shl(128, c3))),
                    or(or(shl(96, c4), shl(64, c5)), or(shl(32, c6), c7))
                )
            }

            digest := and(keccak256(sub(rowPtr, 1), 513), not(sub(shl(96, 1), 1)))

            let m0 :=
                fold(
                    fold(
                        mload(rowPtr),
                        mload(add(rowPtr, 0x100)),
                        r00,
                        r01,
                        r02,
                        r03,
                        r04,
                        r05,
                        r06,
                        r07,
                        1
                    ),
                    fold(
                        mload(add(rowPtr, 0x80)),
                        mload(add(rowPtr, 0x180)),
                        r00,
                        r01,
                        r02,
                        r03,
                        r04,
                        r05,
                        r06,
                        r07,
                        1
                    ),
                    r10,
                    r11,
                    r12,
                    r13,
                    r14,
                    r15,
                    r16,
                    r17,
                    0
                )
            let m1 :=
                fold(
                    fold(
                        mload(add(rowPtr, 0x20)),
                        mload(add(rowPtr, 0x120)),
                        r00,
                        r01,
                        r02,
                        r03,
                        r04,
                        r05,
                        r06,
                        r07,
                        1
                    ),
                    fold(
                        mload(add(rowPtr, 0xa0)),
                        mload(add(rowPtr, 0x1a0)),
                        r00,
                        r01,
                        r02,
                        r03,
                        r04,
                        r05,
                        r06,
                        r07,
                        1
                    ),
                    r10,
                    r11,
                    r12,
                    r13,
                    r14,
                    r15,
                    r16,
                    r17,
                    0
                )
            let m2 :=
                fold(
                    fold(
                        mload(add(rowPtr, 0x40)),
                        mload(add(rowPtr, 0x140)),
                        r00,
                        r01,
                        r02,
                        r03,
                        r04,
                        r05,
                        r06,
                        r07,
                        1
                    ),
                    fold(
                        mload(add(rowPtr, 0xc0)),
                        mload(add(rowPtr, 0x1c0)),
                        r00,
                        r01,
                        r02,
                        r03,
                        r04,
                        r05,
                        r06,
                        r07,
                        1
                    ),
                    r10,
                    r11,
                    r12,
                    r13,
                    r14,
                    r15,
                    r16,
                    r17,
                    0
                )
            let m3 :=
                fold(
                    fold(
                        mload(add(rowPtr, 0x60)),
                        mload(add(rowPtr, 0x160)),
                        r00,
                        r01,
                        r02,
                        r03,
                        r04,
                        r05,
                        r06,
                        r07,
                        1
                    ),
                    fold(
                        mload(add(rowPtr, 0xe0)),
                        mload(add(rowPtr, 0x1e0)),
                        r00,
                        r01,
                        r02,
                        r03,
                        r04,
                        r05,
                        r06,
                        r07,
                        1
                    ),
                    r10,
                    r11,
                    r12,
                    r13,
                    r14,
                    r15,
                    r16,
                    r17,
                    0
                )
            evalValue := fold(
                fold(m0, m2, r20, r21, r22, r23, r24, r25, r26, r27, 0),
                fold(m1, m3, r20, r21, r22, r23, r24, r25, r26, r27, 0),
                r30,
                r31,
                r32,
                r33,
                r34,
                r35,
                r36,
                r37,
                0
            )
        }
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

        (
            uint256 r00,
            uint256 r01,
            uint256 r02,
            uint256 r03,
            uint256 r04,
            uint256 r05,
            uint256 r06,
            uint256 r07
        ) = _unpackCoeffs(p0);
        (
            uint256 r10,
            uint256 r11,
            uint256 r12,
            uint256 r13,
            uint256 r14,
            uint256 r15,
            uint256 r16,
            uint256 r17
        ) = _unpackCoeffs(p1);
        (
            uint256 r20,
            uint256 r21,
            uint256 r22,
            uint256 r23,
            uint256 r24,
            uint256 r25,
            uint256 r26,
            uint256 r27
        ) = _unpackCoeffs(p2);
        (
            uint256 r30,
            uint256 r31,
            uint256 r32,
            uint256 r33,
            uint256 r34,
            uint256 r35,
            uint256 r36,
            uint256 r37
        ) = _unpackCoeffs(p3);

        uint256 l0 = _foldOnceBase(v0, v8, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l1 = _foldOnceBase(v1, v9, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l2 = _foldOnceBase(v2, v10, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l3 = _foldOnceBase(v3, v11, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l4 = _foldOnceBase(v4, v12, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l5 = _foldOnceBase(v5, v13, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l6 = _foldOnceBase(v6, v14, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 l7 = _foldOnceBase(v7, v15, r00, r01, r02, r03, r04, r05, r06, r07);
        uint256 m0 = _foldOnceWithCoeffs(l0, l4, r10, r11, r12, r13, r14, r15, r16, r17);
        uint256 m1 = _foldOnceWithCoeffs(l1, l5, r10, r11, r12, r13, r14, r15, r16, r17);
        uint256 m2 = _foldOnceWithCoeffs(l2, l6, r10, r11, r12, r13, r14, r15, r16, r17);
        uint256 m3 = _foldOnceWithCoeffs(l3, l7, r10, r11, r12, r13, r14, r15, r16, r17);
        uint256 n0 = _foldOnceWithCoeffs(m0, m2, r20, r21, r22, r23, r24, r25, r26, r27);
        uint256 n1 = _foldOnceWithCoeffs(m1, m3, r20, r21, r22, r23, r24, r25, r26, r27);
        return _foldOnceWithCoeffs(n0, n1, r30, r31, r32, r33, r34, r35, r36, r37);
    }

    function _foldOnceBase(
        uint256 a0,
        uint256 a1,
        uint256 r0,
        uint256 r1,
        uint256 r2,
        uint256 r3,
        uint256 r4,
        uint256 r5,
        uint256 r6,
        uint256 r7
    ) private pure returns (uint256 out) {
        assembly ("memory-safe") {
            let M := 0x7f000001
            let d := sub(add(a1, M), a0)
            out := or(
                or(
                    or(shl(224, mod(add(a0, mul(r0, d)), M)), shl(192, mulmod(r1, d, M))),
                    or(shl(160, mulmod(r2, d, M)), shl(128, mulmod(r3, d, M)))
                ),
                or(
                    or(shl(96, mulmod(r4, d, M)), shl(64, mulmod(r5, d, M))),
                    or(shl(32, mulmod(r6, d, M)), mulmod(r7, d, M))
                )
            )
        }
    }

    function foldOncePackedForTest(uint256 a0, uint256 a1, uint256 r)
        internal
        pure
        returns (uint256)
    {
        (
            uint256 r0,
            uint256 r1,
            uint256 r2,
            uint256 r3,
            uint256 r4,
            uint256 r5,
            uint256 r6,
            uint256 r7
        ) = _unpackCoeffs(r);
        return _foldOnceWithCoeffs(a0, a1, r0, r1, r2, r3, r4, r5, r6, r7);
    }

    function foldOncePackedSchoolbookForTest(uint256 a0, uint256 a1, uint256 r)
        internal
        pure
        returns (uint256)
    {
        (
            uint256 r0,
            uint256 r1,
            uint256 r2,
            uint256 r3,
            uint256 r4,
            uint256 r5,
            uint256 r6,
            uint256 r7
        ) = _unpackCoeffs(r);
        return _foldOnceWithCoeffsSchoolbook(a0, a1, r0, r1, r2, r3, r4, r5, r6, r7);
    }

    function _foldOnceWithCoeffs(
        uint256 a0,
        uint256 a1,
        uint256 r0,
        uint256 r1,
        uint256 r2,
        uint256 r3,
        uint256 r4,
        uint256 r5,
        uint256 r6,
        uint256 r7
    ) private pure returns (uint256 out) {
        return _foldOnceWithCoeffsKaratsuba(a0, a1, r0, r1, r2, r3, r4, r5, r6, r7);
    }

    function _foldOnceWithCoeffsSchoolbook(
        uint256 a0,
        uint256 a1,
        uint256 r0,
        uint256 r1,
        uint256 r2,
        uint256 r3,
        uint256 r4,
        uint256 r5,
        uint256 r6,
        uint256 r7
    ) private pure returns (uint256 out) {
        assembly ("memory-safe") {
            let M := 0x7f000001
            let m := 0xffffffff

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

    function _foldOnceWithCoeffsKaratsuba(
        uint256 a0,
        uint256 a1,
        uint256 r0,
        uint256 r1,
        uint256 r2,
        uint256 r3,
        uint256 r4,
        uint256 r5,
        uint256 r6,
        uint256 r7
    ) private pure returns (uint256 out) {
        assembly ("memory-safe") {
            let M := 0x7f000001
            let m := 0xffffffff

            function mul2(a0_, a1_, b0_, b1_) -> p0_, p1_, p2_ {
                p0_ := mul(a0_, b0_)
                p1_ := add(mul(a0_, b1_), mul(a1_, b0_))
                p2_ := mul(a1_, b1_)
            }

            function mul4(a0_, a1_, a2_, a3_, b0_, b1_, b2_, b3_) ->
                p0_,
                p1_,
                p2_,
                p3_,
                p4_,
                p5_,
                p6_
            {
                let l0_, l1_, l2_ := mul2(a0_, a1_, b0_, b1_)
                let h0_, h1_, h2_ := mul2(a2_, a3_, b2_, b3_)
                let m0_, m1_, m2_ :=
                    mul2(add(a0_, a2_), add(a1_, a3_), add(b0_, b2_), add(b1_, b3_))

                let x0_ := sub(sub(m0_, l0_), h0_)
                let x1_ := sub(sub(m1_, l1_), h1_)
                let x2_ := sub(sub(m2_, l2_), h2_)

                p0_ := l0_
                p1_ := l1_
                p2_ := add(l2_, x0_)
                p3_ := x1_
                p4_ := add(x2_, h0_)
                p5_ := h1_
                p6_ := h2_
            }

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

            let scratch := mload(0x40)

            {
                let p00, p01, p02, p03, p04, p05, p06 := mul4(d0, d1, d2, d3, r0, r1, r2, r3)
                mstore(scratch, p00)
                mstore(add(scratch, 0x20), p01)
                mstore(add(scratch, 0x40), p02)
                mstore(add(scratch, 0x60), p03)
                mstore(add(scratch, 0x80), p04)
                mstore(add(scratch, 0xa0), p05)
                mstore(add(scratch, 0xc0), p06)
            }

            {
                let p20, p21, p22, p23, p24, p25, p26 := mul4(d4, d5, d6, d7, r4, r5, r6, r7)
                let hiBase := add(scratch, 0xe0)
                mstore(hiBase, p20)
                mstore(add(hiBase, 0x20), p21)
                mstore(add(hiBase, 0x40), p22)
                mstore(add(hiBase, 0x60), p23)
                mstore(add(hiBase, 0x80), p24)
                mstore(add(hiBase, 0xa0), p25)
                mstore(add(hiBase, 0xc0), p26)
            }

            let q0, q1, q2, q3, q4, q5, q6 :=
                mul4(
                    add(d0, d4),
                    add(d1, d5),
                    add(d2, d6),
                    add(d3, d7),
                    add(r0, r4),
                    add(r1, r5),
                    add(r2, r6),
                    add(r3, r7)
                )

            let hiBase := add(scratch, 0xe0)

            let l0 := mload(scratch)
            let h0 := mload(hiBase)
            let l4 := mload(add(scratch, 0x80))
            let h4 := mload(add(hiBase, 0x80))
            let x0 := sub(sub(q0, l0), h0)
            let x4 := sub(sub(q4, l4), h4)
            let c0 := mod(add(a00, add(l0, mul(3, add(h0, x4)))), M)
            let c4 := mod(add(a04, add(add(l4, mul(3, h4)), x0)), M)

            let l1 := mload(add(scratch, 0x20))
            let h1 := mload(add(hiBase, 0x20))
            let l5 := mload(add(scratch, 0xa0))
            let h5 := mload(add(hiBase, 0xa0))
            let x1 := sub(sub(q1, l1), h1)
            let x5 := sub(sub(q5, l5), h5)
            let c1 := mod(add(a01, add(l1, mul(3, add(h1, x5)))), M)
            let c5 := mod(add(a05, add(add(l5, mul(3, h5)), x1)), M)

            let l2 := mload(add(scratch, 0x40))
            let h2 := mload(add(hiBase, 0x40))
            let l6 := mload(add(scratch, 0xc0))
            let h6 := mload(add(hiBase, 0xc0))
            let x2 := sub(sub(q2, l2), h2)
            let x6 := sub(sub(q6, l6), h6)
            let c2 := mod(add(a02, add(l2, mul(3, add(h2, x6)))), M)
            let c6 := mod(add(a06, add(add(l6, mul(3, h6)), x2)), M)

            let l3 := mload(add(scratch, 0x60))
            let h3 := mload(add(hiBase, 0x60))
            let c3 := mod(add(a03, add(l3, mul(3, h3))), M)
            let c7 := mod(add(a07, sub(sub(q3, l3), h3)), M)

            out := or(
                or(or(shl(224, c0), shl(192, c1)), or(shl(160, c2), shl(128, c3))),
                or(or(shl(96, c4), shl(64, c5)), or(shl(32, c6), c7))
            )
        }
    }

    function _unpackCoeffs(uint256 packed)
        internal
        pure
        returns (
            uint256 c0,
            uint256 c1,
            uint256 c2,
            uint256 c3,
            uint256 c4,
            uint256 c5,
            uint256 c6,
            uint256 c7
        )
    {
        c0 = packed >> 224;
        c1 = (packed >> 192) & 0xffffffff;
        c2 = (packed >> 160) & 0xffffffff;
        c3 = (packed >> 128) & 0xffffffff;
        c4 = (packed >> 96) & 0xffffffff;
        c5 = (packed >> 64) & 0xffffffff;
        c6 = (packed >> 32) & 0xffffffff;
        c7 = packed & 0xffffffff;
    }
}
