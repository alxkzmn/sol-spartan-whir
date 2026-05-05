// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { KoalaBear } from "../../field/KoalaBear.sol";
import { KoalaBearExt5 } from "../../field/KoalaBearExt5.sol";
import { KoalaBearExt5Precompile } from "../../field/KoalaBearExt5Precompile.sol";
import { MerkleVerifier } from "../../merkle/MerkleVerifier.sol";
import { KeccakChallenger } from "../../transcript/KeccakChallenger.sol";
import { WhirStructs } from "../WhirStructs.sol";
import {
    WhirBlobCodec5
} from "../k22_jb100_ext5_lir4_ff4_rsv3_pow28/WhirBlobCodec5_k22_jb100_ext5_lir4_ff4_rsv3_pow28.sol";
import { WhirVerifierUtils5 } from "../k22_jb100_ext5_lir4_ff4_rsv3_pow28/WhirVerifierUtils5.sol";

library WhirVerifierCore5Precompile {
    using KeccakChallenger for KeccakChallenger.State;

    struct EqStatement {
        uint256 numVariables;
        uint256[] flatPoints;
        uint256[] evaluations;
    }

    struct SelectStatement {
        uint256 numVariables;
        uint256[] vars;
    }

    struct Constraint {
        uint256 challenge;
        EqStatement eqStatement;
        SelectStatement selStatement;
    }

    struct ParsedCommitment {
        bytes32 root;
        EqStatement oodStatement;
    }

    struct FixedParsedCommitment {
        bytes32 root;
        uint256[] oodFlatPoints;
        uint256 oodEvaluation;
    }

    error CommitmentMismatch(bytes32 expected, bytes32 actual);
    error ProofRoundCountMismatch(uint256 expected, uint256 actual);
    error StatementLengthMismatch(uint256 points, uint256 evaluations);
    error StatementPointArityMismatch(uint256 index, uint256 expected, uint256 actual);
    error OodAnswerCountMismatch(uint256 expected, uint256 actual);
    error FinalPolyLengthMismatch(uint256 expected, uint256 actual);
    error FinalQueryBatchPresenceMismatch(bool expected, bool actual);
    error FinalSumcheckPresenceMismatch(bool expected, bool actual);
    error QueryBatchKindMismatch(uint8 expected, uint8 actual);
    error QueryBatchCountMismatch(uint256 expected, uint256 actual);
    error QueryBatchRowLengthMismatch(uint256 expected, uint256 actual);
    error MerkleRootMismatch(bytes32 expected, bytes32 actual);
    error InvalidPowWitness();
    error SumcheckPolynomialLengthMismatch(uint256 expected, uint256 actual);
    error SumcheckPowWitnessLengthMismatch(uint256 expected, uint256 actual);
    error StirConstraintFailed(uint256 index);
    error FinalConstraintMismatch(uint256 expected, uint256 actual);
    error InconsistentConstraintArity(uint256 eqNumVariables, uint256 selNumVariables);
    error RandomnessLengthMismatch(uint256 expected, uint256 actual);

    function _powBatch10(
        uint256 base,
        uint256 e0,
        uint256 e1,
        uint256 e2,
        uint256 e3,
        uint256 e4,
        uint256 e5,
        uint256 e6,
        uint256 e7,
        uint256 e8,
        uint256 e9
    )
        private
        pure
        returns (
            uint256 p0,
            uint256 p1,
            uint256 p2,
            uint256 p3,
            uint256 p4,
            uint256 p5,
            uint256 p6,
            uint256 p7,
            uint256 p8,
            uint256 p9
        )
    {
        p0 = 1;
        p1 = 1;
        p2 = 1;
        p3 = 1;
        p4 = 1;
        p5 = 1;
        p6 = 1;
        p7 = 1;
        p8 = 1;
        p9 = 1;

        unchecked {
            while (true) {
                if ((e0 & 1) != 0) p0 = KoalaBear.mul(p0, base);
                if ((e1 & 1) != 0) p1 = KoalaBear.mul(p1, base);
                if ((e2 & 1) != 0) p2 = KoalaBear.mul(p2, base);
                if ((e3 & 1) != 0) p3 = KoalaBear.mul(p3, base);
                if ((e4 & 1) != 0) p4 = KoalaBear.mul(p4, base);
                if ((e5 & 1) != 0) p5 = KoalaBear.mul(p5, base);
                if ((e6 & 1) != 0) p6 = KoalaBear.mul(p6, base);
                if ((e7 & 1) != 0) p7 = KoalaBear.mul(p7, base);
                if ((e8 & 1) != 0) p8 = KoalaBear.mul(p8, base);
                if ((e9 & 1) != 0) p9 = KoalaBear.mul(p9, base);

                e0 >>= 1;
                e1 >>= 1;
                e2 >>= 1;
                e3 >>= 1;
                e4 >>= 1;
                e5 >>= 1;
                e6 >>= 1;
                e7 >>= 1;
                e8 >>= 1;
                e9 >>= 1;

                if ((e0 | e1 | e2 | e3 | e4 | e5 | e6 | e7 | e8 | e9) == 0) break;

                base = KoalaBear.mul(base, base);
            }
        }
    }

    function _fillSelVarsPow(uint256[] memory selVars, uint256 base, uint256 count) private pure {
        unchecked {
            uint256 i;
            for (; i + 10 <= count; i += 10) {
                uint256 e0;
                uint256 e1;
                uint256 e2;
                uint256 e3;
                uint256 e4;
                uint256 e5;
                uint256 e6;
                uint256 e7;
                uint256 e8;
                uint256 e9;
                assembly ("memory-safe") {
                    let ptr := add(add(selVars, 0x20), shl(5, i))
                    e0 := mload(ptr)
                    e1 := mload(add(ptr, 0x20))
                    e2 := mload(add(ptr, 0x40))
                    e3 := mload(add(ptr, 0x60))
                    e4 := mload(add(ptr, 0x80))
                    e5 := mload(add(ptr, 0xa0))
                    e6 := mload(add(ptr, 0xc0))
                    e7 := mload(add(ptr, 0xe0))
                    e8 := mload(add(ptr, 0x100))
                    e9 := mload(add(ptr, 0x120))
                }
                (
                    uint256 p0,
                    uint256 p1,
                    uint256 p2,
                    uint256 p3,
                    uint256 p4,
                    uint256 p5,
                    uint256 p6,
                    uint256 p7,
                    uint256 p8,
                    uint256 p9
                ) = _powBatch10(base, e0, e1, e2, e3, e4, e5, e6, e7, e8, e9);
                assembly ("memory-safe") {
                    let ptr := add(add(selVars, 0x20), shl(5, i))
                    mstore(ptr, p0)
                    mstore(add(ptr, 0x20), p1)
                    mstore(add(ptr, 0x40), p2)
                    mstore(add(ptr, 0x60), p3)
                    mstore(add(ptr, 0x80), p4)
                    mstore(add(ptr, 0xa0), p5)
                    mstore(add(ptr, 0xc0), p6)
                    mstore(add(ptr, 0xe0), p7)
                    mstore(add(ptr, 0x100), p8)
                    mstore(add(ptr, 0x120), p9)
                }
            }
            for (; i < count; ++i) {
                selVars[i] = KoalaBear.pow(base, selVars[i]);
            }
        }
    }

    function _computeExtension5RootAndEvalsBlob16(
        uint256[] memory indices,
        bytes calldata blob,
        uint256 valuesOffset,
        uint256 depth,
        uint256 decommOffset,
        uint256 decommLen,
        uint256 p0,
        uint256 p1,
        uint256 p2,
        uint256 p3
    ) private view returns (bytes32 root, uint256[] memory rowEvals) {
        uint256 count = indices.length;
        if (count == 0) {
            revert MerkleVerifier.EmptyIndices();
        }

        uint256[] memory frontierEntries;
        assembly ("memory-safe") {
            frontierEntries := mload(0x40)
            mstore(frontierEntries, count)
            rowEvals := add(add(frontierEntries, 0x20), shl(5, count))
            mstore(rowEvals, count)
            mstore(0x40, add(add(rowEvals, 0x20), shl(5, count)))
        }

        uint256 eqWeightsPtr = _computeDim4EqWeightsPrecompile(p0, p1, p2, p3);

        unchecked {
            uint256 prevIdx;
            for (uint256 i = 0; i < count; ++i) {
                uint256 idx = indices[i];
                if (i != 0 && prevIdx >= idx) {
                    revert MerkleVerifier.IndicesNotStrictlyIncreasing(prevIdx, idx);
                }
                prevIdx = idx;

                uint256 rowOffset = valuesOffset + i * 320;
                (bytes32 hash, uint256 evalValue) =
                    _hashAndEvaluateExtension5RowDim4BlobMac(blob, rowOffset, eqWeightsPtr);
                rowEvals[i] = evalValue;

                assembly ("memory-safe") {
                    mstore(add(add(frontierEntries, 0x20), shl(5, i)), or(hash, idx))
                }
            }
        }

        root = MerkleVerifier.computeRootFromPackedFrontier20Blob(
            frontierEntries, count, depth, blob, decommOffset, decommLen
        );
    }

    function _hashAndEvaluateExtension5RowDim4BlobMac(
        bytes calldata blob,
        uint256 offset,
        uint256 weightsPtr
    ) private view returns (bytes32 digest, uint256 evalValue) {
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
        uint256 inputPtr;
        uint256 outputPtr;
        uint256 macFieldId = KoalaBearExt5Precompile.EXTFIELD_MAC_FIELD_ID_KOALABEAR_EXT5;
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
                    iszero(lt(and(shr(96, packed), mask), modulus))
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

            inputPtr := ptr
            outputPtr := add(inputPtr, 0x420)
            mstore(0x40, add(outputPtr, 0x20))
            mstore(inputPtr, or(shl(240, macFieldId), shl(224, 16)))

            // This MAC input is fixed-shape: exactly 16 row values and 16 weights.
            function storePair(base, index, weight, value) {
                let dst := add(add(base, 0x08), shl(6, index))
                mstore(dst, weight)
                mstore(add(dst, 0x20), value)
            }

            storePair(inputPtr, 0, mload(weightsPtr), v0)
            storePair(inputPtr, 1, mload(add(weightsPtr, 0x20)), v1)
            storePair(inputPtr, 2, mload(add(weightsPtr, 0x40)), v2)
            storePair(inputPtr, 3, mload(add(weightsPtr, 0x60)), v3)
            storePair(inputPtr, 4, mload(add(weightsPtr, 0x80)), v4)
            storePair(inputPtr, 5, mload(add(weightsPtr, 0xa0)), v5)
            storePair(inputPtr, 6, mload(add(weightsPtr, 0xc0)), v6)
            storePair(inputPtr, 7, mload(add(weightsPtr, 0xe0)), v7)
            storePair(inputPtr, 8, mload(add(weightsPtr, 0x100)), v8)
            storePair(inputPtr, 9, mload(add(weightsPtr, 0x120)), v9)
            storePair(inputPtr, 10, mload(add(weightsPtr, 0x140)), v10)
            storePair(inputPtr, 11, mload(add(weightsPtr, 0x160)), v11)
            storePair(inputPtr, 12, mload(add(weightsPtr, 0x180)), v12)
            storePair(inputPtr, 13, mload(add(weightsPtr, 0x1a0)), v13)
            storePair(inputPtr, 14, mload(add(weightsPtr, 0x1c0)), v14)
            storePair(inputPtr, 15, mload(add(weightsPtr, 0x1e0)), v15)
        }

        KoalaBearExt5Precompile.macInto(inputPtr, 0x408, outputPtr);
        assembly ("memory-safe") {
            evalValue := mload(outputPtr)
        }
    }

    function _computeBaseRootAndEvals16(
        uint256[] memory indices,
        uint256[] calldata flatValues,
        uint256 depth,
        bytes32[] calldata decommitments,
        uint256 p0,
        uint256 p1,
        uint256 p2,
        uint256 p3
    ) private pure returns (bytes32 root, uint256[] memory rowEvals) {
        uint256 count = indices.length;
        if (count == 0) {
            revert MerkleVerifier.EmptyIndices();
        }

        uint256[] memory frontierEntries;
        assembly ("memory-safe") {
            frontierEntries := mload(0x40)
            mstore(frontierEntries, count)
            rowEvals := add(add(frontierEntries, 0x20), shl(5, count))
            mstore(rowEvals, count)
            mstore(0x40, add(add(rowEvals, 0x20), shl(5, count)))
        }

        unchecked {
            uint256 prevIdx;
            for (uint256 i = 0; i < count; ++i) {
                uint256 idx = indices[i];
                if (i != 0 && prevIdx >= idx) {
                    revert MerkleVerifier.IndicesNotStrictlyIncreasing(prevIdx, idx);
                }
                prevIdx = idx;

                (bytes32 hash, uint256 evalValue) = WhirVerifierUtils5._hashAndEvaluateBaseRowDim4PackedPoints(
                    flatValues, i * 16, p0, p1, p2, p3
                );
                rowEvals[i] = evalValue;

                assembly ("memory-safe") {
                    mstore(add(add(frontierEntries, 0x20), shl(5, i)), or(hash, idx))
                }
            }
        }

        root = MerkleVerifier.computeRootFromPackedFrontier20(
            frontierEntries, count, depth, decommitments
        );
    }

    function _computeExtension5RootAndEvals16(
        uint256[] memory indices,
        uint256[] calldata flatValues,
        uint256 depth,
        bytes32[] calldata decommitments,
        uint256 p0,
        uint256 p1,
        uint256 p2,
        uint256 p3
    ) private pure returns (bytes32 root, uint256[] memory rowEvals) {
        uint256 count = indices.length;
        if (count == 0) {
            revert MerkleVerifier.EmptyIndices();
        }

        uint256[] memory frontierEntries;
        assembly ("memory-safe") {
            frontierEntries := mload(0x40)
            mstore(frontierEntries, count)
            rowEvals := add(add(frontierEntries, 0x20), shl(5, count))
            mstore(rowEvals, count)
            mstore(0x40, add(add(rowEvals, 0x20), shl(5, count)))
        }

        uint256[] memory point = new uint256[](4);
        point[0] = p0;
        point[1] = p1;
        point[2] = p2;
        point[3] = p3;

        unchecked {
            uint256 prevIdx;
            for (uint256 i = 0; i < count; ++i) {
                uint256 idx = indices[i];
                if (i != 0 && prevIdx >= idx) {
                    revert MerkleVerifier.IndicesNotStrictlyIncreasing(prevIdx, idx);
                }
                prevIdx = idx;

                uint256 rowStart = i * 16;
                bytes32 hash = MerkleVerifier.hashLeafExtension5Slice20(flatValues, rowStart, 16);
                rowEvals[i] = WhirVerifierUtils5.evaluateExtensionRowAsExt5(
                    flatValues, rowStart, 16, point
                );

                assembly ("memory-safe") {
                    mstore(add(add(frontierEntries, 0x20), shl(5, i)), or(hash, idx))
                }
            }
        }

        root = MerkleVerifier.computeRootFromPackedFrontier20(
            frontierEntries, count, depth, decommitments
        );
    }

    function _verifyFinalStirChallengesBlob16(
        bytes32 expectedRoot,
        uint256 numQueries,
        uint256 depth,
        uint256 foldedDomainGen,
        bytes calldata blob,
        uint256 valuesOffset,
        uint256 decommOffset,
        uint256 decommLen,
        uint256[] memory indices,
        uint256[] memory allRandomness,
        uint256 randomnessOffset,
        uint256 finalPolyOffset,
        uint256 finalPolyLength
    ) private view {
        uint256 pointBase;
        assembly ("memory-safe") {
            pointBase := add(add(allRandomness, 0x20), shl(5, randomnessOffset))
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

        bytes32 computedRoot;
        uint256[] memory rowEvals;
        (computedRoot, rowEvals) = _computeExtension5RootAndEvalsBlob16(
            indices, blob, valuesOffset, depth, decommOffset, decommLen, p0, p1, p2, p3
        );

        if (computedRoot != expectedRoot) {
            revert MerkleRootMismatch(expectedRoot, computedRoot);
        }

        unchecked {
            if (finalPolyLength == 64 && numQueries == 14) {
                uint256 idx0;
                uint256 idx1;
                uint256 idx2;
                uint256 idx3;
                uint256 idx4;
                uint256 idx5;
                uint256 idx6;
                uint256 idx7;
                uint256 idx8;
                uint256 idx9;
                assembly ("memory-safe") {
                    let indicesBase := add(indices, 0x20)
                    idx0 := mload(indicesBase)
                    idx1 := mload(add(indicesBase, 0x20))
                    idx2 := mload(add(indicesBase, 0x40))
                    idx3 := mload(add(indicesBase, 0x60))
                    idx4 := mload(add(indicesBase, 0x80))
                    idx5 := mload(add(indicesBase, 0xa0))
                    idx6 := mload(add(indicesBase, 0xc0))
                    idx7 := mload(add(indicesBase, 0xe0))
                    idx8 := mload(add(indicesBase, 0x100))
                    idx9 := mload(add(indicesBase, 0x120))
                }
                (
                    uint256 point0,
                    uint256 point1,
                    uint256 point2,
                    uint256 point3,
                    uint256 point4,
                    uint256 point5,
                    uint256 point6,
                    uint256 point7,
                    uint256 point8,
                    uint256 point9
                ) = _powBatch10(
                    foldedDomainGen, idx0, idx1, idx2, idx3, idx4, idx5, idx6, idx7, idx8, idx9
                );

                uint256 rowEvalsBase;
                assembly ("memory-safe") {
                    rowEvalsBase := add(rowEvals, 0x20)
                }
                uint256 mismatchPlusOne = WhirVerifierUtils5.checkHornerBaseBlob64Matches5Raw(
                    blob, finalPolyOffset, point0, point1, point2, point3, point4, rowEvalsBase, 0
                );
                if (mismatchPlusOne != 0) {
                    revert StirConstraintFailed(mismatchPlusOne - 1);
                }
                mismatchPlusOne = WhirVerifierUtils5.checkHornerBaseBlob64Matches5Raw(
                    blob, finalPolyOffset, point5, point6, point7, point8, point9, rowEvalsBase, 5
                );
                if (mismatchPlusOne != 0) {
                    revert StirConstraintFailed(mismatchPlusOne + 4);
                }

                for (uint256 i = 10; i < 14; ++i) {
                    uint256 point = KoalaBear.pow(foldedDomainGen, indices[i]);
                    if (
                        WhirVerifierUtils5.hornerBaseBlob64Pairwise(blob, finalPolyOffset, point)
                            != rowEvals[i]
                    ) {
                        revert StirConstraintFailed(i);
                    }
                }
                return;
            }

            for (uint256 i = 0; i < numQueries; ++i) {
                uint256 point = KoalaBear.pow(foldedDomainGen, indices[i]);
                if (
                    WhirVerifierUtils5.hornerBaseBlob(blob, finalPolyOffset, finalPolyLength, point)
                        != rowEvals[i]
                ) {
                    revert StirConstraintFailed(i);
                }
            }
        }
    }

    function _verifyStirAndCombineConstraintBlob16NativeFused(
        KeccakChallenger.State memory challenger,
        bytes32 expectedRoot,
        uint256 numQueries,
        uint256 depth,
        uint256 foldedDomainGen,
        bytes calldata blob,
        uint256 valuesOffset,
        uint256 decommOffset,
        uint256 decommLen,
        uint256[] memory indices,
        uint256[] memory allRandomness,
        uint256 randomnessOffset,
        uint8 expectedKind,
        uint256 oodAnswer
    )
        private
        view
        returns (uint256 challenge, uint256 claimedContribution, uint256[] memory selVars)
    {
        uint256 pointBase;
        assembly ("memory-safe") {
            pointBase := add(add(allRandomness, 0x20), shl(5, randomnessOffset))
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
        (uint256 r00, uint256 r01, uint256 r02, uint256 r03, uint256 r04) =
            WhirVerifierUtils5._unpackCoeffs(p0);
        (uint256 r10, uint256 r11, uint256 r12, uint256 r13, uint256 r14) =
            WhirVerifierUtils5._unpackCoeffs(p1);
        (uint256 r20, uint256 r21, uint256 r22, uint256 r23, uint256 r24) =
            WhirVerifierUtils5._unpackCoeffs(p2);
        (uint256 r30, uint256 r31, uint256 r32, uint256 r33, uint256 r34) =
            WhirVerifierUtils5._unpackCoeffs(p3);
        challenge = WhirVerifierUtils5.sampleExt5(challenger);
        selVars = indices;

        uint256[] memory frontierEntries;
        assembly ("memory-safe") {
            frontierEntries := mload(0x40)
            mstore(frontierEntries, numQueries)
            mstore(0x40, add(add(frontierEntries, 0x20), shl(5, numQueries)))
        }

        unchecked {
            uint256 rowOffset;
            uint256 frontierPtr;
            assembly ("memory-safe") {
                frontierPtr := add(add(frontierEntries, 0x20), shl(5, numQueries))
            }

            if (expectedKind == 0) {
                uint256 eqWeightsPtr = _computeDim4EqWeightsPrecompile(p0, p1, p2, p3);
                rowOffset = valuesOffset + numQueries * 64;
                uint256 nextHigher;
                for (uint256 i = numQueries; i > 0; --i) {
                    uint256 pos = i - 1;
                    uint256 idx = indices[pos];
                    if (i != numQueries && idx >= nextHigher) {
                        revert MerkleVerifier.IndicesNotStrictlyIncreasing(idx, nextHigher);
                    }
                    nextHigher = idx;
                    rowOffset -= 64;

                    (bytes32 hash, uint256 evalValue) = WhirVerifierUtils5._hashAndEvaluateBaseRowDim4BlobUnpacked(
                        blob,
                        rowOffset,
                        eqWeightsPtr,
                        r00,
                        r01,
                        r02,
                        r03,
                        r04,
                        r10,
                        r11,
                        r12,
                        r13,
                        r14,
                        r20,
                        r21,
                        r22,
                        r23,
                        r24,
                        r30,
                        r31,
                        r32,
                        r33,
                        r34
                    );
                    claimedContribution = _hornerStep(claimedContribution, challenge, evalValue);

                    assembly ("memory-safe") {
                        frontierPtr := sub(frontierPtr, 0x20)
                        mstore(frontierPtr, or(hash, idx))
                    }
                }
            } else {
                uint256 eqWeightsPtr = _computeDim4EqWeightsPrecompile(p0, p1, p2, p3);
                rowOffset = valuesOffset + numQueries * 320;
                uint256 nextHigher;
                for (uint256 i = numQueries; i > 0; --i) {
                    uint256 pos = i - 1;
                    uint256 idx = indices[pos];
                    if (i != numQueries && idx >= nextHigher) {
                        revert MerkleVerifier.IndicesNotStrictlyIncreasing(idx, nextHigher);
                    }
                    nextHigher = idx;
                    rowOffset -= 320;

                    (bytes32 hash, uint256 evalValue) =
                        _hashAndEvaluateExtension5RowDim4BlobMac(blob, rowOffset, eqWeightsPtr);
                    claimedContribution = _hornerStep(claimedContribution, challenge, evalValue);

                    assembly ("memory-safe") {
                        frontierPtr := sub(frontierPtr, 0x20)
                        mstore(frontierPtr, or(hash, idx))
                    }
                }
            }
        }

        bytes32 computedRoot = MerkleVerifier.computeRootFromPackedFrontier20Blob(
            frontierEntries, numQueries, depth, blob, decommOffset, decommLen
        );
        if (computedRoot != expectedRoot) {
            revert MerkleRootMismatch(expectedRoot, computedRoot);
        }

        _fillSelVarsPow(selVars, foldedDomainGen, numQueries);
        claimedContribution = _hornerStep(claimedContribution, challenge, oodAnswer);
    }

    function _verifyRoundStirAndCombineConstraintBlob(
        KeccakChallenger.State memory challenger,
        bytes32 expectedRoot,
        bytes calldata blob,
        uint256 valuesOffset,
        uint256 decommLen,
        uint256 powWitnessOffset,
        uint256[] memory allRandomness,
        uint256 randomnessOffset,
        uint256 oodAnswer,
        uint256 powBits,
        uint256 domainSize,
        uint256 numQueries,
        uint256 depth,
        uint256 foldedDomainGen,
        uint8 expectedKind,
        uint256 valuesByteLen
    )
        internal
        view
        returns (
            uint256 challenge,
            uint256 claimedContribution,
            uint256[] memory selVars,
            uint256 nextOffset
        )
    {
        _checkWitnessBaseLeBlob(challenger, powBits, blob, powWitnessOffset);
        challenger.sampleBase();

        uint256[] memory indices =
            WhirVerifierUtils5.sampleStirQueries(challenger, domainSize, 4, numQueries);
        if (indices.length != numQueries) {
            revert QueryBatchCountMismatch(numQueries, indices.length);
        }

        uint256 decommOffset = valuesOffset + valuesByteLen;
        nextOffset = decommOffset + decommLen * 20;

        (challenge, claimedContribution, selVars) = _verifyStirAndCombineConstraintBlob16NativeFused(
            challenger,
            expectedRoot,
            numQueries,
            depth,
            foldedDomainGen,
            blob,
            valuesOffset,
            decommOffset,
            decommLen,
            indices,
            allRandomness,
            randomnessOffset,
            expectedKind,
            oodAnswer
        );
    }

    function _verifyFinalStirChallengesBlobFixed(
        KeccakChallenger.State memory challenger,
        bytes32 expectedRoot,
        bytes calldata blob,
        uint256 valuesOffset,
        uint256 decommLen,
        uint256 powWitnessOffset,
        uint256[] memory allRandomness,
        uint256 randomnessOffset,
        uint256 finalPolyOffset
    ) internal view returns (uint256 nextOffset) {
        _checkWitnessBaseLeBlob(challenger, 24, blob, powWitnessOffset);

        uint256[] memory indices =
            WhirVerifierUtils5.sampleStirQueries(challenger, 2_097_152, 4, 14);
        if (indices.length != 14) {
            revert QueryBatchCountMismatch(14, indices.length);
        }

        uint256 decommOffset = valuesOffset + 14 * 16 * 20;
        nextOffset = decommOffset + decommLen * 20;

        _verifyFinalStirChallengesBlob16(
            expectedRoot,
            14,
            17,
            373_019_801,
            blob,
            valuesOffset,
            decommOffset,
            decommLen,
            indices,
            allRandomness,
            randomnessOffset,
            finalPolyOffset,
            64
        );
        return nextOffset;
    }

    function _parseCommitment(
        KeccakChallenger.State memory challenger,
        bytes32 root,
        uint256[] calldata oodAnswers,
        uint256 numVariables,
        uint256 oodSamples
    ) internal pure returns (ParsedCommitment memory parsed) {
        if (oodAnswers.length != oodSamples) {
            revert OodAnswerCountMismatch(oodSamples, oodAnswers.length);
        }

        challenger.observeHashU64Digest(root);

        parsed.root = root;
        parsed.oodStatement.numVariables = numVariables;
        parsed.oodStatement.flatPoints = new uint256[](oodSamples * numVariables);
        parsed.oodStatement.evaluations = new uint256[](oodSamples);

        unchecked {
            for (uint256 i = 0; i < oodSamples; ++i) {
                uint256 point = WhirVerifierUtils5.sampleExt5(challenger);
                WhirVerifierUtils5.expandFromUnivariateExtInto(
                    parsed.oodStatement.flatPoints, i * numVariables, point, numVariables
                );

                uint256 evalValue = oodAnswers[i];
                WhirVerifierUtils5.observeValidatedExt5(challenger, evalValue);
                parsed.oodStatement.evaluations[i] = evalValue;
            }
        }
    }

    function _parseFixedCommitment22x1Blob(
        KeccakChallenger.State memory challenger,
        bytes calldata blob,
        uint256 offset
    )
        internal
        pure
        returns (bytes32 root, uint256 oodPoint, uint256 oodEvaluation, uint256 nextOffset)
    {
        return _parseFixedCommitmentPointBlob(challenger, blob, offset);
    }

    function _parseFixedCommitment18x1Blob(
        KeccakChallenger.State memory challenger,
        bytes calldata blob,
        uint256 offset
    )
        internal
        pure
        returns (bytes32 root, uint256 oodPoint, uint256 oodEvaluation, uint256 nextOffset)
    {
        return _parseFixedCommitmentPointBlob(challenger, blob, offset);
    }

    function _parseFixedCommitment14x1Blob(
        KeccakChallenger.State memory challenger,
        bytes calldata blob,
        uint256 offset
    )
        internal
        pure
        returns (bytes32 root, uint256 oodPoint, uint256 oodEvaluation, uint256 nextOffset)
    {
        return _parseFixedCommitmentPointBlob(challenger, blob, offset);
    }

    function _parseFixedCommitment10x1Blob(
        KeccakChallenger.State memory challenger,
        bytes calldata blob,
        uint256 offset
    )
        internal
        pure
        returns (bytes32 root, uint256 oodPoint, uint256 oodEvaluation, uint256 nextOffset)
    {
        return _parseFixedCommitmentPointBlob(challenger, blob, offset);
    }

    function _parseFixedCommitmentPointBlob(
        KeccakChallenger.State memory challenger,
        bytes calldata blob,
        uint256 offset
    )
        private
        pure
        returns (bytes32 root, uint256 oodPoint, uint256 oodEvaluation, uint256 nextOffset)
    {
        (root, offset) = WhirBlobCodec5.readDigest20(blob, offset);
        challenger.observeHashU64Digest(root);
        oodPoint = WhirVerifierUtils5.sampleExt5(challenger);
        oodEvaluation = challenger.observeReadValidatedPackedExt5Le(blob, offset);
        nextOffset = offset + 20;
    }

    function _checkWitnessBaseLeBlob(
        KeccakChallenger.State memory challenger,
        uint256 bits,
        bytes calldata blob,
        uint256 offset
    ) internal pure {
        if (bits == 0) {
            return;
        }

        challenger.observeBytesCalldata(blob, offset, 4);
        if (challenger.sampleBitsUnchecked(bits) != 0) {
            revert InvalidPowWitness();
        }
    }

    function _verifySumcheck(
        WhirStructs.SumcheckData calldata sumcheck,
        KeccakChallenger.State memory challenger,
        uint256 claimedEval,
        uint256 expectedRounds,
        uint256 powBits,
        uint256[] memory allRandomness,
        uint256 randomnessCursor
    )
        internal
        pure
        returns (
            uint256 updatedClaimedEval,
            uint256[] memory foldingRandomness,
            uint256 updatedCursor
        )
    {
        uint256 expectedPolyEvals = expectedRounds * 2;
        if (sumcheck.polynomialEvals.length != expectedPolyEvals) {
            revert SumcheckPolynomialLengthMismatch(
                expectedPolyEvals, sumcheck.polynomialEvals.length
            );
        }

        uint256 expectedWitnesses = powBits > 0 ? expectedRounds : 0;
        if (sumcheck.powWitnesses.length != expectedWitnesses) {
            revert SumcheckPowWitnessLengthMismatch(expectedWitnesses, sumcheck.powWitnesses.length);
        }

        updatedClaimedEval = claimedEval;
        updatedCursor = randomnessCursor;
        foldingRandomness = new uint256[](expectedRounds);

        unchecked {
            for (uint256 i = 0; i < expectedRounds; ++i) {
                uint256 c0 = sumcheck.polynomialEvals[2 * i];
                uint256 c2 = sumcheck.polynomialEvals[2 * i + 1];

                challenger.observeValidatedPackedExt5Pair(c0, c2);

                if (powBits > 0) {
                    if (!challenger.checkWitness(powBits, sumcheck.powWitnesses[i])) {
                        revert InvalidPowWitness();
                    }
                }

                uint256 r = WhirVerifierUtils5.sampleExt5(challenger);
                foldingRandomness[i] = r;
                allRandomness[updatedCursor] = r;
                updatedCursor += 1;
                updatedClaimedEval = KoalaBearExt5.extrapolate_012(
                    c0, KoalaBearExt5.sub(updatedClaimedEval, c0), c2, r
                );
            }
        }
    }

    function _verifySumcheckBlob(
        bytes calldata blob,
        uint256 offset,
        KeccakChallenger.State memory challenger,
        uint256 claimedEval,
        uint256 expectedRounds,
        uint256 powBits,
        uint256[] memory allRandomness,
        uint256 randomnessCursor
    )
        internal
        pure
        returns (uint256 updatedClaimedEval, uint256 updatedCursor, uint256 nextOffset)
    {
        updatedClaimedEval = claimedEval;
        updatedCursor = randomnessCursor;
        nextOffset = offset;

        unchecked {
            for (uint256 i = 0; i < expectedRounds; ++i) {
                (uint256 c0, uint256 c2) =
                    challenger.observeReadValidatedPackedExt5LePair(blob, nextOffset);
                nextOffset += 40;

                if (powBits > 0) {
                    _checkWitnessBaseLeBlob(
                        challenger, powBits, blob, offset + expectedRounds * 40 + i * 4
                    );
                }

                uint256 r = WhirVerifierUtils5.sampleExt5(challenger);
                allRandomness[updatedCursor] = r;
                updatedCursor += 1;
                updatedClaimedEval =
                    KoalaBearExt5.extrapolate_012_from_sumcheck(c0, updatedClaimedEval, c2, r);
            }
        }

        if (powBits > 0) {
            nextOffset = offset + expectedRounds * 40 + expectedRounds * 4;
        }
    }

    function _verifySumcheckBlob6NoPow(
        bytes calldata blob,
        uint256 offset,
        KeccakChallenger.State memory challenger,
        uint256 claimedEval,
        uint256[] memory allRandomness,
        uint256 randomnessCursor
    )
        internal
        pure
        returns (uint256 updatedClaimedEval, uint256 updatedCursor, uint256 nextOffset)
    {
        updatedClaimedEval = claimedEval;
        updatedCursor = randomnessCursor;
        nextOffset = offset;

        (uint256 c0, uint256 c2) = challenger.observeReadValidatedPackedExt5LePair(blob, nextOffset);
        nextOffset += 40;
        uint256 r = WhirVerifierUtils5.sampleExt5(challenger);
        allRandomness[updatedCursor] = r;
        updatedCursor += 1;
        updatedClaimedEval =
            KoalaBearExt5.extrapolate_012_from_sumcheck(c0, updatedClaimedEval, c2, r);

        (c0, c2) = challenger.observeReadValidatedPackedExt5LePair(blob, nextOffset);
        nextOffset += 40;
        r = WhirVerifierUtils5.sampleExt5(challenger);
        allRandomness[updatedCursor] = r;
        updatedCursor += 1;
        updatedClaimedEval =
            KoalaBearExt5.extrapolate_012_from_sumcheck(c0, updatedClaimedEval, c2, r);

        (c0, c2) = challenger.observeReadValidatedPackedExt5LePair(blob, nextOffset);
        nextOffset += 40;
        r = WhirVerifierUtils5.sampleExt5(challenger);
        allRandomness[updatedCursor] = r;
        updatedCursor += 1;
        updatedClaimedEval =
            KoalaBearExt5.extrapolate_012_from_sumcheck(c0, updatedClaimedEval, c2, r);

        (c0, c2) = challenger.observeReadValidatedPackedExt5LePair(blob, nextOffset);
        nextOffset += 40;
        r = WhirVerifierUtils5.sampleExt5(challenger);
        allRandomness[updatedCursor] = r;
        updatedCursor += 1;
        updatedClaimedEval =
            KoalaBearExt5.extrapolate_012_from_sumcheck(c0, updatedClaimedEval, c2, r);

        (c0, c2) = challenger.observeReadValidatedPackedExt5LePair(blob, nextOffset);
        nextOffset += 40;
        r = WhirVerifierUtils5.sampleExt5(challenger);
        allRandomness[updatedCursor] = r;
        updatedCursor += 1;
        updatedClaimedEval =
            KoalaBearExt5.extrapolate_012_from_sumcheck(c0, updatedClaimedEval, c2, r);

        (c0, c2) = challenger.observeReadValidatedPackedExt5LePair(blob, nextOffset);
        nextOffset += 40;
        r = WhirVerifierUtils5.sampleExt5(challenger);
        allRandomness[updatedCursor] = r;
        updatedCursor += 1;
        updatedClaimedEval =
            KoalaBearExt5.extrapolate_012_from_sumcheck(c0, updatedClaimedEval, c2, r);
    }

    function _verifyStirAndCombineConstraint(
        KeccakChallenger.State memory challenger,
        bytes32 expectedRoot,
        uint256 powBits,
        uint256 numQueries,
        uint256,
        uint256 foldingFactor,
        uint256 domainSize,
        uint256 foldedDomainGen,
        WhirStructs.QueryBatchOpening calldata queryBatch,
        bool queryBatchPresent,
        uint256 powWitness,
        uint256[] memory foldingRandomness,
        uint8 expectedKind,
        uint256[] calldata oodAnswers
    )
        internal
        view
        returns (uint256 challenge, uint256 claimedContribution, uint256[] memory selVars)
    {
        if (powBits > 0 && !challenger.checkWitness(powBits, powWitness)) {
            revert InvalidPowWitness();
        }

        challenger.sampleBase();

        if (!queryBatchPresent) {
            if (numQueries != 0) {
                revert FinalQueryBatchPresenceMismatch(true, false);
            }
            challenge = WhirVerifierUtils5.sampleExt5(challenger);
            unchecked {
                for (uint256 i = oodAnswers.length; i > 0; --i) {
                    claimedContribution =
                        _hornerStep(claimedContribution, challenge, oodAnswers[i - 1]);
                }
            }
            selVars = new uint256[](0);
            return (challenge, claimedContribution, selVars);
        }

        uint256[] memory indices = WhirVerifierUtils5.sampleStirQueries(
            challenger, domainSize, foldingFactor, numQueries
        );

        if (queryBatch.kind != expectedKind) {
            revert QueryBatchKindMismatch(expectedKind, queryBatch.kind);
        }
        if (queryBatch.numQueries != indices.length) {
            revert QueryBatchCountMismatch(indices.length, queryBatch.numQueries);
        }

        uint256 expectedRowLen = uint256(1) << foldingFactor;
        if (queryBatch.rowLen != expectedRowLen) {
            revert QueryBatchRowLengthMismatch(expectedRowLen, queryBatch.rowLen);
        }

        uint256 depth = WhirVerifierUtils5.log2Strict(domainSize >> foldingFactor);

        if (expectedRowLen == 16 && foldingFactor == 4) {
            bytes32 fastRoot;
            uint256[] memory rowEvals;
            if (expectedKind == 0) {
                (fastRoot, rowEvals) = _computeBaseRootAndEvals16(
                    indices,
                    queryBatch.values,
                    depth,
                    queryBatch.decommitments,
                    foldingRandomness[0],
                    foldingRandomness[1],
                    foldingRandomness[2],
                    foldingRandomness[3]
                );
            } else {
                (fastRoot, rowEvals) = _computeExtension5RootAndEvals16(
                    indices,
                    queryBatch.values,
                    depth,
                    queryBatch.decommitments,
                    foldingRandomness[0],
                    foldingRandomness[1],
                    foldingRandomness[2],
                    foldingRandomness[3]
                );
            }

            if (fastRoot != expectedRoot) {
                revert MerkleRootMismatch(expectedRoot, fastRoot);
            }

            challenge = WhirVerifierUtils5.sampleExt5(challenger);
            selVars = indices;

            unchecked {
                for (uint256 i = indices.length; i > 0; --i) {
                    uint256 idx = i - 1;
                    selVars[idx] = KoalaBear.pow(foldedDomainGen, indices[idx]);
                    claimedContribution = _hornerStep(claimedContribution, challenge, rowEvals[idx]);
                }

                for (uint256 i = oodAnswers.length; i > 0; --i) {
                    claimedContribution =
                        _hornerStep(claimedContribution, challenge, oodAnswers[i - 1]);
                }
            }
            return (challenge, claimedContribution, selVars);
        }

        bytes32 computedRoot = expectedKind == 0
            ? MerkleVerifier.computeRootFromFlatBaseRows20(
                indices, queryBatch.values, queryBatch.rowLen, depth, queryBatch.decommitments
            )
            : MerkleVerifier.computeRootFromFlatExtension5Rows20(
                indices, queryBatch.values, queryBatch.rowLen, depth, queryBatch.decommitments
            );

        if (computedRoot != expectedRoot) {
            revert MerkleRootMismatch(expectedRoot, computedRoot);
        }

        challenge = WhirVerifierUtils5.sampleExt5(challenger);
        selVars = indices;

        unchecked {
            for (uint256 i = indices.length; i > 0; --i) {
                uint256 idx = i - 1;
                selVars[idx] = KoalaBear.pow(foldedDomainGen, indices[idx]);

                uint256 rowStart = idx * queryBatch.rowLen;
                uint256 evalValue = expectedKind == 0
                    ? WhirVerifierUtils5.evaluateBaseRowAsExt5(
                        queryBatch.values, rowStart, queryBatch.rowLen, foldingRandomness
                    )
                    : WhirVerifierUtils5.evaluateExtensionRowAsExt5(
                        queryBatch.values, rowStart, queryBatch.rowLen, foldingRandomness
                    );
                claimedContribution = _hornerStep(claimedContribution, challenge, evalValue);
            }

            for (uint256 i = oodAnswers.length; i > 0; --i) {
                claimedContribution = _hornerStep(claimedContribution, challenge, oodAnswers[i - 1]);
            }
        }
    }

    function _verifyFinalStirChallengesRaw(
        KeccakChallenger.State memory challenger,
        bytes32 expectedRoot,
        uint256 powBits,
        uint256 numQueries,
        uint256 foldingFactor,
        uint256 domainSize,
        uint256 foldedDomainGen,
        WhirStructs.QueryBatchOpening calldata queryBatch,
        bool queryBatchPresent,
        uint256 powWitness,
        uint256[] memory foldingRandomness,
        uint8 expectedKind,
        uint256[] calldata finalPoly
    ) internal pure {
        if (powBits > 0 && !challenger.checkWitness(powBits, powWitness)) {
            revert InvalidPowWitness();
        }

        if (!queryBatchPresent) {
            if (numQueries != 0) {
                revert FinalQueryBatchPresenceMismatch(true, false);
            }
            return;
        }

        uint256[] memory indices = WhirVerifierUtils5.sampleStirQueries(
            challenger, domainSize, foldingFactor, numQueries
        );

        if (queryBatch.kind != expectedKind) {
            revert QueryBatchKindMismatch(expectedKind, queryBatch.kind);
        }
        if (queryBatch.numQueries != indices.length) {
            revert QueryBatchCountMismatch(indices.length, queryBatch.numQueries);
        }

        uint256 expectedRowLen = uint256(1) << foldingFactor;
        if (queryBatch.rowLen != expectedRowLen) {
            revert QueryBatchRowLengthMismatch(expectedRowLen, queryBatch.rowLen);
        }

        uint256 depth = WhirVerifierUtils5.log2Strict(domainSize >> foldingFactor);

        if (expectedRowLen == 16 && foldingFactor == 4) {
            bytes32 fastRoot;
            uint256[] memory rowEvals;
            if (expectedKind == 0) {
                (fastRoot, rowEvals) = _computeBaseRootAndEvals16(
                    indices,
                    queryBatch.values,
                    depth,
                    queryBatch.decommitments,
                    foldingRandomness[0],
                    foldingRandomness[1],
                    foldingRandomness[2],
                    foldingRandomness[3]
                );
            } else {
                (fastRoot, rowEvals) = _computeExtension5RootAndEvals16(
                    indices,
                    queryBatch.values,
                    depth,
                    queryBatch.decommitments,
                    foldingRandomness[0],
                    foldingRandomness[1],
                    foldingRandomness[2],
                    foldingRandomness[3]
                );
            }

            if (fastRoot != expectedRoot) {
                revert MerkleRootMismatch(expectedRoot, fastRoot);
            }

            if (indices.length == 10) {
                uint256 idx0;
                uint256 idx1;
                uint256 idx2;
                uint256 idx3;
                uint256 idx4;
                uint256 idx5;
                uint256 idx6;
                uint256 idx7;
                uint256 idx8;
                uint256 idx9;
                assembly ("memory-safe") {
                    let indicesBase := add(indices, 0x20)
                    idx0 := mload(indicesBase)
                    idx1 := mload(add(indicesBase, 0x20))
                    idx2 := mload(add(indicesBase, 0x40))
                    idx3 := mload(add(indicesBase, 0x60))
                    idx4 := mload(add(indicesBase, 0x80))
                    idx5 := mload(add(indicesBase, 0xa0))
                    idx6 := mload(add(indicesBase, 0xc0))
                    idx7 := mload(add(indicesBase, 0xe0))
                    idx8 := mload(add(indicesBase, 0x100))
                    idx9 := mload(add(indicesBase, 0x120))
                }
                (
                    uint256 point0,
                    uint256 point1,
                    uint256 point2,
                    uint256 point3,
                    uint256 point4,
                    uint256 point5,
                    uint256 point6,
                    uint256 point7,
                    uint256 point8,
                    uint256 point9
                ) = _powBatch10(
                    foldedDomainGen, idx0, idx1, idx2, idx3, idx4, idx5, idx6, idx7, idx8, idx9
                );

                if (WhirVerifierUtils5.hornerBase(finalPoly, point0) != rowEvals[0]) {
                    revert StirConstraintFailed(0);
                }
                if (WhirVerifierUtils5.hornerBase(finalPoly, point1) != rowEvals[1]) {
                    revert StirConstraintFailed(1);
                }
                if (WhirVerifierUtils5.hornerBase(finalPoly, point2) != rowEvals[2]) {
                    revert StirConstraintFailed(2);
                }
                if (WhirVerifierUtils5.hornerBase(finalPoly, point3) != rowEvals[3]) {
                    revert StirConstraintFailed(3);
                }
                if (WhirVerifierUtils5.hornerBase(finalPoly, point4) != rowEvals[4]) {
                    revert StirConstraintFailed(4);
                }
                if (WhirVerifierUtils5.hornerBase(finalPoly, point5) != rowEvals[5]) {
                    revert StirConstraintFailed(5);
                }
                if (WhirVerifierUtils5.hornerBase(finalPoly, point6) != rowEvals[6]) {
                    revert StirConstraintFailed(6);
                }
                if (WhirVerifierUtils5.hornerBase(finalPoly, point7) != rowEvals[7]) {
                    revert StirConstraintFailed(7);
                }
                if (WhirVerifierUtils5.hornerBase(finalPoly, point8) != rowEvals[8]) {
                    revert StirConstraintFailed(8);
                }
                if (WhirVerifierUtils5.hornerBase(finalPoly, point9) != rowEvals[9]) {
                    revert StirConstraintFailed(9);
                }
                return;
            }

            unchecked {
                for (uint256 i = 0; i < indices.length; ++i) {
                    uint256 point = KoalaBear.pow(foldedDomainGen, indices[i]);
                    if (WhirVerifierUtils5.hornerBase(finalPoly, point) != rowEvals[i]) {
                        revert StirConstraintFailed(i);
                    }
                }
            }
            return;
        }

        bytes32 computedRoot = expectedKind == 0
            ? MerkleVerifier.computeRootFromFlatBaseRows20(
                indices, queryBatch.values, queryBatch.rowLen, depth, queryBatch.decommitments
            )
            : MerkleVerifier.computeRootFromFlatExtension5Rows20(
                indices, queryBatch.values, queryBatch.rowLen, depth, queryBatch.decommitments
            );

        if (computedRoot != expectedRoot) {
            revert MerkleRootMismatch(expectedRoot, computedRoot);
        }

        unchecked {
            for (uint256 i = 0; i < indices.length; ++i) {
                uint256 point = KoalaBear.pow(foldedDomainGen, indices[i]);
                uint256 rowStart = i * queryBatch.rowLen;
                uint256 expectedEval = expectedKind == 0
                    ? WhirVerifierUtils5.evaluateBaseRowAsExt5(
                        queryBatch.values, rowStart, queryBatch.rowLen, foldingRandomness
                    )
                    : WhirVerifierUtils5.evaluateExtensionRowAsExt5(
                        queryBatch.values, rowStart, queryBatch.rowLen, foldingRandomness
                    );
                if (WhirVerifierUtils5.hornerBase(finalPoly, point) != expectedEval) {
                    revert StirConstraintFailed(i);
                }
            }
        }
    }

    function _combineInitialConstraintEvalsSingleRaw(
        uint256 challenge,
        uint256 statementEval,
        uint256 oodEval
    ) internal view returns (uint256 total) {
        total = _hornerStep(total, challenge, oodEval);
        total = _hornerStep(total, challenge, statementEval);
    }

    function _evaluateFixedEqTermsBlobRaw(
        bytes calldata blob,
        uint256 statementPointOffset,
        uint256 initialOodPoint,
        uint256 round0OodPoint,
        uint256 round1OodPoint,
        uint256 round2OodPoint,
        uint256[] memory fullPoint
    )
        internal
        view
        returns (
            uint256 statementEq,
            uint256 initialEq,
            uint256 round0Eq,
            uint256 round1Eq,
            uint256 round2Eq
        )
    {
        statementEq = KoalaBearExt5.ONE;
        initialEq = KoalaBearExt5.ONE;
        round0Eq = KoalaBearExt5.ONE;
        round1Eq = KoalaBearExt5.ONE;
        round2Eq = KoalaBearExt5.ONE;

        uint256 initialCurrent = initialOodPoint;
        uint256 round0Current = round0OodPoint;
        uint256 round1Current = round1OodPoint;
        uint256 round2Current = round2OodPoint;
        uint256 pointBase;
        assembly ("memory-safe") {
            pointBase := add(fullPoint, 0x20)
        }

        uint256 batchInput;
        uint256 batchOutput;
        assembly ("memory-safe") {
            batchInput := mload(0x40)
            batchOutput := add(batchInput, 0x240)
            mstore(0x40, add(batchInput, 0x400))
        }

        unchecked {
            for (uint256 i = 22; i > 0; --i) {
                uint256 q;
                uint256 statementPointValue;
                assembly ("memory-safe") {
                    let idx := sub(i, 1)
                    q := mload(add(pointBase, shl(5, idx)))
                    statementPointValue := and(
                        calldataload(add(add(blob.offset, statementPointOffset), mul(20, idx))),
                        not(sub(shl(96, 1), 1))
                    )
                }

                uint256 eqCount = 2;
                _storeMulPair(batchInput, 0, statementPointValue, q);
                _storeMulPair(batchInput, 1, initialCurrent, q);

                if (i > 4) {
                    _storeMulPair(batchInput, eqCount, round0Current, q);
                    ++eqCount;
                    if (i > 8) {
                        _storeMulPair(batchInput, eqCount, round1Current, q);
                        ++eqCount;
                        if (i > 12) {
                            _storeMulPair(batchInput, eqCount, round2Current, q);
                            ++eqCount;
                        }
                    }
                }

                KoalaBearExt5Precompile.mulBatchInto(batchInput, eqCount << 6, batchOutput);

                _storeMulPair(
                    batchInput,
                    0,
                    statementEq,
                    _eqTermFromProduct(_loadBatchWord(batchOutput, 0), statementPointValue, q)
                );
                _storeMulPair(
                    batchInput,
                    1,
                    initialEq,
                    _eqTermFromProduct(_loadBatchWord(batchOutput, 1), initialCurrent, q)
                );

                uint256 opCount = eqCount;
                if (i > 4) {
                    _storeMulPair(
                        batchInput,
                        2,
                        round0Eq,
                        _eqTermFromProduct(_loadBatchWord(batchOutput, 2), round0Current, q)
                    );
                    if (i > 8) {
                        _storeMulPair(
                            batchInput,
                            3,
                            round1Eq,
                            _eqTermFromProduct(_loadBatchWord(batchOutput, 3), round1Current, q)
                        );
                        if (i > 12) {
                            _storeMulPair(
                                batchInput,
                                4,
                                round2Eq,
                                _eqTermFromProduct(_loadBatchWord(batchOutput, 4), round2Current, q)
                            );
                        }
                    }
                }

                _storeMulPair(batchInput, opCount, initialCurrent, initialCurrent);
                ++opCount;
                if (i > 4) {
                    _storeMulPair(batchInput, opCount, round0Current, round0Current);
                    ++opCount;
                    if (i > 8) {
                        _storeMulPair(batchInput, opCount, round1Current, round1Current);
                        ++opCount;
                        if (i > 12) {
                            _storeMulPair(batchInput, opCount, round2Current, round2Current);
                            ++opCount;
                        }
                    }
                }

                KoalaBearExt5Precompile.mulBatchInto(batchInput, opCount << 6, batchOutput);

                statementEq = _loadBatchWord(batchOutput, 0);
                initialEq = _loadBatchWord(batchOutput, 1);
                if (i > 4) {
                    round0Eq = _loadBatchWord(batchOutput, 2);
                    if (i > 8) {
                        round1Eq = _loadBatchWord(batchOutput, 3);
                        if (i > 12) {
                            round2Eq = _loadBatchWord(batchOutput, 4);
                        }
                    }
                }

                initialCurrent = _loadBatchWord(batchOutput, eqCount);
                if (i > 4) {
                    round0Current = _loadBatchWord(batchOutput, eqCount + 1);
                    if (i > 8) {
                        round1Current = _loadBatchWord(batchOutput, eqCount + 2);
                        if (i > 12) {
                            round2Current = _loadBatchWord(batchOutput, eqCount + 3);
                        }
                    }
                }
            }
        }
    }

    function _evaluateInitialConstraintSingleCalldataRaw(
        uint256 challenge,
        uint256[] calldata statementPoint,
        uint256[] memory oodFlatPoints,
        uint256[] memory fullPoint
    ) internal view returns (uint256 total) {
        uint256 numVariables = statementPoint.length;
        uint256 pointOffset = fullPoint.length - numVariables;

        total = _hornerStep(
            total, challenge, _eqPolyEvalAt(oodFlatPoints, 0, fullPoint, pointOffset, numVariables)
        );
        total = _hornerStep(
            total,
            challenge,
            _eqPolyEvalAtCalldata(statementPoint, fullPoint, pointOffset, numVariables)
        );
    }

    function _evaluateConstraintSelectRaw(
        uint256 challenge,
        uint256[] memory eqFlatPoints,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) internal view returns (uint256 total) {
        uint256 numVariables = eqFlatPoints.length;
        uint256 pointOffset = fullPoint.length - numVariables;

        unchecked {
            for (uint256 i = selVars.length; i > 0; --i) {
                total = _hornerStep(
                    total,
                    challenge,
                    WhirVerifierUtils5.selectPolyEval(
                        selVars[i - 1], fullPoint, pointOffset, numVariables
                    )
                );
            }
        }

        total = _hornerStep(
            total, challenge, _eqPolyEvalAt(eqFlatPoints, 0, fullPoint, pointOffset, numVariables)
        );
    }

    function _evaluateConstraintSelectRaw18WithPrecomputedEq(
        uint256 challenge,
        uint256 eqEval,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) internal view returns (uint256 total) {
        unchecked {
            for (uint256 i = selVars.length; i > 0; --i) {
                total = _hornerStep(
                    total, challenge, _selectPolyEvalFixed(selVars[i - 1], fullPoint, 4, 18)
                );
            }
        }
        total = _hornerStep(total, challenge, eqEval);
    }

    function _evaluateConstraintSelectRaw14WithPrecomputedEq(
        uint256 challenge,
        uint256 eqEval,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) internal view returns (uint256 total) {
        unchecked {
            for (uint256 i = selVars.length; i > 0; --i) {
                total = _hornerStep(
                    total, challenge, _selectPolyEvalFixed(selVars[i - 1], fullPoint, 8, 14)
                );
            }
        }
        total = _hornerStep(total, challenge, eqEval);
    }

    function _evaluateConstraintSelectRaw10WithPrecomputedEq(
        uint256 challenge,
        uint256 eqEval,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) internal view returns (uint256 total) {
        unchecked {
            for (uint256 i = selVars.length; i > 0; --i) {
                total = _hornerStep(
                    total, challenge, _selectPolyEvalFixed(selVars[i - 1], fullPoint, 12, 10)
                );
            }
        }
        total = _hornerStep(total, challenge, eqEval);
    }

    function _eqPolyEvalAt(
        uint256[] memory point,
        uint256 pointStart,
        uint256[] memory fullPoint,
        uint256 pointOffset,
        uint256 numVariables
    ) internal view returns (uint256 acc) {
        acc = KoalaBearExt5.ONE;
        unchecked {
            for (uint256 i = 0; i < numVariables; ++i) {
                acc = KoalaBearExt5Precompile.mul(
                    acc, _eqTerm(point[pointStart + i], fullPoint[pointOffset + i])
                );
            }
        }
    }

    function _eqPolyEvalAtCalldata(
        uint256[] calldata point,
        uint256[] memory fullPoint,
        uint256 pointOffset,
        uint256 numVariables
    ) internal view returns (uint256 acc) {
        if (point.length != numVariables) {
            revert StatementPointArityMismatch(0, numVariables, point.length);
        }

        acc = KoalaBearExt5.ONE;
        unchecked {
            for (uint256 i = 0; i < numVariables; ++i) {
                acc = KoalaBearExt5Precompile.mul(
                    acc, _eqTerm(point[i], fullPoint[pointOffset + i])
                );
            }
        }
    }

    function _evaluateFinalValue(
        uint256[] calldata finalPoly,
        uint256[] memory finalSumcheckRandomness
    ) internal pure returns (uint256) {
        if (finalSumcheckRandomness.length == 0) {
            return finalPoly[0];
        }

        uint256[] memory evals = new uint256[](finalPoly.length);
        unchecked {
            for (uint256 i = 0; i < finalPoly.length; ++i) {
                uint256 value = finalPoly[i];
                WhirVerifierUtils5.validatePackedExt5(value);
                evals[i] = value;
            }
        }
        return WhirVerifierUtils5.evaluateHypercubeMemory(evals, finalSumcheckRandomness);
    }

    function _evaluateFinalValueBlob(
        bytes calldata blob,
        uint256 offset,
        uint256 polyLen,
        uint256[] memory allRandomness,
        uint256 pointOffset,
        uint256 pointLen
    ) internal pure returns (uint256) {
        if (polyLen == 64 && pointLen == 6) {
            return WhirVerifierUtils5.evaluateFinalValueBlob64Dim6(
                blob, offset, allRandomness, pointOffset
            );
        }
        return WhirVerifierUtils5.evaluateExtensionRowAsExt5Blob(
            blob, offset, polyLen, allRandomness, pointOffset, pointLen
        );
    }

    function _selectPolyEvalFixed(
        uint256 var_,
        uint256[] memory fullPoint,
        uint256 pointOffset,
        uint256 numVariables
    ) internal pure returns (uint256 acc) {
        acc = KoalaBearExt5.ONE;
        uint256 current = var_;

        unchecked {
            for (uint256 i = numVariables; i > 0; --i) {
                uint256 scalar = current == 0 ? KoalaBear.MODULUS - 1 : current - 1;
                acc = _mulBySelectTermExt5(acc, fullPoint[pointOffset + i - 1], scalar);
                current = KoalaBear.mul(current, current);
            }
        }
    }

    function _mulBySelectTermExt5(uint256 acc, uint256 pointValue, uint256 scalar)
        private
        pure
        returns (uint256 out)
    {
        assembly ("memory-safe") {
            let M := 0x7f000001
            let mask := 0xffffffff

            let a0 := shr(224, acc)
            let a1 := and(shr(192, acc), mask)
            let a2 := and(shr(160, acc), mask)
            let a3 := and(shr(128, acc), mask)
            let a4 := and(shr(96, acc), mask)

            let t0 := add(1, mul(scalar, shr(224, pointValue)))
            let t1 := mul(scalar, and(shr(192, pointValue), mask))
            let t2 := mul(scalar, and(shr(160, pointValue), mask))
            let t3 := mul(scalar, and(shr(128, pointValue), mask))
            let t4 := mul(scalar, and(shr(96, pointValue), mask))

            let c0 := mul(a0, t0)
            let c1 := add(mul(a0, t1), mul(a1, t0))
            let c2 := add(add(mul(a0, t2), mul(a1, t1)), mul(a2, t0))
            let c3 := add(add(add(mul(a0, t3), mul(a1, t2)), mul(a2, t1)), mul(a3, t0))
            let c4 :=
                add(add(add(add(mul(a0, t4), mul(a1, t3)), mul(a2, t2)), mul(a3, t1)), mul(a4, t0))
            let c5 := add(add(add(mul(a1, t4), mul(a2, t3)), mul(a3, t2)), mul(a4, t1))
            let c6 := add(add(mul(a2, t4), mul(a3, t3)), mul(a4, t2))
            let c7 := add(mul(a3, t4), mul(a4, t3))
            let c8 := mul(a4, t4)
            let bias := shl(70, M)

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

    function _hornerStep(uint256 total, uint256 challenge, uint256 weight)
        internal
        view
        returns (uint256)
    {
        return KoalaBearExt5Precompile.add(KoalaBearExt5Precompile.mul(total, challenge), weight);
    }

    function _eqTerm(uint256 p, uint256 q) internal view returns (uint256) {
        return _eqTermFromProduct(KoalaBearExt5Precompile.mul(p, q), p, q);
    }

    function _eqTermFromProduct(uint256 product, uint256 p, uint256 q)
        private
        pure
        returns (uint256)
    {
        return KoalaBearExt5Precompile.sub(
            KoalaBearExt5Precompile.sub(
                KoalaBearExt5Precompile.add(
                    KoalaBearExt5Precompile.mulBase(product, 2), KoalaBearExt5Precompile.ONE
                ),
                p
            ),
            q
        );
    }

    function _computeDim4EqWeightsPrecompile(uint256 p0, uint256 p1, uint256 p2, uint256 p3)
        private
        view
        returns (uint256 weightsPtr)
    {
        uint256 q0 = KoalaBearExt5Precompile.sub(KoalaBearExt5Precompile.ONE, p0);
        uint256 q1 = KoalaBearExt5Precompile.sub(KoalaBearExt5Precompile.ONE, p1);
        uint256 q2 = KoalaBearExt5Precompile.sub(KoalaBearExt5Precompile.ONE, p2);
        uint256 q3 = KoalaBearExt5Precompile.sub(KoalaBearExt5Precompile.ONE, p3);

        uint256 batchInput;
        uint256 batchOutput;
        assembly ("memory-safe") {
            weightsPtr := mload(0x40)
            batchInput := add(weightsPtr, 0x200)
            batchOutput := add(batchInput, 0x400)
            mstore(0x40, add(batchOutput, 0x200))
        }

        _storeMulPair(batchInput, 0, q0, q1);
        _storeMulPair(batchInput, 1, q0, p1);
        _storeMulPair(batchInput, 2, p0, q1);
        _storeMulPair(batchInput, 3, p0, p1);
        KoalaBearExt5Precompile.mulBatchInto(batchInput, 0x100, batchOutput);

        uint256 a00 = _loadBatchWord(batchOutput, 0);
        uint256 a01 = _loadBatchWord(batchOutput, 1);
        uint256 a10 = _loadBatchWord(batchOutput, 2);
        uint256 a11 = _loadBatchWord(batchOutput, 3);

        _storeMulPair(batchInput, 0, a00, q2);
        _storeMulPair(batchInput, 1, a00, p2);
        _storeMulPair(batchInput, 2, a01, q2);
        _storeMulPair(batchInput, 3, a01, p2);
        _storeMulPair(batchInput, 4, a10, q2);
        _storeMulPair(batchInput, 5, a10, p2);
        _storeMulPair(batchInput, 6, a11, q2);
        _storeMulPair(batchInput, 7, a11, p2);
        KoalaBearExt5Precompile.mulBatchInto(batchInput, 0x200, batchOutput);

        unchecked {
            for (uint256 i = 0; i < 8; ++i) {
                uint256 prefix = _loadBatchWord(batchOutput, i);
                _storeMulPair(batchInput, i << 1, prefix, q3);
                _storeMulPair(batchInput, (i << 1) + 1, prefix, p3);
            }
        }
        KoalaBearExt5Precompile.mulBatchInto(batchInput, 0x400, weightsPtr);
    }

    function _storeMulPair(uint256 ptr, uint256 index, uint256 a, uint256 b) private pure {
        assembly ("memory-safe") {
            let offset := shl(6, index)
            mstore(add(ptr, offset), a)
            mstore(add(add(ptr, offset), 0x20), b)
        }
    }

    function _loadBatchWord(uint256 ptr, uint256 index) private pure returns (uint256 value) {
        assembly ("memory-safe") {
            value := mload(add(ptr, shl(5, index)))
        }
    }
}
