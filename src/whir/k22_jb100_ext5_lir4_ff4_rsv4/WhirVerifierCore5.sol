// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { KoalaBear } from "../../field/KoalaBear.sol";
import { KoalaBearExt5 } from "../../field/KoalaBearExt5.sol";
import { MerkleVerifier } from "../../merkle/MerkleVerifier.sol";
import { KeccakChallenger } from "../../transcript/KeccakChallenger.sol";
import { WhirStructs } from "../WhirStructs.sol";
import { WhirBlobCodec5 } from "./WhirBlobCodec5_k22_jb100_ext5_lir4_ff4_rsv4.sol";
import { WhirVerifierUtils5 } from "./WhirVerifierUtils5.sol";

library WhirVerifierCore5 {
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

    function _computeBaseRootAndEvalsBlob16(
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

        uint256 eqWeightsPtr = WhirVerifierUtils5._computeDim4EqWeights(p0, p1, p2, p3);

        unchecked {
            uint256 prevIdx;
            for (uint256 i = 0; i < count; ++i) {
                uint256 idx = indices[i];
                if (i != 0 && prevIdx >= idx) {
                    revert MerkleVerifier.IndicesNotStrictlyIncreasing(prevIdx, idx);
                }
                prevIdx = idx;

                uint256 rowOffset = valuesOffset + i * 64;
                (bytes32 hash, uint256 evalValue) = WhirVerifierUtils5._hashAndEvaluateBaseRowDim4BlobPackedPoints(
                    blob, rowOffset, eqWeightsPtr
                );
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

        uint256 eqWeightsPtr = WhirVerifierUtils5._computeDim4EqWeightsUnpacked(p0, p1, p2, p3);

        unchecked {
            uint256 prevIdx;
            for (uint256 i = 0; i < count; ++i) {
                uint256 idx = indices[i];
                if (i != 0 && prevIdx >= idx) {
                    revert MerkleVerifier.IndicesNotStrictlyIncreasing(prevIdx, idx);
                }
                prevIdx = idx;

                uint256 rowOffset = valuesOffset + i * 320;
                (bytes32 hash, uint256 evalValue) = WhirVerifierUtils5._hashAndEvaluateExtension5RowDim4BlobPackedPoints(
                    blob, rowOffset, eqWeightsPtr
                );
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

    function _verifyStirAndCombineConstraintBlob16(
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
        pure
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

        bytes32 computedRoot;
        uint256[] memory rowEvals;
        if (expectedKind == 0) {
            (computedRoot, rowEvals) = _computeBaseRootAndEvalsBlob16(
                indices, blob, valuesOffset, depth, decommOffset, decommLen, p0, p1, p2, p3
            );
        } else {
            (computedRoot, rowEvals) = _computeExtension5RootAndEvalsBlob16(
                indices, blob, valuesOffset, depth, decommOffset, decommLen, p0, p1, p2, p3
            );
        }

        if (computedRoot != expectedRoot) {
            revert MerkleRootMismatch(expectedRoot, computedRoot);
        }

        challenge = WhirVerifierUtils5.sampleExt5(challenger);
        selVars = indices;

        unchecked {
            for (uint256 i = numQueries; i > 0; --i) {
                uint256 idx = i - 1;
                selVars[idx] = KoalaBear.pow(foldedDomainGen, indices[idx]);
                claimedContribution = _hornerStep(claimedContribution, challenge, rowEvals[idx]);
            }
        }

        claimedContribution = _hornerStep(claimedContribution, challenge, oodAnswer);
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
        uint8 expectedKind,
        uint256 finalPolyOffset,
        uint256 finalPolyLength
    ) private pure {
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
        if (expectedKind == 0) {
            (computedRoot, rowEvals) = _computeBaseRootAndEvalsBlob16(
                indices, blob, valuesOffset, depth, decommOffset, decommLen, p0, p1, p2, p3
            );
        } else {
            (computedRoot, rowEvals) = _computeExtension5RootAndEvalsBlob16(
                indices, blob, valuesOffset, depth, decommOffset, decommLen, p0, p1, p2, p3
            );
        }

        if (computedRoot != expectedRoot) {
            revert MerkleRootMismatch(expectedRoot, computedRoot);
        }

        unchecked {
            if (finalPolyLength == 64 && numQueries == 16) {
                uint256 mismatchPlusOne = WhirVerifierUtils5.checkHornerBaseBlob64Matches5(
                    blob, finalPolyOffset, indices, 0, foldedDomainGen, rowEvals, 0
                );
                if (mismatchPlusOne != 0) {
                    revert StirConstraintFailed(mismatchPlusOne - 1);
                }
                mismatchPlusOne = WhirVerifierUtils5.checkHornerBaseBlob64Matches5(
                    blob, finalPolyOffset, indices, 5, foldedDomainGen, rowEvals, 5
                );
                if (mismatchPlusOne != 0) {
                    revert StirConstraintFailed(mismatchPlusOne + 4);
                }
                mismatchPlusOne = WhirVerifierUtils5.checkHornerBaseBlob64Matches5(
                    blob, finalPolyOffset, indices, 10, foldedDomainGen, rowEvals, 10
                );
                if (mismatchPlusOne != 0) {
                    revert StirConstraintFailed(mismatchPlusOne + 9);
                }
                uint256 point = KoalaBear.pow(foldedDomainGen, indices[15]);
                if (
                    WhirVerifierUtils5.hornerBaseBlob(blob, finalPolyOffset, 64, point)
                        != rowEvals[15]
                ) {
                    revert StirConstraintFailed(15);
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
        pure
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
                uint256 eqWeightsPtr = WhirVerifierUtils5._computeDim4EqWeights(p0, p1, p2, p3);
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

                    (bytes32 hash, uint256 evalValue) = WhirVerifierUtils5._hashAndEvaluateBaseRowDim4BlobPackedPoints(
                        blob, rowOffset, eqWeightsPtr
                    );
                    claimedContribution = _hornerStep(claimedContribution, challenge, evalValue);
                    selVars[pos] = KoalaBear.pow(foldedDomainGen, idx);

                    assembly ("memory-safe") {
                        frontierPtr := sub(frontierPtr, 0x20)
                        mstore(frontierPtr, or(hash, idx))
                    }
                }
            } else {
                uint256 eqWeightsPtr =
                    WhirVerifierUtils5._computeDim4EqWeightsUnpacked(p0, p1, p2, p3);
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

                    (bytes32 hash, uint256 evalValue) = WhirVerifierUtils5._hashAndEvaluateExtension5RowDim4BlobPackedPoints(
                        blob, rowOffset, eqWeightsPtr
                    );
                    claimedContribution = _hornerStep(claimedContribution, challenge, evalValue);
                    selVars[pos] = KoalaBear.pow(foldedDomainGen, idx);

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

        claimedContribution = _hornerStep(claimedContribution, challenge, oodAnswer);
    }

    function _verifyRound0StirAndCombineConstraintBlob(
        KeccakChallenger.State memory challenger,
        bytes32 expectedRoot,
        bytes calldata blob,
        uint256 valuesOffset,
        uint256 decommLen,
        uint256 powWitnessOffset,
        uint256[] memory allRandomness,
        uint256 randomnessOffset,
        uint256 oodAnswer
    )
        internal
        pure
        returns (
            uint256 challenge,
            uint256 claimedContribution,
            uint256[] memory selVars,
            uint256 nextOffset
        )
    {
        _checkWitnessBaseLeBlob(challenger, 25, blob, powWitnessOffset);
        challenger.sampleBase();

        uint256[] memory indices =
            WhirVerifierUtils5.sampleStirQueries(challenger, 67_108_864, 4, 39);
        if (indices.length != 39) {
            revert QueryBatchCountMismatch(39, indices.length);
        }

        uint256 decommOffset = valuesOffset + 39 * 16 * 4;
        nextOffset = decommOffset + decommLen * 20;

        (challenge, claimedContribution, selVars) = _verifyStirAndCombineConstraintBlob16NativeFused(
            challenger,
            expectedRoot,
            39,
            22,
            542_991_299,
            blob,
            valuesOffset,
            decommOffset,
            decommLen,
            indices,
            allRandomness,
            randomnessOffset,
            0,
            oodAnswer
        );
    }

    function _verifyRound1StirAndCombineConstraintBlob(
        KeccakChallenger.State memory challenger,
        bytes32 expectedRoot,
        bytes calldata blob,
        uint256 valuesOffset,
        uint256 decommLen,
        uint256 powWitnessOffset,
        uint256[] memory allRandomness,
        uint256 randomnessOffset,
        uint256 oodAnswer
    )
        internal
        pure
        returns (
            uint256 challenge,
            uint256 claimedContribution,
            uint256[] memory selVars,
            uint256 nextOffset
        )
    {
        _checkWitnessBaseLeBlob(challenger, 25, blob, powWitnessOffset);
        challenger.sampleBase();

        uint256[] memory indices =
            WhirVerifierUtils5.sampleStirQueries(challenger, 4_194_304, 4, 39);
        if (indices.length != 39) {
            revert QueryBatchCountMismatch(39, indices.length);
        }

        uint256 decommOffset = valuesOffset + 39 * 16 * 20;
        nextOffset = decommOffset + decommLen * 20;

        (challenge, claimedContribution, selVars) = _verifyStirAndCombineConstraintBlob16NativeFused(
            challenger,
            expectedRoot,
            39,
            18,
            1_816_824_389,
            blob,
            valuesOffset,
            decommOffset,
            decommLen,
            indices,
            allRandomness,
            randomnessOffset,
            1,
            oodAnswer
        );
    }

    function _verifyRound2StirAndCombineConstraintBlob(
        KeccakChallenger.State memory challenger,
        bytes32 expectedRoot,
        bytes calldata blob,
        uint256 valuesOffset,
        uint256 decommLen,
        uint256 powWitnessOffset,
        uint256[] memory allRandomness,
        uint256 randomnessOffset,
        uint256 oodAnswer
    )
        internal
        pure
        returns (
            uint256 challenge,
            uint256 claimedContribution,
            uint256[] memory selVars,
            uint256 nextOffset
        )
    {
        _checkWitnessBaseLeBlob(challenger, 25, blob, powWitnessOffset);
        challenger.sampleBase();

        uint256[] memory indices =
            WhirVerifierUtils5.sampleStirQueries(challenger, 2_097_152, 4, 22);
        if (indices.length != 22) {
            revert QueryBatchCountMismatch(22, indices.length);
        }

        uint256 decommOffset = valuesOffset + 22 * 16 * 20;
        nextOffset = decommOffset + decommLen * 20;

        (challenge, claimedContribution, selVars) = _verifyStirAndCombineConstraintBlob16NativeFused(
            challenger,
            expectedRoot,
            22,
            17,
            373_019_801,
            blob,
            valuesOffset,
            decommOffset,
            decommLen,
            indices,
            allRandomness,
            randomnessOffset,
            1,
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
    ) internal pure returns (uint256 nextOffset) {
        _checkWitnessBaseLeBlob(challenger, 22, blob, powWitnessOffset);

        uint256[] memory indices =
            WhirVerifierUtils5.sampleStirQueries(challenger, 1_048_576, 4, 16);
        if (indices.length != 16) {
            revert QueryBatchCountMismatch(16, indices.length);
        }

        uint256 decommOffset = valuesOffset + 16 * 16 * 20;
        nextOffset = decommOffset + decommLen * 20;
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

        _verifyFinalStirChallengesBlob16(
            expectedRoot,
            16,
            16,
            1_848_593_786,
            blob,
            valuesOffset,
            decommOffset,
            decommLen,
            indices,
            allRandomness,
            randomnessOffset,
            1,
            finalPolyOffset,
            64
        );
        return nextOffset;
    }

    function _statementFromCalldata(
        WhirStructs.WhirStatement calldata statement,
        uint256 numVariables
    ) internal pure returns (EqStatement memory eqStatement) {
        if (statement.points.length != statement.evaluations.length) {
            revert StatementLengthMismatch(statement.points.length, statement.evaluations.length);
        }

        eqStatement.numVariables = numVariables;
        eqStatement.flatPoints = new uint256[](statement.points.length * numVariables);
        eqStatement.evaluations = new uint256[](statement.evaluations.length);

        unchecked {
            for (uint256 i = 0; i < statement.points.length; ++i) {
                if (statement.points[i].length != numVariables) {
                    revert StatementPointArityMismatch(i, numVariables, statement.points[i].length);
                }

                for (uint256 j = 0; j < numVariables; ++j) {
                    uint256 pointValue = statement.points[i][j];
                    WhirVerifierUtils5.validatePackedExt5(pointValue);
                    eqStatement.flatPoints[i * numVariables + j] = pointValue;
                }

                uint256 evalValue = statement.evaluations[i];
                WhirVerifierUtils5.validatePackedExt5(evalValue);
                eqStatement.evaluations[i] = evalValue;
            }
        }
    }

    function _concatenateEq(EqStatement memory lhs, EqStatement memory rhs)
        internal
        pure
        returns (EqStatement memory out)
    {
        if (lhs.numVariables != rhs.numVariables) {
            revert InconsistentConstraintArity(lhs.numVariables, rhs.numVariables);
        }

        uint256 pointCountL = lhs.evaluations.length;
        uint256 pointCountR = rhs.evaluations.length;
        uint256 numVariables = lhs.numVariables;

        out.numVariables = numVariables;
        out.flatPoints = new uint256[]((pointCountL + pointCountR) * numVariables);
        out.evaluations = new uint256[](pointCountL + pointCountR);

        unchecked {
            for (uint256 i = 0; i < lhs.flatPoints.length; ++i) {
                out.flatPoints[i] = lhs.flatPoints[i];
            }
            for (uint256 i = 0; i < rhs.flatPoints.length; ++i) {
                out.flatPoints[lhs.flatPoints.length + i] = rhs.flatPoints[i];
            }
            for (uint256 i = 0; i < pointCountL; ++i) {
                out.evaluations[i] = lhs.evaluations[i];
            }
            for (uint256 i = 0; i < pointCountR; ++i) {
                out.evaluations[pointCountL + i] = rhs.evaluations[i];
            }
        }
    }

    function _emptySelect(uint256 numVariables) internal pure returns (SelectStatement memory sel) {
        sel.numVariables = numVariables;
        sel.vars = new uint256[](0);
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

    function _parseFixedCommitment1Blob(
        KeccakChallenger.State memory challenger,
        bytes calldata blob,
        uint256 offset,
        uint256 numVariables
    ) internal pure returns (FixedParsedCommitment memory parsed, uint256 nextOffset) {
        (parsed.root, offset) = WhirBlobCodec5.readDigest20(blob, offset);
        challenger.observeHashU64Digest(parsed.root);

        parsed.oodFlatPoints = new uint256[](numVariables);
        uint256 point = WhirVerifierUtils5.sampleExt5(challenger);
        WhirVerifierUtils5.expandFromUnivariateExtInto(parsed.oodFlatPoints, 0, point, numVariables);
        parsed.oodEvaluation = challenger.observeReadValidatedPackedExt5Le(blob, offset);
        nextOffset = offset + 20;
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

    function _verifySumcheckBlob4NoPow(
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
        pure
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

    function _verifyStirAndCombineConstraintBlob(
        KeccakChallenger.State memory challenger,
        bytes32 expectedRoot,
        uint256 powBits,
        uint256 numQueries,
        uint256 foldingFactor,
        uint256 domainSize,
        uint256 foldedDomainGen,
        bytes calldata blob,
        uint256 valuesOffset,
        uint256 decommLen,
        uint256 powWitnessOffset,
        uint256[] memory allRandomness,
        uint256 randomnessOffset,
        uint8 expectedKind,
        uint256 oodAnswer
    )
        internal
        pure
        returns (
            uint256 challenge,
            uint256 claimedContribution,
            uint256[] memory selVars,
            uint256 nextOffset
        )
    {
        _checkWitnessBaseLeBlob(challenger, powBits, blob, powWitnessOffset);
        return _verifyStirAndCombineConstraintBlobAfterWitness(
            challenger,
            expectedRoot,
            numQueries,
            foldingFactor,
            domainSize,
            foldedDomainGen,
            blob,
            valuesOffset,
            decommLen,
            allRandomness,
            randomnessOffset,
            expectedKind,
            oodAnswer
        );
    }

    function _verifyStirAndCombineConstraintBlobAfterWitness(
        KeccakChallenger.State memory challenger,
        bytes32 expectedRoot,
        uint256 numQueries,
        uint256 foldingFactor,
        uint256 domainSize,
        uint256 foldedDomainGen,
        bytes calldata blob,
        uint256 valuesOffset,
        uint256 decommLen,
        uint256[] memory allRandomness,
        uint256 randomnessOffset,
        uint8 expectedKind,
        uint256 oodAnswer
    )
        private
        pure
        returns (
            uint256 challenge,
            uint256 claimedContribution,
            uint256[] memory selVars,
            uint256 nextOffset
        )
    {
        challenger.sampleBase();

        uint256[] memory indices = WhirVerifierUtils5.sampleStirQueries(
            challenger, domainSize, foldingFactor, numQueries
        );
        if (indices.length != numQueries) {
            revert QueryBatchCountMismatch(numQueries, indices.length);
        }

        uint256 rowLen = uint256(1) << foldingFactor;
        uint256 stride = expectedKind == 0 ? 4 : 32;
        uint256 depth = WhirVerifierUtils5.log2Strict(domainSize >> foldingFactor);
        uint256 decommOffset = valuesOffset + numQueries * rowLen * stride;
        nextOffset = decommOffset + decommLen * 20;

        if (rowLen == 16 && foldingFactor == 4) {
            (challenge, claimedContribution, selVars) = _verifyStirAndCombineConstraintBlob16(
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
            return (challenge, claimedContribution, selVars, nextOffset);
        }

        bytes32 computedRoot = expectedKind == 0
            ? MerkleVerifier.computeRootFromFlatBaseRows20Blob(
                indices, blob, valuesOffset, rowLen, depth, decommOffset, decommLen
            )
            : MerkleVerifier.computeRootFromFlatExtension8Rows20Blob(
                indices, blob, valuesOffset, rowLen, depth, decommOffset, decommLen
            );

        if (computedRoot != expectedRoot) {
            revert MerkleRootMismatch(expectedRoot, computedRoot);
        }

        challenge = WhirVerifierUtils5.sampleExt5(challenger);
        selVars = indices;

        unchecked {
            for (uint256 i = numQueries; i > 0; --i) {
                uint256 idx = i - 1;
                selVars[idx] = KoalaBear.pow(foldedDomainGen, indices[idx]);
                uint256 rowOffset = valuesOffset + idx * rowLen * stride;
                uint256 evalValue = expectedKind == 0
                    ? WhirVerifierUtils5.evaluateBaseRowAsExt5Blob(
                        blob, rowOffset, rowLen, allRandomness, randomnessOffset, foldingFactor
                    )
                    : WhirVerifierUtils5.evaluateExtensionRowAsExt5Blob(
                        blob, rowOffset, rowLen, allRandomness, randomnessOffset, foldingFactor
                    );
                claimedContribution = _hornerStep(claimedContribution, challenge, evalValue);
            }
        }

        claimedContribution = _hornerStep(claimedContribution, challenge, oodAnswer);
    }

    function _verifyFinalStirChallengesBlob(
        KeccakChallenger.State memory challenger,
        bytes32 expectedRoot,
        uint256 powBits,
        uint256 numQueries,
        uint256 foldingFactor,
        uint256 domainSize,
        uint256 foldedDomainGen,
        bytes calldata blob,
        uint256 valuesOffset,
        uint256 decommLen,
        uint256 powWitnessOffset,
        uint256[] memory allRandomness,
        uint256 randomnessOffset,
        uint8 expectedKind,
        uint256 finalPolyOffset,
        uint256 finalPolyLength
    ) internal pure returns (uint256 nextOffset) {
        _checkWitnessBaseLeBlob(challenger, powBits, blob, powWitnessOffset);

        uint256[] memory indices = WhirVerifierUtils5.sampleStirQueries(
            challenger, domainSize, foldingFactor, numQueries
        );
        if (indices.length != numQueries) {
            revert QueryBatchCountMismatch(numQueries, indices.length);
        }

        uint256 rowLen = uint256(1) << foldingFactor;
        uint256 stride = expectedKind == 0 ? 4 : 32;
        uint256 depth = WhirVerifierUtils5.log2Strict(domainSize >> foldingFactor);
        uint256 decommOffset = valuesOffset + numQueries * rowLen * stride;
        nextOffset = decommOffset + decommLen * 20;

        if (rowLen == 16 && foldingFactor == 4) {
            _verifyFinalStirChallengesBlob16(
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
                finalPolyOffset,
                finalPolyLength
            );
            return nextOffset;
        }

        bytes32 computedRoot = expectedKind == 0
            ? MerkleVerifier.computeRootFromFlatBaseRows20Blob(
                indices, blob, valuesOffset, rowLen, depth, decommOffset, decommLen
            )
            : MerkleVerifier.computeRootFromFlatExtension8Rows20Blob(
                indices, blob, valuesOffset, rowLen, depth, decommOffset, decommLen
            );

        if (computedRoot != expectedRoot) {
            revert MerkleRootMismatch(expectedRoot, computedRoot);
        }

        unchecked {
            for (uint256 i = 0; i < numQueries; ++i) {
                uint256 point = KoalaBear.pow(foldedDomainGen, indices[i]);
                uint256 rowOffset = valuesOffset + i * rowLen * stride;
                uint256 expectedEval = expectedKind == 0
                    ? WhirVerifierUtils5.evaluateBaseRowAsExt5Blob(
                        blob, rowOffset, rowLen, allRandomness, randomnessOffset, foldingFactor
                    )
                    : WhirVerifierUtils5.evaluateExtensionRowAsExt5Blob(
                        blob, rowOffset, rowLen, allRandomness, randomnessOffset, foldingFactor
                    );
                if (
                    WhirVerifierUtils5.hornerBaseBlob(blob, finalPolyOffset, finalPolyLength, point)
                        != expectedEval
                ) {
                    revert StirConstraintFailed(i);
                }
            }
        }
    }

    function _combineEqEvals(uint256 challenge, EqStatement memory eqStatement)
        internal
        pure
        returns (uint256 total)
    {
        unchecked {
            for (uint256 i = eqStatement.evaluations.length; i > 0; --i) {
                total = _hornerStep(total, challenge, eqStatement.evaluations[i - 1]);
            }
        }
    }

    function _combineInitialConstraintEvalsSingleRaw(
        uint256 challenge,
        uint256 statementEval,
        uint256 oodEval
    ) internal pure returns (uint256 total) {
        total = _hornerStep(total, challenge, oodEval);
        total = _hornerStep(total, challenge, statementEval);
    }

    function _evaluateInitialConstraintSingleBlobRaw(
        uint256 challenge,
        bytes calldata blob,
        uint256 statementPointOffset,
        uint256 oodPoint,
        uint256[] memory fullPoint
    ) internal pure returns (uint256 total) {
        total = _hornerStep(total, challenge, _eqPolyEvalExpandedPointAt22At0(oodPoint, fullPoint));
        total = _hornerStep(
            total, challenge, _eqPolyEvalAtBlob22(blob, statementPointOffset, fullPoint)
        );
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
        pure
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

                statementEq = KoalaBearExt5.mul(statementEq, _eqTerm(statementPointValue, q));
                initialEq = KoalaBearExt5.mul(initialEq, _eqTerm(initialCurrent, q));
                initialCurrent = KoalaBearExt5.square(initialCurrent);

                if (i > 4) {
                    round0Eq = KoalaBearExt5.mul(round0Eq, _eqTerm(round0Current, q));
                    round0Current = KoalaBearExt5.square(round0Current);
                    if (i > 8) {
                        round1Eq = KoalaBearExt5.mul(round1Eq, _eqTerm(round1Current, q));
                        round1Current = KoalaBearExt5.square(round1Current);
                        if (i > 12) {
                            round2Eq = KoalaBearExt5.mul(round2Eq, _eqTerm(round2Current, q));
                            round2Current = KoalaBearExt5.square(round2Current);
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
    ) internal pure returns (uint256 total) {
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

    function _evaluateInitialConstraintSingleMemoryRaw(
        uint256 challenge,
        uint256[] memory statementPoint,
        uint256[] memory oodFlatPoints,
        uint256[] memory fullPoint
    ) internal pure returns (uint256 total) {
        uint256 numVariables = statementPoint.length;
        uint256 pointOffset = fullPoint.length - numVariables;

        total = _hornerStep(
            total, challenge, _eqPolyEvalAt(oodFlatPoints, 0, fullPoint, pointOffset, numVariables)
        );
        total = _hornerStep(
            total,
            challenge,
            _eqPolyEvalAtMemory(statementPoint, fullPoint, pointOffset, numVariables)
        );
    }

    function _evaluateConstraintSelectRaw(
        uint256 challenge,
        uint256[] memory eqFlatPoints,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) internal pure returns (uint256 total) {
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

    function _evaluateConstraintSelectRaw18(
        uint256 challenge,
        uint256 oodPoint,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) internal pure returns (uint256 total) {
        return _evaluateConstraintSelectRaw18WithPrecomputedEq(
            challenge, _eqPolyEvalExpandedPointAt18At4(oodPoint, fullPoint), selVars, fullPoint
        );
    }

    function _evaluateConstraintSelectRaw18WithPrecomputedEq(
        uint256 challenge,
        uint256 eqEval,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) internal pure returns (uint256 total) {
        unchecked {
            for (uint256 i = selVars.length; i > 0; --i) {
                total = _hornerStep(
                    total, challenge, _selectPolyEvalFixed(selVars[i - 1], fullPoint, 4, 18)
                );
            }
        }
        total = _hornerStep(total, challenge, eqEval);
    }

    function _evaluateConstraintSelectRaw14(
        uint256 challenge,
        uint256 oodPoint,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) internal pure returns (uint256 total) {
        return _evaluateConstraintSelectRaw14WithPrecomputedEq(
            challenge, _eqPolyEvalExpandedPointAt14At8(oodPoint, fullPoint), selVars, fullPoint
        );
    }

    function _evaluateConstraintSelectRaw14WithPrecomputedEq(
        uint256 challenge,
        uint256 eqEval,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) internal pure returns (uint256 total) {
        unchecked {
            for (uint256 i = selVars.length; i > 0; --i) {
                total = _hornerStep(
                    total, challenge, _selectPolyEvalFixed(selVars[i - 1], fullPoint, 8, 14)
                );
            }
        }
        total = _hornerStep(total, challenge, eqEval);
    }

    function _evaluateConstraintSelectRaw10(
        uint256 challenge,
        uint256 oodPoint,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) internal pure returns (uint256 total) {
        return _evaluateConstraintSelectRaw10WithPrecomputedEq(
            challenge, _eqPolyEvalExpandedPointAt10At12(oodPoint, fullPoint), selVars, fullPoint
        );
    }

    function _evaluateConstraintSelectRaw10WithPrecomputedEq(
        uint256 challenge,
        uint256 eqEval,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) internal pure returns (uint256 total) {
        unchecked {
            for (uint256 i = selVars.length; i > 0; --i) {
                total = _hornerStep(
                    total, challenge, _selectPolyEvalFixed(selVars[i - 1], fullPoint, 12, 10)
                );
            }
        }
        total = _hornerStep(total, challenge, eqEval);
    }

    function _eqPolyEvalExpandedPointAt22At0(uint256 point, uint256[] memory fullPoint)
        internal
        pure
        returns (uint256)
    {
        return _eqPolyEvalExpandedPointAtOffset(point, fullPoint, 0, 22);
    }

    function _eqPolyEvalExpandedPointAt18At4(uint256 point, uint256[] memory fullPoint)
        internal
        pure
        returns (uint256)
    {
        return _eqPolyEvalExpandedPointAtOffset(point, fullPoint, 4, 18);
    }

    function _eqPolyEvalExpandedPointAt14At8(uint256 point, uint256[] memory fullPoint)
        internal
        pure
        returns (uint256)
    {
        return _eqPolyEvalExpandedPointAtOffset(point, fullPoint, 8, 14);
    }

    function _eqPolyEvalExpandedPointAt10At12(uint256 point, uint256[] memory fullPoint)
        internal
        pure
        returns (uint256)
    {
        return _eqPolyEvalExpandedPointAtOffset(point, fullPoint, 12, 10);
    }

    function _eqPolyEvalExpandedPointAtOffset(
        uint256 point,
        uint256[] memory fullPoint,
        uint256 pointOffset,
        uint256 numVariables
    ) internal pure returns (uint256 acc) {
        acc = KoalaBearExt5.ONE;
        uint256 current = point;

        unchecked {
            for (uint256 i = numVariables; i > 0; --i) {
                acc = KoalaBearExt5.mul(acc, _eqTerm(current, fullPoint[pointOffset + i - 1]));
                current = KoalaBearExt5.square(current);
            }
        }
    }

    function _eqPolyEvalAt(
        uint256[] memory point,
        uint256 pointStart,
        uint256[] memory fullPoint,
        uint256 pointOffset,
        uint256 numVariables
    ) internal pure returns (uint256 acc) {
        acc = KoalaBearExt5.ONE;
        unchecked {
            for (uint256 i = 0; i < numVariables; ++i) {
                acc = KoalaBearExt5.mul(
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
    ) internal pure returns (uint256 acc) {
        if (point.length != numVariables) {
            revert StatementPointArityMismatch(0, numVariables, point.length);
        }

        acc = KoalaBearExt5.ONE;
        unchecked {
            for (uint256 i = 0; i < numVariables; ++i) {
                acc = KoalaBearExt5.mul(acc, _eqTerm(point[i], fullPoint[pointOffset + i]));
            }
        }
    }

    function _eqPolyEvalAtBlob22(
        bytes calldata blob,
        uint256 blobOffset,
        uint256[] memory fullPoint
    ) internal pure returns (uint256 acc) {
        acc = KoalaBearExt5.ONE;
        unchecked {
            for (uint256 i = 0; i < 22; ++i) {
                uint256 p;
                assembly ("memory-safe") {
                    p := and(
                        calldataload(add(add(blob.offset, blobOffset), mul(20, i))),
                        not(sub(shl(96, 1), 1))
                    )
                }
                acc = KoalaBearExt5.mul(acc, _eqTerm(p, fullPoint[i]));
            }
        }
    }

    function _eqPolyEvalAtMemory(
        uint256[] memory point,
        uint256[] memory fullPoint,
        uint256 pointOffset,
        uint256 numVariables
    ) internal pure returns (uint256 acc) {
        if (point.length != numVariables) {
            revert StatementPointArityMismatch(0, numVariables, point.length);
        }

        acc = KoalaBearExt5.ONE;
        unchecked {
            for (uint256 i = 0; i < numVariables; ++i) {
                acc = KoalaBearExt5.mul(acc, _eqTerm(point[i], fullPoint[pointOffset + i]));
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
        pure
        returns (uint256)
    {
        return KoalaBearExt5.add(KoalaBearExt5.mul(total, challenge), weight);
    }

    function _eqTerm(uint256 p, uint256 q) internal pure returns (uint256) {
        return KoalaBearExt5.add(
            KoalaBearExt5.ONE,
            KoalaBearExt5.sub(
                KoalaBearExt5.sub(KoalaBearExt5.mulBase(KoalaBearExt5.mul(p, q), 2), p), q
            )
        );
    }
}
