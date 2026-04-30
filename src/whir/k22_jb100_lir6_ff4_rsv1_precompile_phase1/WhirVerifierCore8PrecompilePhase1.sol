// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { KoalaBear } from "../../field/KoalaBear.sol";
import { KoalaBearExt8 } from "../../field/KoalaBearExt8.sol";
import { KoalaBearExt8Precompile } from "../../field/KoalaBearExt8Precompile.sol";
import { MerkleVerifier } from "../../merkle/MerkleVerifier.sol";
import { KeccakChallenger } from "../../transcript/KeccakChallenger.sol";
import { WhirStructs } from "../WhirStructs.sol";
import {
    WhirBlobCodec8
} from "../k22_jb100_lir6_ff4_rsv1/WhirBlobCodec8_k22_jb100_lir6_ff4_rsv1.sol";
import { WhirVerifierUtils8 } from "../k22_jb100_lir6_ff4_rsv1/WhirVerifierUtils8.sol";

library WhirVerifierCore8PrecompilePhase1 {
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
        view
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

        uint256 eqWeightsPtr = WhirVerifierUtils8._computeDim4EqWeights(p0, p1, p2, p3);

        unchecked {
            uint256 prevIdx;
            for (uint256 i = 0; i < count; ++i) {
                uint256 idx = indices[i];
                if (i != 0 && prevIdx >= idx) {
                    revert MerkleVerifier.IndicesNotStrictlyIncreasing(prevIdx, idx);
                }
                prevIdx = idx;

                uint256 rowOffset = valuesOffset + i * 64;
                (bytes32 hash, uint256 evalValue) = WhirVerifierUtils8._hashAndEvaluateBaseRowDim4BlobPackedPoints(
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

    function _computeExtension8RootAndEvalsBlob16(
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

        unchecked {
            uint256 prevIdx;
            for (uint256 i = 0; i < count; ++i) {
                uint256 idx = indices[i];
                if (i != 0 && prevIdx >= idx) {
                    revert MerkleVerifier.IndicesNotStrictlyIncreasing(prevIdx, idx);
                }
                prevIdx = idx;

                uint256 rowOffset = valuesOffset + i * 512;
                (bytes32 hash, uint256 evalValue) =
                    _hashAndEvaluateExtensionRowDim4BlobPrecompile(blob, rowOffset, p0, p1, p2, p3);
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

    function _hashAndEvaluateExtensionRowDim4BlobPrecompile(
        bytes calldata blob,
        uint256 offset,
        uint256 p0,
        uint256 p1,
        uint256 p2,
        uint256 p3
    ) private view returns (bytes32 digest, uint256 evalValue) {
        uint256 rowBase = _copyHashAndValidateExtensionRow(blob, offset);
        digest = _hashCopiedExtensionRow(rowBase);
        evalValue = _foldExtensionRowPrecompile(rowBase, p0, p1, p2, p3);
    }

    function _copyHashAndValidateExtensionRow(bytes calldata blob, uint256 offset)
        private
        pure
        returns (uint256 rowBase)
    {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore8(ptr, 0x00)
            rowBase := add(ptr, 0x01)
            calldatacopy(rowBase, add(blob.offset, offset), 0x200)
            mstore(0x40, add(ptr, 0x240))
        }

        unchecked {
            for (uint256 i = 0; i < 16; ++i) {
                WhirVerifierUtils8.validatePackedExt8(_extensionRowWord(rowBase, i));
            }
        }
    }

    function _hashCopiedExtensionRow(uint256 rowBase) private pure returns (bytes32 digest) {
        assembly ("memory-safe") {
            digest := and(keccak256(sub(rowBase, 1), 513), not(sub(shl(96, 1), 1)))
        }
    }

    function _foldExtensionRowPrecompile(
        uint256 rowBase,
        uint256 p0,
        uint256 p1,
        uint256 p2,
        uint256 p3
    ) private view returns (uint256) {
        uint256 m0 = _foldOncePrecompile(
            _foldOncePrecompile(_extensionRowWord(rowBase, 0), _extensionRowWord(rowBase, 8), p0),
            _foldOncePrecompile(_extensionRowWord(rowBase, 4), _extensionRowWord(rowBase, 12), p0),
            p1
        );
        uint256 m1 = _foldOncePrecompile(
            _foldOncePrecompile(_extensionRowWord(rowBase, 1), _extensionRowWord(rowBase, 9), p0),
            _foldOncePrecompile(_extensionRowWord(rowBase, 5), _extensionRowWord(rowBase, 13), p0),
            p1
        );
        uint256 m2 = _foldOncePrecompile(
            _foldOncePrecompile(_extensionRowWord(rowBase, 2), _extensionRowWord(rowBase, 10), p0),
            _foldOncePrecompile(_extensionRowWord(rowBase, 6), _extensionRowWord(rowBase, 14), p0),
            p1
        );
        uint256 m3 = _foldOncePrecompile(
            _foldOncePrecompile(_extensionRowWord(rowBase, 3), _extensionRowWord(rowBase, 11), p0),
            _foldOncePrecompile(_extensionRowWord(rowBase, 7), _extensionRowWord(rowBase, 15), p0),
            p1
        );
        return
            _foldOncePrecompile(
                _foldOncePrecompile(m0, m2, p2), _foldOncePrecompile(m1, m3, p2), p3
            );
    }

    function _extensionRowWord(uint256 rowBase, uint256 i) private pure returns (uint256 word) {
        assembly ("memory-safe") {
            word := mload(add(rowBase, shl(5, i)))
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

        unchecked {
            uint256 prevIdx;
            for (uint256 i = 0; i < count; ++i) {
                uint256 idx = indices[i];
                if (i != 0 && prevIdx >= idx) {
                    revert MerkleVerifier.IndicesNotStrictlyIncreasing(prevIdx, idx);
                }
                prevIdx = idx;

                (bytes32 hash, uint256 evalValue) = WhirVerifierUtils8._hashAndEvaluateBaseRowDim4PackedPoints(
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

    function _computeExtension8RootAndEvals16(
        uint256[] memory indices,
        uint256[] calldata flatValues,
        uint256 depth,
        bytes32[] calldata decommitments,
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

        unchecked {
            uint256 prevIdx;
            for (uint256 i = 0; i < count; ++i) {
                uint256 idx = indices[i];
                if (i != 0 && prevIdx >= idx) {
                    revert MerkleVerifier.IndicesNotStrictlyIncreasing(prevIdx, idx);
                }
                prevIdx = idx;

                (bytes32 hash, uint256 evalValue) = WhirVerifierUtils8._hashAndEvaluateExtensionRowDim4PackedPoints(
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

        bytes32 computedRoot;
        uint256[] memory rowEvals;
        if (expectedKind == 0) {
            (computedRoot, rowEvals) = _computeBaseRootAndEvalsBlob16(
                indices, blob, valuesOffset, depth, decommOffset, decommLen, p0, p1, p2, p3
            );
        } else {
            (computedRoot, rowEvals) = _computeExtension8RootAndEvalsBlob16(
                indices, blob, valuesOffset, depth, decommOffset, decommLen, p0, p1, p2, p3
            );
        }

        if (computedRoot != expectedRoot) {
            revert MerkleRootMismatch(expectedRoot, computedRoot);
        }

        challenge = WhirVerifierUtils8.sampleExt8(challenger);
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
        if (expectedKind == 0) {
            (computedRoot, rowEvals) = _computeBaseRootAndEvalsBlob16(
                indices, blob, valuesOffset, depth, decommOffset, decommLen, p0, p1, p2, p3
            );
        } else {
            (computedRoot, rowEvals) = _computeExtension8RootAndEvalsBlob16(
                indices, blob, valuesOffset, depth, decommOffset, decommLen, p0, p1, p2, p3
            );
        }

        if (computedRoot != expectedRoot) {
            revert MerkleRootMismatch(expectedRoot, computedRoot);
        }

        unchecked {
            if (finalPolyLength == 64) {
                uint256 rowEvalsBase;
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
                    rowEvalsBase := add(rowEvals, 0x20)
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

                uint256 mismatchPlusOne = WhirVerifierUtils8.checkHornerBaseBlob64Matches5Raw(
                    blob, finalPolyOffset, point0, point1, point2, point3, point4, rowEvalsBase, 0
                );
                if (mismatchPlusOne != 0) {
                    revert StirConstraintFailed(mismatchPlusOne - 1);
                }
                mismatchPlusOne = WhirVerifierUtils8.checkHornerBaseBlob64Matches5Raw(
                    blob, finalPolyOffset, point5, point6, point7, point8, point9, rowEvalsBase, 5
                );
                if (mismatchPlusOne != 0) {
                    revert StirConstraintFailed(mismatchPlusOne + 4);
                }
                return;
            }

            for (uint256 i = 0; i < numQueries; ++i) {
                uint256 point = KoalaBear.pow(foldedDomainGen, indices[i]);
                if (
                    WhirVerifierUtils8.hornerBaseBlob(blob, finalPolyOffset, finalPolyLength, point)
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

        challenge = WhirVerifierUtils8.sampleExt8(challenger);
        selVars = indices;

        uint256[] memory frontierEntries;
        assembly ("memory-safe") {
            frontierEntries := mload(0x40)
            mstore(frontierEntries, numQueries)
            mstore(0x40, add(add(frontierEntries, 0x20), shl(5, numQueries)))
        }

        uint256 eqWeightsPtr = WhirVerifierUtils8._computeDim4EqWeights(p0, p1, p2, p3);

        unchecked {
            uint256 rowOffset;
            uint256 frontierPtr;
            assembly ("memory-safe") {
                frontierPtr := add(add(frontierEntries, 0x20), shl(5, numQueries))
            }

            if (expectedKind == 0) {
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

                    (bytes32 hash, uint256 evalValue) = WhirVerifierUtils8._hashAndEvaluateBaseRowDim4BlobPackedPoints(
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
                rowOffset = valuesOffset + numQueries * 512;
                uint256 nextHigher;
                for (uint256 i = numQueries; i > 0; --i) {
                    uint256 pos = i - 1;
                    uint256 idx = indices[pos];
                    if (i != numQueries && idx >= nextHigher) {
                        revert MerkleVerifier.IndicesNotStrictlyIncreasing(idx, nextHigher);
                    }
                    nextHigher = idx;
                    rowOffset -= 512;

                    (bytes32 hash, uint256 evalValue) = _hashAndEvaluateExtensionRowDim4BlobPrecompile(
                        blob, rowOffset, p0, p1, p2, p3
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
        view
        returns (
            uint256 challenge,
            uint256 claimedContribution,
            uint256[] memory selVars,
            uint256 nextOffset
        )
    {
        _checkWitnessBaseLeBlob(challenger, 29, blob, powWitnessOffset);
        challenger.sampleBase();

        uint256[] memory indices =
            WhirVerifierUtils8.sampleStirQueries(challenger, 268_435_456, 4, 24);
        if (indices.length != 24) {
            revert QueryBatchCountMismatch(24, indices.length);
        }

        uint256 decommOffset = valuesOffset + 24 * 16 * 4;
        nextOffset = decommOffset + decommLen * 20;

        (challenge, claimedContribution, selVars) = _verifyStirAndCombineConstraintBlob16NativeFused(
            challenger,
            expectedRoot,
            24,
            24,
            1_791_270_792,
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
        view
        returns (
            uint256 challenge,
            uint256 claimedContribution,
            uint256[] memory selVars,
            uint256 nextOffset
        )
    {
        _checkWitnessBaseLeBlob(challenger, 29, blob, powWitnessOffset);
        challenger.sampleBase();

        uint256[] memory indices =
            WhirVerifierUtils8.sampleStirQueries(challenger, 134_217_728, 4, 16);
        if (indices.length != 16) {
            revert QueryBatchCountMismatch(16, indices.length);
        }

        uint256 decommOffset = valuesOffset + 16 * 16 * 32;
        nextOffset = decommOffset + decommLen * 20;

        (challenge, claimedContribution, selVars) = _verifyStirAndCombineConstraintBlob16NativeFused(
            challenger,
            expectedRoot,
            16,
            23,
            1_760_025_929,
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
        view
        returns (
            uint256 challenge,
            uint256 claimedContribution,
            uint256[] memory selVars,
            uint256 nextOffset
        )
    {
        _checkWitnessBaseLeBlob(challenger, 28, blob, powWitnessOffset);
        challenger.sampleBase();

        uint256[] memory indices =
            WhirVerifierUtils8.sampleStirQueries(challenger, 67_108_864, 4, 12);
        if (indices.length != 12) {
            revert QueryBatchCountMismatch(12, indices.length);
        }

        uint256 decommOffset = valuesOffset + 12 * 16 * 32;
        nextOffset = decommOffset + decommLen * 20;

        (challenge, claimedContribution, selVars) = _verifyStirAndCombineConstraintBlob16NativeFused(
            challenger,
            expectedRoot,
            12,
            22,
            542_991_299,
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
    ) internal view returns (uint256 nextOffset) {
        _checkWitnessBaseLeBlob(challenger, 25, blob, powWitnessOffset);

        uint256[] memory indices =
            WhirVerifierUtils8.sampleStirQueries(challenger, 33_554_432, 4, 10);
        if (indices.length != 10) {
            revert QueryBatchCountMismatch(10, indices.length);
        }

        uint256 decommOffset = valuesOffset + 10 * 16 * 32;
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
            10,
            21,
            1_213_133_211,
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
    ) internal view returns (EqStatement memory eqStatement) {
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
                    WhirVerifierUtils8.validatePackedExt8(pointValue);
                    eqStatement.flatPoints[i * numVariables + j] = pointValue;
                }

                uint256 evalValue = statement.evaluations[i];
                WhirVerifierUtils8.validatePackedExt8(evalValue);
                eqStatement.evaluations[i] = evalValue;
            }
        }
    }

    function _concatenateEq(EqStatement memory lhs, EqStatement memory rhs)
        internal
        view
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

    function _emptySelect(uint256 numVariables) internal view returns (SelectStatement memory sel) {
        sel.numVariables = numVariables;
        sel.vars = new uint256[](0);
    }

    function _parseCommitment(
        KeccakChallenger.State memory challenger,
        bytes32 root,
        uint256[] calldata oodAnswers,
        uint256 numVariables,
        uint256 oodSamples
    ) internal view returns (ParsedCommitment memory parsed) {
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
                uint256 point = WhirVerifierUtils8.sampleExt8(challenger);
                WhirVerifierUtils8.expandFromUnivariateExtInto(
                    parsed.oodStatement.flatPoints, i * numVariables, point, numVariables
                );

                uint256 evalValue = oodAnswers[i];
                WhirVerifierUtils8.observeValidatedExt8(challenger, evalValue);
                parsed.oodStatement.evaluations[i] = evalValue;
            }
        }
    }

    function _parseFixedCommitment1Blob(
        KeccakChallenger.State memory challenger,
        bytes calldata blob,
        uint256 offset,
        uint256 numVariables
    ) internal view returns (FixedParsedCommitment memory parsed, uint256 nextOffset) {
        (parsed.root, offset) = WhirBlobCodec8.readDigest20(blob, offset);
        challenger.observeHashU64Digest(parsed.root);

        parsed.oodFlatPoints = new uint256[](numVariables);
        uint256 point = WhirVerifierUtils8.sampleExt8(challenger);
        WhirVerifierUtils8.expandFromUnivariateExtInto(parsed.oodFlatPoints, 0, point, numVariables);
        parsed.oodEvaluation = challenger.observeReadValidatedPackedExt8Le(blob, offset);
        nextOffset = offset + 32;
    }

    function _parseFixedCommitment22x1Blob(
        KeccakChallenger.State memory challenger,
        bytes calldata blob,
        uint256 offset
    )
        internal
        view
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
        view
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
        view
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
        view
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
        view
        returns (bytes32 root, uint256 oodPoint, uint256 oodEvaluation, uint256 nextOffset)
    {
        (root, offset) = WhirBlobCodec8.readDigest20(blob, offset);
        challenger.observeHashU64Digest(root);
        oodPoint = WhirVerifierUtils8.sampleExt8(challenger);
        oodEvaluation = challenger.observeReadValidatedPackedExt8Le(blob, offset);
        nextOffset = offset + 32;
    }

    function _checkWitnessBaseLeBlob(
        KeccakChallenger.State memory challenger,
        uint256 bits,
        bytes calldata blob,
        uint256 offset
    ) internal view {
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
        view
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

                challenger.observeValidatedPackedExt8Pair(c0, c2);

                if (powBits > 0) {
                    if (!challenger.checkWitness(powBits, sumcheck.powWitnesses[i])) {
                        revert InvalidPowWitness();
                    }
                }

                uint256 r = WhirVerifierUtils8.sampleExt8(challenger);
                foldingRandomness[i] = r;
                allRandomness[updatedCursor] = r;
                updatedCursor += 1;
                updatedClaimedEval = KoalaBearExt8.extrapolate_012(
                    c0, KoalaBearExt8.sub(updatedClaimedEval, c0), c2, r
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
        view
        returns (uint256 updatedClaimedEval, uint256 updatedCursor, uint256 nextOffset)
    {
        updatedClaimedEval = claimedEval;
        updatedCursor = randomnessCursor;
        nextOffset = offset;

        unchecked {
            for (uint256 i = 0; i < expectedRounds; ++i) {
                (uint256 c0, uint256 c2) =
                    challenger.observeReadValidatedPackedExt8LePair(blob, nextOffset);
                nextOffset += 64;

                if (powBits > 0) {
                    _checkWitnessBaseLeBlob(
                        challenger, powBits, blob, offset + expectedRounds * 64 + i * 4
                    );
                }

                uint256 r = WhirVerifierUtils8.sampleExt8(challenger);
                allRandomness[updatedCursor] = r;
                updatedCursor += 1;
                updatedClaimedEval =
                    KoalaBearExt8.extrapolate_012_from_sumcheck(c0, updatedClaimedEval, c2, r);
            }
        }

        if (powBits > 0) {
            nextOffset = offset + expectedRounds * 64 + expectedRounds * 4;
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
        view
        returns (uint256 updatedClaimedEval, uint256 updatedCursor, uint256 nextOffset)
    {
        updatedClaimedEval = claimedEval;
        updatedCursor = randomnessCursor;
        nextOffset = offset;

        (uint256 c0, uint256 c2) = challenger.observeReadValidatedPackedExt8LePair(blob, nextOffset);
        nextOffset += 64;
        uint256 r = WhirVerifierUtils8.sampleExt8(challenger);
        allRandomness[updatedCursor] = r;
        updatedCursor += 1;
        updatedClaimedEval =
            KoalaBearExt8.extrapolate_012_from_sumcheck(c0, updatedClaimedEval, c2, r);

        (c0, c2) = challenger.observeReadValidatedPackedExt8LePair(blob, nextOffset);
        nextOffset += 64;
        r = WhirVerifierUtils8.sampleExt8(challenger);
        allRandomness[updatedCursor] = r;
        updatedCursor += 1;
        updatedClaimedEval =
            KoalaBearExt8.extrapolate_012_from_sumcheck(c0, updatedClaimedEval, c2, r);

        (c0, c2) = challenger.observeReadValidatedPackedExt8LePair(blob, nextOffset);
        nextOffset += 64;
        r = WhirVerifierUtils8.sampleExt8(challenger);
        allRandomness[updatedCursor] = r;
        updatedCursor += 1;
        updatedClaimedEval =
            KoalaBearExt8.extrapolate_012_from_sumcheck(c0, updatedClaimedEval, c2, r);

        (c0, c2) = challenger.observeReadValidatedPackedExt8LePair(blob, nextOffset);
        nextOffset += 64;
        r = WhirVerifierUtils8.sampleExt8(challenger);
        allRandomness[updatedCursor] = r;
        updatedCursor += 1;
        updatedClaimedEval =
            KoalaBearExt8.extrapolate_012_from_sumcheck(c0, updatedClaimedEval, c2, r);
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
        view
        returns (uint256 updatedClaimedEval, uint256 updatedCursor, uint256 nextOffset)
    {
        updatedClaimedEval = claimedEval;
        updatedCursor = randomnessCursor;
        nextOffset = offset;

        (uint256 c0, uint256 c2) = challenger.observeReadValidatedPackedExt8LePair(blob, nextOffset);
        nextOffset += 64;
        uint256 r = WhirVerifierUtils8.sampleExt8(challenger);
        allRandomness[updatedCursor] = r;
        updatedCursor += 1;
        updatedClaimedEval =
            KoalaBearExt8.extrapolate_012_from_sumcheck(c0, updatedClaimedEval, c2, r);

        (c0, c2) = challenger.observeReadValidatedPackedExt8LePair(blob, nextOffset);
        nextOffset += 64;
        r = WhirVerifierUtils8.sampleExt8(challenger);
        allRandomness[updatedCursor] = r;
        updatedCursor += 1;
        updatedClaimedEval =
            KoalaBearExt8.extrapolate_012_from_sumcheck(c0, updatedClaimedEval, c2, r);

        (c0, c2) = challenger.observeReadValidatedPackedExt8LePair(blob, nextOffset);
        nextOffset += 64;
        r = WhirVerifierUtils8.sampleExt8(challenger);
        allRandomness[updatedCursor] = r;
        updatedCursor += 1;
        updatedClaimedEval =
            KoalaBearExt8.extrapolate_012_from_sumcheck(c0, updatedClaimedEval, c2, r);

        (c0, c2) = challenger.observeReadValidatedPackedExt8LePair(blob, nextOffset);
        nextOffset += 64;
        r = WhirVerifierUtils8.sampleExt8(challenger);
        allRandomness[updatedCursor] = r;
        updatedCursor += 1;
        updatedClaimedEval =
            KoalaBearExt8.extrapolate_012_from_sumcheck(c0, updatedClaimedEval, c2, r);

        (c0, c2) = challenger.observeReadValidatedPackedExt8LePair(blob, nextOffset);
        nextOffset += 64;
        r = WhirVerifierUtils8.sampleExt8(challenger);
        allRandomness[updatedCursor] = r;
        updatedCursor += 1;
        updatedClaimedEval =
            KoalaBearExt8.extrapolate_012_from_sumcheck(c0, updatedClaimedEval, c2, r);

        (c0, c2) = challenger.observeReadValidatedPackedExt8LePair(blob, nextOffset);
        nextOffset += 64;
        r = WhirVerifierUtils8.sampleExt8(challenger);
        allRandomness[updatedCursor] = r;
        updatedCursor += 1;
        updatedClaimedEval =
            KoalaBearExt8.extrapolate_012_from_sumcheck(c0, updatedClaimedEval, c2, r);
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
            challenge = WhirVerifierUtils8.sampleExt8(challenger);
            unchecked {
                for (uint256 i = oodAnswers.length; i > 0; --i) {
                    claimedContribution =
                        _hornerStep(claimedContribution, challenge, oodAnswers[i - 1]);
                }
            }
            selVars = new uint256[](0);
            return (challenge, claimedContribution, selVars);
        }

        uint256[] memory indices = WhirVerifierUtils8.sampleStirQueries(
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

        uint256 depth = WhirVerifierUtils8.log2Strict(domainSize >> foldingFactor);

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
                (fastRoot, rowEvals) = _computeExtension8RootAndEvals16(
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

            challenge = WhirVerifierUtils8.sampleExt8(challenger);
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
            : MerkleVerifier.computeRootFromFlatExtension8Rows20(
                indices, queryBatch.values, queryBatch.rowLen, depth, queryBatch.decommitments
            );

        if (computedRoot != expectedRoot) {
            revert MerkleRootMismatch(expectedRoot, computedRoot);
        }

        challenge = WhirVerifierUtils8.sampleExt8(challenger);
        selVars = indices;

        unchecked {
            for (uint256 i = indices.length; i > 0; --i) {
                uint256 idx = i - 1;
                selVars[idx] = KoalaBear.pow(foldedDomainGen, indices[idx]);

                uint256 rowStart = idx * queryBatch.rowLen;
                uint256 evalValue = expectedKind == 0
                    ? WhirVerifierUtils8.evaluateBaseRowAsExt8(
                        queryBatch.values, rowStart, queryBatch.rowLen, foldingRandomness
                    )
                    : WhirVerifierUtils8.evaluateExtensionRowAsExt8(
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
    ) internal view {
        if (powBits > 0 && !challenger.checkWitness(powBits, powWitness)) {
            revert InvalidPowWitness();
        }

        if (!queryBatchPresent) {
            if (numQueries != 0) {
                revert FinalQueryBatchPresenceMismatch(true, false);
            }
            return;
        }

        uint256[] memory indices = WhirVerifierUtils8.sampleStirQueries(
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

        uint256 depth = WhirVerifierUtils8.log2Strict(domainSize >> foldingFactor);

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
                (fastRoot, rowEvals) = _computeExtension8RootAndEvals16(
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

                if (WhirVerifierUtils8.hornerBase(finalPoly, point0) != rowEvals[0]) {
                    revert StirConstraintFailed(0);
                }
                if (WhirVerifierUtils8.hornerBase(finalPoly, point1) != rowEvals[1]) {
                    revert StirConstraintFailed(1);
                }
                if (WhirVerifierUtils8.hornerBase(finalPoly, point2) != rowEvals[2]) {
                    revert StirConstraintFailed(2);
                }
                if (WhirVerifierUtils8.hornerBase(finalPoly, point3) != rowEvals[3]) {
                    revert StirConstraintFailed(3);
                }
                if (WhirVerifierUtils8.hornerBase(finalPoly, point4) != rowEvals[4]) {
                    revert StirConstraintFailed(4);
                }
                if (WhirVerifierUtils8.hornerBase(finalPoly, point5) != rowEvals[5]) {
                    revert StirConstraintFailed(5);
                }
                if (WhirVerifierUtils8.hornerBase(finalPoly, point6) != rowEvals[6]) {
                    revert StirConstraintFailed(6);
                }
                if (WhirVerifierUtils8.hornerBase(finalPoly, point7) != rowEvals[7]) {
                    revert StirConstraintFailed(7);
                }
                if (WhirVerifierUtils8.hornerBase(finalPoly, point8) != rowEvals[8]) {
                    revert StirConstraintFailed(8);
                }
                if (WhirVerifierUtils8.hornerBase(finalPoly, point9) != rowEvals[9]) {
                    revert StirConstraintFailed(9);
                }
                return;
            }

            unchecked {
                for (uint256 i = 0; i < indices.length; ++i) {
                    uint256 point = KoalaBear.pow(foldedDomainGen, indices[i]);
                    if (WhirVerifierUtils8.hornerBase(finalPoly, point) != rowEvals[i]) {
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
            : MerkleVerifier.computeRootFromFlatExtension8Rows20(
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
                    ? WhirVerifierUtils8.evaluateBaseRowAsExt8(
                        queryBatch.values, rowStart, queryBatch.rowLen, foldingRandomness
                    )
                    : WhirVerifierUtils8.evaluateExtensionRowAsExt8(
                        queryBatch.values, rowStart, queryBatch.rowLen, foldingRandomness
                    );
                if (WhirVerifierUtils8.hornerBase(finalPoly, point) != expectedEval) {
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
        view
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
        view
        returns (
            uint256 challenge,
            uint256 claimedContribution,
            uint256[] memory selVars,
            uint256 nextOffset
        )
    {
        challenger.sampleBase();

        uint256[] memory indices = WhirVerifierUtils8.sampleStirQueries(
            challenger, domainSize, foldingFactor, numQueries
        );
        if (indices.length != numQueries) {
            revert QueryBatchCountMismatch(numQueries, indices.length);
        }

        uint256 rowLen = uint256(1) << foldingFactor;
        uint256 stride = expectedKind == 0 ? 4 : 32;
        uint256 depth = WhirVerifierUtils8.log2Strict(domainSize >> foldingFactor);
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

        challenge = WhirVerifierUtils8.sampleExt8(challenger);
        selVars = indices;

        unchecked {
            for (uint256 i = numQueries; i > 0; --i) {
                uint256 idx = i - 1;
                selVars[idx] = KoalaBear.pow(foldedDomainGen, indices[idx]);
                uint256 rowOffset = valuesOffset + idx * rowLen * stride;
                uint256 evalValue = expectedKind == 0
                    ? WhirVerifierUtils8.evaluateBaseRowAsExt8Blob(
                        blob, rowOffset, rowLen, allRandomness, randomnessOffset, foldingFactor
                    )
                    : WhirVerifierUtils8.evaluateExtensionRowAsExt8Blob(
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
    ) internal view returns (uint256 nextOffset) {
        _checkWitnessBaseLeBlob(challenger, powBits, blob, powWitnessOffset);

        uint256[] memory indices = WhirVerifierUtils8.sampleStirQueries(
            challenger, domainSize, foldingFactor, numQueries
        );
        if (indices.length != numQueries) {
            revert QueryBatchCountMismatch(numQueries, indices.length);
        }

        uint256 rowLen = uint256(1) << foldingFactor;
        uint256 stride = expectedKind == 0 ? 4 : 32;
        uint256 depth = WhirVerifierUtils8.log2Strict(domainSize >> foldingFactor);
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
                    ? WhirVerifierUtils8.evaluateBaseRowAsExt8Blob(
                        blob, rowOffset, rowLen, allRandomness, randomnessOffset, foldingFactor
                    )
                    : WhirVerifierUtils8.evaluateExtensionRowAsExt8Blob(
                        blob, rowOffset, rowLen, allRandomness, randomnessOffset, foldingFactor
                    );
                if (
                    WhirVerifierUtils8.hornerBaseBlob(blob, finalPolyOffset, finalPolyLength, point)
                        != expectedEval
                ) {
                    revert StirConstraintFailed(i);
                }
            }
        }
    }

    function _combineEqEvals(uint256 challenge, EqStatement memory eqStatement)
        internal
        view
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
    ) internal view returns (uint256 total) {
        total = _hornerStep(total, challenge, oodEval);
        total = _hornerStep(total, challenge, statementEval);
    }

    function _evaluateInitialConstraintSingleBlobRaw(
        uint256 challenge,
        bytes calldata blob,
        uint256 statementPointOffset,
        uint256 oodPoint,
        uint256[] memory fullPoint
    ) internal view returns (uint256 total) {
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
        view
        returns (
            uint256 statementEq,
            uint256 initialEq,
            uint256 round0Eq,
            uint256 round1Eq,
            uint256 round2Eq
        )
    {
        statementEq = KoalaBearExt8.ONE;
        initialEq = KoalaBearExt8.ONE;
        round0Eq = KoalaBearExt8.ONE;
        round1Eq = KoalaBearExt8.ONE;
        round2Eq = KoalaBearExt8.ONE;

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
                    let pointOffset := shl(5, sub(i, 1))
                    q := mload(add(pointBase, pointOffset))
                    statementPointValue := calldataload(
                        add(add(blob.offset, statementPointOffset), pointOffset)
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

                KoalaBearExt8Precompile.mulBatchInto(batchInput, eqCount << 6, batchOutput);

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

                KoalaBearExt8Precompile.mulBatchInto(batchInput, opCount << 6, batchOutput);

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

    function _evaluateInitialConstraintSingleMemoryRaw(
        uint256 challenge,
        uint256[] memory statementPoint,
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
            _eqPolyEvalAtMemory(statementPoint, fullPoint, pointOffset, numVariables)
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
                    WhirVerifierUtils8.selectPolyEval(
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
    ) internal view returns (uint256 total) {
        return _evaluateConstraintSelectRaw18WithPrecomputedEq(
            challenge, _eqPolyEvalExpandedPointAt18At4(oodPoint, fullPoint), selVars, fullPoint
        );
    }

    function _evaluateConstraintSelectRaw18WithPrecomputedEq(
        uint256 challenge,
        uint256 eqEval,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) internal view returns (uint256 total) {
        uint256 ch0;
        uint256 ch1;
        uint256 ch2;
        uint256 ch3;
        uint256 ch4;
        uint256 ch5;
        uint256 ch6;
        uint256 ch7;
        assembly ("memory-safe") {
            ch0 := shr(224, challenge)
            ch1 := and(shr(192, challenge), 0xffffffff)
            ch2 := and(shr(160, challenge), 0xffffffff)
            ch3 := and(shr(128, challenge), 0xffffffff)
            ch4 := and(shr(96, challenge), 0xffffffff)
            ch5 := and(shr(64, challenge), 0xffffffff)
            ch6 := and(shr(32, challenge), 0xffffffff)
            ch7 := and(challenge, 0xffffffff)
        }
        unchecked {
            for (uint256 i = 24; i > 0; --i) {
                total = _hornerStepWithChallengeCoeffs(
                    total,
                    _selectPolyEvalAt18At4(selVars[i - 1], fullPoint),
                    ch0,
                    ch1,
                    ch2,
                    ch3,
                    ch4,
                    ch5,
                    ch6,
                    ch7
                );
            }
        }
        total =
            _hornerStepWithChallengeCoeffs(total, eqEval, ch0, ch1, ch2, ch3, ch4, ch5, ch6, ch7);
    }

    function _evaluateConstraintSelectRaw14(
        uint256 challenge,
        uint256 oodPoint,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) internal view returns (uint256 total) {
        return _evaluateConstraintSelectRaw14WithPrecomputedEq(
            challenge, _eqPolyEvalExpandedPointAt14At8(oodPoint, fullPoint), selVars, fullPoint
        );
    }

    function _evaluateConstraintSelectRaw14WithPrecomputedEq(
        uint256 challenge,
        uint256 eqEval,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) internal view returns (uint256 total) {
        uint256 ch0;
        uint256 ch1;
        uint256 ch2;
        uint256 ch3;
        uint256 ch4;
        uint256 ch5;
        uint256 ch6;
        uint256 ch7;
        assembly ("memory-safe") {
            ch0 := shr(224, challenge)
            ch1 := and(shr(192, challenge), 0xffffffff)
            ch2 := and(shr(160, challenge), 0xffffffff)
            ch3 := and(shr(128, challenge), 0xffffffff)
            ch4 := and(shr(96, challenge), 0xffffffff)
            ch5 := and(shr(64, challenge), 0xffffffff)
            ch6 := and(shr(32, challenge), 0xffffffff)
            ch7 := and(challenge, 0xffffffff)
        }
        unchecked {
            for (uint256 i = 16; i > 0; --i) {
                total = _hornerStepWithChallengeCoeffs(
                    total,
                    _selectPolyEvalAt14At8(selVars[i - 1], fullPoint),
                    ch0,
                    ch1,
                    ch2,
                    ch3,
                    ch4,
                    ch5,
                    ch6,
                    ch7
                );
            }
        }
        total =
            _hornerStepWithChallengeCoeffs(total, eqEval, ch0, ch1, ch2, ch3, ch4, ch5, ch6, ch7);
    }

    function _evaluateConstraintSelectRaw10(
        uint256 challenge,
        uint256 oodPoint,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) internal view returns (uint256 total) {
        return _evaluateConstraintSelectRaw10WithPrecomputedEq(
            challenge, _eqPolyEvalExpandedPointAt10At12(oodPoint, fullPoint), selVars, fullPoint
        );
    }

    function _evaluateConstraintSelectRaw10WithPrecomputedEq(
        uint256 challenge,
        uint256 eqEval,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) internal view returns (uint256 total) {
        uint256 ch0;
        uint256 ch1;
        uint256 ch2;
        uint256 ch3;
        uint256 ch4;
        uint256 ch5;
        uint256 ch6;
        uint256 ch7;
        assembly ("memory-safe") {
            ch0 := shr(224, challenge)
            ch1 := and(shr(192, challenge), 0xffffffff)
            ch2 := and(shr(160, challenge), 0xffffffff)
            ch3 := and(shr(128, challenge), 0xffffffff)
            ch4 := and(shr(96, challenge), 0xffffffff)
            ch5 := and(shr(64, challenge), 0xffffffff)
            ch6 := and(shr(32, challenge), 0xffffffff)
            ch7 := and(challenge, 0xffffffff)
        }
        unchecked {
            for (uint256 i = 12; i > 0; --i) {
                total = _hornerStepWithChallengeCoeffs(
                    total,
                    _selectPolyEvalAt10At12(selVars[i - 1], fullPoint),
                    ch0,
                    ch1,
                    ch2,
                    ch3,
                    ch4,
                    ch5,
                    ch6,
                    ch7
                );
            }
        }
        total =
            _hornerStepWithChallengeCoeffs(total, eqEval, ch0, ch1, ch2, ch3, ch4, ch5, ch6, ch7);
    }

    function _selectPolyEvalAt18At4(uint256 var_, uint256[] memory fullPoint)
        internal
        view
        returns (uint256 acc)
    {
        return _selectPolyEvalFixed(var_, fullPoint, 4, 18);
    }

    function _selectPolyEvalAt14At8(uint256 var_, uint256[] memory fullPoint)
        internal
        view
        returns (uint256 acc)
    {
        return _selectPolyEvalFixed(var_, fullPoint, 8, 14);
    }

    function _selectPolyEvalAt10At12(uint256 var_, uint256[] memory fullPoint)
        internal
        view
        returns (uint256 acc)
    {
        return _selectPolyEvalFixed(var_, fullPoint, 12, 10);
    }

    function _evaluateConstraints(Constraint[] memory constraints, uint256[] memory allRandomness)
        internal
        view
        returns (uint256 total)
    {
        unchecked {
            for (uint256 i = 0; i < constraints.length; ++i) {
                total = KoalaBearExt8.add(total, _evaluateConstraint(constraints[i], allRandomness));
            }
        }
    }

    function _evaluateConstraint(Constraint memory constraint, uint256[] memory fullPoint)
        internal
        view
        returns (uint256 total)
    {
        uint256 numVariables = constraint.eqStatement.numVariables;
        if (
            constraint.selStatement.vars.length != 0
                && constraint.selStatement.numVariables != numVariables
        ) {
            revert InconsistentConstraintArity(numVariables, constraint.selStatement.numVariables);
        }
        uint256 pointOffset = fullPoint.length - numVariables;

        unchecked {
            for (uint256 i = constraint.selStatement.vars.length; i > 0; --i) {
                total = _hornerStep(
                    total,
                    constraint.challenge,
                    WhirVerifierUtils8.selectPolyEval(
                        constraint.selStatement.vars[i - 1], fullPoint, pointOffset, numVariables
                    )
                );
            }
            for (uint256 i = constraint.eqStatement.evaluations.length; i > 0; --i) {
                total = _hornerStep(
                    total,
                    constraint.challenge,
                    _eqPolyEvalAt(
                        constraint.eqStatement.flatPoints,
                        (i - 1) * numVariables,
                        fullPoint,
                        pointOffset,
                        numVariables
                    )
                );
            }
        }
    }

    function _eqPolyEvalAt(
        uint256[] memory flatPoints,
        uint256 pointStart,
        uint256[] memory fullPoint,
        uint256 pointOffset,
        uint256 numVariables
    ) internal view returns (uint256 acc) {
        acc = KoalaBearExt8.ONE;
        unchecked {
            for (uint256 i = 0; i < numVariables; ++i) {
                uint256 p = flatPoints[pointStart + i];
                uint256 q = fullPoint[pointOffset + i];
                acc = KoalaBearExt8Precompile.mul(acc, _eqTerm(p, q));
            }
        }
    }

    function _eqPolyEvalExpandedPoint(
        uint256 point,
        uint256[] memory fullPoint,
        uint256 pointOffset,
        uint256 numVariables
    ) internal view returns (uint256 acc) {
        acc = KoalaBearExt8.ONE;
        uint256 current = point;
        unchecked {
            for (uint256 i = numVariables; i > 0; --i) {
                uint256 q = fullPoint[pointOffset + i - 1];
                acc = KoalaBearExt8Precompile.mul(acc, _eqTerm(current, q));
                current = KoalaBearExt8Precompile.square(current);
            }
        }
    }

    function _eqPolyEvalExpandedPointAt22At0(uint256 point, uint256[] memory fullPoint)
        internal
        view
        returns (uint256 acc)
    {
        acc = KoalaBearExt8.ONE;
        uint256 current = point;
        uint256 pointBase;
        assembly ("memory-safe") {
            pointBase := add(fullPoint, 0x20)
        }

        unchecked {
            for (uint256 i = 22; i > 0; --i) {
                uint256 q;
                assembly ("memory-safe") {
                    q := mload(add(pointBase, shl(5, sub(i, 1))))
                }
                acc = KoalaBearExt8Precompile.mul(acc, _eqTerm(current, q));
                current = KoalaBearExt8Precompile.square(current);
            }
        }
    }

    function _eqPolyEvalExpandedPointAt18At4(uint256 point, uint256[] memory fullPoint)
        internal
        view
        returns (uint256 acc)
    {
        acc = KoalaBearExt8.ONE;
        uint256 current = point;
        uint256 pointBase;
        assembly ("memory-safe") {
            pointBase := add(add(fullPoint, 0x20), 0x80)
        }

        unchecked {
            for (uint256 i = 18; i > 0; --i) {
                uint256 q;
                assembly ("memory-safe") {
                    q := mload(add(pointBase, shl(5, sub(i, 1))))
                }
                acc = KoalaBearExt8Precompile.mul(acc, _eqTerm(current, q));
                current = KoalaBearExt8Precompile.square(current);
            }
        }
    }

    function _eqPolyEvalExpandedPointAt14At8(uint256 point, uint256[] memory fullPoint)
        internal
        view
        returns (uint256 acc)
    {
        acc = KoalaBearExt8.ONE;
        uint256 current = point;
        uint256 pointBase;
        assembly ("memory-safe") {
            pointBase := add(add(fullPoint, 0x20), 0x100)
        }

        unchecked {
            for (uint256 i = 14; i > 0; --i) {
                uint256 q;
                assembly ("memory-safe") {
                    q := mload(add(pointBase, shl(5, sub(i, 1))))
                }
                acc = KoalaBearExt8Precompile.mul(acc, _eqTerm(current, q));
                current = KoalaBearExt8Precompile.square(current);
            }
        }
    }

    function _eqPolyEvalExpandedPointAt10At12(uint256 point, uint256[] memory fullPoint)
        internal
        view
        returns (uint256 acc)
    {
        acc = KoalaBearExt8.ONE;
        uint256 current = point;
        uint256 pointBase;
        assembly ("memory-safe") {
            pointBase := add(add(fullPoint, 0x20), 0x180)
        }

        unchecked {
            for (uint256 i = 10; i > 0; --i) {
                uint256 q;
                assembly ("memory-safe") {
                    q := mload(add(pointBase, shl(5, sub(i, 1))))
                }
                acc = KoalaBearExt8Precompile.mul(acc, _eqTerm(current, q));
                current = KoalaBearExt8Precompile.square(current);
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

        acc = KoalaBearExt8.ONE;
        unchecked {
            for (uint256 i = 0; i < numVariables; ++i) {
                uint256 p = point[i];
                uint256 q = fullPoint[pointOffset + i];
                acc = KoalaBearExt8Precompile.mul(acc, _eqTerm(p, q));
            }
        }
    }

    function _eqPolyEvalAtBlob(
        bytes calldata blob,
        uint256 blobOffset,
        uint256[] memory fullPoint,
        uint256 pointOffset,
        uint256 numVariables
    ) internal view returns (uint256 acc) {
        acc = KoalaBearExt8.ONE;
        unchecked {
            for (uint256 i = 0; i < numVariables; ++i) {
                uint256 p;
                assembly ("memory-safe") {
                    p := calldataload(add(add(blob.offset, blobOffset), shl(5, i)))
                }
                uint256 q = fullPoint[pointOffset + i];
                acc = KoalaBearExt8Precompile.mul(acc, _eqTerm(p, q));
            }
        }
    }

    function _eqPolyEvalAtBlob22(
        bytes calldata blob,
        uint256 blobOffset,
        uint256[] memory fullPoint
    ) internal view returns (uint256 acc) {
        acc = KoalaBearExt8.ONE;
        unchecked {
            for (uint256 i = 0; i < 22; ++i) {
                uint256 p;
                assembly ("memory-safe") {
                    p := calldataload(add(add(blob.offset, blobOffset), shl(5, i)))
                }
                acc = KoalaBearExt8Precompile.mul(acc, _eqTerm(p, fullPoint[i]));
            }
        }
    }

    function _eqPolyEvalAtMemory(
        uint256[] memory point,
        uint256[] memory fullPoint,
        uint256 pointOffset,
        uint256 numVariables
    ) internal view returns (uint256 acc) {
        if (point.length != numVariables) {
            revert StatementPointArityMismatch(0, numVariables, point.length);
        }

        acc = KoalaBearExt8.ONE;
        unchecked {
            for (uint256 i = 0; i < numVariables; ++i) {
                uint256 p = point[i];
                uint256 q = fullPoint[pointOffset + i];
                acc = KoalaBearExt8Precompile.mul(acc, _eqTerm(p, q));
            }
        }
    }

    function _evaluateFinalValue(
        uint256[] calldata finalPoly,
        uint256[] memory finalSumcheckRandomness
    ) internal view returns (uint256) {
        if (finalSumcheckRandomness.length == 0) {
            return finalPoly[0];
        }

        uint256[] memory evals = new uint256[](finalPoly.length);
        unchecked {
            for (uint256 i = 0; i < finalPoly.length; ++i) {
                uint256 value = finalPoly[i];
                WhirVerifierUtils8.validatePackedExt8(value);
                evals[i] = value;
            }
        }
        return WhirVerifierUtils8.evaluateHypercubeMemory(evals, finalSumcheckRandomness);
    }

    function _evaluateFinalValueBlob(
        bytes calldata blob,
        uint256 offset,
        uint256 polyLen,
        uint256[] memory allRandomness,
        uint256 pointOffset,
        uint256 pointLen
    ) internal view returns (uint256) {
        if (polyLen == 64 && pointLen == 6) {
            return _evaluateFinalValueBlob64Dim6Precompile(blob, offset, allRandomness, pointOffset);
        }
        return WhirVerifierUtils8.evaluateExtensionRowAsExt8Blob(
            blob, offset, polyLen, allRandomness, pointOffset, pointLen
        );
    }

    function _evaluateFinalValueBlob64Dim6Precompile(
        bytes calldata blob,
        uint256 offset,
        uint256[] memory fullPoint,
        uint256 pointOffset
    ) private view returns (uint256) {
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

                uint256 a0 = _foldOncePrecompile(v0, v32, p0);
                uint256 a1 = _foldOncePrecompile(v16, v48, p0);
                uint256 b0 = _foldOncePrecompile(a0, a1, p1);
                uint256 a2 = _foldOncePrecompile(v8, v40, p0);
                uint256 a3 = _foldOncePrecompile(v24, v56, p0);
                uint256 b1 = _foldOncePrecompile(a2, a3, p1);
                uint256 evalValue = _foldOncePrecompile(b0, b1, p2);
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
                uint256 evalValue = _foldOncePrecompile(left, right, p3);
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
                uint256 evalValue = _foldOncePrecompile(left, right, p4);
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
        return _foldOncePrecompile(eval0, eval1, p5);
    }

    function _foldOncePrecompile(uint256 a0, uint256 a1, uint256 r) private view returns (uint256) {
        return KoalaBearExt8Precompile.add(
            a0, KoalaBearExt8Precompile.mul(KoalaBearExt8Precompile.sub(a1, a0), r)
        );
    }

    function _selectPolyEvalFixed(
        uint256 var_,
        uint256[] memory fullPoint,
        uint256 pointOffset,
        uint256 numVariables
    ) internal view returns (uint256 acc) {
        acc = KoalaBearExt8.ONE;
        uint256 current = var_;

        unchecked {
            for (uint256 i = numVariables; i > 0; --i) {
                uint256 scalar = current == 0 ? KoalaBear.MODULUS - 1 : current - 1;
                uint256 term = KoalaBearExt8Precompile.add(
                    KoalaBearExt8Precompile.ONE,
                    KoalaBearExt8Precompile.mulBase(fullPoint[pointOffset + i - 1], scalar)
                );
                acc = KoalaBearExt8Precompile.mul(acc, term);
                current = KoalaBear.mul(current, current);
            }
        }
    }

    function _hornerStep(uint256 total, uint256 challenge, uint256 weight)
        internal
        view
        returns (uint256)
    {
        return KoalaBearExt8Precompile.add(KoalaBearExt8Precompile.mul(total, challenge), weight);
    }

    function _hornerStepWithChallengeCoeffs(
        uint256 total,
        uint256 weight,
        uint256 ch0,
        uint256 ch1,
        uint256 ch2,
        uint256 ch3,
        uint256 ch4,
        uint256 ch5,
        uint256 ch6,
        uint256 ch7
    ) internal view returns (uint256 out) {
        assembly ("memory-safe") {
            let M := 0x7f000001
            let m := 0xffffffff

            let a0 := shr(224, total)
            let a1 := and(shr(192, total), m)
            let a2 := and(shr(160, total), m)
            let a3 := and(shr(128, total), m)
            let a4 := and(shr(96, total), m)
            let a5 := and(shr(64, total), m)
            let a6 := and(shr(32, total), m)
            let a7 := and(total, m)

            let w0 := shr(224, weight)
            let w1 := and(shr(192, weight), m)
            let w2 := and(shr(160, weight), m)
            let w3 := and(shr(128, weight), m)
            let w4 := and(shr(96, weight), m)
            let w5 := and(shr(64, weight), m)
            let w6 := and(shr(32, weight), m)
            let w7 := and(weight, m)

            let c0 :=
                mod(
                    add(
                        add(
                            mul(a0, ch0),
                            mul(
                                3,
                                add(
                                    add(
                                        add(mul(a1, ch7), mul(a2, ch6)),
                                        add(mul(a3, ch5), mul(a4, ch4))
                                    ),
                                    add(add(mul(a5, ch3), mul(a6, ch2)), mul(a7, ch1))
                                )
                            )
                        ),
                        w0
                    ),
                    M
                )
            let c1 :=
                mod(
                    add(
                        add(
                            add(mul(a0, ch1), mul(a1, ch0)),
                            mul(
                                3,
                                add(
                                    add(
                                        add(mul(a2, ch7), mul(a3, ch6)),
                                        add(mul(a4, ch5), mul(a5, ch4))
                                    ),
                                    add(mul(a6, ch3), mul(a7, ch2))
                                )
                            )
                        ),
                        w1
                    ),
                    M
                )
            let c2 :=
                mod(
                    add(
                        add(
                            add(add(mul(a0, ch2), mul(a1, ch1)), mul(a2, ch0)),
                            mul(
                                3,
                                add(
                                    add(mul(a3, ch7), mul(a4, ch6)),
                                    add(mul(a5, ch5), add(mul(a6, ch4), mul(a7, ch3)))
                                )
                            )
                        ),
                        w2
                    ),
                    M
                )
            let c3 :=
                mod(
                    add(
                        add(
                            add(add(add(mul(a0, ch3), mul(a1, ch2)), mul(a2, ch1)), mul(a3, ch0)),
                            mul(
                                3,
                                add(
                                    add(mul(a4, ch7), mul(a5, ch6)),
                                    add(mul(a6, ch5), mul(a7, ch4))
                                )
                            )
                        ),
                        w3
                    ),
                    M
                )
            let c4 :=
                mod(
                    add(
                        add(
                            add(
                                add(
                                    add(add(mul(a0, ch4), mul(a1, ch3)), mul(a2, ch2)),
                                    mul(a3, ch1)
                                ),
                                mul(a4, ch0)
                            ),
                            mul(3, add(add(mul(a5, ch7), mul(a6, ch6)), mul(a7, ch5)))
                        ),
                        w4
                    ),
                    M
                )
            let c5 :=
                mod(
                    add(
                        add(
                            add(
                                add(
                                    add(
                                        add(add(mul(a0, ch5), mul(a1, ch4)), mul(a2, ch3)),
                                        mul(a3, ch2)
                                    ),
                                    mul(a4, ch1)
                                ),
                                mul(a5, ch0)
                            ),
                            mul(3, add(mul(a6, ch7), mul(a7, ch6)))
                        ),
                        w5
                    ),
                    M
                )
            let c6 :=
                mod(
                    add(
                        add(
                            add(
                                add(
                                    add(
                                        add(add(mul(a0, ch6), mul(a1, ch5)), mul(a2, ch4)),
                                        mul(a3, ch3)
                                    ),
                                    mul(a4, ch2)
                                ),
                                mul(a5, ch1)
                            ),
                            add(mul(a6, ch0), mul(3, mul(a7, ch7)))
                        ),
                        w6
                    ),
                    M
                )
            let c7 :=
                mod(
                    add(
                        add(
                            add(
                                add(
                                    add(
                                        add(
                                            add(add(mul(a0, ch7), mul(a1, ch6)), mul(a2, ch5)),
                                            mul(a3, ch4)
                                        ),
                                        mul(a4, ch3)
                                    ),
                                    mul(a5, ch2)
                                ),
                                mul(a6, ch1)
                            ),
                            mul(a7, ch0)
                        ),
                        w7
                    ),
                    M
                )

            out := or(
                or(or(shl(224, c0), shl(192, c1)), or(shl(160, c2), shl(128, c3))),
                or(or(shl(96, c4), shl(64, c5)), or(shl(32, c6), c7))
            )
        }
    }

    function _eqTerm(uint256 p, uint256 q) internal view returns (uint256) {
        return _eqTermFromProduct(KoalaBearExt8Precompile.mul(p, q), p, q);
    }

    function _eqTermFromProduct(uint256 product, uint256 p, uint256 q)
        private
        pure
        returns (uint256)
    {
        return KoalaBearExt8Precompile.sub(
            KoalaBearExt8Precompile.sub(
                KoalaBearExt8Precompile.add(
                    KoalaBearExt8Precompile.mulBase(product, 2), KoalaBearExt8Precompile.ONE
                ),
                p
            ),
            q
        );
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
