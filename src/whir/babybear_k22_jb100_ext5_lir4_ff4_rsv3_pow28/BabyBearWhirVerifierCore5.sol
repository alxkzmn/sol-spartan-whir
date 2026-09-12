// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { BabyBear } from "../../field/BabyBear.sol";
import { BabyBearExt5 } from "../../field/BabyBearExt5.sol";
import { BabyBearMerkleVerifier } from "../../merkle/BabyBearMerkleVerifier.sol";
import { BabyBearKeccakChallenger } from "../../transcript/BabyBearKeccakChallenger.sol";
import { WhirStructs } from "../WhirStructs.sol";
import {
    BabyBearWhirBlobCodec5
} from "./BabyBearWhirBlobCodec5_k22_jb100_ext5_lir4_ff4_rsv3_pow28.sol";
import { BabyBearWhirVerifierUtils5 } from "./BabyBearWhirVerifierUtils5.sol";

library BabyBearWhirVerifierCore5 {
    using BabyBearKeccakChallenger for BabyBearKeccakChallenger.State;

    bytes private constant POW_TABLE_ROUND0 =
        hex"0000000121fd55bc18adc27d74b9d8f10ba067a360012c3f129f02d676eee5d43e9430e84c9f48516b550a4e458eb0353af850f06db7256626a4be5f1c2242ce000000015cf5713f4cabd6a65982449154c131f40f7420766cdd6f8c6d62035f77cad3991af15b5831103de64d6de2b02d8f532b72d761134f12dc6a3d1fc5710000000162c3d2b111c33e2a285bddaf4c7347150c16682f64cec38459eb6f374fe612261e252db5694286033c9405534913074861d4717c19e993791f4f83f800000001145e952d688442f943eaf147674561673f2d718c64c212f447a2eb1f17b56c6433abffa96c51e8ef405805c6069d34706927fdb8626a25033698a89b00000001669d60902d4cc4da33f5d0d00bb4c4e41d55a51a49f2f32b37fb9e005ee99486541a603a0a92c240139aa77004b49e085fbdcbf35365f4e936c54c860000000167055c217800000010faa3e00000000167055c217800000010faa3e00000000167055c217800000010faa3e00000000167055c217800000010faa3e0";
    bytes private constant POW_TABLE_ROUND1 =
        hex"000000013e9430e85cf5713f4d9c4ca84cabd6a647f5eac259824491760fc02d54c131f40d5023090f7420765f7c75b76cdd6f8c21c1b0d76d62035f655614c30000000177cad39962c3d2b109c2bfaa11c33e2a535565e1285bddaf036abf154c73471539bc63be0c16682f4b47f41464cec384303e8dab59eb6f376b0235da000000014fe61226145e952d286551fa688442f94d76865e43eaf1470b682fec674561672bed182c3f2d718c28720dc764c212f46245b11147a2eb1f0dde9d1f0000000117b56c64669d60901bc05dd02d4cc4da5837a9a733f5d0d058e93efe0bb4c4e45c9104e51d55a51a6ab1c35f49f2f32b4547e53737fb9e0007e22fe5000000015ee9948667055c210c9ea3ba7800000019166b7b10faa3e06b615c47000000015ee9948667055c210c9ea3ba7800000019166b7b10faa3e06b615c47";
    bytes private constant POW_TABLE_ROUND2 =
        hex"000000015cf5713f4cabd6a65982449154c131f40f7420766cdd6f8c6d62035f77cad3991af15b5831103de64d6de2b02d8f532b72d761134f12dc6a3d1fc5710000000162c3d2b111c33e2a285bddaf4c7347150c16682f64cec38459eb6f374fe612261e252db5694286033c9405534913074861d4717c19e993791f4f83f800000001145e952d688442f943eaf147674561673f2d718c64c212f447a2eb1f17b56c6433abffa96c51e8ef405805c6069d34706927fdb8626a25033698a89b00000001669d60902d4cc4da33f5d0d00bb4c4e41d55a51a49f2f32b37fb9e005ee99486541a603a0a92c240139aa77004b49e085fbdcbf35365f4e936c54c860000000167055c217800000010faa3e00000000167055c217800000010faa3e00000000167055c217800000010faa3e00000000167055c217800000010faa3e0";
    bytes private constant POW_TABLE_FINAL =
        hex"000000014cabd6a654c131f46cdd6f8c77cad39931103de62d8f532b4f12dc6a62c3d2b12e3b102953a802b220a546cc09c2bfaa20d1df9b049361627482a4570000000111c33e2a4c73471564cec3844fe61226694286034913074819e99379145e952d1ae87f9a215e94a4317f9d01286551fa6fed403c739dc06f4eec542e00000001688442f96745616764c212f417b56c646c51e8ef069d3470626a2503669d609032d82754016933f11dc10e6b1bc05dd0055f2aeb2f1f99085244da4d000000012d4cc4da0bb4c4e449f2f32b5ee994860a92c24004b49e085365f4e967055c213501cd6e5376917a5d0f6e440c9ea3ba54e64439563112a72c1c334800000001780000000000000178000000000000017800000000000001780000000000000178000000000000017800000000000001780000000000000178000000";

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
                if ((e0 & 1) != 0) p0 = BabyBear.mul(p0, base);
                if ((e1 & 1) != 0) p1 = BabyBear.mul(p1, base);
                if ((e2 & 1) != 0) p2 = BabyBear.mul(p2, base);
                if ((e3 & 1) != 0) p3 = BabyBear.mul(p3, base);
                if ((e4 & 1) != 0) p4 = BabyBear.mul(p4, base);
                if ((e5 & 1) != 0) p5 = BabyBear.mul(p5, base);
                if ((e6 & 1) != 0) p6 = BabyBear.mul(p6, base);
                if ((e7 & 1) != 0) p7 = BabyBear.mul(p7, base);
                if ((e8 & 1) != 0) p8 = BabyBear.mul(p8, base);
                if ((e9 & 1) != 0) p9 = BabyBear.mul(p9, base);

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

                base = BabyBear.mul(base, base);
            }
        }
    }

    function _fillSelVarsPow(uint256[] memory selVars, uint256 base, uint256 count) private pure {
        uint256 freePtr;
        assembly ("memory-safe") {
            freePtr := mload(0x40)
        }

        // STIR indices are sampled below each folded-domain size, so the fixed bases below receive
        // exponents of at most 22, 19, 18, and 17 bits. A regenerated schedule must update both the
        // generator dispatch and its matching table; an unknown generator uses the general path.
        bytes memory table;
        if (base == 570_250_684) {
            table = POW_TABLE_ROUND0;
        } else if (base == 1_049_899_240) {
            table = POW_TABLE_ROUND1;
        } else if (base == 1_559_589_183) {
            table = POW_TABLE_ROUND2;
        } else if (base == 1_286_330_022) {
            table = POW_TABLE_FINAL;
        } else {
            unchecked {
                for (uint256 i = 0; i < count; ++i) {
                    selVars[i] = BabyBear.pow(base, selVars[i]);
                }
            }
            return;
        }

        assembly ("memory-safe") {
            let modulus := 0x78000001
            let tableStart := add(table, 0x20)
            let tableEnd := add(tableStart, mload(table))
            let values := add(selVars, 0x20)
            let valuesEnd := add(values, shl(5, count))
            for { let valuePtr := values } lt(valuePtr, valuesEnd) {
                valuePtr := add(valuePtr, 0x20)
            } {
                let exponent := mload(valuePtr)
                let result := 1
                for { let windowPtr := tableStart } lt(windowPtr, tableEnd) {
                    windowPtr := add(windowPtr, 0x40)
                } {
                    let digit := and(exponent, 0x0f)
                    let power := shr(224, mload(add(windowPtr, shl(2, digit))))
                    result := mulmod(result, power, modulus)
                    exponent := shr(4, exponent)
                }
                mstore(valuePtr, result)
            }
            mstore(0x40, freePtr)
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
    ) private pure returns (bytes32 root, uint256[] memory rowEvals) {
        uint256 count = indices.length;
        if (count == 0) {
            revert BabyBearMerkleVerifier.EmptyIndices();
        }

        uint256[] memory frontierEntries;
        assembly ("memory-safe") {
            frontierEntries := mload(0x40)
            mstore(frontierEntries, count)
            rowEvals := add(add(frontierEntries, 0x20), shl(5, count))
            mstore(rowEvals, count)
            mstore(0x40, add(add(rowEvals, 0x20), shl(5, count)))
        }

        (uint256 r00, uint256 r01, uint256 r02, uint256 r03, uint256 r04) =
            BabyBearWhirVerifierUtils5._unpackCoeffs(p0);
        (uint256 r10, uint256 r11, uint256 r12, uint256 r13, uint256 r14) =
            BabyBearWhirVerifierUtils5._unpackCoeffs(p1);
        (uint256 r20, uint256 r21, uint256 r22, uint256 r23, uint256 r24) =
            BabyBearWhirVerifierUtils5._unpackCoeffs(p2);
        (uint256 r30, uint256 r31, uint256 r32, uint256 r33, uint256 r34) =
            BabyBearWhirVerifierUtils5._unpackCoeffs(p3);
        uint256 eqWeightsPtr =
            BabyBearWhirVerifierUtils5._computeDim4EqWeightsUnpacked(p0, p1, p2, p3);

        unchecked {
            uint256 prevIdx;
            for (uint256 i = 0; i < count; ++i) {
                uint256 idx = indices[i];
                if (i != 0 && prevIdx >= idx) {
                    revert BabyBearMerkleVerifier.IndicesNotStrictlyIncreasing(prevIdx, idx);
                }
                prevIdx = idx;

                uint256 rowOffset = valuesOffset + i * 320;
                (bytes32 hash, uint256 evalValue) = BabyBearWhirVerifierUtils5._hashAndEvaluateExtension5RowDim4BlobUnpacked(
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
                rowEvals[i] = evalValue;

                assembly ("memory-safe") {
                    mstore(add(add(frontierEntries, 0x20), shl(5, i)), or(hash, idx))
                }
            }
        }

        root = BabyBearMerkleVerifier.computeRootFromPackedFrontier20Blob(
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
            revert BabyBearMerkleVerifier.EmptyIndices();
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
                    revert BabyBearMerkleVerifier.IndicesNotStrictlyIncreasing(prevIdx, idx);
                }
                prevIdx = idx;

                (bytes32 hash, uint256 evalValue) = BabyBearWhirVerifierUtils5._hashAndEvaluateBaseRowDim4PackedPoints(
                    flatValues, i * 16, p0, p1, p2, p3
                );
                rowEvals[i] = evalValue;

                assembly ("memory-safe") {
                    mstore(add(add(frontierEntries, 0x20), shl(5, i)), or(hash, idx))
                }
            }
        }

        root = BabyBearMerkleVerifier.computeRootFromPackedFrontier20(
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
            revert BabyBearMerkleVerifier.EmptyIndices();
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
                    revert BabyBearMerkleVerifier.IndicesNotStrictlyIncreasing(prevIdx, idx);
                }
                prevIdx = idx;

                uint256 rowStart = i * 16;
                bytes32 hash =
                    BabyBearMerkleVerifier.hashLeafExtension5Slice20(flatValues, rowStart, 16);
                rowEvals[i] = BabyBearWhirVerifierUtils5.evaluateExtensionRowAsExt5(
                    flatValues, rowStart, 16, point
                );

                assembly ("memory-safe") {
                    mstore(add(add(frontierEntries, 0x20), shl(5, i)), or(hash, idx))
                }
            }
        }

        root = BabyBearMerkleVerifier.computeRootFromPackedFrontier20(
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
        (computedRoot, rowEvals) = _computeExtension5RootAndEvalsBlob16(
            indices, blob, valuesOffset, depth, decommOffset, decommLen, p0, p1, p2, p3
        );

        if (computedRoot != expectedRoot) {
            revert MerkleRootMismatch(expectedRoot, computedRoot);
        }

        unchecked {
            if (finalPolyLength == 64 && numQueries == 14) {
                uint256 packedFinalPtr =
                    BabyBearWhirVerifierUtils5._prepareHornerRadix64(blob, finalPolyOffset);
                _fillSelVarsPow(indices, foldedDomainGen, numQueries);
                uint256 point0;
                uint256 point1;
                uint256 point2;
                uint256 point3;
                uint256 point4;
                uint256 point5;
                uint256 point6;
                uint256 point7;
                uint256 point8;
                uint256 point9;
                assembly ("memory-safe") {
                    let indicesBase := add(indices, 0x20)
                    point0 := mload(indicesBase)
                    point1 := mload(add(indicesBase, 0x20))
                    point2 := mload(add(indicesBase, 0x40))
                    point3 := mload(add(indicesBase, 0x60))
                    point4 := mload(add(indicesBase, 0x80))
                    point5 := mload(add(indicesBase, 0xa0))
                    point6 := mload(add(indicesBase, 0xc0))
                    point7 := mload(add(indicesBase, 0xe0))
                    point8 := mload(add(indicesBase, 0x100))
                    point9 := mload(add(indicesBase, 0x120))
                }

                uint256 rowEvalsBase;
                assembly ("memory-safe") {
                    rowEvalsBase := add(rowEvals, 0x20)
                }
                uint256 mismatchPlusOne = BabyBearWhirVerifierUtils5._checkHornerRadix64(
                    packedFinalPtr, point0, point1, point2, point3, point4, rowEvalsBase, 0
                );
                if (mismatchPlusOne != 0) {
                    revert StirConstraintFailed(mismatchPlusOne - 1);
                }
                mismatchPlusOne = BabyBearWhirVerifierUtils5._checkHornerRadix64(
                    packedFinalPtr, point5, point6, point7, point8, point9, rowEvalsBase, 5
                );
                if (mismatchPlusOne != 0) {
                    revert StirConstraintFailed(mismatchPlusOne + 4);
                }

                for (uint256 i = 10; i < 14; ++i) {
                    uint256 point = indices[i];
                    if (
                        BabyBearWhirVerifierUtils5._hornerRadix64(packedFinalPtr, point)
                            != rowEvals[i]
                    ) {
                        revert StirConstraintFailed(i);
                    }
                }
                return;
            }

            for (uint256 i = 0; i < numQueries; ++i) {
                uint256 point = BabyBear.pow(foldedDomainGen, indices[i]);
                if (
                    BabyBearWhirVerifierUtils5.hornerBaseBlob(
                            blob, finalPolyOffset, finalPolyLength, point
                        ) != rowEvals[i]
                ) {
                    revert StirConstraintFailed(i);
                }
            }
        }
    }

    function _verifyStirAndCombineConstraintBlob16NativeFused(
        BabyBearKeccakChallenger.State memory challenger,
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
        (uint256 r00, uint256 r01, uint256 r02, uint256 r03, uint256 r04) =
            BabyBearWhirVerifierUtils5._unpackCoeffs(p0);
        (uint256 r10, uint256 r11, uint256 r12, uint256 r13, uint256 r14) =
            BabyBearWhirVerifierUtils5._unpackCoeffs(p1);
        (uint256 r20, uint256 r21, uint256 r22, uint256 r23, uint256 r24) =
            BabyBearWhirVerifierUtils5._unpackCoeffs(p2);
        (uint256 r30, uint256 r31, uint256 r32, uint256 r33, uint256 r34) =
            BabyBearWhirVerifierUtils5._unpackCoeffs(p3);
        challenge = BabyBearWhirVerifierUtils5.sampleExt5(challenger);
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
                uint256 eqWeightsPtr = BabyBearWhirVerifierUtils5._prepareBaseRadix80(
                    BabyBearWhirVerifierUtils5._computeDim4EqWeights(p0, p1, p2, p3)
                );
                rowOffset = valuesOffset + numQueries * 64;
                uint256 nextHigher;
                for (uint256 i = numQueries; i > 0; --i) {
                    uint256 pos = i - 1;
                    uint256 idx = indices[pos];
                    if (i != numQueries && idx >= nextHigher) {
                        revert BabyBearMerkleVerifier.IndicesNotStrictlyIncreasing(idx, nextHigher);
                    }
                    nextHigher = idx;
                    rowOffset -= 64;

                    (bytes32 hash, uint256 evalValue) = BabyBearWhirVerifierUtils5._hashAndEvaluateBaseRowDim4BlobUnpacked(
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
                uint256 eqWeightsPtr =
                    BabyBearWhirVerifierUtils5._computeDim4EqWeightsUnpacked(p0, p1, p2, p3);
                uint256 challengePtr = BabyBearWhirVerifierUtils5._prepareRowChallenge(challenge);
                rowOffset = valuesOffset + numQueries * 320;
                uint256 nextHigher;
                for (uint256 i = numQueries; i > 0; --i) {
                    uint256 pos = i - 1;
                    uint256 idx = indices[pos];
                    if (i != numQueries && idx >= nextHigher) {
                        revert BabyBearMerkleVerifier.IndicesNotStrictlyIncreasing(idx, nextHigher);
                    }
                    nextHigher = idx;
                    rowOffset -= 320;

                    bytes32 hash;
                    (hash, claimedContribution) = BabyBearWhirVerifierUtils5._hashAndFoldExtensionRow(
                        blob, rowOffset, eqWeightsPtr, claimedContribution, challengePtr
                    );

                    assembly ("memory-safe") {
                        frontierPtr := sub(frontierPtr, 0x20)
                        mstore(frontierPtr, or(hash, idx))
                    }
                }
            }
        }

        bytes32 computedRoot = BabyBearMerkleVerifier.computeRootFromPackedFrontier20Blob(
            frontierEntries, numQueries, depth, blob, decommOffset, decommLen
        );
        if (computedRoot != expectedRoot) {
            revert MerkleRootMismatch(expectedRoot, computedRoot);
        }

        _fillSelVarsPow(selVars, foldedDomainGen, numQueries);
        claimedContribution = _hornerStep(claimedContribution, challenge, oodAnswer);
    }

    function _verifyRoundStirAndCombineConstraintBlob(
        BabyBearKeccakChallenger.State memory challenger,
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
        pure
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
            BabyBearWhirVerifierUtils5.sampleStirQueries(challenger, domainSize, 4, numQueries);
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
        BabyBearKeccakChallenger.State memory challenger,
        bytes32 expectedRoot,
        bytes calldata blob,
        uint256 valuesOffset,
        uint256 decommLen,
        uint256 powWitnessOffset,
        uint256[] memory allRandomness,
        uint256 randomnessOffset,
        uint256 finalPolyOffset
    ) internal pure returns (uint256 nextOffset) {
        _checkWitnessBaseLeBlob(challenger, 24, blob, powWitnessOffset);

        uint256[] memory indices =
            BabyBearWhirVerifierUtils5.sampleStirQueries(challenger, 2_097_152, 4, 14);
        if (indices.length != 14) {
            revert QueryBatchCountMismatch(14, indices.length);
        }

        uint256 decommOffset = valuesOffset + 14 * 16 * 20;
        nextOffset = decommOffset + decommLen * 20;

        _verifyFinalStirChallengesBlob16(
            expectedRoot,
            14,
            17,
            1_286_330_022,
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
        BabyBearKeccakChallenger.State memory challenger,
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
                uint256 point = BabyBearWhirVerifierUtils5.sampleExt5(challenger);
                BabyBearWhirVerifierUtils5.expandFromUnivariateExtInto(
                    parsed.oodStatement.flatPoints, i * numVariables, point, numVariables
                );

                uint256 evalValue = oodAnswers[i];
                BabyBearWhirVerifierUtils5.observeValidatedExt5(challenger, evalValue);
                parsed.oodStatement.evaluations[i] = evalValue;
            }
        }
    }

    function _parseFixedCommitment22x1Blob(
        BabyBearKeccakChallenger.State memory challenger,
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
        BabyBearKeccakChallenger.State memory challenger,
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
        BabyBearKeccakChallenger.State memory challenger,
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
        BabyBearKeccakChallenger.State memory challenger,
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
        BabyBearKeccakChallenger.State memory challenger,
        bytes calldata blob,
        uint256 offset
    )
        private
        pure
        returns (bytes32 root, uint256 oodPoint, uint256 oodEvaluation, uint256 nextOffset)
    {
        (root, offset) = BabyBearWhirBlobCodec5.readDigest20(blob, offset);
        challenger.observeHashU64Digest(root);
        oodPoint = BabyBearWhirVerifierUtils5.sampleExt5(challenger);
        oodEvaluation = challenger.observeReadValidatedPackedExt5Le(blob, offset);
        nextOffset = offset + 20;
    }

    function _checkWitnessBaseLeBlob(
        BabyBearKeccakChallenger.State memory challenger,
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
        BabyBearKeccakChallenger.State memory challenger,
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

                uint256 r = BabyBearWhirVerifierUtils5.sampleExt5(challenger);
                foldingRandomness[i] = r;
                allRandomness[updatedCursor] = r;
                updatedCursor += 1;
                updatedClaimedEval = BabyBearExt5.extrapolate_012(
                    c0, BabyBearExt5.sub(updatedClaimedEval, c0), c2, r
                );
            }
        }
    }

    function _verifySumcheckBlob(
        bytes calldata blob,
        uint256 offset,
        BabyBearKeccakChallenger.State memory challenger,
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

                uint256 r = BabyBearWhirVerifierUtils5.sampleExt5(challenger);
                allRandomness[updatedCursor] = r;
                updatedCursor += 1;
                updatedClaimedEval =
                    BabyBearExt5.extrapolate_012_from_sumcheck(c0, updatedClaimedEval, c2, r);
            }
        }

        if (powBits > 0) {
            nextOffset = offset + expectedRounds * 40 + expectedRounds * 4;
        }
    }

    function _verifySumcheckBlob6NoPow(
        bytes calldata blob,
        uint256 offset,
        BabyBearKeccakChallenger.State memory challenger,
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
        uint256 r = BabyBearWhirVerifierUtils5.sampleExt5(challenger);
        allRandomness[updatedCursor] = r;
        updatedCursor += 1;
        updatedClaimedEval =
            BabyBearExt5.extrapolate_012_from_sumcheck(c0, updatedClaimedEval, c2, r);

        (c0, c2) = challenger.observeReadValidatedPackedExt5LePair(blob, nextOffset);
        nextOffset += 40;
        r = BabyBearWhirVerifierUtils5.sampleExt5(challenger);
        allRandomness[updatedCursor] = r;
        updatedCursor += 1;
        updatedClaimedEval =
            BabyBearExt5.extrapolate_012_from_sumcheck(c0, updatedClaimedEval, c2, r);

        (c0, c2) = challenger.observeReadValidatedPackedExt5LePair(blob, nextOffset);
        nextOffset += 40;
        r = BabyBearWhirVerifierUtils5.sampleExt5(challenger);
        allRandomness[updatedCursor] = r;
        updatedCursor += 1;
        updatedClaimedEval =
            BabyBearExt5.extrapolate_012_from_sumcheck(c0, updatedClaimedEval, c2, r);

        (c0, c2) = challenger.observeReadValidatedPackedExt5LePair(blob, nextOffset);
        nextOffset += 40;
        r = BabyBearWhirVerifierUtils5.sampleExt5(challenger);
        allRandomness[updatedCursor] = r;
        updatedCursor += 1;
        updatedClaimedEval =
            BabyBearExt5.extrapolate_012_from_sumcheck(c0, updatedClaimedEval, c2, r);

        (c0, c2) = challenger.observeReadValidatedPackedExt5LePair(blob, nextOffset);
        nextOffset += 40;
        r = BabyBearWhirVerifierUtils5.sampleExt5(challenger);
        allRandomness[updatedCursor] = r;
        updatedCursor += 1;
        updatedClaimedEval =
            BabyBearExt5.extrapolate_012_from_sumcheck(c0, updatedClaimedEval, c2, r);

        (c0, c2) = challenger.observeReadValidatedPackedExt5LePair(blob, nextOffset);
        nextOffset += 40;
        r = BabyBearWhirVerifierUtils5.sampleExt5(challenger);
        allRandomness[updatedCursor] = r;
        updatedCursor += 1;
        updatedClaimedEval =
            BabyBearExt5.extrapolate_012_from_sumcheck(c0, updatedClaimedEval, c2, r);
    }

    function _verifyStirAndCombineConstraint(
        BabyBearKeccakChallenger.State memory challenger,
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
            challenge = BabyBearWhirVerifierUtils5.sampleExt5(challenger);
            unchecked {
                for (uint256 i = oodAnswers.length; i > 0; --i) {
                    claimedContribution =
                        _hornerStep(claimedContribution, challenge, oodAnswers[i - 1]);
                }
            }
            selVars = new uint256[](0);
            return (challenge, claimedContribution, selVars);
        }

        uint256[] memory indices = BabyBearWhirVerifierUtils5.sampleStirQueries(
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

        uint256 depth = BabyBearWhirVerifierUtils5.log2Strict(domainSize >> foldingFactor);

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

            challenge = BabyBearWhirVerifierUtils5.sampleExt5(challenger);
            selVars = indices;

            unchecked {
                for (uint256 i = indices.length; i > 0; --i) {
                    uint256 idx = i - 1;
                    selVars[idx] = BabyBear.pow(foldedDomainGen, indices[idx]);
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
            ? BabyBearMerkleVerifier.computeRootFromFlatBaseRows20(
                indices, queryBatch.values, queryBatch.rowLen, depth, queryBatch.decommitments
            )
            : BabyBearMerkleVerifier.computeRootFromFlatExtension5Rows20(
                indices, queryBatch.values, queryBatch.rowLen, depth, queryBatch.decommitments
            );

        if (computedRoot != expectedRoot) {
            revert MerkleRootMismatch(expectedRoot, computedRoot);
        }

        challenge = BabyBearWhirVerifierUtils5.sampleExt5(challenger);
        selVars = indices;

        unchecked {
            for (uint256 i = indices.length; i > 0; --i) {
                uint256 idx = i - 1;
                selVars[idx] = BabyBear.pow(foldedDomainGen, indices[idx]);

                uint256 rowStart = idx * queryBatch.rowLen;
                uint256 evalValue = expectedKind == 0
                    ? BabyBearWhirVerifierUtils5.evaluateBaseRowAsExt5(
                        queryBatch.values, rowStart, queryBatch.rowLen, foldingRandomness
                    )
                    : BabyBearWhirVerifierUtils5.evaluateExtensionRowAsExt5(
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
        BabyBearKeccakChallenger.State memory challenger,
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

        uint256[] memory indices = BabyBearWhirVerifierUtils5.sampleStirQueries(
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

        uint256 depth = BabyBearWhirVerifierUtils5.log2Strict(domainSize >> foldingFactor);

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

                if (BabyBearWhirVerifierUtils5.hornerBase(finalPoly, point0) != rowEvals[0]) {
                    revert StirConstraintFailed(0);
                }
                if (BabyBearWhirVerifierUtils5.hornerBase(finalPoly, point1) != rowEvals[1]) {
                    revert StirConstraintFailed(1);
                }
                if (BabyBearWhirVerifierUtils5.hornerBase(finalPoly, point2) != rowEvals[2]) {
                    revert StirConstraintFailed(2);
                }
                if (BabyBearWhirVerifierUtils5.hornerBase(finalPoly, point3) != rowEvals[3]) {
                    revert StirConstraintFailed(3);
                }
                if (BabyBearWhirVerifierUtils5.hornerBase(finalPoly, point4) != rowEvals[4]) {
                    revert StirConstraintFailed(4);
                }
                if (BabyBearWhirVerifierUtils5.hornerBase(finalPoly, point5) != rowEvals[5]) {
                    revert StirConstraintFailed(5);
                }
                if (BabyBearWhirVerifierUtils5.hornerBase(finalPoly, point6) != rowEvals[6]) {
                    revert StirConstraintFailed(6);
                }
                if (BabyBearWhirVerifierUtils5.hornerBase(finalPoly, point7) != rowEvals[7]) {
                    revert StirConstraintFailed(7);
                }
                if (BabyBearWhirVerifierUtils5.hornerBase(finalPoly, point8) != rowEvals[8]) {
                    revert StirConstraintFailed(8);
                }
                if (BabyBearWhirVerifierUtils5.hornerBase(finalPoly, point9) != rowEvals[9]) {
                    revert StirConstraintFailed(9);
                }
                return;
            }

            unchecked {
                for (uint256 i = 0; i < indices.length; ++i) {
                    uint256 point = BabyBear.pow(foldedDomainGen, indices[i]);
                    if (BabyBearWhirVerifierUtils5.hornerBase(finalPoly, point) != rowEvals[i]) {
                        revert StirConstraintFailed(i);
                    }
                }
            }
            return;
        }

        bytes32 computedRoot = expectedKind == 0
            ? BabyBearMerkleVerifier.computeRootFromFlatBaseRows20(
                indices, queryBatch.values, queryBatch.rowLen, depth, queryBatch.decommitments
            )
            : BabyBearMerkleVerifier.computeRootFromFlatExtension5Rows20(
                indices, queryBatch.values, queryBatch.rowLen, depth, queryBatch.decommitments
            );

        if (computedRoot != expectedRoot) {
            revert MerkleRootMismatch(expectedRoot, computedRoot);
        }

        unchecked {
            for (uint256 i = 0; i < indices.length; ++i) {
                uint256 point = BabyBear.pow(foldedDomainGen, indices[i]);
                uint256 rowStart = i * queryBatch.rowLen;
                uint256 expectedEval = expectedKind == 0
                    ? BabyBearWhirVerifierUtils5.evaluateBaseRowAsExt5(
                        queryBatch.values, rowStart, queryBatch.rowLen, foldingRandomness
                    )
                    : BabyBearWhirVerifierUtils5.evaluateExtensionRowAsExt5(
                        queryBatch.values, rowStart, queryBatch.rowLen, foldingRandomness
                    );
                if (BabyBearWhirVerifierUtils5.hornerBase(finalPoly, point) != expectedEval) {
                    revert StirConstraintFailed(i);
                }
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
        uint256 initialCurrent = initialOodPoint;
        uint256 round0Current = round0OodPoint;
        uint256 round1Current = round1OodPoint;
        uint256 round2Current = round2OodPoint;
        uint256 pointBase;
        uint256[10] memory state;
        uint256[4] memory cache;
        assembly ("memory-safe") {
            pointBase := add(fullPoint, 0x20)
        }

        unchecked {
            {
                uint256 q;
                uint256 statementPointValue;
                assembly ("memory-safe") {
                    q := mload(add(pointBase, 672))
                    statementPointValue := and(
                        calldataload(add(add(blob.offset, statementPointOffset), 420)),
                        not(sub(shl(96, 1), 1))
                    )
                }
                _prepareEqTermForms(q, cache);
                _initialEqAt(_stateAt(state, 0), statementPointValue, cache);
                _initialEqAt(_stateAt(state, 1), initialCurrent, cache);
                _initialEqAt(_stateAt(state, 2), round0Current, cache);
                _initialEqAt(_stateAt(state, 3), round1Current, cache);
                _initialEqAt(_stateAt(state, 4), round2Current, cache);
                initialCurrent = BabyBearExt5.square(initialCurrent);
                round0Current = BabyBearExt5.square(round0Current);
                round1Current = BabyBearExt5.square(round1Current);
                round2Current = BabyBearExt5.square(round2Current);
            }
            for (uint256 i = 21; i > 0; --i) {
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

                _prepareEqTermForms(q, cache);
                _accEqAt(_stateAt(state, 0), statementPointValue, cache);
                _accEqAt(_stateAt(state, 1), initialCurrent, cache);
                initialCurrent = BabyBearExt5.square(initialCurrent);

                if (i > 4) {
                    _accEqAt(_stateAt(state, 2), round0Current, cache);
                    round0Current = BabyBearExt5.square(round0Current);
                    if (i > 8) {
                        _accEqAt(_stateAt(state, 3), round1Current, cache);
                        round1Current = BabyBearExt5.square(round1Current);
                        if (i > 12) {
                            _accEqAt(_stateAt(state, 4), round2Current, cache);
                            round2Current = BabyBearExt5.square(round2Current);
                        }
                    }
                }
            }
        }
        statementEq = _packAt(_stateAt(state, 0));
        initialEq = _packAt(_stateAt(state, 1));
        round0Eq = _packAt(_stateAt(state, 2));
        round1Eq = _packAt(_stateAt(state, 3));
        round2Eq = _packAt(_stateAt(state, 4));
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
                    BabyBearWhirVerifierUtils5.selectPolyEval(
                        selVars[i - 1], fullPoint, pointOffset, numVariables
                    )
                );
            }
        }

        total = _hornerStep(
            total, challenge, _eqPolyEvalAt(eqFlatPoints, 0, fullPoint, pointOffset, numVariables)
        );
    }

    function _evaluateConstraintCubicRaw18WithPrecomputedEq(
        uint256 challenge,
        uint256 eqEval,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) internal pure returns (uint256 total) {
        uint256 consumer = _prepareConsumer(challenge);
        uint256 low;
        uint256 rev;
        unchecked {
            for (uint256 i = selVars.length; i > 0; --i) {
                (low, rev) = _selectAndHorner(selVars[i - 1], fullPoint, 4, 18, low, rev, consumer);
            }
        }
        total = _hornerStep(_packSelectCubicForms(low, rev), challenge, eqEval);
    }

    function _evaluateConstraintCubicRaw14WithPrecomputedEq(
        uint256 challenge,
        uint256 eqEval,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) internal pure returns (uint256 total) {
        uint256 consumer = _prepareConsumer(challenge);
        uint256 low;
        uint256 rev;
        unchecked {
            for (uint256 i = selVars.length; i > 0; --i) {
                (low, rev) = _selectAndHorner(selVars[i - 1], fullPoint, 8, 14, low, rev, consumer);
            }
        }
        total = _hornerStep(_packSelectCubicForms(low, rev), challenge, eqEval);
    }

    function _evaluateConstraintCubicRaw10WithPrecomputedEq(
        uint256 challenge,
        uint256 eqEval,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) internal pure returns (uint256 total) {
        uint256 consumer = _prepareConsumer(challenge);
        uint256 low;
        uint256 rev;
        unchecked {
            for (uint256 i = selVars.length; i > 0; --i) {
                (low, rev) = _selectAndHorner(selVars[i - 1], fullPoint, 12, 10, low, rev, consumer);
            }
        }
        total = _hornerStep(_packSelectCubicForms(low, rev), challenge, eqEval);
    }

    function _eqPolyEvalAt(
        uint256[] memory point,
        uint256 pointStart,
        uint256[] memory fullPoint,
        uint256 pointOffset,
        uint256 numVariables
    ) internal pure returns (uint256 acc) {
        acc = BabyBearExt5.ONE;
        unchecked {
            for (uint256 i = 0; i < numVariables; ++i) {
                acc = BabyBearExt5.mul(
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

        acc = BabyBearExt5.ONE;
        unchecked {
            for (uint256 i = 0; i < numVariables; ++i) {
                acc = BabyBearExt5.mul(acc, _eqTerm(point[i], fullPoint[pointOffset + i]));
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
                BabyBearWhirVerifierUtils5.validatePackedExt5(value);
                evals[i] = value;
            }
        }
        return BabyBearWhirVerifierUtils5.evaluateHypercubeMemory(evals, finalSumcheckRandomness);
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
            return BabyBearWhirVerifierUtils5.evaluateFinalValueBlob64Dim6(
                blob, offset, allRandomness, pointOffset
            );
        }
        return BabyBearWhirVerifierUtils5.evaluateExtensionRowAsExt5Blob(
            blob, offset, polyLen, allRandomness, pointOffset, pointLen
        );
    }

    function _selectCubicPolyEvalFixed(
        uint256 current,
        uint256[] memory cache,
        uint256 pointOffset,
        uint256 n
    ) internal pure returns (uint256) {
        if (n == 0) return uint256(1) << 224;
        unchecked {
            // `_prepareSelectCubicPairs` stores pairs (4,5), (6,7), ... at 160-byte strides.
            // Start from the pair ending at `pointOffset + n - 1` and walk backwards.
            uint256 pairIndex = (pointOffset + n - 6) / 2;
            uint256 ptr;
            assembly ("memory-safe") { ptr := add(add(cache, 32), mul(pairIndex, 160)) }
            (uint256 low, uint256 rev, uint256 next) = _evaluateSelectCubicPair(ptr, current);
            for (uint256 i = n / 2 - 1; i > 0; --i) {
                ptr -= 160;
                uint256 bLow;
                uint256 bRev;
                (bLow, bRev, next) = _evaluateSelectCubicPair(ptr, next);
                (low, rev) = _mulSelectCubicForms(low, rev, bLow, bRev);
            }
            return _packSelectCubicForms(low, rev);
        }
    }

    function _selectCubicPolyEvalFixedPair(
        uint256 a,
        uint256 b,
        uint256[] memory cache,
        uint256 offset,
        uint256 n
    ) internal pure returns (uint256, uint256) {
        return (
            _selectCubicPolyEvalFixed(a, cache, offset, n),
            _selectCubicPolyEvalFixed(b, cache, offset, n)
        );
    }

    function _hornerStep(uint256 total, uint256 challenge, uint256 weight)
        internal
        pure
        returns (uint256)
    {
        return BabyBearExt5.add(BabyBearExt5.mul(total, challenge), weight);
    }

    function _eqTerm(uint256 p, uint256 q) internal pure returns (uint256) {
        uint256 out;
        assembly ("memory-safe") {
            let M := 0x78000001
            let mask := 0xffffffff

            let p0 := shr(224, p)
            let p1 := and(shr(192, p), mask)
            let p2 := and(shr(160, p), mask)
            let p3 := and(shr(128, p), mask)
            let p4 := and(shr(96, p), mask)

            let q0 := shr(224, q)
            let q1 := and(shr(192, q), mask)
            let q2 := and(shr(160, q), mask)
            let q3 := and(shr(128, q), mask)
            let q4 := and(shr(96, q), mask)

            let c0 := mul(p0, q0)
            let c1 := add(mul(p0, q1), mul(p1, q0))
            let c2 := add(add(mul(p0, q2), mul(p1, q1)), mul(p2, q0))
            let c3 := add(add(add(mul(p0, q3), mul(p1, q2)), mul(p2, q1)), mul(p3, q0))
            let c4 :=
                add(add(add(add(mul(p0, q4), mul(p1, q3)), mul(p2, q2)), mul(p3, q1)), mul(p4, q0))
            let c5 := add(add(add(mul(p1, q4), mul(p2, q3)), mul(p3, q2)), mul(p4, q1))
            let c6 := add(add(mul(p2, q4), mul(p3, q3)), mul(p4, q2))
            let c7 := add(mul(p3, q4), mul(p4, q3))
            let c8 := mul(p4, q4)

            let m0 := add(c0, shl(1, c5))
            let m1 := add(c1, shl(1, c6))
            let m2 := add(c2, shl(1, c7))
            let m3 := add(c3, shl(1, c8))
            let m4 := c4

            let b := shl(2, M)
            let o0 := mod(add(add(add(1, shl(1, m0)), b), sub(0, add(p0, q0))), M)
            let o1 := mod(add(add(shl(1, m1), b), sub(0, add(p1, q1))), M)
            let o2 := mod(add(add(shl(1, m2), b), sub(0, add(p2, q2))), M)
            let o3 := mod(add(add(shl(1, m3), b), sub(0, add(p3, q3))), M)
            let o4 := mod(add(add(shl(1, m4), b), sub(0, add(p4, q4))), M)

            out := or(
                or(or(shl(224, o0), shl(192, o1)), or(shl(160, o2), shl(128, o3))),
                shl(96, o4)
            )
        }
        return out;
    }

    function _prepareSelectCubicPairs(uint256[] memory point)
        internal
        pure
        returns (uint256[] memory cache)
    {
        cache = new uint256[](45);
        for (uint256 i; i < 9; ++i) {
            uint256 r = point[2 * i + 5];
            uint256 s = point[2 * i + 4];
            uint256 d = BabyBearExt5.mul(r, s);
            uint256 b = BabyBearExt5.sub(r, d);
            uint256 cc = BabyBearExt5.sub(s, d);
            uint256 a =
                BabyBearExt5.add(BabyBearExt5.sub(BabyBearExt5.sub(uint256(1) << 224, r), s), d);
            uint256 ptr;
            assembly ("memory-safe") { ptr := add(add(cache, 32), mul(i, 160)) }
            _storeLow(ptr, a);
            _storeLow(ptr + 32, b);
            _storeLow(ptr + 64, cc);
            _storeLow(ptr + 96, d);
            assembly ("memory-safe") {
                mstore(
                    add(ptr, 128),
                    or(
                        or(and(shr(96, a), 0xffffffff), shl(64, and(shr(96, b), 0xffffffff))),
                        or(
                            shl(128, and(shr(96, cc), 0xffffffff)),
                            shl(192, and(shr(96, d), 0xffffffff))
                        )
                    )
                )
            }
        }
    }

    function _mulSelectCubicForms(uint256 aLow, uint256 aRev, uint256 bLow, uint256 bRev)
        private
        pure
        returns (uint256 lowOut, uint256 revOut)
    {
        assembly ("memory-safe") {
            let M := 0x78000001
            let c4 :=
                add(
                    shr(192, mul(aLow, or(shr(64, bLow), shl(192, and(bRev, 0xffffffff))))),
                    mul(and(aRev, 0xffffffff), and(bLow, 0xffffffff))
                )
            let low := mul(aLow, bLow)
            let high := mul(aRev, bRev)
            let c0 := and(low, 0xffffffffffffffff)
            let c1 := and(shr(64, low), 0xffffffffffffffff)
            let c2 := and(shr(128, low), 0xffffffffffffffff)
            let c3 := shr(192, low)
            let c5 := shr(192, high)
            let c6 := and(shr(128, high), 0xffffffffffffffff)
            let c7 := and(shr(64, high), 0xffffffffffffffff)
            let c8 := and(high, 0xffffffffffffffff)
            let o0 := mod(add(c0, shl(1, c5)), M)
            let o1 := mod(add(c1, shl(1, c6)), M)
            let o2 := mod(add(c2, shl(1, c7)), M)
            let o3 := mod(add(c3, shl(1, c8)), M)
            let o4 := mod(c4, M)
            lowOut := or(or(o0, shl(64, o1)), or(shl(128, o2), shl(192, o3)))
            revOut := or(or(o4, shl(64, o3)), or(shl(128, o2), shl(192, o1)))
        }
    }

    function _packSelectCubicForms(uint256 low, uint256 rev) private pure returns (uint256 out) {
        assembly ("memory-safe") {
            out := or(
                or(
                    or(shl(224, and(low, 0xffffffff)), shl(192, and(shr(64, low), 0xffffffff))),
                    or(shl(160, and(shr(128, low), 0xffffffff)), shl(128, shr(192, low)))
                ),
                shl(96, and(rev, 0xffffffff))
            )
        }
    }

    function _evaluateSelectCubicPair(uint256 ptr, uint256 x)
        private
        pure
        returns (uint256 lowOut, uint256 revOut, uint256 next)
    {
        assembly ("memory-safe") {
            let M := 0x78000001
            let x2 := mulmod(x, x, M)
            let x3 := mulmod(x2, x, M)
            next := mulmod(x2, x2, M)
            let low :=
                add(
                    add(mload(ptr), mul(mload(add(ptr, 32)), x)),
                    add(mul(mload(add(ptr, 64)), x2), mul(mload(add(ptr, 96)), x3))
                )
            let last :=
                shr(
                    192,
                    mul(mload(add(ptr, 128)), or(or(x3, shl(64, x2)), or(shl(128, x), shl(192, 1))))
                )
            let o0 := mod(and(low, 0xffffffffffffffff), M)
            let o1 := mod(and(shr(64, low), 0xffffffffffffffff), M)
            let o2 := mod(and(shr(128, low), 0xffffffffffffffff), M)
            let o3 := mod(shr(192, low), M)
            let o4 := mod(last, M)
            lowOut := or(or(o0, shl(64, o1)), or(shl(128, o2), shl(192, o3)))
            revOut := or(or(o4, shl(64, o3)), or(shl(128, o2), shl(192, o1)))
        }
    }

    function _storeLow(uint256 ptr, uint256 b) private pure {
        assembly ("memory-safe") {
            mstore(
                ptr,
                or(
                    or(shr(224, b), shl(64, and(shr(192, b), 0xffffffff))),
                    or(
                        shl(128, and(shr(160, b), 0xffffffff)),
                        shl(192, and(shr(128, b), 0xffffffff))
                    )
                )
            )
        }
    }

    function _prepareConsumer(uint256 challenge) private pure returns (uint256 ptr) {
        assembly ("memory-safe") {
            ptr := mload(0x40)
            mstore(0x40, add(ptr, 224))
            mstore(
                ptr,
                or(
                    or(
                        and(shr(224, challenge), 0xffffffff),
                        shl(64, and(shr(192, challenge), 0xffffffff))
                    ),
                    or(
                        shl(128, and(shr(160, challenge), 0xffffffff)),
                        shl(192, and(shr(128, challenge), 0xffffffff))
                    )
                )
            )
            mstore(
                add(ptr, 32),
                or(
                    or(
                        and(shr(96, challenge), 0xffffffff),
                        shl(64, and(shr(128, challenge), 0xffffffff))
                    ),
                    or(
                        shl(128, and(shr(160, challenge), 0xffffffff)),
                        shl(192, and(shr(192, challenge), 0xffffffff))
                    )
                )
            )
        }
    }

    function _consumerProduct(uint256 aLow, uint256 aRev, uint256 ptr) private pure {
        assembly ("memory-safe") {
            let bLow := mload(ptr)
            let bRev := mload(add(ptr, 32))
            let c4 :=
                add(
                    shr(192, mul(aLow, or(shr(64, bLow), shl(192, and(bRev, 0xffffffff))))),
                    mul(and(aRev, 0xffffffff), and(bLow, 0xffffffff))
                )
            let low := mul(aLow, bLow)
            let high := mul(aRev, bRev)
            let c0 := and(low, 0xffffffffffffffff)
            let c1 := and(shr(64, low), 0xffffffffffffffff)
            let c2 := and(shr(128, low), 0xffffffffffffffff)
            let c3 := shr(192, low)
            let c5 := shr(192, high)
            let c6 := and(shr(128, high), 0xffffffffffffffff)
            let c7 := and(shr(64, high), 0xffffffffffffffff)
            let c8 := and(high, 0xffffffffffffffff)

            mstore(add(ptr, 64), add(c0, shl(1, c5)))
            mstore(add(ptr, 96), add(c1, shl(1, c6)))
            mstore(add(ptr, 128), add(c2, shl(1, c7)))
            mstore(add(ptr, 160), add(c3, shl(1, c8)))
            mstore(add(ptr, 192), c4)
        }
    }

    function _multiplyAdd(uint256 aLow, uint256 aRev, uint256 bLow, uint256 bRev, uint256 ptr)
        private
        pure
        returns (uint256 lowOut, uint256 revOut)
    {
        assembly ("memory-safe") {
            let M := 0x78000001
            let c4 :=
                add(
                    shr(192, mul(aLow, or(shr(64, bLow), shl(192, and(bRev, 0xffffffff))))),
                    mul(and(aRev, 0xffffffff), and(bLow, 0xffffffff))
                )
            let low := mul(aLow, bLow)
            let high := mul(aRev, bRev)
            let c0 := and(low, 0xffffffffffffffff)
            let c1 := and(shr(64, low), 0xffffffffffffffff)
            let c2 := and(shr(128, low), 0xffffffffffffffff)
            let c3 := shr(192, low)
            let c5 := shr(192, high)
            let c6 := and(shr(128, high), 0xffffffffffffffff)
            let c7 := and(shr(64, high), 0xffffffffffffffff)
            let c8 := and(high, 0xffffffffffffffff)

            let o0 := mod(add(add(c0, shl(1, c5)), mload(add(ptr, 64))), M)
            let o1 := mod(add(add(c1, shl(1, c6)), mload(add(ptr, 96))), M)
            let o2 := mod(add(add(c2, shl(1, c7)), mload(add(ptr, 128))), M)
            let o3 := mod(add(add(c3, shl(1, c8)), mload(add(ptr, 160))), M)
            let o4 := mod(add(c4, mload(add(ptr, 192))), M)
            lowOut := or(or(o0, shl(64, o1)), or(shl(128, o2), shl(192, o3)))
            revOut := or(or(o4, shl(64, o3)), or(shl(128, o2), shl(192, o1)))
        }
    }

    function _selectAndHorner(
        uint256 current,
        uint256[] memory cache,
        uint256 pointOffset,
        uint256 n,
        uint256 totalLow,
        uint256 totalRev,
        uint256 consumer
    ) private pure returns (uint256, uint256) {
        _consumerProduct(totalLow, totalRev, consumer);
        uint256 pairIndex = (pointOffset + n - 6) / 2;
        uint256 ptr;
        assembly ("memory-safe") { ptr := add(add(cache, 32), mul(pairIndex, 160)) }
        (uint256 low, uint256 rev, uint256 next) = _evaluateSelectCubicPair(ptr, current);
        unchecked {
            for (uint256 i = n / 2 - 1; i > 1; --i) {
                ptr -= 160;
                uint256 bLow;
                uint256 bRev;
                (bLow, bRev, next) = _evaluateSelectCubicPair(ptr, next);
                (low, rev) = _mulSelectCubicForms(low, rev, bLow, bRev);
            }
            ptr -= 160;
        }
        uint256 lastLow;
        uint256 lastRev;
        (lastLow, lastRev,) = _evaluateSelectCubicPair(ptr, next);
        return _multiplyAdd(low, rev, lastLow, lastRev, consumer);
    }

    function _eqTermForms(uint256 acc, uint256[4] memory cache)
        internal
        pure
        returns (uint256 outLow, uint256 outRev)
    {
        assembly ("memory-safe") {
            let M := 0x78000001
            let mask := 0xffffffff

            let low
            let high
            let c4
            {
                let a0 := mod(add(shr(224, acc), shr(1, M)), M)
                let a1 := and(shr(192, acc), mask)
                let a2 := and(shr(160, acc), mask)
                let a3 := and(shr(128, acc), mask)
                let a4 := and(shr(96, acc), mask)
                let bLow := mload(cache)
                let aLow := or(or(a0, shl(64, a1)), or(shl(128, a2), shl(192, a3)))
                c4 := add(
                    shr(192, mul(aLow, mload(add(cache, 32)))),
                    mul(a4, and(bLow, 0xffffffff))
                )
                low := mul(aLow, bLow)
                high := mul(
                    or(or(a4, shl(64, a3)), or(shl(128, a2), shl(192, a1))),
                    mload(add(cache, 64))
                )
            }
            let laneMask := 0xffffffffffffffff
            let c0 := and(low, laneMask)
            let c1 := and(shr(64, low), laneMask)
            let c2 := and(shr(128, low), laneMask)
            let c3 := shr(192, low)
            let c5 := shr(192, high)
            let c6 := and(shr(128, high), laneMask)
            let c7 := and(shr(64, high), laneMask)
            let c8 := and(high, laneMask)
            let o0 := mod(add(shl(1, add(c0, shl(1, c5))), add(shr(1, M), 1)), M)
            let o1 := mod(shl(1, add(c1, shl(1, c6))), M)
            let o2 := mod(shl(1, add(c2, shl(1, c7))), M)
            let o3 := mod(shl(1, add(c3, shl(1, c8))), M)
            let o4 := mod(shl(1, c4), M)
            outLow := or(or(o0, shl(64, o1)), or(shl(128, o2), shl(192, o3)))
            outRev := or(or(o4, shl(64, o3)), or(shl(128, o2), shl(192, o1)))
        }
    }

    function _mulEqTermForms(uint256 aLow, uint256 aRev, uint256 bLow, uint256 bRev)
        internal
        pure
        returns (uint256 outLow, uint256 outRev)
    {
        assembly ("memory-safe") {
            let M := 0x78000001
            let mask := 0xffffffff

            let low := mul(aLow, bLow)
            let high := mul(aRev, bRev)
            let c4 :=
                add(
                    shr(192, mul(aLow, or(shr(64, bLow), shl(192, and(bRev, 0xffffffff))))),
                    mul(and(aRev, 0xffffffff), and(bLow, 0xffffffff))
                )
            let laneMask := 0xffffffffffffffff
            let c0 := and(low, laneMask)
            let c1 := and(shr(64, low), laneMask)
            let c2 := and(shr(128, low), laneMask)
            let c3 := shr(192, low)
            let c5 := shr(192, high)
            let c6 := and(shr(128, high), laneMask)
            let c7 := and(shr(64, high), laneMask)
            let c8 := and(high, laneMask)
            let o0 := mod(add(c0, shl(1, c5)), M)
            let o1 := mod(add(c1, shl(1, c6)), M)
            let o2 := mod(add(c2, shl(1, c7)), M)
            let o3 := mod(add(c3, shl(1, c8)), M)
            let o4 := mod(c4, M)
            outLow := or(or(o0, shl(64, o1)), or(shl(128, o2), shl(192, o3)))
            outRev := or(or(o4, shl(64, o3)), or(shl(128, o2), shl(192, o1)))
        }
    }

    function _stateAt(uint256[10] memory state, uint256 index) private pure returns (uint256 ptr) {
        assembly ("memory-safe") { ptr := add(state, shl(6, index)) }
    }

    function _initialEqAt(uint256 ptr, uint256 a, uint256[4] memory cache) private pure {
        (uint256 low, uint256 rev) = _eqTermForms(a, cache);
        assembly ("memory-safe") {
            mstore(ptr, low)
            mstore(add(ptr, 32), rev)
        }
    }

    function _accEqAt(uint256 ptr, uint256 a, uint256[4] memory cache) private pure {
        (uint256 low, uint256 rev) = _eqTermForms(a, cache);
        uint256 aLow;
        uint256 aRev;
        assembly ("memory-safe") {
            aLow := mload(ptr)
            aRev := mload(add(ptr, 32))
        }
        (low, rev) = _mulEqTermForms(aLow, aRev, low, rev);
        assembly ("memory-safe") {
            mstore(ptr, low)
            mstore(add(ptr, 32), rev)
        }
    }

    function _packAt(uint256 ptr) private pure returns (uint256) {
        uint256 low;
        uint256 rev;
        assembly ("memory-safe") {
            low := mload(ptr)
            rev := mload(add(ptr, 32))
        }
        return _packForms(low, rev);
    }

    function _packForms(uint256 low, uint256 rev) private pure returns (uint256 out) {
        assembly ("memory-safe") {
            out := or(
                or(
                    or(shl(224, and(low, 0xffffffff)), shl(192, and(shr(64, low), 0xffffffff))),
                    or(shl(160, and(shr(128, low), 0xffffffff)), shl(128, shr(192, low)))
                ),
                shl(96, and(rev, 0xffffffff))
            )
        }
    }

    function _prepareEqTermForms(uint256 q, uint256[4] memory cache) internal pure {
        assembly ("memory-safe") {
            let M := 0x78000001
            let q0 := and(shr(224, q), 0xffffffff)
            let q1 := and(shr(192, q), 0xffffffff)
            let q2 := and(shr(160, q), 0xffffffff)
            let q3 := and(shr(128, q), 0xffffffff)
            let q4 := and(shr(96, q), 0xffffffff)
            q0 := mod(add(q0, shr(1, M)), M)
            let low := or(or(q0, shl(64, q1)), or(shl(128, q2), shl(192, q3)))
            mstore(cache, low)
            mstore(add(cache, 32), or(shr(64, low), shl(192, q4)))
            mstore(add(cache, 64), or(or(q4, shl(64, q3)), or(shl(128, q2), shl(192, q1))))
        }
    }
}
