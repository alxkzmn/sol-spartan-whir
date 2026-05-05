// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test, console } from "forge-std/Test.sol";

import { KoalaBearExt5 } from "../src/field/KoalaBearExt5.sol";
import {
    QuinticWhirFixedConfig_k22_jb100_ext5_lir4_ff4_rsv3_pow28 as QuinticWhirFixedConfig
} from "../src/generated/QuinticWhirFixedConfig_k22_jb100_ext5_lir4_ff4_rsv3_pow28.sol";
import { KeccakChallenger } from "../src/transcript/KeccakChallenger.sol";
import { WhirStructs } from "../src/whir/WhirStructs.sol";
import {
    WhirBlobCodec5
} from "../src/whir/k22_jb100_ext5_lir4_ff4_rsv3_pow28/WhirBlobCodec5_k22_jb100_ext5_lir4_ff4_rsv3_pow28.sol";
import {
    WhirVerifierCore5
} from "../src/whir/k22_jb100_ext5_lir4_ff4_rsv3_pow28/WhirVerifierCore5.sol";
import {
    WhirVerifierUtils5
} from "../src/whir/k22_jb100_ext5_lir4_ff4_rsv3_pow28/WhirVerifierUtils5.sol";

contract WhirProfileHarness5Pow28Rsv3 {
    using KeccakChallenger for KeccakChallenger.State;

    struct NativeBreakdown {
        uint256 total;
        uint256 setup;
        uint256 initialSumcheck;
        uint256 round0Parse;
        uint256 round0Stir;
        uint256 round0Sumcheck;
        uint256 round1Parse;
        uint256 round1Stir;
        uint256 round1Sumcheck;
        uint256 round2Parse;
        uint256 round2Stir;
        uint256 round2Sumcheck;
        uint256 observeFinalPoly;
        uint256 finalStir;
        uint256 finalSumcheck;
        uint256 constraintEvaluation;
        uint256 finalValueCheck;
    }

    function profileNativeBlobBreakdown(bytes32 expectedCommitment, bytes calldata blob)
        external
        view
        returns (NativeBreakdown memory bd)
    {
        uint256 totalStart = gasleft();
        uint256 g;

        g = gasleft();
        (
            uint256 round0DecommLen,
            uint256 round1DecommLen,
            uint256 round2DecommLen,
            uint256 finalDecommLen
        ) = _validateHeaderNative(blob);

        uint256 offset = WhirBlobCodec5.HEADER_BYTES;
        KeccakChallenger.State memory challenger;
        QuinticWhirFixedConfig.observePattern(challenger);

        uint256 statementPointOffset = offset;
        uint256 statementEval;
        unchecked {
            for (uint256 i = 0; i < QuinticWhirFixedConfig.NUM_VARIABLES; ++i) {
                uint256 pointValue;
                (pointValue, offset) = WhirBlobCodec5.readExt5(blob, offset);
                WhirVerifierUtils5.validatePackedExt5(pointValue);
            }
        }

        (statementEval, offset) = WhirBlobCodec5.readExt5(blob, offset);
        WhirVerifierUtils5.validatePackedExt5(statementEval);

        (
            bytes32 prevRoot,
            uint256 initialOodPoint,
            uint256 initialOodEvaluation,
            uint256 nextOffset
        ) = WhirVerifierCore5._parseFixedCommitment22x1Blob(challenger, blob, offset);
        offset = nextOffset;
        if (prevRoot != expectedCommitment) {
            revert WhirVerifierCore5.CommitmentMismatch(expectedCommitment, prevRoot);
        }

        uint256 initialConstraintChallenge = WhirVerifierUtils5.sampleExt5(challenger);
        uint256 claimedEval = WhirVerifierCore5._combineInitialConstraintEvalsSingleRaw(
            initialConstraintChallenge, statementEval, initialOodEvaluation
        );
        uint256[] memory allRandomness = new uint256[](QuinticWhirFixedConfig.NUM_VARIABLES);
        uint256 randomnessCursor;
        bd.setup = g - gasleft();

        uint256 round0RandomnessOffset = randomnessCursor;
        g = gasleft();
        (claimedEval, randomnessCursor, offset) = WhirVerifierCore5._verifySumcheckBlob(
            blob, offset, challenger, claimedEval, 4, 27, allRandomness, randomnessCursor
        );
        bd.initialSumcheck = g - gasleft();

        uint256 round0ConstraintChallenge;
        uint256 round0OodPoint;
        uint256[] memory round0SelVars;
        uint256 round1RandomnessOffset;
        {
            bytes32 round0Root;
            uint256 round0OodEvaluation;
            g = gasleft();
            (round0Root, round0OodPoint, round0OodEvaluation, offset) =
                WhirVerifierCore5._parseFixedCommitment18x1Blob(challenger, blob, offset);
            bd.round0Parse = g - gasleft();

            uint256 round0PowWitnessOffset = offset;
            unchecked {
                offset += 4;
            }

            uint256 round0Contribution;
            g = gasleft();
            (round0ConstraintChallenge, round0Contribution, round0SelVars, offset) =
                WhirVerifierCore5._verifyRoundStirAndCombineConstraintBlob(
                    challenger,
                    prevRoot,
                    blob,
                    offset,
                    round0DecommLen,
                    round0PowWitnessOffset,
                    allRandomness,
                    round0RandomnessOffset,
                    round0OodEvaluation,
                    27,
                    67_108_864,
                    38,
                    22,
                    542_991_299,
                    0,
                    38 * 16 * 4
                );
            bd.round0Stir = g - gasleft();
            claimedEval = KoalaBearExt5.add(claimedEval, round0Contribution);

            round1RandomnessOffset = randomnessCursor;
            g = gasleft();
            (claimedEval, randomnessCursor, offset) = WhirVerifierCore5._verifySumcheckBlob(
                blob, offset, challenger, claimedEval, 4, 22, allRandomness, randomnessCursor
            );
            bd.round0Sumcheck = g - gasleft();
            prevRoot = round0Root;
        }

        uint256 round1ConstraintChallenge;
        uint256 round1OodPoint;
        uint256[] memory round1SelVars;
        uint256 round2RandomnessOffset;
        {
            bytes32 round1Root;
            uint256 round1OodEvaluation;
            g = gasleft();
            (round1Root, round1OodPoint, round1OodEvaluation, offset) =
                WhirVerifierCore5._parseFixedCommitment14x1Blob(challenger, blob, offset);
            bd.round1Parse = g - gasleft();

            uint256 round1PowWitnessOffset = offset;
            unchecked {
                offset += 4;
            }

            uint256 round1Contribution;
            g = gasleft();
            (round1ConstraintChallenge, round1Contribution, round1SelVars, offset) =
                WhirVerifierCore5._verifyRoundStirAndCombineConstraintBlob(
                    challenger,
                    prevRoot,
                    blob,
                    offset,
                    round1DecommLen,
                    round1PowWitnessOffset,
                    allRandomness,
                    round1RandomnessOffset,
                    round1OodEvaluation,
                    25,
                    8_388_608,
                    31,
                    19,
                    339_671_193,
                    1,
                    31 * 16 * 20
                );
            bd.round1Stir = g - gasleft();
            claimedEval = KoalaBearExt5.add(claimedEval, round1Contribution);

            round2RandomnessOffset = randomnessCursor;
            g = gasleft();
            (claimedEval, randomnessCursor, offset) = WhirVerifierCore5._verifySumcheckBlob(
                blob, offset, challenger, claimedEval, 4, 25, allRandomness, randomnessCursor
            );
            bd.round1Sumcheck = g - gasleft();
            prevRoot = round1Root;
        }

        uint256 round2ConstraintChallenge;
        uint256 round2OodPoint;
        uint256[] memory round2SelVars;
        uint256 finalStirRandomnessOffset;
        {
            bytes32 round2Root;
            uint256 round2OodEvaluation;
            g = gasleft();
            (round2Root, round2OodPoint, round2OodEvaluation, offset) =
                WhirVerifierCore5._parseFixedCommitment10x1Blob(challenger, blob, offset);
            bd.round2Parse = g - gasleft();

            uint256 round2PowWitnessOffset = offset;
            unchecked {
                offset += 4;
            }

            uint256 round2Contribution;
            g = gasleft();
            (round2ConstraintChallenge, round2Contribution, round2SelVars, offset) =
                WhirVerifierCore5._verifyRoundStirAndCombineConstraintBlob(
                    challenger,
                    prevRoot,
                    blob,
                    offset,
                    round2DecommLen,
                    round2PowWitnessOffset,
                    allRandomness,
                    round2RandomnessOffset,
                    round2OodEvaluation,
                    26,
                    4_194_304,
                    19,
                    18,
                    1_816_824_389,
                    1,
                    19 * 16 * 20
                );
            bd.round2Stir = g - gasleft();
            claimedEval = KoalaBearExt5.add(claimedEval, round2Contribution);

            finalStirRandomnessOffset = randomnessCursor;
            g = gasleft();
            (claimedEval, randomnessCursor, offset) = WhirVerifierCore5._verifySumcheckBlob(
                blob, offset, challenger, claimedEval, 4, 27, allRandomness, randomnessCursor
            );
            bd.round2Sumcheck = g - gasleft();
            prevRoot = round2Root;
        }

        uint256 finalPolyOffset = offset;
        g = gasleft();
        unchecked {
            for (uint256 i = 0; i < QuinticWhirFixedConfig.FINAL_POLY_LENGTH; i += 2) {
                uint256 coeff0;
                uint256 coeff1;
                (coeff0, offset) = WhirBlobCodec5.readExt5(blob, offset);
                (coeff1, offset) = WhirBlobCodec5.readExt5(blob, offset);
                challenger.observeValidatedPackedExt5Pair(coeff0, coeff1);
            }
        }
        bd.observeFinalPoly = g - gasleft();

        uint256 finalPowWitnessOffset = offset;
        unchecked {
            offset += 4;
        }

        g = gasleft();
        offset = WhirVerifierCore5._verifyFinalStirChallengesBlobFixed(
            challenger,
            prevRoot,
            blob,
            offset,
            finalDecommLen,
            finalPowWitnessOffset,
            allRandomness,
            finalStirRandomnessOffset,
            finalPolyOffset
        );
        bd.finalStir = g - gasleft();

        uint256 finalSumcheckStart = randomnessCursor;
        g = gasleft();
        (claimedEval, randomnessCursor, offset) = WhirVerifierCore5._verifySumcheckBlob6NoPow(
            blob, offset, challenger, claimedEval, allRandomness, randomnessCursor
        );
        bd.finalSumcheck = g - gasleft();

        if (randomnessCursor != QuinticWhirFixedConfig.NUM_VARIABLES) {
            revert WhirVerifierCore5.RandomnessLengthMismatch(
                QuinticWhirFixedConfig.NUM_VARIABLES, randomnessCursor
            );
        }

        uint256 evaluationOfWeights;
        g = gasleft();
        {
            (
                uint256 statementEq,
                uint256 initialEq,
                uint256 round0Eq,
                uint256 round1Eq,
                uint256 round2Eq
            ) = WhirVerifierCore5._evaluateFixedEqTermsBlobRaw(
                blob,
                statementPointOffset,
                initialOodPoint,
                round0OodPoint,
                round1OodPoint,
                round2OodPoint,
                allRandomness
            );
            evaluationOfWeights = WhirVerifierCore5._combineInitialConstraintEvalsSingleRaw(
                initialConstraintChallenge, statementEq, initialEq
            );
            evaluationOfWeights = KoalaBearExt5.add(
                evaluationOfWeights,
                WhirVerifierCore5._evaluateConstraintSelectRaw18WithPrecomputedEq(
                    round0ConstraintChallenge, round0Eq, round0SelVars, allRandomness
                )
            );
            evaluationOfWeights = KoalaBearExt5.add(
                evaluationOfWeights,
                WhirVerifierCore5._evaluateConstraintSelectRaw14WithPrecomputedEq(
                    round1ConstraintChallenge, round1Eq, round1SelVars, allRandomness
                )
            );
            evaluationOfWeights = KoalaBearExt5.add(
                evaluationOfWeights,
                WhirVerifierCore5._evaluateConstraintSelectRaw10WithPrecomputedEq(
                    round2ConstraintChallenge, round2Eq, round2SelVars, allRandomness
                )
            );
        }
        bd.constraintEvaluation = g - gasleft();

        g = gasleft();
        uint256 finalValue = WhirVerifierCore5._evaluateFinalValueBlob(
            blob,
            finalPolyOffset,
            QuinticWhirFixedConfig.FINAL_POLY_LENGTH,
            allRandomness,
            finalSumcheckStart,
            QuinticWhirFixedConfig.FINAL_SUMCHECK_ROUNDS
        );
        uint256 expected = KoalaBearExt5.mul(evaluationOfWeights, finalValue);
        if (claimedEval != expected) {
            revert WhirVerifierCore5.FinalConstraintMismatch(expected, claimedEval);
        }
        bd.finalValueCheck = g - gasleft();
        bd.total = totalStart - gasleft();
    }

    function _validateHeaderNative(bytes calldata blob)
        private
        pure
        returns (
            uint256 round0DecommLen,
            uint256 round1DecommLen,
            uint256 round2DecommLen,
            uint256 finalDecommLen
        )
    {
        if (blob.length < WhirBlobCodec5.HEADER_BYTES) {
            revert WhirBlobCodec5.BlobTooShort();
        }

        uint256 magic;
        uint256 version;
        uint256 digestBytes;
        uint256 extensionDegree;
        uint256 roundCount;
        uint256 flags;
        assembly ("memory-safe") {
            let base := blob.offset
            let word := calldataload(base)
            magic := shr(224, word)
            version := and(shr(208, word), 0xffff)
            digestBytes := byte(6, word)
            extensionDegree := byte(7, word)
            roundCount := byte(8, word)
            flags := byte(9, word)
            round0DecommLen := and(shr(160, word), 0xffff)
            round1DecommLen := and(shr(144, word), 0xffff)
            round2DecommLen := and(shr(128, word), 0xffff)
            finalDecommLen := and(shr(112, word), 0xffff)
        }

        if (magic != WhirBlobCodec5.MAGIC) {
            revert WhirBlobCodec5.BlobMagicMismatch();
        }
        if (version != WhirBlobCodec5.VERSION) {
            revert WhirBlobCodec5.BlobVersionMismatch();
        }
        if (digestBytes != WhirBlobCodec5.EFFECTIVE_DIGEST_BYTES) {
            revert WhirBlobCodec5.BlobDigestWidthMismatch();
        }
        if (extensionDegree != WhirBlobCodec5.EXTENSION_DEGREE) {
            revert WhirBlobCodec5.BlobExtensionDegreeMismatch();
        }
        if (roundCount != WhirBlobCodec5.ROUND_COUNT) {
            revert WhirBlobCodec5.BlobRoundCountMismatch();
        }
        if (flags != WhirBlobCodec5.FLAGS) {
            revert WhirBlobCodec5.BlobFlagsMismatch();
        }

        uint256 expectedLen = 18 + 22 * 20 + 20 + 20 + 20 + 8 * 20 + 4 * 4 + 20 + 20 + 4 + 38 * 16
            * 4 + round0DecommLen * 20 + 8 * 20 + 4 * 4 + 20 + 20 + 4 + 31 * 16 * 20
            + round1DecommLen * 20 + 8 * 20 + 4 * 4 + 20 + 20 + 4 + 19 * 16 * 20 + round2DecommLen
            * 20 + 8 * 20 + 4 * 4 + 64 * 20 + 4 + 14 * 16 * 20 + finalDecommLen * 20 + 12 * 20;
        if (blob.length != expectedLen) {
            revert WhirBlobCodec5.BlobLengthMismatch();
        }
    }
}

contract WhirGasProfile5Pow28Rsv3Test is Test {
    string internal constant TESTDATA = "testdata/";

    WhirProfileHarness5Pow28Rsv3 internal harness;

    function setUp() external {
        harness = new WhirProfileHarness5Pow28Rsv3();
    }

    function testProfileNativeBlobBreakdown5Pow28Rsv3() external view {
        WhirStructs.WhirProof memory proof = abi.decode(
            vm.readFileBinary(
                string.concat(
                    TESTDATA, "quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_success_proof.abi"
                )
            ),
            (WhirStructs.WhirProof)
        );
        bytes memory blob = vm.readFileBinary(
            string.concat(TESTDATA, "quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_success.blob")
        );

        WhirProfileHarness5Pow28Rsv3.NativeBreakdown memory bd =
            harness.profileNativeBlobBreakdown(proof.initialCommitment, blob);

        uint256 phaseSum = bd.setup + bd.initialSumcheck + bd.round0Parse + bd.round0Stir
            + bd.round0Sumcheck + bd.round1Parse + bd.round1Stir + bd.round1Sumcheck
            + bd.round2Parse + bd.round2Stir + bd.round2Sumcheck + bd.observeFinalPoly
            + bd.finalStir + bd.finalSumcheck + bd.constraintEvaluation + bd.finalValueCheck;

        console.log("=== Quintic Native Blob Breakdown ===");
        console.log("Setup:                  ", bd.setup);
        console.log("Initial sumcheck:       ", bd.initialSumcheck);
        console.log("Round0 parse commitment:", bd.round0Parse);
        console.log("Round0 STIR:            ", bd.round0Stir);
        console.log("Round0 sumcheck:        ", bd.round0Sumcheck);
        console.log("Round1 parse commitment:", bd.round1Parse);
        console.log("Round1 STIR:            ", bd.round1Stir);
        console.log("Round1 sumcheck:        ", bd.round1Sumcheck);
        console.log("Round2 parse commitment:", bd.round2Parse);
        console.log("Round2 STIR:            ", bd.round2Stir);
        console.log("Round2 sumcheck:        ", bd.round2Sumcheck);
        console.log("Observe final poly:     ", bd.observeFinalPoly);
        console.log("Final STIR:             ", bd.finalStir);
        console.log("Final sumcheck:         ", bd.finalSumcheck);
        console.log("Constraint evaluation:  ", bd.constraintEvaluation);
        console.log("Final value check:      ", bd.finalValueCheck);
        console.log("---");
        console.log("Phase sum:              ", phaseSum);
        console.log("Harness total:          ", bd.total);
        console.log("Unattributed overhead:  ", bd.total - phaseSum);
    }
}
