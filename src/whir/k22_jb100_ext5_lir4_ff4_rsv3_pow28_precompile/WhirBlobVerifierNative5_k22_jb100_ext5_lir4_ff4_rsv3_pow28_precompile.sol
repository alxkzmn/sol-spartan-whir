// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { KoalaBearExt5 } from "../../field/KoalaBearExt5.sol";
import { KoalaBearExt5Precompile } from "../../field/KoalaBearExt5Precompile.sol";
import {
    QuinticWhirFixedConfig_k22_jb100_ext5_lir4_ff4_rsv3_pow28 as QuinticWhirFixedConfig
} from "../../generated/QuinticWhirFixedConfig_k22_jb100_ext5_lir4_ff4_rsv3_pow28.sol";
import { KeccakChallenger } from "../../transcript/KeccakChallenger.sol";
import {
    WhirBlobCodec5
} from "../k22_jb100_ext5_lir4_ff4_rsv3_pow28/WhirBlobCodec5_k22_jb100_ext5_lir4_ff4_rsv3_pow28.sol";
import {
    WhirVerifierCore5Precompile as WhirVerifierCore5
} from "./WhirVerifierCore5Precompile.sol";
import { WhirVerifierUtils5 } from "../k22_jb100_ext5_lir4_ff4_rsv3_pow28/WhirVerifierUtils5.sol";

contract WhirBlobVerifierNative5_k22_jb100_ext5_lir4_ff4_rsv3_pow28_precompile {
    using KeccakChallenger for KeccakChallenger.State;

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

    function verify(bytes32 expectedCommitment, bytes calldata blob) external view returns (bool) {
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
        uint256 initialConstraintChallenge;
        uint256 statementEval;
        uint256 initialOodPoint;
        uint256 round0ConstraintChallenge;
        uint256 round0OodPoint;
        uint256[] memory round0SelVars;
        uint256 round1ConstraintChallenge;
        uint256 round1OodPoint;
        uint256[] memory round1SelVars;
        uint256 round2ConstraintChallenge;
        uint256 round2OodPoint;
        uint256[] memory round2SelVars;

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
            uint256 parsedInitialOodPoint,
            uint256 initialOodEvaluation,
            uint256 nextOffset
        ) = WhirVerifierCore5._parseFixedCommitment22x1Blob(challenger, blob, offset);
        offset = nextOffset;

        if (prevRoot != expectedCommitment) {
            revert WhirVerifierCore5.CommitmentMismatch(expectedCommitment, prevRoot);
        }

        initialOodPoint = parsedInitialOodPoint;
        initialConstraintChallenge = WhirVerifierUtils5.sampleExt5(challenger);

        uint256 claimedEval = WhirVerifierCore5._combineInitialConstraintEvalsSingleRaw(
            initialConstraintChallenge, statementEval, initialOodEvaluation
        );

        uint256[] memory allRandomness = new uint256[](QuinticWhirFixedConfig.NUM_VARIABLES);
        uint256 randomnessCursor = 0;
        uint256 round0RandomnessOffset = randomnessCursor;
        uint256 round1RandomnessOffset;
        uint256 round2RandomnessOffset;
        uint256 finalStirRandomnessOffset;

        (claimedEval, randomnessCursor, offset) = WhirVerifierCore5._verifySumcheckBlob(
            blob, offset, challenger, claimedEval, 4, 27, allRandomness, randomnessCursor
        );

        {
            bytes32 round0Root;
            uint256 round0OodEvaluation;
            (round0Root, round0OodPoint, round0OodEvaluation, offset) =
                WhirVerifierCore5._parseFixedCommitment18x1Blob(challenger, blob, offset);

            uint256 round0PowWitnessOffset = offset;
            unchecked {
                offset += 4;
            }

            uint256 round0Contribution;
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
            claimedEval = KoalaBearExt5.add(claimedEval, round0Contribution);

            round1RandomnessOffset = randomnessCursor;
            (claimedEval, randomnessCursor, offset) = WhirVerifierCore5._verifySumcheckBlob(
                blob, offset, challenger, claimedEval, 4, 22, allRandomness, randomnessCursor
            );
            prevRoot = round0Root;
        }

        {
            bytes32 round1Root;
            uint256 round1OodEvaluation;
            (round1Root, round1OodPoint, round1OodEvaluation, offset) =
                WhirVerifierCore5._parseFixedCommitment14x1Blob(challenger, blob, offset);

            uint256 round1PowWitnessOffset = offset;
            unchecked {
                offset += 4;
            }

            uint256 round1Contribution;
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
            claimedEval = KoalaBearExt5.add(claimedEval, round1Contribution);

            round2RandomnessOffset = randomnessCursor;
            (claimedEval, randomnessCursor, offset) = WhirVerifierCore5._verifySumcheckBlob(
                blob, offset, challenger, claimedEval, 4, 25, allRandomness, randomnessCursor
            );
            prevRoot = round1Root;
        }

        {
            bytes32 round2Root;
            uint256 round2OodEvaluation;
            (round2Root, round2OodPoint, round2OodEvaluation, offset) =
                WhirVerifierCore5._parseFixedCommitment10x1Blob(challenger, blob, offset);

            uint256 round2PowWitnessOffset = offset;
            unchecked {
                offset += 4;
            }

            uint256 round2Contribution;
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
            claimedEval = KoalaBearExt5.add(claimedEval, round2Contribution);

            finalStirRandomnessOffset = randomnessCursor;
            (claimedEval, randomnessCursor, offset) = WhirVerifierCore5._verifySumcheckBlob(
                blob, offset, challenger, claimedEval, 4, 27, allRandomness, randomnessCursor
            );
            prevRoot = round2Root;
        }

        uint256 finalPolyOffset = offset;
        unchecked {
            for (uint256 i = 0; i < QuinticWhirFixedConfig.FINAL_POLY_LENGTH; i += 2) {
                uint256 coeff0;
                uint256 coeff1;
                (coeff0, offset) = WhirBlobCodec5.readExt5(blob, offset);
                (coeff1, offset) = WhirBlobCodec5.readExt5(blob, offset);
                challenger.observeValidatedPackedExt5Pair(coeff0, coeff1);
            }
        }

        uint256 finalPowWitnessOffset = offset;
        unchecked {
            offset += 4;
        }

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

        uint256 finalSumcheckStart = randomnessCursor;
        (claimedEval, randomnessCursor, offset) = WhirVerifierCore5._verifySumcheckBlob6NoPow(
            blob, offset, challenger, claimedEval, allRandomness, randomnessCursor
        );

        if (randomnessCursor != QuinticWhirFixedConfig.NUM_VARIABLES) {
            revert WhirVerifierCore5.RandomnessLengthMismatch(
                QuinticWhirFixedConfig.NUM_VARIABLES, randomnessCursor
            );
        }

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
        uint256 evaluationOfWeights = WhirVerifierCore5._combineInitialConstraintEvalsSingleRaw(
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
        uint256 finalValue = WhirVerifierCore5._evaluateFinalValueBlob(
            blob,
            finalPolyOffset,
            QuinticWhirFixedConfig.FINAL_POLY_LENGTH,
            allRandomness,
            finalSumcheckStart,
            QuinticWhirFixedConfig.FINAL_SUMCHECK_ROUNDS
        );
        uint256 expected = KoalaBearExt5Precompile.mul(evaluationOfWeights, finalValue);
        if (claimedEval != expected) {
            revert WhirVerifierCore5.FinalConstraintMismatch(expected, claimedEval);
        }

        return true;
    }
}
