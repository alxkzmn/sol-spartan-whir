// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { KoalaBearExt5 } from "../../field/KoalaBearExt5.sol";
import {
    QuinticWhirFixedConfig_k22_jb100_ext5_lir4_ff4_rsv4 as QuinticWhirFixedConfig
} from "../../generated/QuinticWhirFixedConfig_k22_jb100_ext5_lir4_ff4_rsv4.sol";
import { KeccakChallenger } from "../../transcript/KeccakChallenger.sol";
import { WhirBlobCodec5 } from "./WhirBlobCodec5_k22_jb100_ext5_lir4_ff4_rsv4.sol";
import { WhirVerifierCore5 } from "./WhirVerifierCore5.sol";
import { WhirVerifierUtils5 } from "./WhirVerifierUtils5.sol";

contract WhirBlobVerifierNative5_k22_jb100_ext5_lir4_ff4_rsv4 {
    using KeccakChallenger for KeccakChallenger.State;

    function verify(bytes32 expectedCommitment, bytes calldata blob) external pure returns (bool) {
        (
            uint256 round0DecommLen,
            uint256 round1DecommLen,
            uint256 round2DecommLen,
            uint256 finalDecommLen
        ) = WhirBlobCodec5.validateHeader(blob);

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
                WhirVerifierCore5._verifyRound0StirAndCombineConstraintBlob(
                    challenger,
                    prevRoot,
                    blob,
                    offset,
                    round0DecommLen,
                    round0PowWitnessOffset,
                    allRandomness,
                    round0RandomnessOffset,
                    round0OodEvaluation
                );
            claimedEval = KoalaBearExt5.add(claimedEval, round0Contribution);

            round1RandomnessOffset = randomnessCursor;
            (claimedEval, randomnessCursor, offset) = WhirVerifierCore5._verifySumcheckBlob(
                blob, offset, challenger, claimedEval, 4, 19, allRandomness, randomnessCursor
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
                WhirVerifierCore5._verifyRound1StirAndCombineConstraintBlob(
                    challenger,
                    prevRoot,
                    blob,
                    offset,
                    round1DecommLen,
                    round1PowWitnessOffset,
                    allRandomness,
                    round1RandomnessOffset,
                    round1OodEvaluation
                );
            claimedEval = KoalaBearExt5.add(claimedEval, round1Contribution);

            round2RandomnessOffset = randomnessCursor;
            (claimedEval, randomnessCursor, offset) = WhirVerifierCore5._verifySumcheckBlob(
                blob, offset, challenger, claimedEval, 4, 21, allRandomness, randomnessCursor
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
                WhirVerifierCore5._verifyRound2StirAndCombineConstraintBlob(
                    challenger,
                    prevRoot,
                    blob,
                    offset,
                    round2DecommLen,
                    round2PowWitnessOffset,
                    allRandomness,
                    round2RandomnessOffset,
                    round2OodEvaluation
                );
            claimedEval = KoalaBearExt5.add(claimedEval, round2Contribution);

            finalStirRandomnessOffset = randomnessCursor;
            (claimedEval, randomnessCursor, offset) = WhirVerifierCore5._verifySumcheckBlob(
                blob, offset, challenger, claimedEval, 4, 24, allRandomness, randomnessCursor
            );
            prevRoot = round2Root;
        }

        uint256 finalPolyOffset = offset;
        challenger.observeValidatedPackedExt5Blob(
            blob, offset, QuinticWhirFixedConfig.FINAL_POLY_LENGTH
        );
        unchecked {
            offset += QuinticWhirFixedConfig.FINAL_POLY_LENGTH * 20;
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
        uint256 expected = KoalaBearExt5.mul(evaluationOfWeights, finalValue);
        if (claimedEval != expected) {
            revert WhirVerifierCore5.FinalConstraintMismatch(expected, claimedEval);
        }

        return true;
    }
}
