// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { KoalaBearExt4 } from "../field/KoalaBearExt4.sol";
import {
    QuarticWhirLir11FixedConfig
} from "../generated/QuarticWhirFixedConfig_lir11_ff5_rsv3.sol";
import { KeccakChallenger } from "../transcript/KeccakChallenger.sol";
import { WhirBlobCodecLir11 } from "./WhirBlobCodec4_lir11_ff5_rsv3.sol";
import { WhirVerifierCore4 } from "./WhirVerifierCore4.sol";
import { WhirVerifierUtils4 } from "./WhirVerifierUtils4.sol";

contract WhirBlobVerifierNativeLir11 {
    using KeccakChallenger for KeccakChallenger.State;

    function verify(bytes32 expectedCommitment, bytes calldata blob) external pure returns (bool) {
        (uint256 round0DecommLen, uint256 round1DecommLen, uint256 finalDecommLen) =
            WhirBlobCodecLir11.validateHeader(blob);
        round1DecommLen;

        uint256 offset = WhirBlobCodecLir11.HEADER_BYTES;
        KeccakChallenger.State memory challenger;
        QuarticWhirLir11FixedConfig.observePattern(challenger);

        uint256 statementPointOffset = offset;
        unchecked {
            for (uint256 i = 0; i < QuarticWhirLir11FixedConfig.NUM_VARIABLES; ++i) {
                uint256 pointValue;
                (pointValue, offset) = WhirBlobCodecLir11.readExt4(blob, offset);
                WhirVerifierUtils4.validatePackedExt4(pointValue);
            }
        }

        uint256 statementEval;
        (statementEval, offset) = WhirBlobCodecLir11.readExt4(blob, offset);
        WhirVerifierUtils4.validatePackedExt4(statementEval);

        (
            WhirVerifierCore4.FixedParsedCommitment memory parsedCommitment,
            uint256 initialOod0,
            uint256 initialOod1,
            uint256 nextOffset
        ) = WhirVerifierCore4._parseFixedCommitment16x2Blob(challenger, blob, offset);
        offset = nextOffset;

        if (parsedCommitment.root != expectedCommitment) {
            revert WhirVerifierCore4.CommitmentMismatch(expectedCommitment, parsedCommitment.root);
        }

        uint256 initialConstraintChallenge = WhirVerifierUtils4.sampleExt4(challenger);
        uint256 claimedEval = WhirVerifierCore4._hornerStep(
            WhirVerifierCore4._hornerStep(
                WhirVerifierCore4._hornerStep(0, initialConstraintChallenge, initialOod1),
                initialConstraintChallenge,
                initialOod0
            ),
            initialConstraintChallenge,
            statementEval
        );

        uint256[] memory allRandomness = new uint256[](QuarticWhirLir11FixedConfig.NUM_VARIABLES);
        uint256 randomnessCursor = 0;
        uint256 round0ConstraintChallenge;
        uint256[] memory round0EqFlatPoints;
        uint256[] memory round0SelVars;
        uint256 finalStirRandomnessOffset;
        QuarticWhirLir11FixedConfig.RoundConfig memory round0Config =
            QuarticWhirLir11FixedConfig.roundConfig(0);

        uint256 round0RandomnessOffset = randomnessCursor;
        (claimedEval, randomnessCursor, offset) = WhirVerifierCore4._verifySumcheckBlob(
            blob,
            offset,
            challenger,
            claimedEval,
            QuarticWhirLir11FixedConfig.INITIAL_SUMCHECK_ROUNDS,
            QuarticWhirLir11FixedConfig.STARTING_FOLDING_POW_BITS,
            allRandomness,
            randomnessCursor
        );
        WhirVerifierCore4.FixedParsedCommitment memory prevCommitment = parsedCommitment;

        {
            (
                WhirVerifierCore4.FixedParsedCommitment memory round0Commitment,
                uint256 round0Ood0,
                uint256 round0Ood1,
                uint256 afterCommitment
            ) = WhirVerifierCore4._parseFixedCommitment2Blob(
                challenger, blob, offset, round0Config.numVariables
            );
            offset = afterCommitment;

            uint256 round0PowWitnessOffset = offset;
            unchecked {
                offset += 4;
            }

            uint256 round0Contribution;
            (round0ConstraintChallenge, round0Contribution, round0SelVars, offset) =
                WhirVerifierCore4._verifyStirAndCombineConstraintBlob(
                    challenger,
                    prevCommitment.root,
                    round0Config.powBits,
                    round0Config.numQueries,
                    uint256(1) << round0Config.foldingFactor,
                    WhirVerifierUtils4.log2Strict(
                        round0Config.domainSize >> round0Config.foldingFactor
                    ),
                    round0Config.foldedDomainGen,
                    blob,
                    offset,
                    round0DecommLen,
                    round0PowWitnessOffset,
                    allRandomness,
                    round0RandomnessOffset,
                    0,
                    round0Ood0,
                    round0Ood1
                );
            claimedEval = KoalaBearExt4.add(claimedEval, round0Contribution);
            round0EqFlatPoints = round0Commitment.oodFlatPoints;

            finalStirRandomnessOffset = randomnessCursor;
            (claimedEval, randomnessCursor, offset) = WhirVerifierCore4._verifySumcheckBlob(
                blob,
                offset,
                challenger,
                claimedEval,
                round0Config.foldingFactor,
                round0Config.foldingPowBits,
                allRandomness,
                randomnessCursor
            );
            prevCommitment = round0Commitment;
        }

        uint256 finalPolyOffset = offset;
        unchecked {
            for (uint256 i = 0; i < QuarticWhirLir11FixedConfig.FINAL_POLY_LENGTH; i += 2) {
                uint256 coeff0;
                uint256 coeff1;
                (coeff0, offset) = WhirBlobCodecLir11.readExt4(blob, offset);
                (coeff1, offset) = WhirBlobCodecLir11.readExt4(blob, offset);
                WhirVerifierUtils4.validatePackedExt4(coeff0);
                WhirVerifierUtils4.validatePackedExt4(coeff1);
                challenger.observeValidatedPackedExt4Pair(coeff0, coeff1);
            }
        }

        uint256 finalPowWitnessOffset = offset;
        unchecked {
            offset += 4;
        }

        offset = WhirVerifierCore4._verifyFinalStirChallengesBlob(
            challenger,
            prevCommitment.root,
            QuarticWhirLir11FixedConfig.FINAL_POW_BITS,
            QuarticWhirLir11FixedConfig.FINAL_NUM_QUERIES,
            uint256(1) << QuarticWhirLir11FixedConfig.FINAL_FOLDING_FACTOR,
            WhirVerifierUtils4.log2Strict(
                QuarticWhirLir11FixedConfig.FINAL_DOMAIN_SIZE
                    >> QuarticWhirLir11FixedConfig.FINAL_FOLDING_FACTOR
            ),
            QuarticWhirLir11FixedConfig.FINAL_FOLDED_DOMAIN_GEN,
            blob,
            offset,
            finalDecommLen,
            finalPowWitnessOffset,
            allRandomness,
            finalStirRandomnessOffset,
            1,
            finalPolyOffset,
            QuarticWhirLir11FixedConfig.FINAL_POLY_LENGTH
        );

        uint256 finalSumcheckStart = randomnessCursor;
        (claimedEval, randomnessCursor, offset) = WhirVerifierCore4._verifySumcheckBlob(
            blob,
            offset,
            challenger,
            claimedEval,
            QuarticWhirLir11FixedConfig.FINAL_SUMCHECK_ROUNDS,
            0,
            allRandomness,
            randomnessCursor
        );

        if (randomnessCursor != QuarticWhirLir11FixedConfig.NUM_VARIABLES) {
            revert WhirVerifierCore4.RandomnessLengthMismatch(
                QuarticWhirLir11FixedConfig.NUM_VARIABLES, randomnessCursor
            );
        }

        uint256 evaluationOfWeights = WhirVerifierCore4._evaluateConstraintGenericRaw(
            round0ConstraintChallenge, round0EqFlatPoints, round0SelVars, allRandomness
        );
        evaluationOfWeights = KoalaBearExt4.add(
            evaluationOfWeights,
            _evaluateInitialConstraintSingleBlob(
                initialConstraintChallenge,
                blob,
                statementPointOffset,
                parsedCommitment.oodFlatPoints,
                allRandomness
            )
        );

        uint256 finalValue = WhirVerifierUtils4.evaluateExtensionRowBlobAsExt4(
            blob,
            finalPolyOffset,
            QuarticWhirLir11FixedConfig.FINAL_POLY_LENGTH,
            allRandomness,
            finalSumcheckStart,
            QuarticWhirLir11FixedConfig.FINAL_SUMCHECK_ROUNDS
        );
        uint256 expected = KoalaBearExt4.mul(evaluationOfWeights, finalValue);
        if (claimedEval != expected) {
            revert WhirVerifierCore4.FinalConstraintMismatch(expected, claimedEval);
        }
        if (offset != blob.length) {
            revert WhirBlobCodecLir11.BlobTrailingBytes();
        }
        return true;
    }

    function _evaluateInitialConstraintSingleBlob(
        uint256 challenge,
        bytes calldata blob,
        uint256 statementPointOffset,
        uint256[] memory oodFlatPoints,
        uint256[] memory allRandomness
    ) private pure returns (uint256 total) {
        return WhirVerifierCore4._hornerStep(
            WhirVerifierCore4._hornerStep(
                WhirVerifierCore4._hornerStep(
                    0,
                    challenge,
                    WhirVerifierCore4._eqPolyEvalAt(
                        oodFlatPoints,
                        QuarticWhirLir11FixedConfig.NUM_VARIABLES,
                        allRandomness,
                        0,
                        QuarticWhirLir11FixedConfig.NUM_VARIABLES
                    )
                ),
                challenge,
                WhirVerifierCore4._eqPolyEvalAt(
                    oodFlatPoints, 0, allRandomness, 0, QuarticWhirLir11FixedConfig.NUM_VARIABLES
                )
            ),
            challenge,
            WhirVerifierCore4._eqPolyEvalAtBlob(
                blob,
                statementPointOffset,
                allRandomness,
                0,
                QuarticWhirLir11FixedConfig.NUM_VARIABLES
            )
        );
    }
}
