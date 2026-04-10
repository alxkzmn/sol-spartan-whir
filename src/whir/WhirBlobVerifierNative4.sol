// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {KoalaBearExt4} from "../field/KoalaBearExt4.sol";
import {QuarticWhirFixedConfig} from "../generated/QuarticWhirFixedConfig.sol";
import {KeccakChallenger} from "../transcript/KeccakChallenger.sol";
import {WhirBlobCodec4} from "./WhirBlobCodec4.sol";
import {WhirVerifierCore4} from "./WhirVerifierCore4.sol";
import {WhirVerifierUtils4} from "./WhirVerifierUtils4.sol";

contract WhirBlobVerifierNative4 {
    using KeccakChallenger for KeccakChallenger.State;

    function verify(
        bytes32 expectedCommitment,
        bytes calldata blob
    ) external pure returns (bool) {
        (
            uint256 round0DecommLen,
            uint256 round1DecommLen,
            uint256 finalDecommLen
        ) = WhirBlobCodec4.validateHeader(blob);

        uint256 offset = WhirBlobCodec4.HEADER_BYTES;
        KeccakChallenger.State memory challenger;
        QuarticWhirFixedConfig.observePattern(challenger);

        uint256 statementPointOffset = offset;
        unchecked {
            for (uint256 i = 0; i < QuarticWhirFixedConfig.NUM_VARIABLES; ++i) {
                uint256 pointValue;
                (pointValue, offset) = WhirBlobCodec4.readExt4(blob, offset);
                WhirVerifierUtils4.validatePackedExt4(pointValue);
            }
        }

        uint256 statementEval;
        (statementEval, offset) = WhirBlobCodec4.readExt4(blob, offset);
        WhirVerifierUtils4.validatePackedExt4(statementEval);

        (
            WhirVerifierCore4.FixedParsedCommitment memory parsedCommitment,
            uint256 initialOod0,
            uint256 initialOod1,
            uint256 nextOffset
        ) = WhirVerifierCore4._parseFixedCommitment16x2Blob(
                challenger,
                blob,
                offset
            );
        offset = nextOffset;

        if (parsedCommitment.root != expectedCommitment) {
            revert WhirVerifierCore4.CommitmentMismatch(
                expectedCommitment,
                parsedCommitment.root
            );
        }

        uint256 initialConstraintChallenge = WhirVerifierUtils4.sampleExt4(
            challenger
        );
        uint256 claimedEval = WhirVerifierCore4._hornerStep(
            WhirVerifierCore4._hornerStep(
                WhirVerifierCore4._hornerStep(
                    0,
                    initialConstraintChallenge,
                    initialOod1
                ),
                initialConstraintChallenge,
                initialOod0
            ),
            initialConstraintChallenge,
            statementEval
        );

        uint256[] memory allRandomness = new uint256[](
            QuarticWhirFixedConfig.NUM_VARIABLES
        );
        uint256 randomnessCursor = 0;
        uint256 round0ConstraintChallenge;
        uint256[] memory round0EqFlatPoints;
        uint256[] memory round0SelVars;
        uint256 round1ConstraintChallenge;
        uint256[] memory round1EqFlatPoints;
        uint256[] memory round1SelVars;
        uint256 round1RandomnessOffset;
        uint256 finalStirRandomnessOffset;

        uint256 round0RandomnessOffset = randomnessCursor;
        (claimedEval, randomnessCursor, offset) = WhirVerifierCore4
            ._verifySumcheckBlob(
                blob,
                offset,
                challenger,
                claimedEval,
                QuarticWhirFixedConfig.INITIAL_SUMCHECK_ROUNDS,
                QuarticWhirFixedConfig.STARTING_FOLDING_POW_BITS,
                allRandomness,
                randomnessCursor
            );
        WhirVerifierCore4.FixedParsedCommitment
            memory prevCommitment = parsedCommitment;

        {
            (
                WhirVerifierCore4.FixedParsedCommitment memory round0Commitment,
                uint256 round0Ood0,
                uint256 round0Ood1,
                uint256 afterCommitment
            ) = WhirVerifierCore4._parseFixedCommitment12x2Blob(
                    challenger,
                    blob,
                    offset
                );
            offset = afterCommitment;

            uint256 round0PowWitnessOffset = offset;
            unchecked {
                offset += 4;
            }

            uint256 round0Contribution;
            (
                round0ConstraintChallenge,
                round0Contribution,
                round0SelVars,
                offset
            ) = WhirVerifierCore4._verifyStirAndCombineConstraintBlob(
                challenger,
                prevCommitment.root,
                26,
                9,
                18,
                1_816_824_389,
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

            round1RandomnessOffset = randomnessCursor;
            (claimedEval, randomnessCursor, offset) = WhirVerifierCore4
                ._verifySumcheckBlob(
                    blob,
                    offset,
                    challenger,
                    claimedEval,
                    QuarticWhirFixedConfig.FINAL_FOLDING_FACTOR,
                    0,
                    allRandomness,
                    randomnessCursor
                );
            prevCommitment = round0Commitment;
        }

        {
            (
                WhirVerifierCore4.FixedParsedCommitment memory round1Commitment,
                uint256 round1Ood0,
                uint256 round1Ood1,
                uint256 afterCommitment
            ) = WhirVerifierCore4._parseFixedCommitment8x2Blob(
                    challenger,
                    blob,
                    offset
                );
            offset = afterCommitment;

            uint256 round1PowWitnessOffset = offset;
            unchecked {
                offset += 4;
            }

            uint256 round1Contribution;
            (
                round1ConstraintChallenge,
                round1Contribution,
                round1SelVars,
                offset
            ) = WhirVerifierCore4._verifyStirAndCombineConstraintBlob(
                challenger,
                prevCommitment.root,
                26,
                6,
                17,
                373_019_801,
                blob,
                offset,
                round1DecommLen,
                round1PowWitnessOffset,
                allRandomness,
                round1RandomnessOffset,
                1,
                round1Ood0,
                round1Ood1
            );
            claimedEval = KoalaBearExt4.add(claimedEval, round1Contribution);
            round1EqFlatPoints = round1Commitment.oodFlatPoints;

            finalStirRandomnessOffset = randomnessCursor;
            (claimedEval, randomnessCursor, offset) = WhirVerifierCore4
                ._verifySumcheckBlob(
                    blob,
                    offset,
                    challenger,
                    claimedEval,
                    QuarticWhirFixedConfig.FINAL_FOLDING_FACTOR,
                    4,
                    allRandomness,
                    randomnessCursor
                );
            prevCommitment = round1Commitment;
        }

        uint256 finalPolyOffset = offset;
        unchecked {
            for (
                uint256 i = 0;
                i < QuarticWhirFixedConfig.FINAL_POLY_LENGTH;
                i += 2
            ) {
                uint256 coeff0;
                uint256 coeff1;
                (coeff0, offset) = WhirBlobCodec4.readExt4(blob, offset);
                (coeff1, offset) = WhirBlobCodec4.readExt4(blob, offset);
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
            QuarticWhirFixedConfig.FINAL_POW_BITS,
            QuarticWhirFixedConfig.FINAL_NUM_QUERIES,
            16,
            QuarticWhirFixedConfig.FINAL_FOLDED_DOMAIN_GEN,
            blob,
            offset,
            finalDecommLen,
            finalPowWitnessOffset,
            allRandomness,
            finalStirRandomnessOffset,
            1,
            finalPolyOffset,
            QuarticWhirFixedConfig.FINAL_POLY_LENGTH
        );

        uint256 finalSumcheckStart = randomnessCursor;
        (claimedEval, randomnessCursor, offset) = WhirVerifierCore4
            ._verifySumcheckBlob(
                blob,
                offset,
                challenger,
                claimedEval,
                QuarticWhirFixedConfig.FINAL_SUMCHECK_ROUNDS,
                0,
                allRandomness,
                randomnessCursor
            );

        if (randomnessCursor != QuarticWhirFixedConfig.NUM_VARIABLES) {
            revert WhirVerifierCore4.RandomnessLengthMismatch(
                QuarticWhirFixedConfig.NUM_VARIABLES,
                randomnessCursor
            );
        }

        uint256 evaluationOfWeights = WhirVerifierCore4
            ._evaluateConstraintsFixedSelectRaw(
                round0ConstraintChallenge,
                round0EqFlatPoints,
                round0SelVars,
                round1ConstraintChallenge,
                round1EqFlatPoints,
                round1SelVars,
                allRandomness
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

        uint256 finalValue = WhirVerifierUtils4
            ._evaluateExtensionRowDim4BlobWindow(
                blob,
                finalPolyOffset,
                allRandomness,
                finalSumcheckStart
            );
        uint256 expected = KoalaBearExt4.mul(evaluationOfWeights, finalValue);
        if (claimedEval != expected) {
            revert WhirVerifierCore4.FinalConstraintMismatch(
                expected,
                claimedEval
            );
        }
        if (offset != blob.length) {
            revert WhirBlobCodec4.BlobTrailingBytes();
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
        return
            WhirVerifierCore4._hornerStep(
                WhirVerifierCore4._hornerStep(
                    WhirVerifierCore4._hornerStep(
                        0,
                        challenge,
                        WhirVerifierCore4._eqPolyEvalAt(
                            oodFlatPoints,
                            QuarticWhirFixedConfig.NUM_VARIABLES,
                            allRandomness,
                            0,
                            QuarticWhirFixedConfig.NUM_VARIABLES
                        )
                    ),
                    challenge,
                    WhirVerifierCore4._eqPolyEvalAt(
                        oodFlatPoints,
                        0,
                        allRandomness,
                        0,
                        QuarticWhirFixedConfig.NUM_VARIABLES
                    )
                ),
                challenge,
                WhirVerifierCore4._eqPolyEvalAtBlob(
                    blob,
                    statementPointOffset,
                    allRandomness,
                    0,
                    QuarticWhirFixedConfig.NUM_VARIABLES
                )
            );
    }
}
