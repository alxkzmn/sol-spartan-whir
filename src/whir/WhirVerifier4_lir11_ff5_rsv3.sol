// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { KoalaBearExt4 } from "../field/KoalaBearExt4.sol";
import {
    QuarticWhirLir11FixedConfig
} from "../generated/QuarticWhirFixedConfig_lir11_ff5_rsv3.sol";
import { KeccakChallenger } from "../transcript/KeccakChallenger.sol";
import { WhirStructs } from "./WhirStructs.sol";
import { WhirVerifierCore4 } from "./WhirVerifierCore4.sol";
import { WhirVerifierUtils4 } from "./WhirVerifierUtils4.sol";

contract WhirVerifierLir11 {
    using KeccakChallenger for KeccakChallenger.State;

    error FixedRoundCountMismatch();
    error MissingFinalQueryBatch();
    error MissingFinalSumcheck();
    error FixedStatementShapeMismatch();
    error FixedStatementArityMismatch();
    error FixedFinalPolyLengthMismatch();
    error FixedRandomnessLengthMismatch();

    function verify(
        bytes32 expectedCommitment,
        WhirStructs.WhirStatement calldata statement,
        WhirStructs.WhirProof calldata proof
    ) external pure returns (bool) {
        if (proof.rounds.length != QuarticWhirLir11FixedConfig.ROUND_COUNT) {
            revert FixedRoundCountMismatch();
        }

        if (!proof.finalQueryBatchPresent) {
            revert MissingFinalQueryBatch();
        }

        if (!proof.finalSumcheckPresent) {
            revert MissingFinalSumcheck();
        }

        KeccakChallenger.State memory challenger;
        QuarticWhirLir11FixedConfig.observePattern(challenger);

        WhirVerifierCore4.FixedParsedCommitment memory parsedCommitment =
            WhirVerifierCore4._parseFixedCommitment16x2(
                challenger, proof.initialCommitment, proof.initialOodAnswers
            );

        if (parsedCommitment.root != expectedCommitment) {
            revert WhirVerifierCore4.CommitmentMismatch(expectedCommitment, parsedCommitment.root);
        }

        uint256 claimedEval = 0;
        uint256[] memory foldingRandomness;
        uint256[] memory finalSumcheckRandomness;
        uint256[] calldata statementPoint;
        uint256 round0ConstraintChallenge;
        uint256[] memory round0EqFlatPoints;
        uint256[] memory round0SelVars;
        uint256 initialConstraintChallenge = WhirVerifierUtils4.sampleExt4(challenger);
        uint256 statementEval;

        if (statement.points.length != 1 || statement.evaluations.length != 1) {
            revert FixedStatementShapeMismatch();
        }
        statementPoint = statement.points[0];
        if (statementPoint.length != QuarticWhirLir11FixedConfig.NUM_VARIABLES) {
            revert FixedStatementArityMismatch();
        }
        WhirVerifierUtils4.validatePackedExt4Calldata(statementPoint);
        statementEval = statement.evaluations[0];
        WhirVerifierUtils4.validatePackedExt4(statementEval);

        claimedEval = _combineInitialConstraintEvalsSingleRaw(
            initialConstraintChallenge, statementEval, proof.initialOodAnswers
        );

        uint256[] memory allRandomness = new uint256[](QuarticWhirLir11FixedConfig.NUM_VARIABLES);
        uint256 randomnessCursor = 0;

        (claimedEval, foldingRandomness, randomnessCursor) = WhirVerifierCore4._verifySumcheck(
            proof.initialSumcheck,
            challenger,
            claimedEval,
            QuarticWhirLir11FixedConfig.INITIAL_SUMCHECK_ROUNDS,
            QuarticWhirLir11FixedConfig.STARTING_FOLDING_POW_BITS,
            allRandomness,
            randomnessCursor
        );

        WhirVerifierCore4.FixedParsedCommitment memory prevCommitment = parsedCommitment;
        QuarticWhirLir11FixedConfig.RoundConfig memory round0Config =
            QuarticWhirLir11FixedConfig.roundConfig(0);

        {
            WhirStructs.WhirRoundProof calldata round0Proof = proof.rounds[0];
            WhirVerifierCore4.FixedParsedCommitment memory round0Commitment =
                WhirVerifierCore4._parseFixedCommitment2(
                    challenger,
                    round0Proof.commitment,
                    round0Proof.oodAnswers,
                    round0Config.numVariables
                );

            uint256 round0Contribution;
            (round0ConstraintChallenge, round0Contribution, round0SelVars) =
                WhirVerifierCore4._verifyStirAndCombineConstraint(
                    challenger,
                    prevCommitment.root,
                    round0Config.powBits,
                    round0Config.numQueries,
                    round0Config.foldingFactor,
                    round0Config.domainSize,
                    round0Config.foldedDomainGen,
                    round0Proof.queryBatch,
                    true,
                    round0Proof.powWitness,
                    foldingRandomness,
                    0,
                    round0Proof.oodAnswers
                );
            claimedEval = KoalaBearExt4.add(claimedEval, round0Contribution);
            round0EqFlatPoints = round0Commitment.oodFlatPoints;

            (claimedEval, foldingRandomness, randomnessCursor) = WhirVerifierCore4._verifySumcheck(
                round0Proof.sumcheck,
                challenger,
                claimedEval,
                round0Config.foldingFactor,
                round0Config.foldingPowBits,
                allRandomness,
                randomnessCursor
            );

            prevCommitment = round0Commitment;
        }

        if (proof.finalPoly.length != QuarticWhirLir11FixedConfig.FINAL_POLY_LENGTH) {
            revert FixedFinalPolyLengthMismatch();
        }
        challenger.observeValidatedPackedExt4Slice(proof.finalPoly);

        WhirVerifierCore4._verifyFinalStirChallengesRaw(
            challenger,
            prevCommitment.root,
            QuarticWhirLir11FixedConfig.FINAL_POW_BITS,
            QuarticWhirLir11FixedConfig.FINAL_NUM_QUERIES,
            QuarticWhirLir11FixedConfig.FINAL_FOLDING_FACTOR,
            QuarticWhirLir11FixedConfig.FINAL_DOMAIN_SIZE,
            QuarticWhirLir11FixedConfig.FINAL_FOLDED_DOMAIN_GEN,
            proof.finalQueryBatch,
            proof.finalQueryBatchPresent,
            proof.finalPowWitness,
            foldingRandomness,
            1,
            proof.finalPoly
        );

        (claimedEval, finalSumcheckRandomness, randomnessCursor) = WhirVerifierCore4._verifySumcheck(
            proof.finalSumcheck,
            challenger,
            claimedEval,
            QuarticWhirLir11FixedConfig.FINAL_SUMCHECK_ROUNDS,
            QuarticWhirLir11FixedConfig.FINAL_FOLDING_POW_BITS,
            allRandomness,
            randomnessCursor
        );

        if (randomnessCursor != QuarticWhirLir11FixedConfig.NUM_VARIABLES) {
            revert FixedRandomnessLengthMismatch();
        }

        uint256 evaluationOfWeights = WhirVerifierCore4._evaluateConstraintGenericRaw(
            round0ConstraintChallenge, round0EqFlatPoints, round0SelVars, allRandomness
        );
        evaluationOfWeights = KoalaBearExt4.add(
            evaluationOfWeights,
            _evaluateInitialConstraintSingleRaw(
                initialConstraintChallenge,
                statementPoint,
                parsedCommitment.oodFlatPoints,
                allRandomness
            )
        );
        uint256 finalValue =
            WhirVerifierCore4._evaluateFinalValue(proof.finalPoly, finalSumcheckRandomness);
        uint256 expected = KoalaBearExt4.mul(evaluationOfWeights, finalValue);

        if (claimedEval != expected) {
            revert WhirVerifierCore4.FinalConstraintMismatch(expected, claimedEval);
        }

        return true;
    }

    function _combineInitialConstraintEvalsSingleRaw(
        uint256 challenge,
        uint256 statementEval,
        uint256[] calldata initialOodAnswers
    ) private pure returns (uint256 updated) {
        return WhirVerifierCore4._hornerStep(
            WhirVerifierCore4._hornerStep(
                WhirVerifierCore4._hornerStep(0, challenge, initialOodAnswers[1]),
                challenge,
                initialOodAnswers[0]
            ),
            challenge,
            statementEval
        );
    }

    function _evaluateInitialConstraintSingleRaw(
        uint256 challenge,
        uint256[] calldata statementPoint,
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
            WhirVerifierCore4._eqPolyEvalAtCalldata(
                statementPoint, allRandomness, 0, QuarticWhirLir11FixedConfig.NUM_VARIABLES
            )
        );
    }

    function _combineInitialConstraintEvals(
        uint256 challenge,
        WhirStructs.WhirStatement calldata statement,
        uint256[] calldata initialOodAnswers
    ) private pure returns (uint256 updated) {
        if (statement.points.length != statement.evaluations.length) {
            revert WhirVerifierCore4.StatementLengthMismatch(
                statement.points.length, statement.evaluations.length
            );
        }

        if (
            initialOodAnswers.length == QuarticWhirLir11FixedConfig.COMMITMENT_OOD_SAMPLES
                && statement.evaluations.length == 1
        ) {
            uint256 evalValue = statement.evaluations[0];
            WhirVerifierUtils4.validatePackedExt4(evalValue);
            return WhirVerifierCore4._hornerStep(
                WhirVerifierCore4._hornerStep(
                    WhirVerifierCore4._hornerStep(0, challenge, initialOodAnswers[1]),
                    challenge,
                    initialOodAnswers[0]
                ),
                challenge,
                evalValue
            );
        }

        // Horner: Σ challenge^i * eval_i, iterate from last to first
        uint256 horner;
        unchecked {
            for (uint256 i = initialOodAnswers.length; i > 0; --i) {
                horner = WhirVerifierCore4._hornerStep(horner, challenge, initialOodAnswers[i - 1]);
            }
            for (uint256 i = statement.evaluations.length; i > 0; --i) {
                uint256 evalValue = statement.evaluations[i - 1];
                WhirVerifierUtils4.validatePackedExt4(evalValue);
                horner = WhirVerifierCore4._hornerStep(horner, challenge, evalValue);
            }
        }
        updated = horner;
    }

    function _evaluateInitialConstraint(
        uint256 challenge,
        WhirStructs.WhirStatement calldata statement,
        uint256[] memory oodFlatPoints,
        uint256[] memory allRandomness
    ) private pure returns (uint256 total) {
        if (statement.points.length != statement.evaluations.length) {
            revert WhirVerifierCore4.StatementLengthMismatch(
                statement.points.length, statement.evaluations.length
            );
        }
        if (statement.points.length == 1) {
            if (statement.points[0].length != QuarticWhirLir11FixedConfig.NUM_VARIABLES) {
                revert WhirVerifierCore4.StatementPointArityMismatch(
                    0, QuarticWhirLir11FixedConfig.NUM_VARIABLES, statement.points[0].length
                );
            }
            WhirVerifierUtils4.validatePackedExt4Calldata(statement.points[0]);
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
                        oodFlatPoints,
                        0,
                        allRandomness,
                        0,
                        QuarticWhirLir11FixedConfig.NUM_VARIABLES
                    )
                ),
                challenge,
                WhirVerifierCore4._eqPolyEvalAtCalldata(
                    statement.points[0], allRandomness, 0, QuarticWhirLir11FixedConfig.NUM_VARIABLES
                )
            );
        }
        uint256 ch0;
        uint256 ch1;
        uint256 ch2;
        uint256 ch3;
        assembly ("memory-safe") {
            ch0 := shr(224, challenge)
            ch1 := and(shr(192, challenge), 0xffffffff)
            ch2 := and(shr(160, challenge), 0xffffffff)
            ch3 := and(shr(128, challenge), 0xffffffff)
        }

        unchecked {
            for (uint256 i = QuarticWhirLir11FixedConfig.COMMITMENT_OOD_SAMPLES; i > 0; --i) {
                uint256 weight = WhirVerifierCore4._eqPolyEvalAt(
                    oodFlatPoints,
                    (i - 1) * QuarticWhirLir11FixedConfig.NUM_VARIABLES,
                    allRandomness,
                    0,
                    QuarticWhirLir11FixedConfig.NUM_VARIABLES
                );
                assembly ("memory-safe") {
                    let M := 0x7f000001
                    let m := 0xffffffff
                    let W := 3

                    let a0 := shr(224, total)
                    let a1 := and(shr(192, total), m)
                    let a2 := and(shr(160, total), m)
                    let a3 := and(shr(128, total), m)

                    let w0 := shr(224, weight)
                    let w1 := and(shr(192, weight), m)
                    let w2 := and(shr(160, weight), m)
                    let w3 := and(shr(128, weight), m)

                    let r0 :=
                        mod(
                            add(
                                add(
                                    mul(a0, ch0),
                                    mul(W, add(add(mul(a1, ch3), mul(a2, ch2)), mul(a3, ch1)))
                                ),
                                w0
                            ),
                            M
                        )
                    let r1 :=
                        mod(
                            add(
                                add(
                                    add(mul(a0, ch1), mul(a1, ch0)),
                                    mul(W, add(mul(a2, ch3), mul(a3, ch2)))
                                ),
                                w1
                            ),
                            M
                        )
                    let r2 :=
                        mod(
                            add(
                                add(
                                    add(add(mul(a0, ch2), mul(a1, ch1)), mul(a2, ch0)),
                                    mul(W, mul(a3, ch3))
                                ),
                                w2
                            ),
                            M
                        )
                    let r3 :=
                        mod(
                            add(
                                add(
                                    add(add(mul(a0, ch3), mul(a1, ch2)), mul(a2, ch1)),
                                    mul(a3, ch0)
                                ),
                                w3
                            ),
                            M
                        )

                    total := or(or(shl(224, r0), shl(192, r1)), or(shl(160, r2), shl(128, r3)))
                }
            }

            for (uint256 i = statement.points.length; i > 0; --i) {
                WhirVerifierUtils4.validatePackedExt4Calldata(statement.points[i - 1]);
                uint256 weight = WhirVerifierCore4._eqPolyEvalAtCalldata(
                    statement.points[i - 1],
                    allRandomness,
                    0,
                    QuarticWhirLir11FixedConfig.NUM_VARIABLES
                );
                assembly ("memory-safe") {
                    let M := 0x7f000001
                    let m := 0xffffffff
                    let W := 3

                    let a0 := shr(224, total)
                    let a1 := and(shr(192, total), m)
                    let a2 := and(shr(160, total), m)
                    let a3 := and(shr(128, total), m)

                    let w0 := shr(224, weight)
                    let w1 := and(shr(192, weight), m)
                    let w2 := and(shr(160, weight), m)
                    let w3 := and(shr(128, weight), m)

                    let r0 :=
                        mod(
                            add(
                                add(
                                    mul(a0, ch0),
                                    mul(W, add(add(mul(a1, ch3), mul(a2, ch2)), mul(a3, ch1)))
                                ),
                                w0
                            ),
                            M
                        )
                    let r1 :=
                        mod(
                            add(
                                add(
                                    add(mul(a0, ch1), mul(a1, ch0)),
                                    mul(W, add(mul(a2, ch3), mul(a3, ch2)))
                                ),
                                w1
                            ),
                            M
                        )
                    let r2 :=
                        mod(
                            add(
                                add(
                                    add(add(mul(a0, ch2), mul(a1, ch1)), mul(a2, ch0)),
                                    mul(W, mul(a3, ch3))
                                ),
                                w2
                            ),
                            M
                        )
                    let r3 :=
                        mod(
                            add(
                                add(
                                    add(add(mul(a0, ch3), mul(a1, ch2)), mul(a2, ch1)),
                                    mul(a3, ch0)
                                ),
                                w3
                            ),
                            M
                        )

                    total := or(or(shl(224, r0), shl(192, r1)), or(shl(160, r2), shl(128, r3)))
                }
            }
        }
    }
}
