// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {KoalaBearExt4} from "../field/KoalaBearExt4.sol";
import {QuarticWhirFixedConfig} from "../generated/QuarticWhirFixedConfig.sol";
import {KeccakChallenger} from "../transcript/KeccakChallenger.sol";
import {WhirStructs} from "./WhirStructs.sol";
import {WhirVerifierCore4} from "./WhirVerifierCore4.sol";
import {WhirVerifierUtils4} from "./WhirVerifierUtils4.sol";

contract WhirVerifier4 {
    using KeccakChallenger for KeccakChallenger.State;

    function verify(
        bytes32 expectedCommitment,
        WhirStructs.WhirStatement calldata statement,
        WhirStructs.WhirProof calldata proof
    ) external pure returns (bool) {
        if (proof.rounds.length != QuarticWhirFixedConfig.ROUND_COUNT) {
            revert WhirVerifierCore4.ProofRoundCountMismatch(
                QuarticWhirFixedConfig.ROUND_COUNT,
                proof.rounds.length
            );
        }

        bool expectFinalQueryBatch = QuarticWhirFixedConfig
            .EXPECT_FINAL_QUERY_BATCH != 0;
        if (proof.finalQueryBatchPresent != expectFinalQueryBatch) {
            revert WhirVerifierCore4.FinalQueryBatchPresenceMismatch(
                expectFinalQueryBatch,
                proof.finalQueryBatchPresent
            );
        }

        bool expectFinalSumcheck = QuarticWhirFixedConfig
            .EXPECT_FINAL_SUMCHECK != 0;
        if (proof.finalSumcheckPresent != expectFinalSumcheck) {
            revert WhirVerifierCore4.FinalSumcheckPresenceMismatch(
                expectFinalSumcheck,
                proof.finalSumcheckPresent
            );
        }

        KeccakChallenger.State memory challenger;
        QuarticWhirFixedConfig.observePattern(challenger);

        WhirVerifierCore4.ParsedCommitment
            memory parsedCommitment = WhirVerifierCore4._parseCommitment(
                challenger,
                proof.initialCommitment,
                proof.initialOodAnswers,
                QuarticWhirFixedConfig.NUM_VARIABLES,
                QuarticWhirFixedConfig.COMMITMENT_OOD_SAMPLES
            );

        if (parsedCommitment.root != expectedCommitment) {
            revert WhirVerifierCore4.CommitmentMismatch(
                expectedCommitment,
                parsedCommitment.root
            );
        }

        WhirVerifierCore4.Constraint[]
            memory constraints = new WhirVerifierCore4.Constraint[](
                proof.rounds.length
            );
        uint256 constraintCount = 0;
        uint256 claimedEval = 0;
        uint256[] memory foldingRandomness;
        uint256[] memory finalSumcheckRandomness;
        uint256 initialConstraintChallenge = WhirVerifierUtils4.sampleExt4(
            challenger
        );

        claimedEval = _combineInitialConstraintEvals(
            initialConstraintChallenge,
            statement,
            parsedCommitment
        );

        uint256[] memory allRandomness = new uint256[](
            QuarticWhirFixedConfig.NUM_VARIABLES
        );
        uint256 randomnessCursor = 0;

        (claimedEval, foldingRandomness, randomnessCursor) = WhirVerifierCore4
            ._verifySumcheck(
                proof.initialSumcheck,
                challenger,
                claimedEval,
                QuarticWhirFixedConfig.INITIAL_SUMCHECK_ROUNDS,
                QuarticWhirFixedConfig.STARTING_FOLDING_POW_BITS,
                allRandomness,
                randomnessCursor
            );

        WhirVerifierCore4.ParsedCommitment
            memory prevCommitment = parsedCommitment;

        for (
            uint256 roundIndex = 0;
            roundIndex < QuarticWhirFixedConfig.ROUND_COUNT;
            ++roundIndex
        ) {
            QuarticWhirFixedConfig.RoundConfig
                memory roundConfig = QuarticWhirFixedConfig.roundConfig(
                    roundIndex
                );
            WhirStructs.WhirRoundProof calldata roundProof = proof.rounds[
                roundIndex
            ];

            WhirVerifierCore4.ParsedCommitment
                memory newCommitment = WhirVerifierCore4._parseCommitment(
                    challenger,
                    roundProof.commitment,
                    roundProof.oodAnswers,
                    roundConfig.numVariables,
                    roundConfig.oodSamples
                );

            WhirVerifierCore4.SelectStatement
                memory stirStatement = WhirVerifierCore4
                    ._verifyStirChallengesRaw(
                        challenger,
                        prevCommitment.root,
                        roundConfig.powBits,
                        roundConfig.numQueries,
                        roundConfig.numVariables,
                        roundConfig.foldingFactor,
                        roundConfig.domainSize,
                        roundConfig.foldedDomainGen,
                        roundProof.queryBatch,
                        true,
                        roundProof.powWitness,
                        foldingRandomness,
                        true,
                        roundIndex == 0 ? 0 : 1
                    );

            constraints[constraintCount] = WhirVerifierCore4.Constraint({
                challenge: WhirVerifierUtils4.sampleExt4(challenger),
                eqStatement: newCommitment.oodStatement,
                selStatement: stirStatement
            });
            claimedEval = WhirVerifierCore4._combineConstraintEvals(
                claimedEval,
                constraints[constraintCount]
            );
            constraintCount += 1;

            uint256 nextFoldingFactor = roundIndex + 1 <
                QuarticWhirFixedConfig.ROUND_COUNT
                ? QuarticWhirFixedConfig
                    .roundConfig(roundIndex + 1)
                    .foldingFactor
                : QuarticWhirFixedConfig.FINAL_FOLDING_FACTOR;

            (
                claimedEval,
                foldingRandomness,
                randomnessCursor
            ) = WhirVerifierCore4._verifySumcheck(
                roundProof.sumcheck,
                challenger,
                claimedEval,
                nextFoldingFactor,
                roundConfig.foldingPowBits,
                allRandomness,
                randomnessCursor
            );

            prevCommitment = newCommitment;
        }

        if (
            proof.finalPoly.length != QuarticWhirFixedConfig.FINAL_POLY_LENGTH
        ) {
            revert WhirVerifierCore4.FinalPolyLengthMismatch(
                QuarticWhirFixedConfig.FINAL_POLY_LENGTH,
                proof.finalPoly.length
            );
        }
        challenger.observeValidatedPackedExt4Slice(proof.finalPoly);

        WhirVerifierCore4._verifyFinalStirChallengesRaw(
            challenger,
            prevCommitment.root,
            QuarticWhirFixedConfig.FINAL_POW_BITS,
            QuarticWhirFixedConfig.FINAL_NUM_QUERIES,
            QuarticWhirFixedConfig.FINAL_FOLDING_FACTOR,
            QuarticWhirFixedConfig.FINAL_DOMAIN_SIZE,
            QuarticWhirFixedConfig.FINAL_FOLDED_DOMAIN_GEN,
            proof.finalQueryBatch,
            proof.finalQueryBatchPresent,
            proof.finalPowWitness,
            foldingRandomness,
            QuarticWhirFixedConfig.ROUND_COUNT == 0 ? 0 : 1,
            proof.finalPoly
        );

        (
            claimedEval,
            finalSumcheckRandomness,
            randomnessCursor
        ) = WhirVerifierCore4._verifySumcheck(
            proof.finalSumcheck,
            challenger,
            claimedEval,
            QuarticWhirFixedConfig.FINAL_SUMCHECK_ROUNDS,
            QuarticWhirFixedConfig.FINAL_FOLDING_POW_BITS,
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
            ._evaluateConstraintsFixedSelect(constraints, allRandomness);
        evaluationOfWeights = KoalaBearExt4.add(
            evaluationOfWeights,
            _evaluateInitialConstraint(
                initialConstraintChallenge,
                statement,
                parsedCommitment,
                allRandomness
            )
        );
        uint256 finalValue = WhirVerifierCore4._evaluateFinalValue(
            proof.finalPoly,
            finalSumcheckRandomness
        );
        uint256 expected = KoalaBearExt4.mul(evaluationOfWeights, finalValue);

        if (claimedEval != expected) {
            revert WhirVerifierCore4.FinalConstraintMismatch(
                expected,
                claimedEval
            );
        }

        return true;
    }

    function _combineInitialConstraintEvals(
        uint256 challenge,
        WhirStructs.WhirStatement calldata statement,
        WhirVerifierCore4.ParsedCommitment memory parsedCommitment
    ) private pure returns (uint256 updated) {
        if (statement.points.length != statement.evaluations.length) {
            revert WhirVerifierCore4.StatementLengthMismatch(
                statement.points.length,
                statement.evaluations.length
            );
        }

        uint256[] memory oodEvals = parsedCommitment.oodStatement.evaluations;
        uint256 oodLen = oodEvals.length;

        // Horner: Σ challenge^i * eval_i, iterate from last to first
        uint256 horner;
        unchecked {
            for (uint256 i = oodLen; i > 0; --i) {
                horner = KoalaBearExt4.add(
                    oodEvals[i - 1],
                    KoalaBearExt4.mul(horner, challenge)
                );
            }
            for (uint256 i = statement.evaluations.length; i > 0; --i) {
                uint256 evalValue = statement.evaluations[i - 1];
                WhirVerifierUtils4.validatePackedExt4(evalValue);
                horner = KoalaBearExt4.add(
                    evalValue,
                    KoalaBearExt4.mul(horner, challenge)
                );
            }
        }
        updated = horner;
    }

    function _evaluateInitialConstraint(
        uint256 challenge,
        WhirStructs.WhirStatement calldata statement,
        WhirVerifierCore4.ParsedCommitment memory parsedCommitment,
        uint256[] memory allRandomness
    ) private pure returns (uint256 total) {
        if (statement.points.length != statement.evaluations.length) {
            revert WhirVerifierCore4.StatementLengthMismatch(
                statement.points.length,
                statement.evaluations.length
            );
        }

        uint256[] memory oodFlatPoints = parsedCommitment
            .oodStatement
            .flatPoints;
        uint256 oodLen = parsedCommitment.oodStatement.evaluations.length;

        unchecked {
            for (uint256 i = oodLen; i > 0; --i) {
                uint256 weight = WhirVerifierCore4._eqPolyEvalAt(
                    oodFlatPoints,
                    (i - 1) * QuarticWhirFixedConfig.NUM_VARIABLES,
                    allRandomness,
                    0,
                    QuarticWhirFixedConfig.NUM_VARIABLES
                );
                total = KoalaBearExt4.add(
                    weight,
                    KoalaBearExt4.mul(total, challenge)
                );
            }

            for (uint256 i = statement.points.length; i > 0; --i) {
                WhirVerifierUtils4.validatePackedExt4Calldata(
                    statement.points[i - 1]
                );
                uint256 weight = WhirVerifierCore4._eqPolyEvalAtCalldata(
                    statement.points[i - 1],
                    allRandomness,
                    0,
                    QuarticWhirFixedConfig.NUM_VARIABLES
                );
                total = KoalaBearExt4.add(
                    weight,
                    KoalaBearExt4.mul(total, challenge)
                );
            }
        }
    }
}
