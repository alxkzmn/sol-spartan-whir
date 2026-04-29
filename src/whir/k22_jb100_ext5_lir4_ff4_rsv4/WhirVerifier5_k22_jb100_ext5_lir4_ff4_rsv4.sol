// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { KoalaBearExt5 } from "../../field/KoalaBearExt5.sol";
import {
    QuinticWhirFixedConfig_k22_jb100_ext5_lir4_ff4_rsv4 as QuinticWhirFixedConfig
} from "../../generated/QuinticWhirFixedConfig_k22_jb100_ext5_lir4_ff4_rsv4.sol";
import { KeccakChallenger } from "../../transcript/KeccakChallenger.sol";
import { WhirStructs } from "../WhirStructs.sol";
import { WhirVerifierCore5 } from "./WhirVerifierCore5.sol";
import { WhirVerifierUtils5 } from "./WhirVerifierUtils5.sol";

contract WhirVerifier5_k22_jb100_ext5_lir4_ff4_rsv4 {
    using KeccakChallenger for KeccakChallenger.State;

    error FixedRoundCountMismatch();
    error MissingFinalQueryBatch();
    error MissingFinalSumcheck();
    error FixedStatementShapeMismatch();
    error FixedStatementArityMismatch();

    function verify(
        bytes32 expectedCommitment,
        WhirStructs.WhirStatement calldata statement,
        WhirStructs.WhirProof calldata proof
    ) external pure returns (bool) {
        if (proof.rounds.length != QuinticWhirFixedConfig.ROUND_COUNT) {
            revert FixedRoundCountMismatch();
        }
        if (!proof.finalQueryBatchPresent) {
            revert MissingFinalQueryBatch();
        }
        if (!proof.finalSumcheckPresent) {
            revert MissingFinalSumcheck();
        }
        if (proof.finalPoly.length != QuinticWhirFixedConfig.FINAL_POLY_LENGTH) {
            revert WhirVerifierCore5.FinalPolyLengthMismatch(
                QuinticWhirFixedConfig.FINAL_POLY_LENGTH, proof.finalPoly.length
            );
        }

        KeccakChallenger.State memory challenger;
        QuinticWhirFixedConfig.observePattern(challenger);

        uint256 initialConstraintChallenge;
        uint256[] calldata statementPoint;
        uint256 statementEval;
        uint256[] memory initialOodFlatPoints;
        uint256 round0ConstraintChallenge;
        uint256[] memory round0EqFlatPoints;
        uint256[] memory round0SelVars;
        uint256 round1ConstraintChallenge;
        uint256[] memory round1EqFlatPoints;
        uint256[] memory round1SelVars;
        uint256 round2ConstraintChallenge;
        uint256[] memory round2EqFlatPoints;
        uint256[] memory round2SelVars;

        if (statement.points.length != 1 || statement.evaluations.length != 1) {
            revert FixedStatementShapeMismatch();
        }
        statementPoint = statement.points[0];
        if (statementPoint.length != QuinticWhirFixedConfig.NUM_VARIABLES) {
            revert FixedStatementArityMismatch();
        }
        WhirVerifierUtils5.validatePackedExt5Calldata(statementPoint);
        statementEval = statement.evaluations[0];
        WhirVerifierUtils5.validatePackedExt5(statementEval);

        WhirVerifierCore5.ParsedCommitment memory parsedCommitment =
            WhirVerifierCore5._parseCommitment(
                challenger,
                proof.initialCommitment,
                proof.initialOodAnswers,
                QuinticWhirFixedConfig.NUM_VARIABLES,
                QuinticWhirFixedConfig.COMMITMENT_OOD_SAMPLES
            );
        if (parsedCommitment.root != expectedCommitment) {
            revert WhirVerifierCore5.CommitmentMismatch(expectedCommitment, parsedCommitment.root);
        }

        initialConstraintChallenge = WhirVerifierUtils5.sampleExt5(challenger);
        initialOodFlatPoints = parsedCommitment.oodStatement.flatPoints;

        uint256 claimedEval = WhirVerifierCore5._combineInitialConstraintEvalsSingleRaw(
            initialConstraintChallenge, statementEval, parsedCommitment.oodStatement.evaluations[0]
        );

        uint256[] memory allRandomness = new uint256[](QuinticWhirFixedConfig.NUM_VARIABLES);
        uint256[] memory foldingRandomness;
        uint256[] memory finalSumcheckRandomness;
        uint256 randomnessCursor = 0;

        (claimedEval, foldingRandomness, randomnessCursor) = WhirVerifierCore5._verifySumcheck(
            proof.initialSumcheck,
            challenger,
            claimedEval,
            QuinticWhirFixedConfig.INITIAL_SUMCHECK_ROUNDS,
            QuinticWhirFixedConfig.STARTING_FOLDING_POW_BITS,
            allRandomness,
            randomnessCursor
        );

        WhirVerifierCore5.ParsedCommitment memory prevCommitment = parsedCommitment;
        unchecked {
            for (uint256 i = 0; i < QuinticWhirFixedConfig.ROUND_COUNT; ++i) {
                QuinticWhirFixedConfig.RoundConfig memory cfg =
                    QuinticWhirFixedConfig.roundConfig(i);
                WhirStructs.WhirRoundProof calldata roundProof = proof.rounds[i];
                WhirVerifierCore5.ParsedCommitment memory nextCommitment =
                    WhirVerifierCore5._parseCommitment(
                        challenger,
                        roundProof.commitment,
                        roundProof.oodAnswers,
                        cfg.numVariables,
                        cfg.oodSamples
                    );

                uint256 roundConstraintChallenge;
                uint256 roundContribution;
                uint256[] memory selVars;
                (roundConstraintChallenge, roundContribution, selVars) =
                    WhirVerifierCore5._verifyStirAndCombineConstraint(
                        challenger,
                        prevCommitment.root,
                        cfg.powBits,
                        cfg.numQueries,
                        cfg.numVariables,
                        cfg.foldingFactor,
                        cfg.domainSize,
                        cfg.foldedDomainGen,
                        roundProof.queryBatch,
                        true,
                        roundProof.powWitness,
                        foldingRandomness,
                        i == 0 ? 0 : 1,
                        roundProof.oodAnswers
                    );
                claimedEval = KoalaBearExt5.add(claimedEval, roundContribution);
                if (i == 0) {
                    round0ConstraintChallenge = roundConstraintChallenge;
                    round0EqFlatPoints = nextCommitment.oodStatement.flatPoints;
                    round0SelVars = selVars;
                } else if (i == 1) {
                    round1ConstraintChallenge = roundConstraintChallenge;
                    round1EqFlatPoints = nextCommitment.oodStatement.flatPoints;
                    round1SelVars = selVars;
                } else {
                    round2ConstraintChallenge = roundConstraintChallenge;
                    round2EqFlatPoints = nextCommitment.oodStatement.flatPoints;
                    round2SelVars = selVars;
                }

                (claimedEval, foldingRandomness, randomnessCursor) =
                    WhirVerifierCore5._verifySumcheck(
                        roundProof.sumcheck,
                        challenger,
                        claimedEval,
                        cfg.foldingFactor,
                        cfg.foldingPowBits,
                        allRandomness,
                        randomnessCursor
                    );
                prevCommitment = nextCommitment;
            }
        }

        challenger.observeValidatedPackedExt5Slice(proof.finalPoly);

        WhirVerifierCore5._verifyFinalStirChallengesRaw(
            challenger,
            prevCommitment.root,
            QuinticWhirFixedConfig.FINAL_POW_BITS,
            QuinticWhirFixedConfig.FINAL_NUM_QUERIES,
            QuinticWhirFixedConfig.FINAL_FOLDING_FACTOR,
            QuinticWhirFixedConfig.FINAL_DOMAIN_SIZE,
            QuinticWhirFixedConfig.FINAL_FOLDED_DOMAIN_GEN,
            proof.finalQueryBatch,
            proof.finalQueryBatchPresent,
            proof.finalPowWitness,
            foldingRandomness,
            1,
            proof.finalPoly
        );

        (claimedEval, finalSumcheckRandomness, randomnessCursor) = WhirVerifierCore5._verifySumcheck(
            proof.finalSumcheck,
            challenger,
            claimedEval,
            QuinticWhirFixedConfig.FINAL_SUMCHECK_ROUNDS,
            QuinticWhirFixedConfig.FINAL_FOLDING_POW_BITS,
            allRandomness,
            randomnessCursor
        );

        if (randomnessCursor != QuinticWhirFixedConfig.NUM_VARIABLES) {
            revert WhirVerifierCore5.RandomnessLengthMismatch(
                QuinticWhirFixedConfig.NUM_VARIABLES, randomnessCursor
            );
        }

        uint256 evaluationOfWeights = WhirVerifierCore5._evaluateInitialConstraintSingleCalldataRaw(
            initialConstraintChallenge, statementPoint, initialOodFlatPoints, allRandomness
        );
        evaluationOfWeights = KoalaBearExt5.add(
            evaluationOfWeights,
            WhirVerifierCore5._evaluateConstraintSelectRaw(
                round0ConstraintChallenge, round0EqFlatPoints, round0SelVars, allRandomness
            )
        );
        evaluationOfWeights = KoalaBearExt5.add(
            evaluationOfWeights,
            WhirVerifierCore5._evaluateConstraintSelectRaw(
                round1ConstraintChallenge, round1EqFlatPoints, round1SelVars, allRandomness
            )
        );
        evaluationOfWeights = KoalaBearExt5.add(
            evaluationOfWeights,
            WhirVerifierCore5._evaluateConstraintSelectRaw(
                round2ConstraintChallenge, round2EqFlatPoints, round2SelVars, allRandomness
            )
        );
        uint256 finalValue =
            WhirVerifierCore5._evaluateFinalValue(proof.finalPoly, finalSumcheckRandomness);
        uint256 expected = KoalaBearExt5.mul(evaluationOfWeights, finalValue);
        if (claimedEval != expected) {
            revert WhirVerifierCore5.FinalConstraintMismatch(expected, claimedEval);
        }

        return true;
    }
}
