// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { BabyBearExt5 } from "../../field/BabyBearExt5.sol";
import {
    BabyBearQuinticWhirFixedConfig_k22_jb100_ext5_lir4_ff4_rsv3_pow28 as BabyBearQuinticWhirFixedConfig
} from "../../generated/BabyBearQuinticWhirFixedConfig_k22_jb100_ext5_lir4_ff4_rsv3_pow28.sol";
import { BabyBearKeccakChallenger } from "../../transcript/BabyBearKeccakChallenger.sol";
import { WhirStructs } from "../WhirStructs.sol";
import { BabyBearWhirVerifierCore5 } from "./BabyBearWhirVerifierCore5.sol";
import { BabyBearWhirVerifierUtils5 } from "./BabyBearWhirVerifierUtils5.sol";

contract BabyBearWhirVerifier5_k22_jb100_ext5_lir4_ff4_rsv3_pow28 {
    using BabyBearKeccakChallenger for BabyBearKeccakChallenger.State;

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
        if (proof.rounds.length != BabyBearQuinticWhirFixedConfig.ROUND_COUNT) {
            revert FixedRoundCountMismatch();
        }
        if (!proof.finalQueryBatchPresent) {
            revert MissingFinalQueryBatch();
        }
        if (!proof.finalSumcheckPresent) {
            revert MissingFinalSumcheck();
        }
        if (proof.finalPoly.length != BabyBearQuinticWhirFixedConfig.FINAL_POLY_LENGTH) {
            revert BabyBearWhirVerifierCore5.FinalPolyLengthMismatch(
                BabyBearQuinticWhirFixedConfig.FINAL_POLY_LENGTH, proof.finalPoly.length
            );
        }

        BabyBearKeccakChallenger.State memory challenger;
        BabyBearQuinticWhirFixedConfig.observePattern(challenger);

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
        if (statementPoint.length != BabyBearQuinticWhirFixedConfig.NUM_VARIABLES) {
            revert FixedStatementArityMismatch();
        }
        BabyBearWhirVerifierUtils5.validatePackedExt5Calldata(statementPoint);
        statementEval = statement.evaluations[0];
        BabyBearWhirVerifierUtils5.validatePackedExt5(statementEval);

        BabyBearWhirVerifierCore5.ParsedCommitment memory parsedCommitment =
            BabyBearWhirVerifierCore5._parseCommitment(
                challenger,
                proof.initialCommitment,
                proof.initialOodAnswers,
                BabyBearQuinticWhirFixedConfig.NUM_VARIABLES,
                BabyBearQuinticWhirFixedConfig.COMMITMENT_OOD_SAMPLES
            );
        if (parsedCommitment.root != expectedCommitment) {
            revert BabyBearWhirVerifierCore5.CommitmentMismatch(
                expectedCommitment, parsedCommitment.root
            );
        }

        initialConstraintChallenge = BabyBearWhirVerifierUtils5.sampleExt5(challenger);
        initialOodFlatPoints = parsedCommitment.oodStatement.flatPoints;

        uint256 claimedEval = BabyBearWhirVerifierCore5._combineInitialConstraintEvalsSingleRaw(
            initialConstraintChallenge, statementEval, parsedCommitment.oodStatement.evaluations[0]
        );

        uint256[] memory allRandomness = new uint256[](BabyBearQuinticWhirFixedConfig.NUM_VARIABLES);
        uint256[] memory foldingRandomness;
        uint256[] memory finalSumcheckRandomness;
        uint256 randomnessCursor = 0;

        (claimedEval, foldingRandomness, randomnessCursor) =
            BabyBearWhirVerifierCore5._verifySumcheck(
                proof.initialSumcheck,
                challenger,
                claimedEval,
                BabyBearQuinticWhirFixedConfig.INITIAL_SUMCHECK_ROUNDS,
                BabyBearQuinticWhirFixedConfig.STARTING_FOLDING_POW_BITS,
                allRandomness,
                randomnessCursor
            );

        BabyBearWhirVerifierCore5.ParsedCommitment memory prevCommitment = parsedCommitment;
        unchecked {
            for (uint256 i = 0; i < BabyBearQuinticWhirFixedConfig.ROUND_COUNT; ++i) {
                BabyBearQuinticWhirFixedConfig.RoundConfig memory cfg =
                    BabyBearQuinticWhirFixedConfig.roundConfig(i);
                WhirStructs.WhirRoundProof calldata roundProof = proof.rounds[i];
                BabyBearWhirVerifierCore5.ParsedCommitment memory nextCommitment =
                    BabyBearWhirVerifierCore5._parseCommitment(
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
                    BabyBearWhirVerifierCore5._verifyStirAndCombineConstraint(
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
                claimedEval = BabyBearExt5.add(claimedEval, roundContribution);
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
                    BabyBearWhirVerifierCore5._verifySumcheck(
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

        BabyBearWhirVerifierCore5._verifyFinalStirChallengesRaw(
            challenger,
            prevCommitment.root,
            BabyBearQuinticWhirFixedConfig.FINAL_POW_BITS,
            BabyBearQuinticWhirFixedConfig.FINAL_NUM_QUERIES,
            BabyBearQuinticWhirFixedConfig.FINAL_FOLDING_FACTOR,
            BabyBearQuinticWhirFixedConfig.FINAL_DOMAIN_SIZE,
            BabyBearQuinticWhirFixedConfig.FINAL_FOLDED_DOMAIN_GEN,
            proof.finalQueryBatch,
            proof.finalQueryBatchPresent,
            proof.finalPowWitness,
            foldingRandomness,
            1,
            proof.finalPoly
        );

        (claimedEval, finalSumcheckRandomness, randomnessCursor) =
            BabyBearWhirVerifierCore5._verifySumcheck(
                proof.finalSumcheck,
                challenger,
                claimedEval,
                BabyBearQuinticWhirFixedConfig.FINAL_SUMCHECK_ROUNDS,
                BabyBearQuinticWhirFixedConfig.FINAL_FOLDING_POW_BITS,
                allRandomness,
                randomnessCursor
            );

        if (randomnessCursor != BabyBearQuinticWhirFixedConfig.NUM_VARIABLES) {
            revert BabyBearWhirVerifierCore5.RandomnessLengthMismatch(
                BabyBearQuinticWhirFixedConfig.NUM_VARIABLES, randomnessCursor
            );
        }

        uint256 evaluationOfWeights =
            BabyBearWhirVerifierCore5._evaluateInitialConstraintSingleCalldataRaw(
                initialConstraintChallenge, statementPoint, initialOodFlatPoints, allRandomness
            );
        evaluationOfWeights = BabyBearExt5.add(
            evaluationOfWeights,
            BabyBearWhirVerifierCore5._evaluateConstraintSelectRaw(
                round0ConstraintChallenge, round0EqFlatPoints, round0SelVars, allRandomness
            )
        );
        evaluationOfWeights = BabyBearExt5.add(
            evaluationOfWeights,
            BabyBearWhirVerifierCore5._evaluateConstraintSelectRaw(
                round1ConstraintChallenge, round1EqFlatPoints, round1SelVars, allRandomness
            )
        );
        evaluationOfWeights = BabyBearExt5.add(
            evaluationOfWeights,
            BabyBearWhirVerifierCore5._evaluateConstraintSelectRaw(
                round2ConstraintChallenge, round2EqFlatPoints, round2SelVars, allRandomness
            )
        );
        uint256 finalValue =
            BabyBearWhirVerifierCore5._evaluateFinalValue(proof.finalPoly, finalSumcheckRandomness);
        uint256 expected = BabyBearExt5.mul(evaluationOfWeights, finalValue);
        if (claimedEval != expected) {
            revert BabyBearWhirVerifierCore5.FinalConstraintMismatch(expected, claimedEval);
        }

        return true;
    }
}
