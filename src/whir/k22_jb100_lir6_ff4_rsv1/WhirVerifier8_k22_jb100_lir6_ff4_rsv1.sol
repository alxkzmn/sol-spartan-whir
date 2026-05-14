// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { KoalaBearExt8 } from "../../field/KoalaBearExt8.sol";
import {
    OcticWhirFixedConfig_k22_jb100_lir6_ff4_rsv1 as OcticWhirFixedConfig
} from "../../generated/OcticWhirFixedConfig_k22_jb100_lir6_ff4_rsv1.sol";
import { KeccakChallenger } from "../../transcript/KeccakChallenger.sol";
import { WhirStructs } from "../WhirStructs.sol";
import { WhirVerifierCore8 } from "./WhirVerifierCore8.sol";
import { WhirVerifierUtils8 } from "./WhirVerifierUtils8.sol";

contract WhirVerifier8_k22_jb100_lir6_ff4_rsv1 {
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
        if (proof.rounds.length != OcticWhirFixedConfig.ROUND_COUNT) {
            revert FixedRoundCountMismatch();
        }
        if (!proof.finalQueryBatchPresent) {
            revert MissingFinalQueryBatch();
        }
        if (!proof.finalSumcheckPresent) {
            revert MissingFinalSumcheck();
        }
        if (proof.finalPoly.length != OcticWhirFixedConfig.FINAL_POLY_LENGTH) {
            revert WhirVerifierCore8.FinalPolyLengthMismatch(
                OcticWhirFixedConfig.FINAL_POLY_LENGTH, proof.finalPoly.length
            );
        }

        KeccakChallenger.State memory challenger;
        OcticWhirFixedConfig.observePattern(challenger);

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
        if (statementPoint.length != OcticWhirFixedConfig.NUM_VARIABLES) {
            revert FixedStatementArityMismatch();
        }
        WhirVerifierUtils8.validatePackedExt8Calldata(statementPoint);
        statementEval = statement.evaluations[0];
        WhirVerifierUtils8.validatePackedExt8(statementEval);

        WhirVerifierCore8.ParsedCommitment memory parsedCommitment =
            WhirVerifierCore8._parseCommitment(
                challenger,
                proof.initialCommitment,
                proof.initialOodAnswers,
                OcticWhirFixedConfig.NUM_VARIABLES,
                OcticWhirFixedConfig.COMMITMENT_OOD_SAMPLES
            );
        if (parsedCommitment.root != expectedCommitment) {
            revert WhirVerifierCore8.CommitmentMismatch(expectedCommitment, parsedCommitment.root);
        }

        initialConstraintChallenge = WhirVerifierUtils8.sampleExt8(challenger);
        initialOodFlatPoints = parsedCommitment.oodStatement.flatPoints;

        uint256 claimedEval = WhirVerifierCore8._combineInitialConstraintEvalsSingleRaw(
            initialConstraintChallenge, statementEval, parsedCommitment.oodStatement.evaluations[0]
        );

        uint256[] memory allRandomness = new uint256[](OcticWhirFixedConfig.NUM_VARIABLES);
        uint256[] memory foldingRandomness;
        uint256[] memory finalSumcheckRandomness;
        uint256 randomnessCursor = 0;

        (claimedEval, foldingRandomness, randomnessCursor) = WhirVerifierCore8._verifySumcheck(
            proof.initialSumcheck,
            challenger,
            claimedEval,
            OcticWhirFixedConfig.INITIAL_SUMCHECK_ROUNDS,
            OcticWhirFixedConfig.STARTING_FOLDING_POW_BITS,
            allRandomness,
            randomnessCursor
        );

        WhirVerifierCore8.ParsedCommitment memory prevCommitment = parsedCommitment;
        unchecked {
            for (uint256 i = 0; i < OcticWhirFixedConfig.ROUND_COUNT; ++i) {
                OcticWhirFixedConfig.RoundConfig memory cfg = OcticWhirFixedConfig.roundConfig(i);
                WhirStructs.WhirRoundProof calldata roundProof = proof.rounds[i];
                WhirVerifierCore8.ParsedCommitment memory nextCommitment =
                    WhirVerifierCore8._parseCommitment(
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
                    WhirVerifierCore8._verifyStirAndCombineConstraint(
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
                claimedEval = KoalaBearExt8.add(claimedEval, roundContribution);
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
                    WhirVerifierCore8._verifySumcheck(
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

        challenger.observeValidatedPackedExt8Slice(proof.finalPoly);

        WhirVerifierCore8._verifyFinalStirChallengesRaw(
            challenger,
            prevCommitment.root,
            OcticWhirFixedConfig.FINAL_POW_BITS,
            OcticWhirFixedConfig.FINAL_NUM_QUERIES,
            OcticWhirFixedConfig.FINAL_FOLDING_FACTOR,
            OcticWhirFixedConfig.FINAL_DOMAIN_SIZE,
            OcticWhirFixedConfig.FINAL_FOLDED_DOMAIN_GEN,
            proof.finalQueryBatch,
            proof.finalQueryBatchPresent,
            proof.finalPowWitness,
            foldingRandomness,
            1,
            proof.finalPoly
        );

        (claimedEval, finalSumcheckRandomness, randomnessCursor) = WhirVerifierCore8._verifySumcheck(
            proof.finalSumcheck,
            challenger,
            claimedEval,
            OcticWhirFixedConfig.FINAL_SUMCHECK_ROUNDS,
            OcticWhirFixedConfig.FINAL_FOLDING_POW_BITS,
            allRandomness,
            randomnessCursor
        );

        if (randomnessCursor != OcticWhirFixedConfig.NUM_VARIABLES) {
            revert WhirVerifierCore8.RandomnessLengthMismatch(
                OcticWhirFixedConfig.NUM_VARIABLES, randomnessCursor
            );
        }

        uint256 evaluationOfWeights = WhirVerifierCore8._evaluateInitialConstraintSingleCalldataRaw(
            initialConstraintChallenge, statementPoint, initialOodFlatPoints, allRandomness
        );
        evaluationOfWeights = KoalaBearExt8.add(
            evaluationOfWeights,
            WhirVerifierCore8._evaluateConstraintSelectRaw(
                round0ConstraintChallenge, round0EqFlatPoints, round0SelVars, allRandomness
            )
        );
        evaluationOfWeights = KoalaBearExt8.add(
            evaluationOfWeights,
            WhirVerifierCore8._evaluateConstraintSelectRaw(
                round1ConstraintChallenge, round1EqFlatPoints, round1SelVars, allRandomness
            )
        );
        evaluationOfWeights = KoalaBearExt8.add(
            evaluationOfWeights,
            WhirVerifierCore8._evaluateConstraintSelectRaw(
                round2ConstraintChallenge, round2EqFlatPoints, round2SelVars, allRandomness
            )
        );
        uint256 finalValue =
            WhirVerifierCore8._evaluateFinalValue(proof.finalPoly, finalSumcheckRandomness);
        uint256 expected = KoalaBearExt8.mul(evaluationOfWeights, finalValue);
        if (claimedEval != expected) {
            revert WhirVerifierCore8.FinalConstraintMismatch(expected, claimedEval);
        }

        return true;
    }
}
