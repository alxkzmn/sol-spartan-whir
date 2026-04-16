// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test, console } from "forge-std/Test.sol";

import { KoalaBear } from "../src/field/KoalaBear.sol";
import { KoalaBearExt4 } from "../src/field/KoalaBearExt4.sol";
import { KeccakChallenger } from "../src/transcript/KeccakChallenger.sol";
import { QuarticWhirFixedConfig } from "../src/generated/QuarticWhirFixedConfig_lir6_ff5_rsv1.sol";
import { WhirStructs } from "../src/whir/WhirStructs.sol";
import { WhirVerifier4 } from "../src/whir/WhirVerifier4_lir6_ff5_rsv1.sol";
import { WhirVerifierCore4 } from "../src/whir/WhirVerifierCore4.sol";
import { WhirVerifierUtils4 } from "../src/whir/WhirVerifierUtils4.sol";
import { MerkleVerifier } from "../src/merkle/MerkleVerifier.sol";

contract WhirProfileHarness {
    using KeccakChallenger for KeccakChallenger.State;

    struct StirBreakdown {
        uint256 total;
        uint256 sampleQueries;
        uint256 leafHashing;
        uint256 merkleReduction;
        uint256 pow;
        uint256 rowFolding;
        uint256 overhead;
        uint256 queryCount;
        uint256 rowLen;
        uint256 depth;
    }

    function profileParseCommitment(
        bytes32 expectedCommitment,
        WhirStructs.WhirProof calldata proof
    ) external view returns (uint256 gasParseCommitment) {
        uint256 g = gasleft();
        KeccakChallenger.State memory challenger;
        QuarticWhirFixedConfig.observePattern(challenger);
        WhirVerifierCore4.ParsedCommitment memory parsed = WhirVerifierCore4._parseCommitment(
            challenger,
            proof.initialCommitment,
            proof.initialOodAnswers,
            QuarticWhirFixedConfig.NUM_VARIABLES,
            QuarticWhirFixedConfig.COMMITMENT_OOD_SAMPLES
        );
        gasParseCommitment = g - gasleft();

        if (parsed.root != expectedCommitment) {
            revert WhirVerifierCore4.CommitmentMismatch(expectedCommitment, parsed.root);
        }
    }

    function profileConstraintPreparation(
        bytes32 expectedCommitment,
        WhirStructs.WhirStatement calldata statement,
        WhirStructs.WhirProof calldata proof
    )
        external
        view
        returns (uint256 gasParseCommitment, uint256 gasStatementFromCalldata, uint256 gasConcatEq)
    {
        uint256 g;

        KeccakChallenger.State memory challenger;
        QuarticWhirFixedConfig.observePattern(challenger);

        g = gasleft();
        WhirVerifierCore4.ParsedCommitment memory parsed = WhirVerifierCore4._parseCommitment(
            challenger,
            proof.initialCommitment,
            proof.initialOodAnswers,
            QuarticWhirFixedConfig.NUM_VARIABLES,
            QuarticWhirFixedConfig.COMMITMENT_OOD_SAMPLES
        );
        gasParseCommitment = g - gasleft();

        if (parsed.root != expectedCommitment) {
            revert WhirVerifierCore4.CommitmentMismatch(expectedCommitment, parsed.root);
        }

        g = gasleft();
        WhirVerifierCore4.EqStatement memory userStatement = WhirVerifierCore4._statementFromCalldata(
            statement, QuarticWhirFixedConfig.NUM_VARIABLES
        );
        gasStatementFromCalldata = g - gasleft();

        g = gasleft();
        WhirVerifierCore4.EqStatement memory initialEq =
            WhirVerifierCore4._concatenateEq(userStatement, parsed.oodStatement);
        gasConcatEq = g - gasleft();
        require(initialEq.evaluations.length != 0, "PROFILE_EMPTY_EQ");
    }

    function profileInitialSumcheck(
        bytes32 expectedCommitment,
        WhirStructs.WhirStatement calldata statement,
        WhirStructs.WhirProof calldata proof
    ) external view returns (uint256 gasInitialSumcheck) {
        uint256 g;

        KeccakChallenger.State memory challenger;
        QuarticWhirFixedConfig.observePattern(challenger);
        WhirVerifierCore4.ParsedCommitment memory parsed = WhirVerifierCore4._parseCommitment(
            challenger,
            proof.initialCommitment,
            proof.initialOodAnswers,
            QuarticWhirFixedConfig.NUM_VARIABLES,
            QuarticWhirFixedConfig.COMMITMENT_OOD_SAMPLES
        );
        if (parsed.root != expectedCommitment) {
            revert WhirVerifierCore4.CommitmentMismatch(expectedCommitment, parsed.root);
        }

        WhirVerifierCore4.EqStatement memory initialEq = WhirVerifierCore4._concatenateEq(
            WhirVerifierCore4._statementFromCalldata(
                statement, QuarticWhirFixedConfig.NUM_VARIABLES
            ),
            parsed.oodStatement
        );
        uint256 claimedEval = WhirVerifierCore4._combineConstraintEvals(
            0,
            WhirVerifierCore4.Constraint({
                challenge: WhirVerifierUtils4.sampleExt4(challenger),
                eqStatement: initialEq,
                selStatement: WhirVerifierCore4._emptySelect(QuarticWhirFixedConfig.NUM_VARIABLES)
            })
        );

        uint256[] memory allRandomness = new uint256[](QuarticWhirFixedConfig.NUM_VARIABLES);
        uint256[] memory foldingRandomness;
        uint256 randomnessCursor;

        g = gasleft();
        (claimedEval, foldingRandomness, randomnessCursor) = WhirVerifierCore4._verifySumcheck(
            proof.initialSumcheck,
            challenger,
            claimedEval,
            QuarticWhirFixedConfig.INITIAL_SUMCHECK_ROUNDS,
            QuarticWhirFixedConfig.STARTING_FOLDING_POW_BITS,
            allRandomness,
            0
        );
        gasInitialSumcheck = g - gasleft();

        require(claimedEval != 0, "PROFILE_ZERO_CLAIM");
        require(foldingRandomness.length != 0, "PROFILE_EMPTY_FOLD_RANDOMNESS");
        require(randomnessCursor == foldingRandomness.length, "PROFILE_RANDOMNESS_CURSOR");
    }

    function profileObserveFinalPoly(
        bytes32 expectedCommitment,
        WhirStructs.WhirStatement calldata statement,
        WhirStructs.WhirProof calldata proof
    ) external view returns (uint256 gasObserveFinalPoly) {
        KeccakChallenger.State memory challenger;
        QuarticWhirFixedConfig.observePattern(challenger);
        WhirVerifierCore4.ParsedCommitment memory parsed = WhirVerifierCore4._parseCommitment(
            challenger,
            proof.initialCommitment,
            proof.initialOodAnswers,
            QuarticWhirFixedConfig.NUM_VARIABLES,
            QuarticWhirFixedConfig.COMMITMENT_OOD_SAMPLES
        );
        if (parsed.root != expectedCommitment) {
            revert WhirVerifierCore4.CommitmentMismatch(expectedCommitment, parsed.root);
        }

        uint256 claimedEval = WhirVerifierCore4._combineConstraintEvals(
            0,
            WhirVerifierCore4.Constraint({
                challenge: WhirVerifierUtils4.sampleExt4(challenger),
                eqStatement: WhirVerifierCore4._concatenateEq(
                    WhirVerifierCore4._statementFromCalldata(
                        statement, QuarticWhirFixedConfig.NUM_VARIABLES
                    ),
                    parsed.oodStatement
                ),
                selStatement: WhirVerifierCore4._emptySelect(QuarticWhirFixedConfig.NUM_VARIABLES)
            })
        );
        uint256[] memory allRandomness = new uint256[](QuarticWhirFixedConfig.NUM_VARIABLES);
        (claimedEval,,) = WhirVerifierCore4._verifySumcheck(
            proof.initialSumcheck,
            challenger,
            claimedEval,
            QuarticWhirFixedConfig.INITIAL_SUMCHECK_ROUNDS,
            QuarticWhirFixedConfig.STARTING_FOLDING_POW_BITS,
            allRandomness,
            0
        );

        uint256 g = gasleft();
        challenger.observeValidatedPackedExt4Slice(proof.finalPoly);
        gasObserveFinalPoly = g - gasleft();
        require(claimedEval != 0, "PROFILE_ZERO_CLAIM");
    }

    function profileStandaloneFinalSumcheck(WhirStructs.WhirProof calldata proof)
        external
        view
        returns (uint256 gasFinalSumcheck)
    {
        KeccakChallenger.State memory challenger;
        challenger.observeBytes(abi.encodePacked(bytes32(uint256(42))));
        uint256[] memory allRandomness = new uint256[](QuarticWhirFixedConfig.FINAL_SUMCHECK_ROUNDS);
        uint256 g = gasleft();
        WhirVerifierCore4._verifySumcheck(
            proof.finalSumcheck,
            challenger,
            KoalaBearExt4.fromBase(9),
            QuarticWhirFixedConfig.FINAL_SUMCHECK_ROUNDS,
            QuarticWhirFixedConfig.FINAL_FOLDING_POW_BITS,
            allRandomness,
            0
        );
        gasFinalSumcheck = g - gasleft();
    }

    struct FullBreakdown {
        uint256 setup;
        uint256 initialSumcheck;
        uint256 round0Parse;
        uint256 round0Stir;
        uint256 round0Sumcheck;
        uint256 round1Parse;
        uint256 round1Stir;
        uint256 round1Sumcheck;
        uint256 observeFinalPoly;
        uint256 finalStir;
        uint256 finalSelect;
        uint256 finalSumcheck;
        uint256 constraintsFixedSelect;
        uint256 constraintsInitial;
        uint256 constraints;
        uint256 finalCheck;
    }

    struct RoundStepResult {
        WhirVerifierCore4.FixedParsedCommitment nextCommitment;
        WhirVerifierCore4.FixedConstraint constraint;
        uint256 claimedEval;
        uint256[] foldingRandomness;
        uint256 randomnessCursor;
        uint256 gasParse;
        uint256 gasStir;
        uint256 gasSumcheck;
    }

    function profileFullBreakdown(
        bytes32 expectedCommitment,
        WhirStructs.WhirStatement calldata statement,
        WhirStructs.WhirProof calldata proof
    ) external view returns (FullBreakdown memory bd) {
        uint256 g;
        KeccakChallenger.State memory challenger;
        uint256 claimedEval;
        uint256[] memory foldingRandomness;
        uint256[] memory finalSumcheckRandomness;
        uint256 round0ConstraintChallenge;
        uint256[] memory round0EqFlatPoints;
        uint256[] memory round0SelVars;
        uint256 round1ConstraintChallenge;
        uint256[] memory round1EqFlatPoints;
        uint256[] memory round1SelVars;
        uint256[] memory allRandomness = new uint256[](QuarticWhirFixedConfig.NUM_VARIABLES);
        uint256 randomnessCursor;
        WhirVerifierCore4.FixedParsedCommitment memory prevCommitment;

        // --- Setup: observePattern + parseCommitment + combineInitialConstraintEvals ---
        g = gasleft();
        QuarticWhirFixedConfig.observePattern(challenger);
        prevCommitment = WhirVerifierCore4._parseFixedCommitment(
            challenger,
            proof.initialCommitment,
            proof.initialOodAnswers,
            QuarticWhirFixedConfig.NUM_VARIABLES,
            QuarticWhirFixedConfig.COMMITMENT_OOD_SAMPLES
        );
        require(prevCommitment.root == expectedCommitment, "COMMITMENT");
        WhirVerifierCore4.FixedParsedCommitment memory initialParsedCommitment = prevCommitment;
        uint256 initialConstraintChallenge = WhirVerifierUtils4.sampleExt4(challenger);
        {
            require(
                statement.points.length == 1 && statement.evaluations.length == 1,
                "FIXED_STATEMENT_COUNT"
            );
            uint256 evalValue = statement.evaluations[0];
            WhirVerifierUtils4.validatePackedExt4(evalValue);
            claimedEval = WhirVerifierCore4._hornerStep(
                WhirVerifierCore4._hornerStep(
                    WhirVerifierCore4._hornerStep(
                        0, initialConstraintChallenge, proof.initialOodAnswers[1]
                    ),
                    initialConstraintChallenge,
                    proof.initialOodAnswers[0]
                ),
                initialConstraintChallenge,
                evalValue
            );
        }
        bd.setup = g - gasleft();

        // --- Initial Sumcheck ---
        g = gasleft();
        (claimedEval, foldingRandomness, randomnessCursor) = WhirVerifierCore4._verifySumcheck(
            proof.initialSumcheck,
            challenger,
            claimedEval,
            QuarticWhirFixedConfig.INITIAL_SUMCHECK_ROUNDS,
            QuarticWhirFixedConfig.STARTING_FOLDING_POW_BITS,
            allRandomness,
            0
        );
        bd.initialSumcheck = g - gasleft();

        // --- Round 0 ---
        {
            RoundStepResult memory step = _profileRoundStep(
                challenger,
                prevCommitment.root,
                claimedEval,
                foldingRandomness,
                allRandomness,
                randomnessCursor,
                proof.rounds[0],
                QuarticWhirFixedConfig.roundConfig(0),
                QuarticWhirFixedConfig.ROUND_COUNT > 1
                    ? QuarticWhirFixedConfig.roundConfig(1).foldingFactor
                    : QuarticWhirFixedConfig.FINAL_FOLDING_FACTOR,
                0
            );
            prevCommitment = step.nextCommitment;
            claimedEval = step.claimedEval;
            foldingRandomness = step.foldingRandomness;
            randomnessCursor = step.randomnessCursor;
            bd.round0Parse = step.gasParse;
            bd.round0Stir = step.gasStir;
            bd.round0Sumcheck = step.gasSumcheck;
            round0ConstraintChallenge = step.constraint.challenge;
            round0EqFlatPoints = step.constraint.eqFlatPoints;
            round0SelVars = step.constraint.selVars;
        }

        // --- Round 1 ---
        if (QuarticWhirFixedConfig.ROUND_COUNT > 1) {
            RoundStepResult memory step = _profileRoundStep(
                challenger,
                prevCommitment.root,
                claimedEval,
                foldingRandomness,
                allRandomness,
                randomnessCursor,
                proof.rounds[1],
                QuarticWhirFixedConfig.roundConfig(1),
                QuarticWhirFixedConfig.FINAL_FOLDING_FACTOR,
                1
            );
            prevCommitment = step.nextCommitment;
            claimedEval = step.claimedEval;
            foldingRandomness = step.foldingRandomness;
            randomnessCursor = step.randomnessCursor;
            bd.round1Parse = step.gasParse;
            bd.round1Stir = step.gasStir;
            bd.round1Sumcheck = step.gasSumcheck;
            round1ConstraintChallenge = step.constraint.challenge;
            round1EqFlatPoints = step.constraint.eqFlatPoints;
            round1SelVars = step.constraint.selVars;
        }

        // --- Observe Final Poly ---
        g = gasleft();
        challenger.observeValidatedPackedExt4Slice(proof.finalPoly);
        bd.observeFinalPoly = g - gasleft();

        // --- Final STIR ---
        g = gasleft();
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
            1,
            proof.finalPoly
        );
        bd.finalStir = g - gasleft();

        // --- Final Select ---
        bd.finalSelect = 0;

        // --- Final Sumcheck ---
        g = gasleft();
        (claimedEval, finalSumcheckRandomness, randomnessCursor) = WhirVerifierCore4._verifySumcheck(
            proof.finalSumcheck,
            challenger,
            claimedEval,
            QuarticWhirFixedConfig.FINAL_SUMCHECK_ROUNDS,
            QuarticWhirFixedConfig.FINAL_FOLDING_POW_BITS,
            allRandomness,
            randomnessCursor
        );
        bd.finalSumcheck = g - gasleft();

        // --- Evaluate Constraints ---
        uint256 evaluationOfWeights;
        g = gasleft();
        evaluationOfWeights = QuarticWhirFixedConfig.ROUND_COUNT > 1
            ? WhirVerifierCore4._evaluateConstraintsFixedSelectRaw(
                round0ConstraintChallenge,
                round0EqFlatPoints,
                round0SelVars,
                round1ConstraintChallenge,
                round1EqFlatPoints,
                round1SelVars,
                allRandomness
            )
            : WhirVerifierCore4._evaluateConstraintGenericRaw(
                round0ConstraintChallenge, round0EqFlatPoints, round0SelVars, allRandomness
            );
        bd.constraintsFixedSelect = g - gasleft();

        g = gasleft();
        {
            uint256[] memory oodFlatPoints = initialParsedCommitment.oodFlatPoints;
            require(
                statement.points.length == 1 && statement.evaluations.length == 1,
                "FIXED_STATEMENT_COUNT"
            );
            require(
                statement.points[0].length == QuarticWhirFixedConfig.NUM_VARIABLES,
                "FIXED_STATEMENT_ARITY"
            );
            WhirVerifierUtils4.validatePackedExt4Calldata(statement.points[0]);
            uint256 initEval = WhirVerifierCore4._hornerStep(
                WhirVerifierCore4._hornerStep(
                    WhirVerifierCore4._hornerStep(
                        0,
                        initialConstraintChallenge,
                        WhirVerifierCore4._eqPolyEvalAt(
                            oodFlatPoints,
                            QuarticWhirFixedConfig.NUM_VARIABLES,
                            allRandomness,
                            0,
                            QuarticWhirFixedConfig.NUM_VARIABLES
                        )
                    ),
                    initialConstraintChallenge,
                    WhirVerifierCore4._eqPolyEvalAt(
                        oodFlatPoints, 0, allRandomness, 0, QuarticWhirFixedConfig.NUM_VARIABLES
                    )
                ),
                initialConstraintChallenge,
                WhirVerifierCore4._eqPolyEvalAtCalldata(
                    statement.points[0], allRandomness, 0, QuarticWhirFixedConfig.NUM_VARIABLES
                )
            );
            evaluationOfWeights = KoalaBearExt4.add(evaluationOfWeights, initEval);
        }
        bd.constraintsInitial = g - gasleft();
        bd.constraints = bd.constraintsFixedSelect + bd.constraintsInitial;

        // --- Final Check ---
        g = gasleft();
        {
            uint256 finalValue =
                WhirVerifierCore4._evaluateFinalValue(proof.finalPoly, finalSumcheckRandomness);
            uint256 expected = KoalaBearExt4.mul(evaluationOfWeights, finalValue);
            require(claimedEval == expected, "FINAL_CHECK");
        }
        bd.finalCheck = g - gasleft();
    }

    function _profileRoundStep(
        KeccakChallenger.State memory challenger,
        bytes32 expectedRoot,
        uint256 claimedEval,
        uint256[] memory foldingRandomness,
        uint256[] memory allRandomness,
        uint256 randomnessCursor,
        WhirStructs.WhirRoundProof calldata rp,
        QuarticWhirFixedConfig.RoundConfig memory rc,
        uint256 nextFoldingFactor,
        uint8 expectedKind
    ) internal view returns (RoundStepResult memory step) {
        uint256 g = gasleft();
        step.nextCommitment = WhirVerifierCore4._parseFixedCommitment(
            challenger, rp.commitment, rp.oodAnswers, rc.numVariables, rc.oodSamples
        );
        step.gasParse = g - gasleft();

        g = gasleft();
        (uint256 challenge, uint256 roundContribution, uint256[] memory selVars) = WhirVerifierCore4._verifyStirAndCombineConstraint(
            challenger,
            expectedRoot,
            rc.powBits,
            rc.numQueries,
            rc.foldingFactor,
            rc.domainSize,
            rc.foldedDomainGen,
            rp.queryBatch,
            true,
            rp.powWitness,
            foldingRandomness,
            expectedKind,
            rp.oodAnswers
        );
        step.gasStir = g - gasleft();

        step.constraint = WhirVerifierCore4.FixedConstraint({
            challenge: challenge, eqFlatPoints: step.nextCommitment.oodFlatPoints, selVars: selVars
        });
        step.claimedEval = KoalaBearExt4.add(claimedEval, roundContribution);

        g = gasleft();
        (step.claimedEval, step.foldingRandomness, step.randomnessCursor) =
            WhirVerifierCore4._verifySumcheck(
                rp.sumcheck,
                challenger,
                step.claimedEval,
                nextFoldingFactor,
                rc.foldingPowBits,
                allRandomness,
                randomnessCursor
            );
        step.gasSumcheck = g - gasleft();
    }

    function profileStirBreakdowns(
        bytes32 expectedCommitment,
        WhirStructs.WhirStatement calldata statement,
        WhirStructs.WhirProof calldata proof
    )
        external
        view
        returns (
            StirBreakdown memory round0,
            StirBreakdown memory round1,
            StirBreakdown memory finalBd
        )
    {
        KeccakChallenger.State memory challenger;
        QuarticWhirFixedConfig.observePattern(challenger);

        WhirVerifierCore4.ParsedCommitment memory prevCommitment = WhirVerifierCore4._parseCommitment(
            challenger,
            proof.initialCommitment,
            proof.initialOodAnswers,
            QuarticWhirFixedConfig.NUM_VARIABLES,
            QuarticWhirFixedConfig.COMMITMENT_OOD_SAMPLES
        );
        require(prevCommitment.root == expectedCommitment, "COMMITMENT");

        WhirVerifierCore4.Constraint[] memory cArr = new WhirVerifierCore4.Constraint[](3);
        uint256 cCount = 1;

        WhirVerifierCore4.EqStatement memory initialEq = WhirVerifierCore4._concatenateEq(
            WhirVerifierCore4._statementFromCalldata(
                statement, QuarticWhirFixedConfig.NUM_VARIABLES
            ),
            prevCommitment.oodStatement
        );
        cArr[0] = WhirVerifierCore4.Constraint({
            challenge: WhirVerifierUtils4.sampleExt4(challenger),
            eqStatement: initialEq,
            selStatement: WhirVerifierCore4._emptySelect(QuarticWhirFixedConfig.NUM_VARIABLES)
        });

        uint256 claimedEval = WhirVerifierCore4._combineConstraintEvals(0, cArr[0]);
        uint256[] memory allRandomness = new uint256[](QuarticWhirFixedConfig.NUM_VARIABLES);
        uint256 randomnessCursor;
        uint256[] memory foldingRandomness;

        (claimedEval, foldingRandomness, randomnessCursor) = WhirVerifierCore4._verifySumcheck(
            proof.initialSumcheck,
            challenger,
            claimedEval,
            QuarticWhirFixedConfig.INITIAL_SUMCHECK_ROUNDS,
            QuarticWhirFixedConfig.STARTING_FOLDING_POW_BITS,
            allRandomness,
            0
        );

        {
            QuarticWhirFixedConfig.RoundConfig memory rc = QuarticWhirFixedConfig.roundConfig(0);
            WhirStructs.WhirRoundProof calldata rp = proof.rounds[0];
            WhirVerifierCore4.ParsedCommitment memory nc = WhirVerifierCore4._parseCommitment(
                challenger, rp.commitment, rp.oodAnswers, rc.numVariables, rc.oodSamples
            );
            WhirVerifierCore4.SelectStatement memory ss;
            (ss, round0) = _profileStirChallengesRaw(
                challenger,
                prevCommitment.root,
                rc.powBits,
                rc.numQueries,
                rc.numVariables,
                rc.foldingFactor,
                rc.domainSize,
                rc.foldedDomainGen,
                rp.queryBatch,
                true,
                rp.powWitness,
                foldingRandomness,
                true,
                0,
                uint8(QuarticWhirFixedConfig.EFFECTIVE_DIGEST_BYTES)
            );

            cArr[cCount] = WhirVerifierCore4.Constraint({
                challenge: WhirVerifierUtils4.sampleExt4(challenger),
                eqStatement: nc.oodStatement,
                selStatement: ss
            });
            claimedEval = WhirVerifierCore4._combineConstraintEvals(claimedEval, cArr[cCount]);
            cCount += 1;

            (claimedEval, foldingRandomness, randomnessCursor) = WhirVerifierCore4._verifySumcheck(
                rp.sumcheck,
                challenger,
                claimedEval,
                QuarticWhirFixedConfig.ROUND_COUNT > 1
                    ? QuarticWhirFixedConfig.roundConfig(1).foldingFactor
                    : QuarticWhirFixedConfig.FINAL_FOLDING_FACTOR,
                rc.foldingPowBits,
                allRandomness,
                randomnessCursor
            );

            prevCommitment = nc;
        }

        if (QuarticWhirFixedConfig.ROUND_COUNT > 1) {
            QuarticWhirFixedConfig.RoundConfig memory rc = QuarticWhirFixedConfig.roundConfig(1);
            WhirStructs.WhirRoundProof calldata rp = proof.rounds[1];
            WhirVerifierCore4.ParsedCommitment memory nc = WhirVerifierCore4._parseCommitment(
                challenger, rp.commitment, rp.oodAnswers, rc.numVariables, rc.oodSamples
            );
            WhirVerifierCore4.SelectStatement memory ss;
            (ss, round1) = _profileStirChallengesRaw(
                challenger,
                prevCommitment.root,
                rc.powBits,
                rc.numQueries,
                rc.numVariables,
                rc.foldingFactor,
                rc.domainSize,
                rc.foldedDomainGen,
                rp.queryBatch,
                true,
                rp.powWitness,
                foldingRandomness,
                true,
                1,
                uint8(QuarticWhirFixedConfig.EFFECTIVE_DIGEST_BYTES)
            );

            cArr[cCount] = WhirVerifierCore4.Constraint({
                challenge: WhirVerifierUtils4.sampleExt4(challenger),
                eqStatement: nc.oodStatement,
                selStatement: ss
            });
            claimedEval = WhirVerifierCore4._combineConstraintEvals(claimedEval, cArr[cCount]);
            cCount += 1;

            (claimedEval, foldingRandomness, randomnessCursor) = WhirVerifierCore4._verifySumcheck(
                rp.sumcheck,
                challenger,
                claimedEval,
                QuarticWhirFixedConfig.FINAL_FOLDING_FACTOR,
                rc.foldingPowBits,
                allRandomness,
                randomnessCursor
            );

            prevCommitment = nc;
        }

        unchecked {
            for (uint256 i = 0; i < proof.finalPoly.length; ++i) {
                WhirVerifierUtils4.observeValidatedExt4(challenger, proof.finalPoly[i]);
            }
        }

        (, finalBd) = _profileStirChallengesRaw(
            challenger,
            prevCommitment.root,
            QuarticWhirFixedConfig.FINAL_POW_BITS,
            QuarticWhirFixedConfig.FINAL_NUM_QUERIES,
            QuarticWhirFixedConfig.FINAL_NUM_VARIABLES,
            QuarticWhirFixedConfig.FINAL_FOLDING_FACTOR,
            QuarticWhirFixedConfig.FINAL_DOMAIN_SIZE,
            QuarticWhirFixedConfig.FINAL_FOLDED_DOMAIN_GEN,
            proof.finalQueryBatch,
            proof.finalQueryBatchPresent,
            proof.finalPowWitness,
            foldingRandomness,
            false,
            QuarticWhirFixedConfig.ROUND_COUNT == 0 ? 0 : 1,
            uint8(QuarticWhirFixedConfig.EFFECTIVE_DIGEST_BYTES)
        );
    }

    function profileRound0StirOnly(
        bytes32 expectedCommitment,
        WhirStructs.WhirStatement calldata statement,
        WhirStructs.WhirProof calldata proof
    ) external view returns (uint256 gasRound0Stir) {
        KeccakChallenger.State memory challenger;
        QuarticWhirFixedConfig.observePattern(challenger);

        WhirVerifierCore4.ParsedCommitment memory prevCommitment = WhirVerifierCore4._parseCommitment(
            challenger,
            proof.initialCommitment,
            proof.initialOodAnswers,
            QuarticWhirFixedConfig.NUM_VARIABLES,
            QuarticWhirFixedConfig.COMMITMENT_OOD_SAMPLES
        );
        require(prevCommitment.root == expectedCommitment, "COMMITMENT");

        WhirVerifierCore4.Constraint[] memory cArr = new WhirVerifierCore4.Constraint[](1);
        cArr[0] = WhirVerifierCore4.Constraint({
            challenge: WhirVerifierUtils4.sampleExt4(challenger),
            eqStatement: WhirVerifierCore4._concatenateEq(
                WhirVerifierCore4._statementFromCalldata(
                    statement, QuarticWhirFixedConfig.NUM_VARIABLES
                ),
                prevCommitment.oodStatement
            ),
            selStatement: WhirVerifierCore4._emptySelect(QuarticWhirFixedConfig.NUM_VARIABLES)
        });

        uint256 claimedEval = WhirVerifierCore4._combineConstraintEvals(0, cArr[0]);
        uint256[] memory allRandomness = new uint256[](QuarticWhirFixedConfig.NUM_VARIABLES);
        uint256[] memory foldingRandomness;

        (claimedEval, foldingRandomness,) = WhirVerifierCore4._verifySumcheck(
            proof.initialSumcheck,
            challenger,
            claimedEval,
            QuarticWhirFixedConfig.INITIAL_SUMCHECK_ROUNDS,
            QuarticWhirFixedConfig.STARTING_FOLDING_POW_BITS,
            allRandomness,
            0
        );

        QuarticWhirFixedConfig.RoundConfig memory rc = QuarticWhirFixedConfig.roundConfig(0);
        WhirStructs.WhirRoundProof calldata rp = proof.rounds[0];
        WhirVerifierCore4._parseCommitment(
            challenger, rp.commitment, rp.oodAnswers, rc.numVariables, rc.oodSamples
        );
        uint256 g = gasleft();
        WhirVerifierCore4._verifyStirChallengesRaw(
            challenger,
            prevCommitment.root,
            rc.powBits,
            rc.numQueries,
            rc.numVariables,
            rc.foldingFactor,
            rc.domainSize,
            rc.foldedDomainGen,
            rp.queryBatch,
            true,
            rp.powWitness,
            foldingRandomness,
            true,
            0
        );
        gasRound0Stir = g - gasleft();
        require(claimedEval != 0, "PROFILE_ZERO_CLAIM");
    }

    function profileRound1StirOnly(
        bytes32 expectedCommitment,
        WhirStructs.WhirStatement calldata statement,
        WhirStructs.WhirProof calldata proof
    ) external view returns (uint256 gasRound1Stir) {
        if (QuarticWhirFixedConfig.ROUND_COUNT < 2) {
            return 0;
        }

        KeccakChallenger.State memory challenger;
        QuarticWhirFixedConfig.observePattern(challenger);

        WhirVerifierCore4.ParsedCommitment memory prevCommitment = WhirVerifierCore4._parseCommitment(
            challenger,
            proof.initialCommitment,
            proof.initialOodAnswers,
            QuarticWhirFixedConfig.NUM_VARIABLES,
            QuarticWhirFixedConfig.COMMITMENT_OOD_SAMPLES
        );
        require(prevCommitment.root == expectedCommitment, "COMMITMENT");

        WhirVerifierCore4.Constraint[] memory cArr = new WhirVerifierCore4.Constraint[](2);
        cArr[0] = WhirVerifierCore4.Constraint({
            challenge: WhirVerifierUtils4.sampleExt4(challenger),
            eqStatement: WhirVerifierCore4._concatenateEq(
                WhirVerifierCore4._statementFromCalldata(
                    statement, QuarticWhirFixedConfig.NUM_VARIABLES
                ),
                prevCommitment.oodStatement
            ),
            selStatement: WhirVerifierCore4._emptySelect(QuarticWhirFixedConfig.NUM_VARIABLES)
        });

        uint256 claimedEval = WhirVerifierCore4._combineConstraintEvals(0, cArr[0]);
        uint256[] memory allRandomness = new uint256[](QuarticWhirFixedConfig.NUM_VARIABLES);
        uint256 randomnessCursor;
        uint256[] memory foldingRandomness;

        (claimedEval, foldingRandomness, randomnessCursor) = WhirVerifierCore4._verifySumcheck(
            proof.initialSumcheck,
            challenger,
            claimedEval,
            QuarticWhirFixedConfig.INITIAL_SUMCHECK_ROUNDS,
            QuarticWhirFixedConfig.STARTING_FOLDING_POW_BITS,
            allRandomness,
            0
        );

        {
            QuarticWhirFixedConfig.RoundConfig memory rc0 = QuarticWhirFixedConfig.roundConfig(0);
            WhirStructs.WhirRoundProof calldata rp0 = proof.rounds[0];
            WhirVerifierCore4.ParsedCommitment memory nc0 = WhirVerifierCore4._parseCommitment(
                challenger, rp0.commitment, rp0.oodAnswers, rc0.numVariables, rc0.oodSamples
            );
            WhirVerifierCore4.SelectStatement memory ss0 = WhirVerifierCore4._verifyStirChallengesRaw(
                challenger,
                prevCommitment.root,
                rc0.powBits,
                rc0.numQueries,
                rc0.numVariables,
                rc0.foldingFactor,
                rc0.domainSize,
                rc0.foldedDomainGen,
                rp0.queryBatch,
                true,
                rp0.powWitness,
                foldingRandomness,
                true,
                0
            );

            cArr[1] = WhirVerifierCore4.Constraint({
                challenge: WhirVerifierUtils4.sampleExt4(challenger),
                eqStatement: nc0.oodStatement,
                selStatement: ss0
            });
            claimedEval = WhirVerifierCore4._combineConstraintEvals(claimedEval, cArr[1]);

            (claimedEval, foldingRandomness, randomnessCursor) = WhirVerifierCore4._verifySumcheck(
                rp0.sumcheck,
                challenger,
                claimedEval,
                QuarticWhirFixedConfig.ROUND_COUNT > 1
                    ? QuarticWhirFixedConfig.roundConfig(1).foldingFactor
                    : QuarticWhirFixedConfig.FINAL_FOLDING_FACTOR,
                rc0.foldingPowBits,
                allRandomness,
                randomnessCursor
            );

            prevCommitment = nc0;
        }

        QuarticWhirFixedConfig.RoundConfig memory rc1 = QuarticWhirFixedConfig.roundConfig(1);
        WhirStructs.WhirRoundProof calldata rp1 = proof.rounds[1];
        WhirVerifierCore4._parseCommitment(
            challenger, rp1.commitment, rp1.oodAnswers, rc1.numVariables, rc1.oodSamples
        );
        uint256 g = gasleft();
        WhirVerifierCore4._verifyStirChallengesRaw(
            challenger,
            prevCommitment.root,
            rc1.powBits,
            rc1.numQueries,
            rc1.numVariables,
            rc1.foldingFactor,
            rc1.domainSize,
            rc1.foldedDomainGen,
            rp1.queryBatch,
            true,
            rp1.powWitness,
            foldingRandomness,
            true,
            1
        );
        gasRound1Stir = g - gasleft();
        require(claimedEval != 0, "PROFILE_ZERO_CLAIM");
    }

    function profileFinalStirOnly(
        bytes32 expectedCommitment,
        WhirStructs.WhirStatement calldata statement,
        WhirStructs.WhirProof calldata proof
    ) external view returns (uint256 gasFinalStir) {
        KeccakChallenger.State memory challenger;
        QuarticWhirFixedConfig.observePattern(challenger);

        WhirVerifierCore4.Constraint[] memory cArr = new WhirVerifierCore4.Constraint[](3);
        uint256[] memory allRandomness = new uint256[](QuarticWhirFixedConfig.NUM_VARIABLES);
        uint256[] memory foldingRandomness;
        uint256 claimedEval;
        uint256 randomnessCursor;
        WhirVerifierCore4.ParsedCommitment memory prevCommitment = WhirVerifierCore4._parseCommitment(
            challenger,
            proof.initialCommitment,
            proof.initialOodAnswers,
            QuarticWhirFixedConfig.NUM_VARIABLES,
            QuarticWhirFixedConfig.COMMITMENT_OOD_SAMPLES
        );
        require(prevCommitment.root == expectedCommitment, "COMMITMENT");

        cArr[0] = WhirVerifierCore4.Constraint({
            challenge: WhirVerifierUtils4.sampleExt4(challenger),
            eqStatement: WhirVerifierCore4._concatenateEq(
                WhirVerifierCore4._statementFromCalldata(
                    statement, QuarticWhirFixedConfig.NUM_VARIABLES
                ),
                prevCommitment.oodStatement
            ),
            selStatement: WhirVerifierCore4._emptySelect(QuarticWhirFixedConfig.NUM_VARIABLES)
        });
        claimedEval = WhirVerifierCore4._combineConstraintEvals(0, cArr[0]);

        (claimedEval, foldingRandomness, randomnessCursor) = WhirVerifierCore4._verifySumcheck(
            proof.initialSumcheck,
            challenger,
            claimedEval,
            QuarticWhirFixedConfig.INITIAL_SUMCHECK_ROUNDS,
            QuarticWhirFixedConfig.STARTING_FOLDING_POW_BITS,
            allRandomness,
            0
        );

        for (uint256 round = 0; round < proof.rounds.length; ++round) {
            QuarticWhirFixedConfig.RoundConfig memory rc = QuarticWhirFixedConfig.roundConfig(round);
            WhirStructs.WhirRoundProof calldata rp = proof.rounds[round];
            WhirVerifierCore4.ParsedCommitment memory nc = WhirVerifierCore4._parseCommitment(
                challenger, rp.commitment, rp.oodAnswers, rc.numVariables, rc.oodSamples
            );
            WhirVerifierCore4.SelectStatement memory ss = WhirVerifierCore4._verifyStirChallengesRaw(
                challenger,
                prevCommitment.root,
                rc.powBits,
                rc.numQueries,
                rc.numVariables,
                rc.foldingFactor,
                rc.domainSize,
                rc.foldedDomainGen,
                rp.queryBatch,
                true,
                rp.powWitness,
                foldingRandomness,
                true,
                uint8(round)
            );
            cArr[round + 1] = WhirVerifierCore4.Constraint({
                challenge: WhirVerifierUtils4.sampleExt4(challenger),
                eqStatement: nc.oodStatement,
                selStatement: ss
            });
            claimedEval = WhirVerifierCore4._combineConstraintEvals(claimedEval, cArr[round + 1]);
            uint256 nextFoldingFactor = round + 1 < QuarticWhirFixedConfig.ROUND_COUNT
                ? QuarticWhirFixedConfig.roundConfig(round + 1).foldingFactor
                : QuarticWhirFixedConfig.FINAL_FOLDING_FACTOR;
            (claimedEval, foldingRandomness, randomnessCursor) = WhirVerifierCore4._verifySumcheck(
                rp.sumcheck,
                challenger,
                claimedEval,
                nextFoldingFactor,
                rc.foldingPowBits,
                allRandomness,
                randomnessCursor
            );
            prevCommitment = nc;
        }

        unchecked {
            for (uint256 i = 0; i < proof.finalPoly.length; ++i) {
                WhirVerifierUtils4.observeValidatedExt4(challenger, proof.finalPoly[i]);
            }
        }

        uint256 g = gasleft();
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
        gasFinalStir = g - gasleft();
        require(claimedEval != 0, "PROFILE_ZERO_CLAIM");
    }

    function profileConstraintEvaluationOnly(
        bytes32 expectedCommitment,
        WhirStructs.WhirStatement calldata statement,
        WhirStructs.WhirProof calldata proof
    ) external view returns (uint256 gasConstraintEval) {
        KeccakChallenger.State memory challenger;
        QuarticWhirFixedConfig.observePattern(challenger);

        uint256 claimedEval;
        uint256[] memory foldingRandomness;
        uint256[] memory finalSumcheckRandomness;
        uint256 round0ConstraintChallenge;
        uint256[] memory round0EqFlatPoints;
        uint256[] memory round0SelVars;
        uint256 round1ConstraintChallenge;
        uint256[] memory round1EqFlatPoints;
        uint256[] memory round1SelVars;
        uint256[] memory allRandomness = new uint256[](QuarticWhirFixedConfig.NUM_VARIABLES);
        uint256 randomnessCursor;
        WhirVerifierCore4.FixedParsedCommitment memory prevCommitment =
            WhirVerifierCore4._parseFixedCommitment(
                challenger,
                proof.initialCommitment,
                proof.initialOodAnswers,
                QuarticWhirFixedConfig.NUM_VARIABLES,
                QuarticWhirFixedConfig.COMMITMENT_OOD_SAMPLES
            );
        require(prevCommitment.root == expectedCommitment, "COMMITMENT");
        WhirVerifierCore4.FixedParsedCommitment memory initialParsedCommitment = prevCommitment;
        uint256 initialConstraintChallenge = WhirVerifierUtils4.sampleExt4(challenger);
        {
            require(
                statement.points.length == 1 && statement.evaluations.length == 1,
                "FIXED_STATEMENT_COUNT"
            );
            uint256 evalValue = statement.evaluations[0];
            WhirVerifierUtils4.validatePackedExt4(evalValue);
            claimedEval = WhirVerifierCore4._hornerStep(
                WhirVerifierCore4._hornerStep(
                    WhirVerifierCore4._hornerStep(
                        0, initialConstraintChallenge, proof.initialOodAnswers[1]
                    ),
                    initialConstraintChallenge,
                    proof.initialOodAnswers[0]
                ),
                initialConstraintChallenge,
                evalValue
            );
        }

        (claimedEval, foldingRandomness, randomnessCursor) = WhirVerifierCore4._verifySumcheck(
            proof.initialSumcheck,
            challenger,
            claimedEval,
            QuarticWhirFixedConfig.INITIAL_SUMCHECK_ROUNDS,
            QuarticWhirFixedConfig.STARTING_FOLDING_POW_BITS,
            allRandomness,
            0
        );

        for (uint256 round = 0; round < proof.rounds.length; ++round) {
            QuarticWhirFixedConfig.RoundConfig memory rc = QuarticWhirFixedConfig.roundConfig(round);
            WhirStructs.WhirRoundProof calldata rp = proof.rounds[round];
            WhirVerifierCore4.FixedParsedCommitment memory nc =
                WhirVerifierCore4._parseFixedCommitment(
                    challenger, rp.commitment, rp.oodAnswers, rc.numVariables, rc.oodSamples
                );
            (uint256 constraintChallenge, uint256 roundContribution, uint256[] memory stirVars) = WhirVerifierCore4._verifyStirAndCombineConstraint(
                challenger,
                prevCommitment.root,
                rc.powBits,
                rc.numQueries,
                rc.foldingFactor,
                rc.domainSize,
                rc.foldedDomainGen,
                rp.queryBatch,
                true,
                rp.powWitness,
                foldingRandomness,
                uint8(round),
                rp.oodAnswers
            );
            claimedEval = KoalaBearExt4.add(claimedEval, roundContribution);
            if (round == 0) {
                round0ConstraintChallenge = constraintChallenge;
                round0EqFlatPoints = nc.oodFlatPoints;
                round0SelVars = stirVars;
            } else {
                round1ConstraintChallenge = constraintChallenge;
                round1EqFlatPoints = nc.oodFlatPoints;
                round1SelVars = stirVars;
            }
            uint256 nextFoldingFactor = round + 1 < QuarticWhirFixedConfig.ROUND_COUNT
                ? QuarticWhirFixedConfig.roundConfig(round + 1).foldingFactor
                : QuarticWhirFixedConfig.FINAL_FOLDING_FACTOR;
            (claimedEval, foldingRandomness, randomnessCursor) = WhirVerifierCore4._verifySumcheck(
                rp.sumcheck,
                challenger,
                claimedEval,
                nextFoldingFactor,
                rc.foldingPowBits,
                allRandomness,
                randomnessCursor
            );
            prevCommitment = nc;
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
        (claimedEval, finalSumcheckRandomness, randomnessCursor) = WhirVerifierCore4._verifySumcheck(
            proof.finalSumcheck,
            challenger,
            claimedEval,
            QuarticWhirFixedConfig.FINAL_SUMCHECK_ROUNDS,
            QuarticWhirFixedConfig.FINAL_FOLDING_POW_BITS,
            allRandomness,
            randomnessCursor
        );

        uint256 g = gasleft();
        uint256 evaluationOfWeights = QuarticWhirFixedConfig.ROUND_COUNT > 1
            ? WhirVerifierCore4._evaluateConstraintsFixedSelectRaw(
                round0ConstraintChallenge,
                round0EqFlatPoints,
                round0SelVars,
                round1ConstraintChallenge,
                round1EqFlatPoints,
                round1SelVars,
                allRandomness
            )
            : WhirVerifierCore4._evaluateConstraintGenericRaw(
                round0ConstraintChallenge, round0EqFlatPoints, round0SelVars, allRandomness
            );
        {
            uint256[] memory oodFlatPoints = initialParsedCommitment.oodFlatPoints;
            require(
                statement.points.length == 1 && statement.evaluations.length == 1,
                "FIXED_STATEMENT_COUNT"
            );
            require(
                statement.points[0].length == QuarticWhirFixedConfig.NUM_VARIABLES,
                "FIXED_STATEMENT_ARITY"
            );
            WhirVerifierUtils4.validatePackedExt4Calldata(statement.points[0]);
            uint256 initEval = WhirVerifierCore4._hornerStep(
                WhirVerifierCore4._hornerStep(
                    WhirVerifierCore4._hornerStep(
                        0,
                        initialConstraintChallenge,
                        WhirVerifierCore4._eqPolyEvalAt(
                            oodFlatPoints,
                            QuarticWhirFixedConfig.NUM_VARIABLES,
                            allRandomness,
                            0,
                            QuarticWhirFixedConfig.NUM_VARIABLES
                        )
                    ),
                    initialConstraintChallenge,
                    WhirVerifierCore4._eqPolyEvalAt(
                        oodFlatPoints, 0, allRandomness, 0, QuarticWhirFixedConfig.NUM_VARIABLES
                    )
                ),
                initialConstraintChallenge,
                WhirVerifierCore4._eqPolyEvalAtCalldata(
                    statement.points[0], allRandomness, 0, QuarticWhirFixedConfig.NUM_VARIABLES
                )
            );
            evaluationOfWeights = KoalaBearExt4.add(evaluationOfWeights, initEval);
        }
        gasConstraintEval = g - gasleft();

        require(evaluationOfWeights != 0, "PROFILE_ZERO_WEIGHTS");
        require(claimedEval != 0, "PROFILE_ZERO_CLAIM");
        require(finalSumcheckRandomness.length != 0, "PROFILE_EMPTY_FINAL_RANDOMNESS");
    }

    function _profileStirChallengesRaw(
        KeccakChallenger.State memory challenger,
        bytes32 expectedRoot,
        uint256 powBits,
        uint256 numQueries,
        uint256 numVariables,
        uint256 foldingFactor,
        uint256 domainSize,
        uint256 foldedDomainGen,
        WhirStructs.QueryBatchOpening calldata queryBatch,
        bool queryBatchPresent,
        uint256 powWitness,
        uint256[] memory foldingRandomness,
        bool checkpointAfterPow,
        uint8 expectedKind,
        uint8 effectiveDigestBytes
    )
        internal
        view
        returns (WhirVerifierCore4.SelectStatement memory statement, StirBreakdown memory bd)
    {
        uint256 startGas = gasleft();

        if (powBits > 0 && !challenger.checkWitness(powBits, powWitness)) {
            revert WhirVerifierCore4.InvalidPowWitness();
        }

        if (checkpointAfterPow) {
            challenger.sampleBase();
        }

        statement.numVariables = numVariables;

        if (!queryBatchPresent) {
            if (numQueries != 0) {
                revert WhirVerifierCore4.FinalQueryBatchPresenceMismatch(true, false);
            }
            statement.vars = new uint256[](0);
            statement.evaluations = new uint256[](0);
            bd.total = startGas - gasleft();
            bd.overhead = bd.total;
            return (statement, bd);
        }

        uint256 g = gasleft();
        uint256[] memory indices = WhirVerifierUtils4.sampleStirQueries(
            challenger, domainSize, foldingFactor, numQueries
        );
        bd.sampleQueries = g - gasleft();

        if (queryBatch.kind != expectedKind) {
            revert WhirVerifierCore4.QueryBatchKindMismatch(expectedKind, queryBatch.kind);
        }
        if (queryBatch.numQueries != indices.length) {
            revert WhirVerifierCore4.QueryBatchCountMismatch(indices.length, queryBatch.numQueries);
        }

        uint256 expectedRowLen = uint256(1) << foldingFactor;
        if (queryBatch.rowLen != expectedRowLen) {
            revert WhirVerifierCore4.QueryBatchRowLengthMismatch(expectedRowLen, queryBatch.rowLen);
        }

        uint256 depth = WhirVerifierUtils4.log2Strict(domainSize >> foldingFactor);
        bd.queryCount = indices.length;
        bd.rowLen = expectedRowLen;
        bd.depth = depth;

        bytes32[] memory leafHashes = new bytes32[](indices.length);
        g = gasleft();
        unchecked {
            for (uint256 i = 0; i < indices.length; ++i) {
                if (expectedKind == 0) {
                    leafHashes[i] = MerkleVerifier.hashLeafBaseSlice(
                        queryBatch.values,
                        i * queryBatch.rowLen,
                        queryBatch.rowLen,
                        effectiveDigestBytes
                    );
                } else {
                    leafHashes[i] = MerkleVerifier.hashLeafExtensionSlice(
                        queryBatch.values,
                        i * queryBatch.rowLen,
                        queryBatch.rowLen,
                        effectiveDigestBytes
                    );
                }
            }
        }
        bd.leafHashing = g - gasleft();

        g = gasleft();
        bytes32 computedRoot = _computeRootFromLeafHashesProfile(
            indices, leafHashes, depth, queryBatch.decommitments, effectiveDigestBytes
        );
        bd.merkleReduction = g - gasleft();

        if (computedRoot != expectedRoot) {
            revert WhirVerifierCore4.MerkleRootMismatch(expectedRoot, computedRoot);
        }

        statement.vars = new uint256[](indices.length);
        statement.evaluations = new uint256[](indices.length);

        unchecked {
            for (uint256 i = 0; i < indices.length; ++i) {
                g = gasleft();
                statement.vars[i] = KoalaBear.pow(foldedDomainGen, indices[i]);
                bd.pow += g - gasleft();

                uint256 rowStart = i * queryBatch.rowLen;
                g = gasleft();
                statement.evaluations[i] = expectedKind == 0
                    ? WhirVerifierUtils4.evaluateBaseRowAsExt4(
                        queryBatch.values, rowStart, queryBatch.rowLen, foldingRandomness
                    )
                    : WhirVerifierUtils4.evaluateExtensionRowAsExt4(
                        queryBatch.values, rowStart, queryBatch.rowLen, foldingRandomness
                    );
                bd.rowFolding += g - gasleft();
            }
        }

        bd.total = startGas - gasleft();
        uint256 measured =
            bd.sampleQueries + bd.leafHashing + bd.merkleReduction + bd.pow + bd.rowFolding;
        bd.overhead = bd.total - measured;
    }

    function _computeRootFromLeafHashesProfile(
        uint256[] memory indices,
        bytes32[] memory leafHashes,
        uint256 depth,
        bytes32[] calldata decommitments,
        uint256 effectiveDigestBytes
    ) internal pure returns (bytes32) {
        require(indices.length != 0, "EMPTY_INDICES");
        require(indices.length == leafHashes.length, "LEN_MISMATCH");

        unchecked {
            for (uint256 i = 1; i < indices.length; ++i) {
                require(indices[i - 1] < indices[i], "UNSORTED");
            }
        }

        uint256 frontierLen = indices.length;
        uint256[] memory frontierIndices = new uint256[](frontierLen);
        bytes32[] memory frontierHashes = new bytes32[](frontierLen);

        unchecked {
            for (uint256 i = 0; i < frontierLen; ++i) {
                frontierIndices[i] = indices[i];
                frontierHashes[i] = leafHashes[i];
            }
        }

        uint256[] memory nextIndices = new uint256[](frontierLen);
        bytes32[] memory nextHashes = new bytes32[](frontierLen);
        uint256 decommitmentCursor = 0;

        for (uint256 level = 0; level < depth; ++level) {
            uint256 nextLen = 0;
            uint256 cursor = 0;

            while (cursor < frontierLen) {
                uint256 node = frontierIndices[cursor];
                bytes32 hash = frontierHashes[cursor];
                uint256 nextCursor = cursor + 1;
                bool nodeIsRight = (node & 1) != 0;
                bytes32 parentHash;

                if (
                    !nodeIsRight && nextCursor < frontierLen
                        && frontierIndices[nextCursor] == node + 1
                ) {
                    parentHash = MerkleVerifier.compressNode(
                        hash, frontierHashes[nextCursor], effectiveDigestBytes
                    );
                    nextCursor += 1;
                } else {
                    require(decommitmentCursor < decommitments.length, "INSUFFICIENT_DECOMMITMENTS");
                    bytes32 siblingHash = decommitments[decommitmentCursor];
                    decommitmentCursor += 1;

                    parentHash = !nodeIsRight
                        ? MerkleVerifier.compressNode(hash, siblingHash, effectiveDigestBytes)
                        : MerkleVerifier.compressNode(siblingHash, hash, effectiveDigestBytes);
                }

                cursor = nextCursor;
                uint256 parentIndex = node >> 1;
                bool sameParent = nextLen > 0 && nextIndices[nextLen - 1] == parentIndex;
                if (sameParent) {
                    nextHashes[nextLen - 1] = parentHash;
                } else {
                    nextIndices[nextLen] = parentIndex;
                    nextHashes[nextLen] = parentHash;
                    nextLen += 1;
                }
            }

            uint256[] memory tempIndices = frontierIndices;
            frontierIndices = nextIndices;
            nextIndices = tempIndices;

            bytes32[] memory tempHashes = frontierHashes;
            frontierHashes = nextHashes;
            nextHashes = tempHashes;

            frontierLen = nextLen;
        }

        require(decommitmentCursor == decommitments.length, "TRAILING_DECOMMITMENTS");
        require(frontierLen == 1 && frontierIndices[0] == 0, "INVALID_FINAL");
        return frontierHashes[0];
    }

    function profileStirMicro(uint256[] calldata baseValues16, uint256[] calldata extValues16)
        external
        view
        returns (
            uint256 gasHashLeafBase16,
            uint256 gasHashLeafExt16,
            uint256 gasCompressNode,
            uint256 gasPow,
            uint256 gasSampleStirQueries9
        )
    {
        uint256 g;

        g = gasleft();
        for (uint256 i = 0; i < 100; ++i) {
            MerkleVerifier.hashLeafBaseSlice(baseValues16, 0, 16, 20);
        }
        gasHashLeafBase16 = (g - gasleft()) / 100;

        g = gasleft();
        for (uint256 i = 0; i < 100; ++i) {
            MerkleVerifier.hashLeafExtensionSlice(extValues16, 0, 16, 20);
        }
        gasHashLeafExt16 = (g - gasleft()) / 100;

        g = gasleft();
        for (uint256 i = 0; i < 100; ++i) {
            MerkleVerifier.compressNode(bytes32(uint256(i + 1)), bytes32(uint256(i + 42)), 20);
        }
        gasCompressNode = (g - gasleft()) / 100;

        g = gasleft();
        uint256 powSink;
        for (uint256 i = 0; i < 100; ++i) {
            powSink += KoalaBear.pow(1_848_593_786, 100_000 + i * 2718);
        }
        gasPow = (g - gasleft()) / 100;
        require(powSink != 0, "SINK");

        g = gasleft();
        uint256 qsSink;
        for (uint256 i = 0; i < 10; ++i) {
            KeccakChallenger.State memory ch;
            ch.observeBytes(abi.encodePacked(bytes32(uint256(42 + i))));
            uint256[] memory qs = WhirVerifierUtils4.sampleStirQueries(ch, 4_194_304, 4, 9);
            qsSink += qs.length;
        }
        gasSampleStirQueries9 = (g - gasleft()) / 10;
        require(qsSink != 0, "SINK");
    }
}

contract WhirGasProfileTest is Test {
    using KeccakChallenger for KeccakChallenger.State;

    string internal constant TESTDATA = "testdata/";
    WhirProfileHarness internal harness;
    WhirVerifier4 internal verifier;

    function setUp() external {
        harness = new WhirProfileHarness();
        verifier = new WhirVerifier4();
    }

    function testProfileWhirVerify() external view {
        (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof) =
            _loadSuccessFixture();

        uint256 gasParseCommitment = harness.profileParseCommitment(proof.initialCommitment, proof);

        uint256 g = gasleft();
        assertTrue(verifier.verify(proof.initialCommitment, statement, proof));
        uint256 gasVerify = g - gasleft();

        console.log("=== WHIR Verification Gas Profile ===");
        console.log("Parse commitment:     ", gasParseCommitment);
        console.log("Total verify:         ", gasVerify);
        console.log("Remainder:            ", gasVerify - gasParseCommitment);
    }

    function testProfileWhirHotspots() external view {
        (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof) =
            _loadSuccessFixture();

        (uint256 gasParseCommitment, uint256 gasStatementFromCalldata, uint256 gasConcatEq) =
            harness.profileConstraintPreparation(proof.initialCommitment, statement, proof);
        uint256 gasInitialSumcheck =
            harness.profileInitialSumcheck(proof.initialCommitment, statement, proof);
        uint256 gasObserveFinalPoly =
            harness.profileObserveFinalPoly(proof.initialCommitment, statement, proof);
        uint256 gasFinalSumcheck = harness.profileStandaloneFinalSumcheck(proof);

        console.log("=== WHIR Hotspot Profile ===");
        console.log("Parse commitment:      ", gasParseCommitment);
        console.log("Statement copy:        ", gasStatementFromCalldata);
        console.log("Eq concat:             ", gasConcatEq);
        console.log("Initial sumcheck:      ", gasInitialSumcheck);
        console.log("Observe finalPoly:     ", gasObserveFinalPoly);
        console.log("Final sumcheck:        ", gasFinalSumcheck);
    }

    function testProfileMicroBenchmarks() external view {
        uint256 salt = uint256(uint160(address(this)));
        uint256[] memory packedInputs = new uint256[](8);
        unchecked {
            for (uint256 i = 0; i < packedInputs.length; ++i) {
                packedInputs[i] = _runtimePackedExt4(salt, i + 1);
            }
        }

        uint256 gasCheck = gasleft();
        uint256 mulSink;
        for (uint256 i = 0; i < 100; ++i) {
            mulSink |= KoalaBearExt4.mul(packedInputs[i & 7], packedInputs[(i + 3) & 7]);
        }
        uint256 gasMul100 = gasCheck - gasleft();

        gasCheck = gasleft();
        uint256 addSink;
        for (uint256 i = 0; i < 100; ++i) {
            addSink |= KoalaBearExt4.add(packedInputs[i & 7], packedInputs[(i + 3) & 7]);
        }
        uint256 gasAdd100 = gasCheck - gasleft();

        gasCheck = gasleft();
        uint256 subSink;
        for (uint256 i = 0; i < 100; ++i) {
            subSink |= KoalaBearExt4.sub(packedInputs[i & 7], packedInputs[(i + 3) & 7]);
        }
        uint256 gasSub100 = gasCheck - gasleft();

        gasCheck = gasleft();
        uint256 squareSink;
        for (uint256 i = 0; i < 100; ++i) {
            squareSink |= KoalaBearExt4.square(packedInputs[i & 7]);
        }
        uint256 gasSquare100 = gasCheck - gasleft();

        uint256[] memory p = new uint256[](6);
        uint256[] memory q = new uint256[](6);
        for (uint256 i = 0; i < 6; ++i) {
            p[i] = _runtimePackedExt4(salt, (i + 1) * 2);
            q[i] = _runtimePackedExt4(salt, (i + 1) * 2 + 1);
        }
        gasCheck = gasleft();
        uint256 eqSink;
        for (uint256 i = 0; i < 100; ++i) {
            eqSink |= KoalaBearExt4.eq_poly_eval(p, q);
        }
        uint256 gasEqPoly100 = gasCheck - gasleft();

        uint256[] memory point = new uint256[](4);
        for (uint256 i = 0; i < 4; ++i) {
            point[i] = _runtimePackedExt4(salt, 32 + i);
        }
        gasCheck = gasleft();
        uint256 hypercube16Sink;
        for (uint256 i = 0; i < 10; ++i) {
            uint256[] memory evals = _makeRuntimeExt4Evals(salt + i, 16);
            hypercube16Sink |= KoalaBearExt4.evaluate_hypercube(evals, point);
        }
        uint256 gasHypercube10 = gasCheck - gasleft();

        gasCheck = gasleft();
        uint256 sampleBaseSink;
        for (uint256 i = 0; i < 100; ++i) {
            KeccakChallenger.State memory sampleBaseChallenger;
            sampleBaseChallenger.observeBytes(abi.encodePacked(bytes32(uint256(42))));
            sampleBaseSink += sampleBaseChallenger.sampleBase();
        }
        uint256 gasSampleBase100 = gasCheck - gasleft();

        gasCheck = gasleft();
        uint256 sampleExt4Sink;
        for (uint256 i = 0; i < 100; ++i) {
            KeccakChallenger.State memory sampleExt4Challenger;
            sampleExt4Challenger.observeBytes(abi.encodePacked(bytes32(uint256(42))));
            sampleExt4Sink |= WhirVerifierUtils4.sampleExt4(sampleExt4Challenger);
        }
        uint256 gasSampleExt4_100 = gasCheck - gasleft();

        gasCheck = gasleft();
        uint256 sampleBitsSink;
        for (uint256 i = 0; i < 100; ++i) {
            KeccakChallenger.State memory sampleBitsChallenger;
            sampleBitsChallenger.observeBytes(abi.encodePacked(bytes32(uint256(42))));
            sampleBitsSink += sampleBitsChallenger.sampleBits(18);
        }
        uint256 gasSampleBits100 = gasCheck - gasleft();

        KeccakChallenger.State memory ch2;
        ch2.observeBytes(abi.encodePacked(bytes32(uint256(42))));
        gasCheck = gasleft();
        for (uint256 i = 0; i < 100; ++i) {
            ch2.observeBase(uint32(i));
        }
        uint256 gasObserveBase100 = gasCheck - gasleft();

        gasCheck = gasleft();
        uint256 observeExt4Sink;
        for (uint256 i = 0; i < 100; ++i) {
            KeccakChallenger.State memory observeExt4Challenger;
            observeExt4Challenger.observeBytes(abi.encodePacked(bytes32(uint256(42))));
            WhirVerifierUtils4.observeValidatedExt4(observeExt4Challenger, packedInputs[i & 7]);
            observeExt4Sink |= observeExt4Challenger.outputIndex;
        }
        uint256 gasObserveExt4_100 = gasCheck - gasleft();

        gasCheck = gasleft();
        uint256 observeHashU64Sink;
        for (uint256 i = 0; i < 100; ++i) {
            KeccakChallenger.State memory observeDigestChallenger;
            observeDigestChallenger.observeBytes(abi.encodePacked(bytes32(uint256(42))));
            observeDigestChallenger.observeHashU64Digest(bytes32(packedInputs[i & 7]));
            observeHashU64Sink |= observeDigestChallenger.outputIndex;
        }
        uint256 gasObserveHashU64_100 = gasCheck - gasleft();

        gasCheck = gasleft();
        uint256 extrapolateSink;
        for (uint256 i = 0; i < 100; ++i) {
            extrapolateSink |= KoalaBearExt4.extrapolate_012(
                packedInputs[i & 7],
                packedInputs[(i + 1) & 7],
                packedInputs[(i + 2) & 7],
                packedInputs[(i + 3) & 7]
            );
        }
        uint256 gasExtrapolate100 = gasCheck - gasleft();

        uint256[] memory point6 = new uint256[](6);
        for (uint256 i = 0; i < 6; ++i) {
            point6[i] = _runtimePackedExt4(salt, 48 + i);
        }
        gasCheck = gasleft();
        uint256 hypercube64Sink;
        for (uint256 i = 0; i < 10; ++i) {
            uint256[] memory evals64 = _makeRuntimeExt4Evals(salt + i + 32, 64);
            hypercube64Sink |= KoalaBearExt4.evaluate_hypercube(evals64, point6);
        }
        uint256 gasHypercube64_10 = gasCheck - gasleft();
        assertTrue(
            (mulSink | addSink | subSink | squareSink | eqSink | hypercube16Sink | sampleBaseSink
                        | sampleExt4Sink | sampleBitsSink | observeExt4Sink | observeHashU64Sink
                        | extrapolateSink | hypercube64Sink) != 0
        );

        console.log("=== Micro-benchmarks (per-op, averaged) ===");
        console.log("Ext4 mul:               ", gasMul100 / 100);
        console.log("Ext4 add:               ", gasAdd100 / 100);
        console.log("Ext4 sub:               ", gasSub100 / 100);
        console.log("Ext4 square:            ", gasSquare100 / 100);
        console.log("Ext4 extrapolate_012:   ", gasExtrapolate100 / 100);
        console.log("eq_poly_eval (6 vars):  ", gasEqPoly100 / 100);
        console.log("evaluate_hypercube(16): ", gasHypercube10 / 10);
        console.log("evaluate_hypercube(64): ", gasHypercube64_10 / 10);
        console.log("sampleBase:             ", gasSampleBase100 / 100);
        console.log("sampleExt4:             ", gasSampleExt4_100 / 100);
        console.log("sampleBits(18):         ", gasSampleBits100 / 100);
        console.log("observeBase:            ", gasObserveBase100 / 100);
        console.log("observeExt4:            ", gasObserveExt4_100 / 100);
        console.log("observeHashU64Digest:   ", gasObserveHashU64_100 / 100);
    }

    function testProfileFullBreakdown() external view {
        (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof) =
            _loadSuccessFixture();

        WhirProfileHarness.FullBreakdown memory bd =
            harness.profileFullBreakdown(proof.initialCommitment, statement, proof);

        uint256 total = bd.setup + bd.initialSumcheck + bd.round0Parse + bd.round0Stir
            + bd.round0Sumcheck + bd.round1Parse + bd.round1Stir + bd.round1Sumcheck
            + bd.observeFinalPoly + bd.finalStir + bd.finalSelect + bd.finalSumcheck
            + bd.constraints + bd.finalCheck;

        console.log("=== Full Verification Breakdown ===");
        console.log("Setup (pattern+commit+eval):", bd.setup);
        console.log("Initial sumcheck (4r):      ", bd.initialSumcheck);
        console.log("Round0 parse commitment:    ", bd.round0Parse);
        console.log("Round0 STIR (9q d18 base):  ", bd.round0Stir);
        console.log("Round0 sumcheck (4r pow=0): ", bd.round0Sumcheck);
        console.log("Round1 parse commitment:    ", bd.round1Parse);
        console.log("Round1 STIR (6q d17 ext4):  ", bd.round1Stir);
        console.log("Round1 sumcheck (4r pow=4): ", bd.round1Sumcheck);
        console.log("Observe finalPoly (16):     ", bd.observeFinalPoly);
        console.log("Final STIR (5q d16 ext4):   ", bd.finalStir);
        console.log("Final select (5x Horner16): ", bd.finalSelect);
        console.log("Final sumcheck (4r pow=0):  ", bd.finalSumcheck);
        console.log("Constraint fixed select:    ", bd.constraintsFixedSelect);
        console.log("Constraint initial eq:      ", bd.constraintsInitial);
        console.log("Constraint evaluation:      ", bd.constraints);
        console.log("Final value check:          ", bd.finalCheck);
        console.log("---");
        console.log("Sum of phases:              ", total);
    }

    function testProfileConstraintSplit() external view {
        (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof) =
            _loadSuccessFixture();

        WhirProfileHarness.FullBreakdown memory bd =
            harness.profileFullBreakdown(proof.initialCommitment, statement, proof);

        console.log("=== Constraint Split ===");
        console.log("Fixed select:        ", bd.constraintsFixedSelect);
        console.log("Initial constraint:  ", bd.constraintsInitial);
        console.log("Total constraints:   ", bd.constraints);
    }

    function testProfileStirBreakdown() external view {
        (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof) =
            _loadSuccessFixture();

        (
            WhirProfileHarness.StirBreakdown memory round0,
            WhirProfileHarness.StirBreakdown memory round1,
            WhirProfileHarness.StirBreakdown memory finalBd
        ) = harness.profileStirBreakdowns(proof.initialCommitment, statement, proof);

        _logStirBreakdown("Round0", round0);
        _logStirBreakdown("Round1", round1);
        _logStirBreakdown("Final", finalBd);
    }

    function testProfileStirMicro() external view {
        uint256 salt = uint256(uint160(address(this)));

        uint256[] memory baseValues = new uint256[](16);
        for (uint256 i = 0; i < 16; ++i) {
            baseValues[i] = i + 1;
        }

        uint256[] memory extValues = new uint256[](16);
        for (uint256 i = 0; i < 16; ++i) {
            extValues[i] = _runtimePackedExt4(salt, i + 1);
        }

        (
            uint256 gasHashBase,
            uint256 gasHashExt,
            uint256 gasCompress,
            uint256 gasPow,
            uint256 gasSampleQueries
        ) = harness.profileStirMicro(baseValues, extValues);

        console.log("=== STIR Sub-op Micro-benchmarks ===");
        console.log("hashLeafBaseSlice(16):      ", gasHashBase);
        console.log("hashLeafExtSlice(16):       ", gasHashExt);
        console.log("compressNode:               ", gasCompress);
        console.log("KoalaBear.pow(18-bit exp):  ", gasPow);
        console.log("sampleStirQueries(9)+init:  ", gasSampleQueries);
    }

    function testFlameRound0Stir() external view {
        (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof) =
            _loadSuccessFixture();
        uint256 gasRound0 = harness.profileRound0StirOnly(proof.initialCommitment, statement, proof);
        assertGt(gasRound0, 0);
    }

    function testFlameParseCommitment() external view {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        uint256 gasParse = harness.profileParseCommitment(proof.initialCommitment, proof);
        assertGt(gasParse, 0);
    }

    function testFlameConstraintPreparation() external view {
        (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof) =
            _loadSuccessFixture();
        (uint256 gasParseCommitment, uint256 gasStatementFromCalldata, uint256 gasConcatEq) =
            harness.profileConstraintPreparation(proof.initialCommitment, statement, proof);
        assertGt(gasParseCommitment, 0);
        assertGt(gasStatementFromCalldata, 0);
        assertGt(gasConcatEq, 0);
    }

    function testFlameInitialSumcheck() external view {
        (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof) =
            _loadSuccessFixture();
        uint256 gasInitialSumcheck =
            harness.profileInitialSumcheck(proof.initialCommitment, statement, proof);
        assertGt(gasInitialSumcheck, 0);
    }

    function testFlameStandaloneFinalSumcheck() external view {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        uint256 gasFinalSumcheck = harness.profileStandaloneFinalSumcheck(proof);
        assertGt(gasFinalSumcheck, 0);
    }

    function testFlameRound1Stir() external view {
        if (QuarticWhirFixedConfig.ROUND_COUNT < 2) {
            return;
        }

        (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof) =
            _loadSuccessFixture();
        uint256 gasRound1 = harness.profileRound1StirOnly(proof.initialCommitment, statement, proof);
        assertGt(gasRound1, 0);
    }

    function testFlameFinalStir() external view {
        (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof) =
            _loadSuccessFixture();
        uint256 gasFinal = harness.profileFinalStirOnly(proof.initialCommitment, statement, proof);
        assertGt(gasFinal, 0);
    }

    function testFlameConstraintEvaluation() external view {
        (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof) =
            _loadSuccessFixture();
        uint256 gasConstraint =
            harness.profileConstraintEvaluationOnly(proof.initialCommitment, statement, proof);
        assertGt(gasConstraint, 0);
    }

    function _logStirBreakdown(string memory label, WhirProfileHarness.StirBreakdown memory bd)
        internal
        pure
    {
        console.log("=== STIR Breakdown ===");
        console.log(label);
        console.log("total:            ", bd.total);
        console.log("sampleQueries:    ", bd.sampleQueries);
        console.log("leafHashing:      ", bd.leafHashing);
        console.log("merkleReduction:  ", bd.merkleReduction);
        console.log("pow:              ", bd.pow);
        console.log("rowFolding:       ", bd.rowFolding);
        console.log("overhead:         ", bd.overhead);
        console.log("queryCount:       ", bd.queryCount);
        console.log("rowLen:           ", bd.rowLen);
        console.log("depth:            ", bd.depth);
    }

    function _makeRuntimeExt4Evals(uint256 salt, uint256 len)
        internal
        pure
        returns (uint256[] memory evals)
    {
        evals = new uint256[](len);
        unchecked {
            for (uint256 i = 0; i < len; ++i) {
                evals[i] = _runtimePackedExt4(salt, i + 1);
            }
        }
    }

    function _runtimePackedExt4(uint256 salt, uint256 offset) internal pure returns (uint256) {
        uint256 coeff0 = addmod(salt, offset, KoalaBear.MODULUS);
        uint256 coeff1 = addmod(salt, offset * 3, KoalaBear.MODULUS);
        uint256 coeff2 = addmod(salt, offset * 5, KoalaBear.MODULUS);
        uint256 coeff3 = addmod(salt, offset * 7, KoalaBear.MODULUS);
        uint256[4] memory coeffs;
        coeffs[0] = coeff0;
        coeffs[1] = coeff1;
        coeffs[2] = coeff2;
        coeffs[3] = coeff3;
        return KoalaBearExt4.pack(coeffs);
    }

    function _loadSuccessFixture()
        internal
        view
        returns (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof)
    {
        statement = abi.decode(
            vm.readFileBinary(
                string.concat(TESTDATA, "quartic_whir_lir6_ff5_rsv1_success_statement.abi")
            ),
            (WhirStructs.WhirStatement)
        );
        proof = abi.decode(
            vm.readFileBinary(
                string.concat(TESTDATA, "quartic_whir_lir6_ff5_rsv1_success_proof.abi")
            ),
            (WhirStructs.WhirProof)
        );
    }
}
