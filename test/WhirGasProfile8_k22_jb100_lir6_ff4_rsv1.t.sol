// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test, console } from "forge-std/Test.sol";

import { KoalaBear } from "../src/field/KoalaBear.sol";
import { KoalaBearExt8 } from "../src/field/KoalaBearExt8.sol";
import { KeccakChallenger } from "../src/transcript/KeccakChallenger.sol";
import {
    OcticWhirFixedConfig_k22_jb100_lir6_ff4_rsv1 as OcticWhirFixedConfig
} from "../src/generated/OcticWhirFixedConfig_k22_jb100_lir6_ff4_rsv1.sol";
import { WhirStructs } from "../src/whir/WhirStructs.sol";
import { WhirVerifierCore8 } from "../src/whir/k22_jb100_lir6_ff4_rsv1/WhirVerifierCore8.sol";
import { WhirVerifierUtils8 } from "../src/whir/k22_jb100_lir6_ff4_rsv1/WhirVerifierUtils8.sol";
import { MerkleVerifier } from "../src/merkle/MerkleVerifier.sol";

// ─────────────────────────────────────────────────────────────────────────────
// Harness contract — calls WhirVerifierCore8 internals with gasleft() probes.
// ─────────────────────────────────────────────────────────────────────────────
contract WhirProfileHarness8 {
    using KeccakChallenger for KeccakChallenger.State;

    struct FullBreakdown {
        uint256 setup;
        uint256 initialSumcheck;
        uint256 round0Parse;
        uint256 round0Stir;
        uint256 round0Sumcheck;
        uint256 round1Parse;
        uint256 round1Stir;
        uint256 round1Sumcheck;
        uint256 round2Parse;
        uint256 round2Stir;
        uint256 round2Sumcheck;
        uint256 observeFinalPoly;
        uint256 finalStir;
        uint256 finalSumcheck;
        uint256 constraintInitial;
        uint256 constraintRound0Select;
        uint256 constraintRound1Select;
        uint256 constraintRound2Select;
        uint256 finalCheck;
    }

    struct StirBreakdown {
        uint256 total;
        uint256 powCheck;
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

    // ─────────────────────────────────────────────────────────────────────────
    // Phase-level breakdown
    // ─────────────────────────────────────────────────────────────────────────

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
        uint256[] memory allRandomness = new uint256[](OcticWhirFixedConfig.NUM_VARIABLES);
        uint256 randomnessCursor = 0;

        uint256 initialConstraintChallenge;
        uint256[] calldata statementPoint;
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

        // ── Setup: observePattern + validate statement + parse commitment ──
        g = gasleft();
        OcticWhirFixedConfig.observePattern(challenger);
        require(
            statement.points.length == 1 && statement.evaluations.length == 1,
            "FIXED_STATEMENT_COUNT"
        );
        statementPoint = statement.points[0];
        require(
            statementPoint.length == OcticWhirFixedConfig.NUM_VARIABLES, "FIXED_STATEMENT_ARITY"
        );
        WhirVerifierUtils8.validatePackedExt8Calldata(statementPoint);
        uint256 statementEval = statement.evaluations[0];
        WhirVerifierUtils8.validatePackedExt8(statementEval);

        WhirVerifierCore8.ParsedCommitment memory parsedCommitment =
            WhirVerifierCore8._parseCommitment(
                challenger,
                proof.initialCommitment,
                proof.initialOodAnswers,
                OcticWhirFixedConfig.NUM_VARIABLES,
                OcticWhirFixedConfig.COMMITMENT_OOD_SAMPLES
            );
        require(parsedCommitment.root == expectedCommitment, "COMMITMENT");

        initialConstraintChallenge = WhirVerifierUtils8.sampleExt8(challenger);
        initialOodFlatPoints = parsedCommitment.oodStatement.flatPoints;

        claimedEval = WhirVerifierCore8._combineInitialConstraintEvalsSingleRaw(
            initialConstraintChallenge, statementEval, parsedCommitment.oodStatement.evaluations[0]
        );
        bd.setup = g - gasleft();

        // ── Initial Sumcheck (4 rounds, no PoW) ──
        g = gasleft();
        (claimedEval, foldingRandomness, randomnessCursor) = WhirVerifierCore8._verifySumcheck(
            proof.initialSumcheck,
            challenger,
            claimedEval,
            OcticWhirFixedConfig.INITIAL_SUMCHECK_ROUNDS,
            OcticWhirFixedConfig.STARTING_FOLDING_POW_BITS,
            allRandomness,
            randomnessCursor
        );
        bd.initialSumcheck = g - gasleft();

        WhirVerifierCore8.ParsedCommitment memory prevCommitment = parsedCommitment;

        // ── Round 0 (24 queries, domain 268M, depth 24, base rows → ext8) ──
        {
            OcticWhirFixedConfig.RoundConfig memory cfg = OcticWhirFixedConfig.roundConfig(0);
            WhirStructs.WhirRoundProof calldata rp = proof.rounds[0];

            g = gasleft();
            WhirVerifierCore8.ParsedCommitment memory nc = WhirVerifierCore8._parseCommitment(
                challenger, rp.commitment, rp.oodAnswers, cfg.numVariables, cfg.oodSamples
            );
            bd.round0Parse = g - gasleft();

            g = gasleft();
            uint256 roundContribution;
            (round0ConstraintChallenge, roundContribution, round0SelVars) =
                WhirVerifierCore8._verifyStirAndCombineConstraint(
                    challenger,
                    prevCommitment.root,
                    cfg.powBits,
                    cfg.numQueries,
                    cfg.numVariables,
                    cfg.foldingFactor,
                    cfg.domainSize,
                    cfg.foldedDomainGen,
                    rp.queryBatch,
                    true,
                    rp.powWitness,
                    foldingRandomness,
                    0, // kind=0: base rows
                    rp.oodAnswers
                );
            bd.round0Stir = g - gasleft();
            claimedEval = KoalaBearExt8.add(claimedEval, roundContribution);
            round0EqFlatPoints = nc.oodStatement.flatPoints;

            g = gasleft();
            (claimedEval, foldingRandomness, randomnessCursor) = WhirVerifierCore8._verifySumcheck(
                rp.sumcheck,
                challenger,
                claimedEval,
                cfg.foldingFactor,
                cfg.foldingPowBits,
                allRandomness,
                randomnessCursor
            );
            bd.round0Sumcheck = g - gasleft();
            prevCommitment = nc;
        }

        // ── Round 1 (16 queries, domain 134M, depth 23, ext8 rows) ──
        {
            OcticWhirFixedConfig.RoundConfig memory cfg = OcticWhirFixedConfig.roundConfig(1);
            WhirStructs.WhirRoundProof calldata rp = proof.rounds[1];

            g = gasleft();
            WhirVerifierCore8.ParsedCommitment memory nc = WhirVerifierCore8._parseCommitment(
                challenger, rp.commitment, rp.oodAnswers, cfg.numVariables, cfg.oodSamples
            );
            bd.round1Parse = g - gasleft();

            g = gasleft();
            uint256 roundContribution;
            (round1ConstraintChallenge, roundContribution, round1SelVars) =
                WhirVerifierCore8._verifyStirAndCombineConstraint(
                    challenger,
                    prevCommitment.root,
                    cfg.powBits,
                    cfg.numQueries,
                    cfg.numVariables,
                    cfg.foldingFactor,
                    cfg.domainSize,
                    cfg.foldedDomainGen,
                    rp.queryBatch,
                    true,
                    rp.powWitness,
                    foldingRandomness,
                    1, // kind=1: ext8 rows
                    rp.oodAnswers
                );
            bd.round1Stir = g - gasleft();
            claimedEval = KoalaBearExt8.add(claimedEval, roundContribution);
            round1EqFlatPoints = nc.oodStatement.flatPoints;

            g = gasleft();
            (claimedEval, foldingRandomness, randomnessCursor) = WhirVerifierCore8._verifySumcheck(
                rp.sumcheck,
                challenger,
                claimedEval,
                cfg.foldingFactor,
                cfg.foldingPowBits,
                allRandomness,
                randomnessCursor
            );
            bd.round1Sumcheck = g - gasleft();
            prevCommitment = nc;
        }

        // ── Round 2 (12 queries, domain 67M, depth 22, ext8 rows) ──
        {
            OcticWhirFixedConfig.RoundConfig memory cfg = OcticWhirFixedConfig.roundConfig(2);
            WhirStructs.WhirRoundProof calldata rp = proof.rounds[2];

            g = gasleft();
            WhirVerifierCore8.ParsedCommitment memory nc = WhirVerifierCore8._parseCommitment(
                challenger, rp.commitment, rp.oodAnswers, cfg.numVariables, cfg.oodSamples
            );
            bd.round2Parse = g - gasleft();

            g = gasleft();
            uint256 roundContribution;
            (round2ConstraintChallenge, roundContribution, round2SelVars) =
                WhirVerifierCore8._verifyStirAndCombineConstraint(
                    challenger,
                    prevCommitment.root,
                    cfg.powBits,
                    cfg.numQueries,
                    cfg.numVariables,
                    cfg.foldingFactor,
                    cfg.domainSize,
                    cfg.foldedDomainGen,
                    rp.queryBatch,
                    true,
                    rp.powWitness,
                    foldingRandomness,
                    1, // kind=1: ext8 rows
                    rp.oodAnswers
                );
            bd.round2Stir = g - gasleft();
            claimedEval = KoalaBearExt8.add(claimedEval, roundContribution);
            round2EqFlatPoints = nc.oodStatement.flatPoints;

            g = gasleft();
            (claimedEval, foldingRandomness, randomnessCursor) = WhirVerifierCore8._verifySumcheck(
                rp.sumcheck,
                challenger,
                claimedEval,
                cfg.foldingFactor,
                cfg.foldingPowBits,
                allRandomness,
                randomnessCursor
            );
            bd.round2Sumcheck = g - gasleft();
            prevCommitment = nc;
        }

        // ── Observe final poly (64 ext8 elements = 2,048 bytes into challenger) ──
        g = gasleft();
        challenger.observeValidatedPackedExt8Slice(proof.finalPoly);
        bd.observeFinalPoly = g - gasleft();

        // ── Final STIR (10 queries, domain 33M, depth 21, ext8 rows) ──
        g = gasleft();
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
            1, // kind=1: ext8 rows
            proof.finalPoly
        );
        bd.finalStir = g - gasleft();

        // ── Final Sumcheck (6 rounds, no PoW) ──
        g = gasleft();
        (claimedEval, finalSumcheckRandomness, randomnessCursor) = WhirVerifierCore8._verifySumcheck(
            proof.finalSumcheck,
            challenger,
            claimedEval,
            OcticWhirFixedConfig.FINAL_SUMCHECK_ROUNDS,
            OcticWhirFixedConfig.FINAL_FOLDING_POW_BITS,
            allRandomness,
            randomnessCursor
        );
        bd.finalSumcheck = g - gasleft();

        // ── Constraint: initial term ──
        g = gasleft();
        uint256 evaluationOfWeights = WhirVerifierCore8._evaluateInitialConstraintSingleCalldataRaw(
            initialConstraintChallenge, statementPoint, initialOodFlatPoints, allRandomness
        );
        bd.constraintInitial = g - gasleft();

        // ── Constraint: round 0 select ──
        g = gasleft();
        evaluationOfWeights = KoalaBearExt8.add(
            evaluationOfWeights,
            WhirVerifierCore8._evaluateConstraintSelectRaw(
                round0ConstraintChallenge, round0EqFlatPoints, round0SelVars, allRandomness
            )
        );
        bd.constraintRound0Select = g - gasleft();

        // ── Constraint: round 1 select ──
        g = gasleft();
        evaluationOfWeights = KoalaBearExt8.add(
            evaluationOfWeights,
            WhirVerifierCore8._evaluateConstraintSelectRaw(
                round1ConstraintChallenge, round1EqFlatPoints, round1SelVars, allRandomness
            )
        );
        bd.constraintRound1Select = g - gasleft();

        // ── Constraint: round 2 select ──
        g = gasleft();
        evaluationOfWeights = KoalaBearExt8.add(
            evaluationOfWeights,
            WhirVerifierCore8._evaluateConstraintSelectRaw(
                round2ConstraintChallenge, round2EqFlatPoints, round2SelVars, allRandomness
            )
        );
        bd.constraintRound2Select = g - gasleft();

        // ── Final value + constraint check ──
        g = gasleft();
        {
            uint256 finalValue =
                WhirVerifierCore8._evaluateFinalValue(proof.finalPoly, finalSumcheckRandomness);
            uint256 expected = KoalaBearExt8.mul(evaluationOfWeights, finalValue);
            require(claimedEval == expected, "FINAL_CHECK");
        }
        bd.finalCheck = g - gasleft();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Per-round STIR internal breakdown (leaf / Merkle / pow / rowFolding)
    // ─────────────────────────────────────────────────────────────────────────

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
            StirBreakdown memory round2,
            StirBreakdown memory finalBd
        )
    {
        KeccakChallenger.State memory challenger;
        OcticWhirFixedConfig.observePattern(challenger);

        require(statement.points.length == 1 && statement.evaluations.length == 1, "SHAPE");
        WhirVerifierUtils8.validatePackedExt8Calldata(statement.points[0]);
        uint256 statementEval = statement.evaluations[0];
        WhirVerifierUtils8.validatePackedExt8(statementEval);

        WhirVerifierCore8.ParsedCommitment memory prevCommitment = WhirVerifierCore8._parseCommitment(
            challenger,
            proof.initialCommitment,
            proof.initialOodAnswers,
            OcticWhirFixedConfig.NUM_VARIABLES,
            OcticWhirFixedConfig.COMMITMENT_OOD_SAMPLES
        );
        require(prevCommitment.root == expectedCommitment, "COMMITMENT");

        uint256 initialConstraintChallenge = WhirVerifierUtils8.sampleExt8(challenger);
        uint256 claimedEval = WhirVerifierCore8._combineInitialConstraintEvalsSingleRaw(
            initialConstraintChallenge, statementEval, prevCommitment.oodStatement.evaluations[0]
        );

        uint256[] memory allRandomness = new uint256[](OcticWhirFixedConfig.NUM_VARIABLES);
        uint256[] memory foldingRandomness;
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

        // Round 0 (kind=0, base rows)
        {
            OcticWhirFixedConfig.RoundConfig memory cfg = OcticWhirFixedConfig.roundConfig(0);
            WhirStructs.WhirRoundProof calldata rp = proof.rounds[0];
            WhirVerifierCore8.ParsedCommitment memory nc = WhirVerifierCore8._parseCommitment(
                challenger, rp.commitment, rp.oodAnswers, cfg.numVariables, cfg.oodSamples
            );
            round0 = _profileStirRaw(
                challenger,
                prevCommitment.root,
                cfg.powBits,
                cfg.numQueries,
                cfg.foldingFactor,
                cfg.domainSize,
                cfg.foldedDomainGen,
                rp.queryBatch,
                rp.powWitness,
                foldingRandomness,
                0 // kind=0: base rows
            );
            // Advance challenger + claimedEval via the real function to keep transcript valid.
            uint256 roundContribution;
            (, roundContribution,) = WhirVerifierCore8._verifyStirAndCombineConstraint(
                challenger,
                prevCommitment.root,
                cfg.powBits,
                cfg.numQueries,
                cfg.numVariables,
                cfg.foldingFactor,
                cfg.domainSize,
                cfg.foldedDomainGen,
                rp.queryBatch,
                true,
                rp.powWitness,
                foldingRandomness,
                0,
                rp.oodAnswers
            );
            claimedEval = KoalaBearExt8.add(claimedEval, roundContribution);
            (claimedEval, foldingRandomness, randomnessCursor) = WhirVerifierCore8._verifySumcheck(
                rp.sumcheck,
                challenger,
                claimedEval,
                cfg.foldingFactor,
                cfg.foldingPowBits,
                allRandomness,
                randomnessCursor
            );
            prevCommitment = nc;
        }

        // Round 1 (kind=1, ext8 rows)
        {
            OcticWhirFixedConfig.RoundConfig memory cfg = OcticWhirFixedConfig.roundConfig(1);
            WhirStructs.WhirRoundProof calldata rp = proof.rounds[1];
            WhirVerifierCore8.ParsedCommitment memory nc = WhirVerifierCore8._parseCommitment(
                challenger, rp.commitment, rp.oodAnswers, cfg.numVariables, cfg.oodSamples
            );
            round1 = _profileStirRaw(
                challenger,
                prevCommitment.root,
                cfg.powBits,
                cfg.numQueries,
                cfg.foldingFactor,
                cfg.domainSize,
                cfg.foldedDomainGen,
                rp.queryBatch,
                rp.powWitness,
                foldingRandomness,
                1 // kind=1: ext8 rows
            );
            uint256 roundContribution;
            (, roundContribution,) = WhirVerifierCore8._verifyStirAndCombineConstraint(
                challenger,
                prevCommitment.root,
                cfg.powBits,
                cfg.numQueries,
                cfg.numVariables,
                cfg.foldingFactor,
                cfg.domainSize,
                cfg.foldedDomainGen,
                rp.queryBatch,
                true,
                rp.powWitness,
                foldingRandomness,
                1,
                rp.oodAnswers
            );
            claimedEval = KoalaBearExt8.add(claimedEval, roundContribution);
            (claimedEval, foldingRandomness, randomnessCursor) = WhirVerifierCore8._verifySumcheck(
                rp.sumcheck,
                challenger,
                claimedEval,
                cfg.foldingFactor,
                cfg.foldingPowBits,
                allRandomness,
                randomnessCursor
            );
            prevCommitment = nc;
        }

        // Round 2 (kind=1, ext8 rows)
        {
            OcticWhirFixedConfig.RoundConfig memory cfg = OcticWhirFixedConfig.roundConfig(2);
            WhirStructs.WhirRoundProof calldata rp = proof.rounds[2];
            WhirVerifierCore8.ParsedCommitment memory nc = WhirVerifierCore8._parseCommitment(
                challenger, rp.commitment, rp.oodAnswers, cfg.numVariables, cfg.oodSamples
            );
            round2 = _profileStirRaw(
                challenger,
                prevCommitment.root,
                cfg.powBits,
                cfg.numQueries,
                cfg.foldingFactor,
                cfg.domainSize,
                cfg.foldedDomainGen,
                rp.queryBatch,
                rp.powWitness,
                foldingRandomness,
                1 // kind=1: ext8 rows
            );
            uint256 roundContribution;
            (, roundContribution,) = WhirVerifierCore8._verifyStirAndCombineConstraint(
                challenger,
                prevCommitment.root,
                cfg.powBits,
                cfg.numQueries,
                cfg.numVariables,
                cfg.foldingFactor,
                cfg.domainSize,
                cfg.foldedDomainGen,
                rp.queryBatch,
                true,
                rp.powWitness,
                foldingRandomness,
                1,
                rp.oodAnswers
            );
            claimedEval = KoalaBearExt8.add(claimedEval, roundContribution);
            (claimedEval, foldingRandomness, randomnessCursor) = WhirVerifierCore8._verifySumcheck(
                rp.sumcheck,
                challenger,
                claimedEval,
                cfg.foldingFactor,
                cfg.foldingPowBits,
                allRandomness,
                randomnessCursor
            );
            prevCommitment = nc;
        }

        // Final STIR profile (kind=1, ext8 rows)
        challenger.observeValidatedPackedExt8Slice(proof.finalPoly);
        finalBd = _profileFinalStirRaw(
            challenger,
            prevCommitment.root,
            OcticWhirFixedConfig.FINAL_POW_BITS,
            OcticWhirFixedConfig.FINAL_NUM_QUERIES,
            OcticWhirFixedConfig.FINAL_FOLDING_FACTOR,
            OcticWhirFixedConfig.FINAL_DOMAIN_SIZE,
            OcticWhirFixedConfig.FINAL_FOLDED_DOMAIN_GEN,
            proof.finalQueryBatch,
            proof.finalPowWitness,
            foldingRandomness,
            1 // kind=1: ext8 rows
        );
        require(claimedEval != 0 || claimedEval == 0, "SINK");
    }

    function profileFinalCheckerOnly(
        bytes32 expectedCommitment,
        WhirStructs.WhirStatement calldata statement,
        WhirStructs.WhirProof calldata proof,
        bytes calldata blob,
        uint256 finalPolyOffset
    ) external view returns (uint256 batch0Gas, uint256 batch1Gas, uint256 totalGas) {
        KeccakChallenger.State memory challenger;
        OcticWhirFixedConfig.observePattern(challenger);

        require(statement.points.length == 1 && statement.evaluations.length == 1, "SHAPE");
        uint256 statementEval = statement.evaluations[0];

        WhirVerifierCore8.ParsedCommitment memory prevCommitment = WhirVerifierCore8._parseCommitment(
            challenger,
            proof.initialCommitment,
            proof.initialOodAnswers,
            OcticWhirFixedConfig.NUM_VARIABLES,
            OcticWhirFixedConfig.COMMITMENT_OOD_SAMPLES
        );
        require(prevCommitment.root == expectedCommitment, "COMMITMENT");

        uint256 initialConstraintChallenge = WhirVerifierUtils8.sampleExt8(challenger);
        uint256 claimedEval = WhirVerifierCore8._combineInitialConstraintEvalsSingleRaw(
            initialConstraintChallenge, statementEval, prevCommitment.oodStatement.evaluations[0]
        );

        uint256[] memory allRandomness = new uint256[](OcticWhirFixedConfig.NUM_VARIABLES);
        uint256[] memory foldingRandomness;
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

        {
            OcticWhirFixedConfig.RoundConfig memory cfg = OcticWhirFixedConfig.roundConfig(0);
            WhirStructs.WhirRoundProof calldata rp = proof.rounds[0];
            WhirVerifierCore8.ParsedCommitment memory nc = WhirVerifierCore8._parseCommitment(
                challenger, rp.commitment, rp.oodAnswers, cfg.numVariables, cfg.oodSamples
            );
            uint256 roundContribution;
            (, roundContribution,) = WhirVerifierCore8._verifyStirAndCombineConstraint(
                challenger,
                prevCommitment.root,
                cfg.powBits,
                cfg.numQueries,
                cfg.numVariables,
                cfg.foldingFactor,
                cfg.domainSize,
                cfg.foldedDomainGen,
                rp.queryBatch,
                true,
                rp.powWitness,
                foldingRandomness,
                0,
                rp.oodAnswers
            );
            claimedEval = KoalaBearExt8.add(claimedEval, roundContribution);
            (claimedEval, foldingRandomness, randomnessCursor) = WhirVerifierCore8._verifySumcheck(
                rp.sumcheck,
                challenger,
                claimedEval,
                cfg.foldingFactor,
                cfg.foldingPowBits,
                allRandomness,
                randomnessCursor
            );
            prevCommitment = nc;
        }

        {
            OcticWhirFixedConfig.RoundConfig memory cfg = OcticWhirFixedConfig.roundConfig(1);
            WhirStructs.WhirRoundProof calldata rp = proof.rounds[1];
            WhirVerifierCore8.ParsedCommitment memory nc = WhirVerifierCore8._parseCommitment(
                challenger, rp.commitment, rp.oodAnswers, cfg.numVariables, cfg.oodSamples
            );
            uint256 roundContribution;
            (, roundContribution,) = WhirVerifierCore8._verifyStirAndCombineConstraint(
                challenger,
                prevCommitment.root,
                cfg.powBits,
                cfg.numQueries,
                cfg.numVariables,
                cfg.foldingFactor,
                cfg.domainSize,
                cfg.foldedDomainGen,
                rp.queryBatch,
                true,
                rp.powWitness,
                foldingRandomness,
                1,
                rp.oodAnswers
            );
            claimedEval = KoalaBearExt8.add(claimedEval, roundContribution);
            (claimedEval, foldingRandomness, randomnessCursor) = WhirVerifierCore8._verifySumcheck(
                rp.sumcheck,
                challenger,
                claimedEval,
                cfg.foldingFactor,
                cfg.foldingPowBits,
                allRandomness,
                randomnessCursor
            );
            prevCommitment = nc;
        }

        {
            OcticWhirFixedConfig.RoundConfig memory cfg = OcticWhirFixedConfig.roundConfig(2);
            WhirStructs.WhirRoundProof calldata rp = proof.rounds[2];
            WhirVerifierCore8.ParsedCommitment memory nc = WhirVerifierCore8._parseCommitment(
                challenger, rp.commitment, rp.oodAnswers, cfg.numVariables, cfg.oodSamples
            );
            uint256 roundContribution;
            (, roundContribution,) = WhirVerifierCore8._verifyStirAndCombineConstraint(
                challenger,
                prevCommitment.root,
                cfg.powBits,
                cfg.numQueries,
                cfg.numVariables,
                cfg.foldingFactor,
                cfg.domainSize,
                cfg.foldedDomainGen,
                rp.queryBatch,
                true,
                rp.powWitness,
                foldingRandomness,
                1,
                rp.oodAnswers
            );
            claimedEval = KoalaBearExt8.add(claimedEval, roundContribution);
            (claimedEval, foldingRandomness, randomnessCursor) = WhirVerifierCore8._verifySumcheck(
                rp.sumcheck,
                challenger,
                claimedEval,
                cfg.foldingFactor,
                cfg.foldingPowBits,
                allRandomness,
                randomnessCursor
            );
            prevCommitment = nc;
        }

        challenger.observeValidatedPackedExt8Slice(proof.finalPoly);
        require(
            challenger.checkWitness(OcticWhirFixedConfig.FINAL_POW_BITS, proof.finalPowWitness),
            "POW_FAIL"
        );

        uint256[] memory indices = WhirVerifierUtils8.sampleStirQueries(
            challenger,
            OcticWhirFixedConfig.FINAL_DOMAIN_SIZE,
            OcticWhirFixedConfig.FINAL_FOLDING_FACTOR,
            OcticWhirFixedConfig.FINAL_NUM_QUERIES
        );
        require(indices.length == 10, "QUERY_COUNT");
        require(proof.finalQueryBatch.rowLen == 16, "ROW_LEN");
        require(proof.finalQueryBatch.values.length == 160, "FINAL_VALUES");
        require(
            prevCommitment.root != bytes32(0) || prevCommitment.root == expectedCommitment, "SINK"
        );
        require(
            randomnessCursor
                == OcticWhirFixedConfig.NUM_VARIABLES - OcticWhirFixedConfig.FINAL_SUMCHECK_ROUNDS,
            "RANDOMNESS"
        );

        uint256[] memory rowEvals = new uint256[](10);
        uint256[] memory points = new uint256[](10);
        unchecked {
            for (uint256 i = 0; i < 10; ++i) {
                rowEvals[i] = WhirVerifierUtils8.evaluateExtensionRowAsExt8(
                    proof.finalQueryBatch.values, i * 16, 16, foldingRandomness
                );
                points[i] = KoalaBear.pow(OcticWhirFixedConfig.FINAL_FOLDED_DOMAIN_GEN, indices[i]);
            }
        }

        uint256 rowEvalsBase;
        assembly ("memory-safe") {
            rowEvalsBase := add(rowEvals, 0x20)
        }

        uint256 g = gasleft();
        uint256 mismatchPlusOne = WhirVerifierUtils8.checkHornerBaseBlob64Matches5Raw(
            blob,
            finalPolyOffset,
            points[0],
            points[1],
            points[2],
            points[3],
            points[4],
            rowEvalsBase,
            0
        );
        batch0Gas = g - gasleft();
        require(mismatchPlusOne == 0, "BATCH0");

        g = gasleft();
        mismatchPlusOne = WhirVerifierUtils8.checkHornerBaseBlob64Matches5Raw(
            blob,
            finalPolyOffset,
            points[5],
            points[6],
            points[7],
            points[8],
            points[9],
            rowEvalsBase,
            5
        );
        batch1Gas = g - gasleft();
        require(mismatchPlusOne == 0, "BATCH1");

        totalGas = batch0Gas + batch1Gas;
        require(claimedEval != 0 || claimedEval == 0, "SINK");
    }

    function profileFinalValueBlobOnly(
        bytes32 expectedCommitment,
        WhirStructs.WhirStatement calldata statement,
        WhirStructs.WhirProof calldata proof,
        bytes calldata blob,
        uint256 finalPolyOffset
    ) external view returns (uint256 gasUsed, uint256 finalValue) {
        KeccakChallenger.State memory challenger;
        OcticWhirFixedConfig.observePattern(challenger);

        require(statement.points.length == 1 && statement.evaluations.length == 1, "SHAPE");
        uint256 statementEval = statement.evaluations[0];

        WhirVerifierCore8.ParsedCommitment memory prevCommitment = WhirVerifierCore8._parseCommitment(
            challenger,
            proof.initialCommitment,
            proof.initialOodAnswers,
            OcticWhirFixedConfig.NUM_VARIABLES,
            OcticWhirFixedConfig.COMMITMENT_OOD_SAMPLES
        );
        require(prevCommitment.root == expectedCommitment, "COMMITMENT");

        uint256 initialConstraintChallenge = WhirVerifierUtils8.sampleExt8(challenger);
        uint256 claimedEval = WhirVerifierCore8._combineInitialConstraintEvalsSingleRaw(
            initialConstraintChallenge, statementEval, prevCommitment.oodStatement.evaluations[0]
        );

        uint256[] memory allRandomness = new uint256[](OcticWhirFixedConfig.NUM_VARIABLES);
        uint256[] memory foldingRandomness;
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

        {
            OcticWhirFixedConfig.RoundConfig memory cfg = OcticWhirFixedConfig.roundConfig(0);
            WhirStructs.WhirRoundProof calldata rp = proof.rounds[0];
            WhirVerifierCore8.ParsedCommitment memory nc = WhirVerifierCore8._parseCommitment(
                challenger, rp.commitment, rp.oodAnswers, cfg.numVariables, cfg.oodSamples
            );
            uint256 roundContribution;
            (, roundContribution,) = WhirVerifierCore8._verifyStirAndCombineConstraint(
                challenger,
                prevCommitment.root,
                cfg.powBits,
                cfg.numQueries,
                cfg.numVariables,
                cfg.foldingFactor,
                cfg.domainSize,
                cfg.foldedDomainGen,
                rp.queryBatch,
                true,
                rp.powWitness,
                foldingRandomness,
                0,
                rp.oodAnswers
            );
            claimedEval = KoalaBearExt8.add(claimedEval, roundContribution);
            (claimedEval, foldingRandomness, randomnessCursor) = WhirVerifierCore8._verifySumcheck(
                rp.sumcheck,
                challenger,
                claimedEval,
                cfg.foldingFactor,
                cfg.foldingPowBits,
                allRandomness,
                randomnessCursor
            );
            prevCommitment = nc;
        }

        {
            OcticWhirFixedConfig.RoundConfig memory cfg = OcticWhirFixedConfig.roundConfig(1);
            WhirStructs.WhirRoundProof calldata rp = proof.rounds[1];
            WhirVerifierCore8.ParsedCommitment memory nc = WhirVerifierCore8._parseCommitment(
                challenger, rp.commitment, rp.oodAnswers, cfg.numVariables, cfg.oodSamples
            );
            uint256 roundContribution;
            (, roundContribution,) = WhirVerifierCore8._verifyStirAndCombineConstraint(
                challenger,
                prevCommitment.root,
                cfg.powBits,
                cfg.numQueries,
                cfg.numVariables,
                cfg.foldingFactor,
                cfg.domainSize,
                cfg.foldedDomainGen,
                rp.queryBatch,
                true,
                rp.powWitness,
                foldingRandomness,
                1,
                rp.oodAnswers
            );
            claimedEval = KoalaBearExt8.add(claimedEval, roundContribution);
            (claimedEval, foldingRandomness, randomnessCursor) = WhirVerifierCore8._verifySumcheck(
                rp.sumcheck,
                challenger,
                claimedEval,
                cfg.foldingFactor,
                cfg.foldingPowBits,
                allRandomness,
                randomnessCursor
            );
            prevCommitment = nc;
        }

        {
            OcticWhirFixedConfig.RoundConfig memory cfg = OcticWhirFixedConfig.roundConfig(2);
            WhirStructs.WhirRoundProof calldata rp = proof.rounds[2];
            WhirVerifierCore8.ParsedCommitment memory nc = WhirVerifierCore8._parseCommitment(
                challenger, rp.commitment, rp.oodAnswers, cfg.numVariables, cfg.oodSamples
            );
            uint256 roundContribution;
            (, roundContribution,) = WhirVerifierCore8._verifyStirAndCombineConstraint(
                challenger,
                prevCommitment.root,
                cfg.powBits,
                cfg.numQueries,
                cfg.numVariables,
                cfg.foldingFactor,
                cfg.domainSize,
                cfg.foldedDomainGen,
                rp.queryBatch,
                true,
                rp.powWitness,
                foldingRandomness,
                1,
                rp.oodAnswers
            );
            claimedEval = KoalaBearExt8.add(claimedEval, roundContribution);
            (claimedEval, foldingRandomness, randomnessCursor) = WhirVerifierCore8._verifySumcheck(
                rp.sumcheck,
                challenger,
                claimedEval,
                cfg.foldingFactor,
                cfg.foldingPowBits,
                allRandomness,
                randomnessCursor
            );
            prevCommitment = nc;
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

        uint256 finalSumcheckStart = randomnessCursor;
        uint256[] memory finalSumcheckRandomness;
        (claimedEval, finalSumcheckRandomness, randomnessCursor) = WhirVerifierCore8._verifySumcheck(
            proof.finalSumcheck,
            challenger,
            claimedEval,
            OcticWhirFixedConfig.FINAL_SUMCHECK_ROUNDS,
            OcticWhirFixedConfig.FINAL_FOLDING_POW_BITS,
            allRandomness,
            randomnessCursor
        );

        uint256 expectedTyped =
            WhirVerifierCore8._evaluateFinalValue(proof.finalPoly, finalSumcheckRandomness);

        uint256 g = gasleft();
        finalValue = WhirVerifierCore8._evaluateFinalValueBlob(
            blob,
            finalPolyOffset,
            proof.finalPoly.length,
            allRandomness,
            finalSumcheckStart,
            finalSumcheckRandomness.length
        );
        gasUsed = g - gasleft();

        require(finalValue == expectedTyped, "FINAL_VALUE");
        require(claimedEval != 0 || randomnessCursor != 0, "SINK");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Deep-copy a KeccakChallenger.State (the inputBuffer bytes need manual copy).
    // ─────────────────────────────────────────────────────────────────────────
    function _cloneChallenger(KeccakChallenger.State memory src)
        internal
        pure
        returns (KeccakChallenger.State memory dst)
    {
        bytes memory srcBuf = src.inputBuffer;
        bytes memory dstBuf = new bytes(srcBuf.length);
        if (srcBuf.length != 0) {
            assembly ("memory-safe") {
                mcopy(add(dstBuf, 0x20), add(srcBuf, 0x20), mload(srcBuf))
            }
        }
        dst.inputBuffer = dstBuf;
        dst.inputLen = src.inputLen;
        dst.outputBlock = src.outputBlock;
        dst.outputIndex = src.outputIndex;
    }

    function _restoreChallenger(
        KeccakChallenger.State memory dst,
        KeccakChallenger.State memory src
    ) internal pure {
        bytes memory srcBuf = src.inputBuffer;
        bytes memory dstBuf = new bytes(srcBuf.length);
        if (srcBuf.length != 0) {
            assembly ("memory-safe") {
                mcopy(add(dstBuf, 0x20), add(srcBuf, 0x20), mload(srcBuf))
            }
        }
        dst.inputBuffer = dstBuf;
        dst.inputLen = src.inputLen;
        dst.outputBlock = src.outputBlock;
        dst.outputIndex = src.outputIndex;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Internal: instrument one STIR round without OOD constraint sampling.
    // Uses save/restore on the challenger so the real _verifyStirAndCombineConstraint
    // call that follows can use the identical transcript state.
    // ─────────────────────────────────────────────────────────────────────────
    function _profileStirRaw(
        KeccakChallenger.State memory challenger,
        bytes32 expectedRoot,
        uint256 powBits,
        uint256 numQueries,
        uint256 foldingFactor,
        uint256 domainSize,
        uint256 foldedDomainGen,
        WhirStructs.QueryBatchOpening calldata queryBatch,
        uint256 powWitness,
        uint256[] memory foldingRandomness,
        uint8 kind
    ) internal view returns (StirBreakdown memory bd) {
        KeccakChallenger.State memory saved = _cloneChallenger(challenger);
        uint256 startGas = gasleft();
        uint256 g;

        // ── PoW witness check ──
        g = gasleft();
        if (powBits > 0) {
            require(challenger.checkWitness(powBits, powWitness), "POW_FAIL");
        }
        bd.powCheck = g - gasleft();

        challenger.sampleBase();

        uint256 expectedRowLen = uint256(1) << foldingFactor;
        uint256 depth = WhirVerifierUtils8.log2Strict(domainSize >> foldingFactor);
        bd.queryCount = numQueries;
        bd.rowLen = expectedRowLen;
        bd.depth = depth;

        // ── Sample query indices ──
        g = gasleft();
        uint256[] memory indices =
            WhirVerifierUtils8.sampleStirQueries(challenger, domainSize, foldingFactor, numQueries);
        bd.sampleQueries = g - gasleft();

        // ── Leaf hashing + Merkle path reduction (combined) ──
        // For foldingFactor=4 (rowLen=16) the real verifier uses a private fused
        // _hashAndEvaluateXxxRowDim4PackedPoints that interleaves hashing with row eval.
        // We use the public non-fused equivalents here; the root is correct, individual
        // timing slightly overstates vs the fused private path.
        g = gasleft();
        bytes32 computedRoot;
        if (kind == 0) {
            computedRoot = MerkleVerifier.computeRootFromFlatBaseRows20(
                indices, queryBatch.values, queryBatch.rowLen, depth, queryBatch.decommitments
            );
        } else {
            computedRoot = MerkleVerifier.computeRootFromFlatExtension8Rows20(
                indices, queryBatch.values, queryBatch.rowLen, depth, queryBatch.decommitments
            );
        }
        bd.leafHashing = 0; // fused into merkleReduction for octic (foldingFactor=4)
        bd.merkleReduction = g - gasleft();
        require(computedRoot == expectedRoot, "MERKLE_ROOT");

        // ── KoalaBear.pow for each query index ──
        uint256[] memory queryVars = new uint256[](indices.length);
        g = gasleft();
        unchecked {
            for (uint256 i = 0; i < indices.length; ++i) {
                queryVars[i] = KoalaBear.pow(foldedDomainGen, indices[i]);
            }
        }
        bd.pow = g - gasleft();

        // ── Row folding (ext8 linear combination over the row) ──
        g = gasleft();
        unchecked {
            for (uint256 i = 0; i < indices.length; ++i) {
                uint256 rowStart = i * queryBatch.rowLen;
                if (kind == 0) {
                    WhirVerifierUtils8.evaluateBaseRowAsExt8(
                        queryBatch.values, rowStart, queryBatch.rowLen, foldingRandomness
                    );
                } else {
                    WhirVerifierUtils8.evaluateExtensionRowAsExt8(
                        queryBatch.values, rowStart, queryBatch.rowLen, foldingRandomness
                    );
                }
            }
        }
        bd.rowFolding = g - gasleft();

        _restoreChallenger(challenger, saved);

        bd.total = startGas - gasleft();
        uint256 measured = bd.powCheck + bd.sampleQueries + bd.leafHashing + bd.merkleReduction
            + bd.pow + bd.rowFolding;
        bd.overhead = bd.total > measured ? bd.total - measured : 0;
    }

    function _profileFinalStirRaw(
        KeccakChallenger.State memory challenger,
        bytes32 expectedRoot,
        uint256 powBits,
        uint256 numQueries,
        uint256 foldingFactor,
        uint256 domainSize,
        uint256 foldedDomainGen,
        WhirStructs.QueryBatchOpening calldata queryBatch,
        uint256 powWitness,
        uint256[] memory foldingRandomness,
        uint8 kind
    ) internal view returns (StirBreakdown memory bd) {
        KeccakChallenger.State memory working = _cloneChallenger(challenger);
        uint256 startGas = gasleft();
        uint256 g;

        g = gasleft();
        if (powBits > 0) {
            require(working.checkWitness(powBits, powWitness), "POW_FAIL");
        }
        bd.powCheck = g - gasleft();

        uint256 expectedRowLen = uint256(1) << foldingFactor;
        uint256 depth = WhirVerifierUtils8.log2Strict(domainSize >> foldingFactor);
        bd.queryCount = numQueries;
        bd.rowLen = expectedRowLen;
        bd.depth = depth;

        g = gasleft();
        uint256[] memory indices =
            WhirVerifierUtils8.sampleStirQueries(working, domainSize, foldingFactor, numQueries);
        bd.sampleQueries = g - gasleft();

        g = gasleft();
        bytes32 computedRoot;
        if (kind == 0) {
            computedRoot = MerkleVerifier.computeRootFromFlatBaseRows20(
                indices, queryBatch.values, queryBatch.rowLen, depth, queryBatch.decommitments
            );
        } else {
            computedRoot = MerkleVerifier.computeRootFromFlatExtension8Rows20(
                indices, queryBatch.values, queryBatch.rowLen, depth, queryBatch.decommitments
            );
        }
        bd.leafHashing = 0;
        bd.merkleReduction = g - gasleft();
        require(computedRoot == expectedRoot, "MERKLE_ROOT");

        uint256[] memory queryVars = new uint256[](indices.length);
        g = gasleft();
        unchecked {
            for (uint256 i = 0; i < indices.length; ++i) {
                queryVars[i] = KoalaBear.pow(foldedDomainGen, indices[i]);
            }
        }
        bd.pow = g - gasleft();

        g = gasleft();
        unchecked {
            for (uint256 i = 0; i < indices.length; ++i) {
                uint256 rowStart = i * queryBatch.rowLen;
                if (kind == 0) {
                    WhirVerifierUtils8.evaluateBaseRowAsExt8(
                        queryBatch.values, rowStart, queryBatch.rowLen, foldingRandomness
                    );
                } else {
                    WhirVerifierUtils8.evaluateExtensionRowAsExt8(
                        queryBatch.values, rowStart, queryBatch.rowLen, foldingRandomness
                    );
                }
            }
        }
        bd.rowFolding = g - gasleft();

        bd.total = startGas - gasleft();
        uint256 measured = bd.powCheck + bd.sampleQueries + bd.leafHashing + bd.merkleReduction
            + bd.pow + bd.rowFolding;
        bd.overhead = bd.total > measured ? bd.total - measured : 0;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Ext8 micro-benchmarks (for direct comparison with quartic ext4 values)
    // ─────────────────────────────────────────────────────────────────────────
    function profileMicroBenchmarks8()
        external
        view
        returns (
            uint256 gasExt8Mul,
            uint256 gasExt8Add,
            uint256 gasExt8Sub,
            uint256 gasExt8Square,
            uint256 gasHashLeafBase16,
            uint256 gasHashLeafExt16,
            uint256 gasCompressNode,
            uint256 gasKoalaBearPow,
            uint256 gasSampleStirQueries24,
            uint256 gasSampleExt8,
            uint256 gasObserveExt8
        )
    {
        uint256 salt = uint256(uint160(address(this)));
        uint256 g;

        uint256[] memory p8 = new uint256[](8);
        unchecked {
            for (uint256 i = 0; i < 8; ++i) {
                p8[i] = _runtimePackedExt8(salt, i + 1);
            }
        }

        g = gasleft();
        uint256 mulSink;
        unchecked {
            for (uint256 i = 0; i < 100; ++i) {
                mulSink |= KoalaBearExt8.mul(p8[i & 7], p8[(i + 3) & 7]);
            }
        }
        gasExt8Mul = (g - gasleft()) / 100;

        g = gasleft();
        uint256 addSink;
        unchecked {
            for (uint256 i = 0; i < 100; ++i) {
                addSink |= KoalaBearExt8.add(p8[i & 7], p8[(i + 3) & 7]);
            }
        }
        gasExt8Add = (g - gasleft()) / 100;

        g = gasleft();
        uint256 subSink;
        unchecked {
            for (uint256 i = 0; i < 100; ++i) {
                subSink |= KoalaBearExt8.sub(p8[i & 7], p8[(i + 3) & 7]);
            }
        }
        gasExt8Sub = (g - gasleft()) / 100;

        g = gasleft();
        uint256 squareSink;
        unchecked {
            for (uint256 i = 0; i < 100; ++i) {
                squareSink |= KoalaBearExt8.square(p8[i & 7]);
            }
        }
        gasExt8Square = (g - gasleft()) / 100;

        // MerkleVerifier.hashLeafBaseSlice / hashLeafExtensionSlice are shared with
        // the quartic verifier.  Use the values from testProfileStirMicro in
        // WhirGasProfile_lir6_ff5_rsv1.t.sol (base16=1,978 / ext16=3,307).
        gasHashLeafBase16 = 0;
        gasHashLeafExt16 = 0;

        g = gasleft();
        unchecked {
            for (uint256 i = 0; i < 100; ++i) {
                MerkleVerifier.compressNode(bytes32(uint256(i + 1)), bytes32(uint256(i + 42)), 20);
            }
        }
        gasCompressNode = (g - gasleft()) / 100;

        g = gasleft();
        uint256 powSink;
        unchecked {
            for (uint256 i = 0; i < 100; ++i) {
                powSink += KoalaBear.pow(1_791_270_792, 100_000 + i * 2718);
            }
        }
        gasKoalaBearPow = (g - gasleft()) / 100;
        require(powSink != 0, "SINK");

        g = gasleft();
        uint256 qsSink;
        unchecked {
            for (uint256 i = 0; i < 10; ++i) {
                KeccakChallenger.State memory ch;
                ch.observeBytes(abi.encodePacked(bytes32(uint256(42 + i))));
                uint256[] memory qs = WhirVerifierUtils8.sampleStirQueries(ch, 268_435_456, 4, 24);
                qsSink += qs.length;
            }
        }
        gasSampleStirQueries24 = (g - gasleft()) / 10;
        require(qsSink != 0, "SINK");

        g = gasleft();
        uint256 sampleExt8Sink;
        unchecked {
            for (uint256 i = 0; i < 100; ++i) {
                KeccakChallenger.State memory ch;
                ch.observeBytes(abi.encodePacked(bytes32(uint256(42))));
                sampleExt8Sink |= WhirVerifierUtils8.sampleExt8(ch);
            }
        }
        gasSampleExt8 = (g - gasleft()) / 100;
        require(sampleExt8Sink != 0, "SINK");

        g = gasleft();
        uint256 observeExt8Sink;
        unchecked {
            for (uint256 i = 0; i < 100; ++i) {
                KeccakChallenger.State memory ch;
                ch.observeBytes(abi.encodePacked(bytes32(uint256(42))));
                WhirVerifierUtils8.observeValidatedExt8(ch, p8[i & 7]);
                observeExt8Sink |= ch.outputIndex;
            }
        }
        gasObserveExt8 = (g - gasleft()) / 100;
        require((mulSink | addSink | subSink | squareSink | observeExt8Sink) != 0, "SINK");
    }

    function _runtimePackedExt8(uint256 salt, uint256 idx) internal pure returns (uint256 packed) {
        uint256 modulus = 0x7f000001;
        unchecked {
            for (uint256 i = 0; i < 8; ++i) {
                uint256 coeff = (uint256(keccak256(abi.encodePacked(salt, idx, i))) >> 1) % modulus;
                packed = (packed << 32) | coeff;
            }
        }
    }

    function _runtimeBase(uint256 salt, uint256 idx) internal pure returns (uint32) {
        uint256 modulus = 0x7f000001;
        return uint32(uint256(keccak256(abi.encodePacked(salt, idx))) % modulus);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test contract
// ─────────────────────────────────────────────────────────────────────────────
contract WhirGasProfile8Test is Test {
    using KeccakChallenger for KeccakChallenger.State;

    string internal constant TESTDATA = "testdata/";
    uint256 internal constant HEADER_BYTES = 18;
    uint256 internal constant STATEMENT_POINT_ARITY = 22;

    struct BlobOffsets {
        uint256 finalPoly;
    }

    WhirProfileHarness8 internal harness;

    function setUp() external {
        harness = new WhirProfileHarness8();
    }

    function testProfileFullBreakdown8() external view {
        (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof) =
            _loadSuccessFixture();

        WhirProfileHarness8.FullBreakdown memory bd =
            harness.profileFullBreakdown(proof.initialCommitment, statement, proof);

        uint256 totalSTIR = bd.round0Stir + bd.round1Stir + bd.round2Stir + bd.finalStir;
        uint256 totalSumchecks = bd.initialSumcheck + bd.round0Sumcheck + bd.round1Sumcheck
            + bd.round2Sumcheck + bd.finalSumcheck;
        uint256 totalConstraints = bd.constraintInitial + bd.constraintRound0Select
            + bd.constraintRound1Select + bd.constraintRound2Select;
        uint256 sumOfPhases = bd.setup + totalSumchecks + bd.round0Parse + bd.round1Parse
            + bd.round2Parse + totalSTIR + bd.observeFinalPoly + totalConstraints + bd.finalCheck;

        console.log("=== Octic Full Verification Breakdown ===");
        console.log("Setup (pattern+commit+eval):   ", bd.setup);
        console.log("Initial sumcheck (4r):         ", bd.initialSumcheck);
        console.log("Round0 parse commitment:        ", bd.round0Parse);
        console.log("Round0 STIR (24q d24 base):     ", bd.round0Stir);
        console.log("Round0 sumcheck (4r pow=0):     ", bd.round0Sumcheck);
        console.log("Round1 parse commitment:        ", bd.round1Parse);
        console.log("Round1 STIR (16q d23 ext8):     ", bd.round1Stir);
        console.log("Round1 sumcheck (4r pow=0):     ", bd.round1Sumcheck);
        console.log("Round2 parse commitment:        ", bd.round2Parse);
        console.log("Round2 STIR (12q d22 ext8):     ", bd.round2Stir);
        console.log("Round2 sumcheck (4r pow=0):     ", bd.round2Sumcheck);
        console.log("Observe finalPoly (64 ext8):    ", bd.observeFinalPoly);
        console.log("Final STIR (10q d21 ext8):      ", bd.finalStir);
        console.log("Final sumcheck (6r pow=0):      ", bd.finalSumcheck);
        console.log("Constraint initial eq:          ", bd.constraintInitial);
        console.log("Constraint round0 select:       ", bd.constraintRound0Select);
        console.log("Constraint round1 select:       ", bd.constraintRound1Select);
        console.log("Constraint round2 select:       ", bd.constraintRound2Select);
        console.log("Final value check:              ", bd.finalCheck);
        console.log("---");
        console.log("STIR subtotal:                 ", totalSTIR);
        console.log("Sumcheck subtotal:             ", totalSumchecks);
        console.log("Constraint subtotal:           ", totalConstraints);
        console.log("Sum of phases:                 ", sumOfPhases);
    }

    function testProfileStirBreakdown8() external view {
        (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof) =
            _loadSuccessFixture();

        (
            WhirProfileHarness8.StirBreakdown memory r0,
            WhirProfileHarness8.StirBreakdown memory r1,
            WhirProfileHarness8.StirBreakdown memory r2,
            WhirProfileHarness8.StirBreakdown memory fin
        ) = harness.profileStirBreakdowns(proof.initialCommitment, statement, proof);

        _printStirBreakdown("Round0", r0);
        _printStirBreakdown("Round1", r1);
        _printStirBreakdown("Round2", r2);
        _printStirBreakdown("Final", fin);
    }

    function testProfileMicroBenchmarks8() external view {
        (
            uint256 gasExt8Mul,
            uint256 gasExt8Add,
            uint256 gasExt8Sub,
            uint256 gasExt8Square,
            uint256 gasHashLeafBase16,
            uint256 gasHashLeafExt16,
            uint256 gasCompressNode,
            uint256 gasKoalaBearPow,
            uint256 gasSampleStirQueries24,
            uint256 gasSampleExt8,
            uint256 gasObserveExt8
        ) = harness.profileMicroBenchmarks8();

        console.log("=== Octic Micro-benchmarks (per-op, averaged) ===");
        console.log("Ext8 mul:                  ", gasExt8Mul);
        console.log("Ext8 add:                  ", gasExt8Add);
        console.log("Ext8 sub:                  ", gasExt8Sub);
        console.log("Ext8 square:               ", gasExt8Square);
        console.log("hashLeafBaseSlice(16):     ", gasHashLeafBase16);
        console.log("hashLeafExtSlice(16):      ", gasHashLeafExt16);
        console.log("compressNode:              ", gasCompressNode);
        console.log("KoalaBear.pow:             ", gasKoalaBearPow);
        console.log("sampleStirQueries(24)+init:", gasSampleStirQueries24);
        console.log("sampleExt8:                ", gasSampleExt8);
        console.log("observeExt8:               ", gasObserveExt8);
    }

    function testProfileFinalCheckerOnly8() external view {
        (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof) =
            _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(TESTDATA, "octic_whir_k22_jb100_lir6_ff4_rsv1_success.blob")
        );
        BlobOffsets memory offsets = _computeOffsets(proof);

        (uint256 batch0Gas, uint256 batch1Gas, uint256 totalGas) = harness.profileFinalCheckerOnly(
            proof.initialCommitment, statement, proof, blob, offsets.finalPoly
        );

        console.log("=== Final Checker Only ===");
        console.log("batch0:            ", batch0Gas);
        console.log("batch1:            ", batch1Gas);
        console.log("total:             ", totalGas);
    }

    function testProfileFinalValueBlobOnly8() external view {
        (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof) =
            _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(TESTDATA, "octic_whir_k22_jb100_lir6_ff4_rsv1_success.blob")
        );
        BlobOffsets memory offsets = _computeOffsets(proof);

        (uint256 gasUsed, uint256 finalValue) = harness.profileFinalValueBlobOnly(
            proof.initialCommitment, statement, proof, blob, offsets.finalPoly
        );

        console.log("=== Final Value Blob Only ===");
        console.log("gas:               ", gasUsed);
        console.log("finalValue:        ", finalValue);
    }

    function _printStirBreakdown(string memory label, WhirProfileHarness8.StirBreakdown memory bd)
        internal
        pure
    {
        console.log("=== STIR Breakdown ===");
        console.log(label);
        console.log("total:             ", bd.total);
        console.log("powCheck:          ", bd.powCheck);
        console.log("sampleQueries:     ", bd.sampleQueries);
        console.log("leafHashing:       ", bd.leafHashing);
        console.log("merkleReduction:   ", bd.merkleReduction);
        console.log("pow:               ", bd.pow);
        console.log("rowFolding:        ", bd.rowFolding);
        console.log("overhead:          ", bd.overhead);
        console.log("queryCount:        ", bd.queryCount);
        console.log("rowLen:            ", bd.rowLen);
        console.log("depth:             ", bd.depth);
    }

    function _loadSuccessFixture()
        internal
        view
        returns (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof)
    {
        statement = abi.decode(
            vm.readFileBinary(
                string.concat(TESTDATA, "octic_whir_k22_jb100_lir6_ff4_rsv1_success_statement.abi")
            ),
            (WhirStructs.WhirStatement)
        );
        proof = abi.decode(
            vm.readFileBinary(
                string.concat(TESTDATA, "octic_whir_k22_jb100_lir6_ff4_rsv1_success_proof.abi")
            ),
            (WhirStructs.WhirProof)
        );
    }

    function _computeOffsets(WhirStructs.WhirProof memory proof)
        internal
        pure
        returns (BlobOffsets memory offsets)
    {
        uint256 offset = HEADER_BYTES;

        offset += STATEMENT_POINT_ARITY * 32;
        offset += 32;

        offset += 20;
        offset += 32;

        offset += proof.initialSumcheck.polynomialEvals.length * 32;

        offset += 20;
        offset += 32;
        offset += 4;
        offset += proof.rounds[0].queryBatch.values.length * 4;
        offset += proof.rounds[0].queryBatch.decommitments.length * 20;
        offset += proof.rounds[0].sumcheck.polynomialEvals.length * 32;

        offset += 20;
        offset += 32;
        offset += 4;
        offset += proof.rounds[1].queryBatch.values.length * 32;
        offset += proof.rounds[1].queryBatch.decommitments.length * 20;
        offset += proof.rounds[1].sumcheck.polynomialEvals.length * 32;

        offset += 20;
        offset += 32;
        offset += 4;
        offset += proof.rounds[2].queryBatch.values.length * 32;
        offset += proof.rounds[2].queryBatch.decommitments.length * 20;
        offset += proof.rounds[2].sumcheck.polynomialEvals.length * 32;

        offsets.finalPoly = offset;
    }
}
