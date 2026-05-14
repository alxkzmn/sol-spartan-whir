// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test, console } from "forge-std/Test.sol";

import { KoalaBearExt4 } from "../src/field/KoalaBearExt4.sol";
import { KeccakChallenger } from "../src/transcript/KeccakChallenger.sol";
import { QuarticWhirFixedConfig } from "../src/generated/QuarticWhirFixedConfig_lir6_ff5_rsv1.sol";
import { WhirStructs } from "../src/whir/WhirStructs.sol";
import { WhirVerifierCore4 } from "../src/whir/WhirVerifierCore4.sol";
import { WhirVerifierUtils4 } from "../src/whir/WhirVerifierUtils4.sol";

/// @dev Targeted gas calibration for the Python model.
///      Measures individual verifier phases for the current 2-round schedule
///      (Constant(4), lir=6, rs_v=1: 16 → 12 → 8 → 4).
contract GasCalibrationHarness {
    using KeccakChallenger for KeccakChallenger.State;

    struct PhaseGas {
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
        uint256 finalSumcheck;
        uint256 constraintRounds;
        uint256 constraintInitial;
        uint256 finalValueCheck;
    }

    function measurePhases(
        bytes32 expectedCommitment,
        WhirStructs.WhirStatement calldata statement,
        WhirStructs.WhirProof calldata proof
    ) external view returns (PhaseGas memory pg) {
        uint256 g;
        KeccakChallenger.State memory challenger;
        uint256 claimedEval;
        uint256[] memory foldingRandomness;
        uint256[] memory finalSumcheckRandomness;
        uint256[] memory allRandomness = new uint256[](QuarticWhirFixedConfig.NUM_VARIABLES);
        uint256 randomnessCursor;

        // --- Phase 1: Setup ---
        g = gasleft();

        QuarticWhirFixedConfig.observePattern(challenger);

        WhirVerifierCore4.FixedParsedCommitment memory parsedCommitment =
            WhirVerifierCore4._parseFixedCommitment16x2(
                challenger, proof.initialCommitment, proof.initialOodAnswers
            );

        require(parsedCommitment.root == expectedCommitment, "COMMITMENT");

        uint256 initialConstraintChallenge = WhirVerifierUtils4.sampleExt4(challenger);

        require(statement.points.length == 1 && statement.evaluations.length == 1, "STMT_COUNT");
        uint256[] calldata statementPoint = statement.points[0];
        require(statementPoint.length == QuarticWhirFixedConfig.NUM_VARIABLES, "STMT_ARITY");
        WhirVerifierUtils4.validatePackedExt4Calldata(statementPoint);
        uint256 statementEval = statement.evaluations[0];
        WhirVerifierUtils4.validatePackedExt4(statementEval);

        claimedEval = WhirVerifierCore4._hornerStep(
            WhirVerifierCore4._hornerStep(
                WhirVerifierCore4._hornerStep(
                    0, initialConstraintChallenge, proof.initialOodAnswers[1]
                ),
                initialConstraintChallenge,
                proof.initialOodAnswers[0]
            ),
            initialConstraintChallenge,
            statementEval
        );

        pg.setup = g - gasleft();

        // --- Phase 2: Initial Sumcheck ---
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
        pg.initialSumcheck = g - gasleft();

        // --- Phase 3: Round 0 Parse ---
        WhirVerifierCore4.FixedParsedCommitment memory prevCommitment = parsedCommitment;
        QuarticWhirFixedConfig.RoundConfig memory round0Config =
            QuarticWhirFixedConfig.roundConfig(0);
        WhirStructs.WhirRoundProof calldata round0Proof = proof.rounds[0];

        g = gasleft();
        WhirVerifierCore4.FixedParsedCommitment memory round0Commitment =
            WhirVerifierCore4._parseFixedCommitment2(
                challenger,
                round0Proof.commitment,
                round0Proof.oodAnswers,
                round0Config.numVariables
            );
        pg.round0Parse = g - gasleft();

        // --- Phase 4: Round 0 STIR ---
        uint256 round0ConstraintChallenge;
        uint256[] memory round0SelVars;
        g = gasleft();
        {
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
        }
        pg.round0Stir = g - gasleft();

        // --- Phase 5: Round 0 Sumcheck ---
        g = gasleft();
        (claimedEval, foldingRandomness, randomnessCursor) = WhirVerifierCore4._verifySumcheck(
            round0Proof.sumcheck,
            challenger,
            claimedEval,
            round0Config.foldingFactor,
            round0Config.foldingPowBits,
            allRandomness,
            randomnessCursor
        );
        pg.round0Sumcheck = g - gasleft();

        // --- Phase 6: Round 1 Parse ---
        prevCommitment = round0Commitment;
        QuarticWhirFixedConfig.RoundConfig memory round1Config =
            QuarticWhirFixedConfig.roundConfig(1);
        WhirStructs.WhirRoundProof calldata round1Proof = proof.rounds[1];

        g = gasleft();
        WhirVerifierCore4.FixedParsedCommitment memory round1Commitment =
            WhirVerifierCore4._parseFixedCommitment2(
                challenger,
                round1Proof.commitment,
                round1Proof.oodAnswers,
                round1Config.numVariables
            );
        pg.round1Parse = g - gasleft();

        // --- Phase 7: Round 1 STIR ---
        uint256 round1ConstraintChallenge;
        uint256[] memory round1SelVars;
        g = gasleft();
        {
            uint256 round1Contribution;
            (round1ConstraintChallenge, round1Contribution, round1SelVars) =
                WhirVerifierCore4._verifyStirAndCombineConstraint(
                    challenger,
                    prevCommitment.root,
                    round1Config.powBits,
                    round1Config.numQueries,
                    round1Config.foldingFactor,
                    round1Config.domainSize,
                    round1Config.foldedDomainGen,
                    round1Proof.queryBatch,
                    true,
                    round1Proof.powWitness,
                    foldingRandomness,
                    1,
                    round1Proof.oodAnswers
                );
            claimedEval = KoalaBearExt4.add(claimedEval, round1Contribution);
        }
        pg.round1Stir = g - gasleft();

        // --- Phase 8: Round 1 Sumcheck ---
        g = gasleft();
        (claimedEval, foldingRandomness, randomnessCursor) = WhirVerifierCore4._verifySumcheck(
            round1Proof.sumcheck,
            challenger,
            claimedEval,
            round1Config.foldingFactor,
            round1Config.foldingPowBits,
            allRandomness,
            randomnessCursor
        );
        pg.round1Sumcheck = g - gasleft();

        // --- Phase 9: Observe Final Poly ---
        prevCommitment = round1Commitment;
        g = gasleft();
        require(
            proof.finalPoly.length == QuarticWhirFixedConfig.FINAL_POLY_LENGTH, "FINAL_POLY_LEN"
        );
        challenger.observeValidatedPackedExt4Slice(proof.finalPoly);
        pg.observeFinalPoly = g - gasleft();

        // --- Phase 10: Final STIR ---
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
        pg.finalStir = g - gasleft();

        // --- Phase 11: Final Sumcheck ---
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
        pg.finalSumcheck = g - gasleft();

        require(randomnessCursor == QuarticWhirFixedConfig.NUM_VARIABLES, "RANDOMNESS_LEN");

        // --- Phase 12: Constraint evaluation (rounds) ---
        uint256 evaluationOfWeights;
        g = gasleft();
        evaluationOfWeights = WhirVerifierCore4._evaluateConstraintsFixedSelectRaw(
            round0ConstraintChallenge,
            round0Commitment.oodFlatPoints,
            round0SelVars,
            round1ConstraintChallenge,
            round1Commitment.oodFlatPoints,
            round1SelVars,
            allRandomness
        );
        pg.constraintRounds = g - gasleft();

        // --- Phase 13: Constraint evaluation (initial) ---
        g = gasleft();
        {
            uint256 initEval = WhirVerifierCore4._hornerStep(
                WhirVerifierCore4._hornerStep(
                    WhirVerifierCore4._hornerStep(
                        0,
                        initialConstraintChallenge,
                        WhirVerifierCore4._eqPolyEvalAt(
                            parsedCommitment.oodFlatPoints,
                            QuarticWhirFixedConfig.NUM_VARIABLES,
                            allRandomness,
                            0,
                            QuarticWhirFixedConfig.NUM_VARIABLES
                        )
                    ),
                    initialConstraintChallenge,
                    WhirVerifierCore4._eqPolyEvalAt(
                        parsedCommitment.oodFlatPoints,
                        0,
                        allRandomness,
                        0,
                        QuarticWhirFixedConfig.NUM_VARIABLES
                    )
                ),
                initialConstraintChallenge,
                WhirVerifierCore4._eqPolyEvalAtCalldata(
                    statementPoint, allRandomness, 0, QuarticWhirFixedConfig.NUM_VARIABLES
                )
            );
            evaluationOfWeights = KoalaBearExt4.add(evaluationOfWeights, initEval);
        }
        pg.constraintInitial = g - gasleft();

        // --- Phase 14: Final value check ---
        g = gasleft();
        {
            uint256 finalValue =
                WhirVerifierCore4._evaluateFinalValue(proof.finalPoly, finalSumcheckRandomness);
            uint256 expected = KoalaBearExt4.mul(evaluationOfWeights, finalValue);
            require(claimedEval == expected, "FINAL_CHECK");
        }
        pg.finalValueCheck = g - gasleft();
    }
}

contract GasCalibrationTest is Test {
    string internal constant TESTDATA = "testdata/";
    GasCalibrationHarness internal harness;

    function setUp() external {
        harness = new GasCalibrationHarness();
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

    function testMeasurePhases() external view {
        (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof) =
            _loadSuccessFixture();

        GasCalibrationHarness.PhaseGas memory pg =
            harness.measurePhases(proof.initialCommitment, statement, proof);

        uint256 total = pg.setup + pg.initialSumcheck + pg.round0Parse + pg.round0Stir
            + pg.round0Sumcheck + pg.round1Parse + pg.round1Stir + pg.round1Sumcheck
            + pg.observeFinalPoly + pg.finalStir + pg.finalSumcheck + pg.constraintRounds
            + pg.constraintInitial + pg.finalValueCheck;

        console.log("=== Phase-Level Gas Calibration (2-round ff=4) ===");
        console.log("Setup (pattern+commit+eval):", pg.setup);
        console.log("Initial sumcheck (4r):      ", pg.initialSumcheck);
        console.log("Round0 parse commitment:    ", pg.round0Parse);
        console.log("Round0 STIR (9q):           ", pg.round0Stir);
        console.log("Round0 sumcheck (4r pow=0): ", pg.round0Sumcheck);
        console.log("Round1 parse commitment:    ", pg.round1Parse);
        console.log("Round1 STIR (6q):           ", pg.round1Stir);
        console.log("Round1 sumcheck (4r pow=4): ", pg.round1Sumcheck);
        console.log("Observe finalPoly (16 ext4):", pg.observeFinalPoly);
        console.log("Final STIR (5q):            ", pg.finalStir);
        console.log("Final sumcheck (4r pow=0):  ", pg.finalSumcheck);
        console.log("Constraint rounds (2r):     ", pg.constraintRounds);
        console.log("Constraint initial (nv=16): ", pg.constraintInitial);
        console.log("Final value check (16coeff):", pg.finalValueCheck);
        console.log("---");
        console.log("Sum of phases:              ", total);
    }
}
