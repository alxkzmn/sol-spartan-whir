// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";

import {KoalaBear} from "../src/field/KoalaBear.sol";
import {KoalaBearExt4} from "../src/field/KoalaBearExt4.sol";
import {KeccakChallenger} from "../src/transcript/KeccakChallenger.sol";
import {QuarticWhirFixedConfig} from "../src/generated/QuarticWhirFixedConfig.sol";
import {WhirStructs} from "../src/whir/WhirStructs.sol";
import {WhirVerifier4} from "../src/whir/WhirVerifier4.sol";
import {WhirVerifierCore4} from "../src/whir/WhirVerifierCore4.sol";
import {WhirVerifierUtils4} from "../src/whir/WhirVerifierUtils4.sol";
import {MerkleVerifier} from "../src/merkle/MerkleVerifier.sol";

contract WhirProfileHarness {
    using KeccakChallenger for KeccakChallenger.State;

    function profileParseCommitment(
        bytes32 expectedCommitment,
        WhirStructs.WhirProof calldata proof
    ) external view returns (uint256 gasParseCommitment) {
        uint256 g = gasleft();
        KeccakChallenger.State memory challenger;
        QuarticWhirFixedConfig.observePattern(challenger);
        WhirVerifierCore4.ParsedCommitment memory parsed = WhirVerifierCore4
            ._parseCommitment(
                challenger,
                proof.initialCommitment,
                proof.initialOodAnswers,
                QuarticWhirFixedConfig.NUM_VARIABLES,
                QuarticWhirFixedConfig.COMMITMENT_OOD_SAMPLES
            );
        gasParseCommitment = g - gasleft();

        if (parsed.root != expectedCommitment) {
            revert WhirVerifierCore4.CommitmentMismatch(
                expectedCommitment,
                parsed.root
            );
        }
    }

    function profileConstraintPreparation(
        bytes32 expectedCommitment,
        WhirStructs.WhirStatement calldata statement,
        WhirStructs.WhirProof calldata proof
    )
        external
        view
        returns (
            uint256 gasParseCommitment,
            uint256 gasStatementFromCalldata,
            uint256 gasConcatEq
        )
    {
        uint256 g;

        KeccakChallenger.State memory challenger;
        QuarticWhirFixedConfig.observePattern(challenger);

        g = gasleft();
        WhirVerifierCore4.ParsedCommitment memory parsed = WhirVerifierCore4
            ._parseCommitment(
                challenger,
                proof.initialCommitment,
                proof.initialOodAnswers,
                QuarticWhirFixedConfig.NUM_VARIABLES,
                QuarticWhirFixedConfig.COMMITMENT_OOD_SAMPLES
            );
        gasParseCommitment = g - gasleft();

        if (parsed.root != expectedCommitment) {
            revert WhirVerifierCore4.CommitmentMismatch(
                expectedCommitment,
                parsed.root
            );
        }

        g = gasleft();
        WhirVerifierCore4.EqStatement memory userStatement = WhirVerifierCore4
            ._statementFromCalldata(
                statement,
                QuarticWhirFixedConfig.NUM_VARIABLES
            );
        gasStatementFromCalldata = g - gasleft();

        g = gasleft();
        WhirVerifierCore4.EqStatement memory initialEq = WhirVerifierCore4
            ._concatenateEq(userStatement, parsed.oodStatement);
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
        WhirVerifierCore4.ParsedCommitment memory parsed = WhirVerifierCore4
            ._parseCommitment(
                challenger,
                proof.initialCommitment,
                proof.initialOodAnswers,
                QuarticWhirFixedConfig.NUM_VARIABLES,
                QuarticWhirFixedConfig.COMMITMENT_OOD_SAMPLES
            );
        if (parsed.root != expectedCommitment) {
            revert WhirVerifierCore4.CommitmentMismatch(
                expectedCommitment,
                parsed.root
            );
        }

        WhirVerifierCore4.EqStatement memory initialEq = WhirVerifierCore4
            ._concatenateEq(
                WhirVerifierCore4._statementFromCalldata(
                    statement,
                    QuarticWhirFixedConfig.NUM_VARIABLES
                ),
                parsed.oodStatement
            );
        uint256 claimedEval = WhirVerifierCore4._combineConstraintEvals(
            0,
            WhirVerifierCore4.Constraint({
                challenge: WhirVerifierUtils4.sampleExt4(challenger),
                eqStatement: initialEq,
                selStatement: WhirVerifierCore4._emptySelect(
                    QuarticWhirFixedConfig.NUM_VARIABLES
                )
            })
        );

        uint256[] memory allRandomness = new uint256[](
            QuarticWhirFixedConfig.NUM_VARIABLES
        );
        uint256[] memory foldingRandomness;
        uint256 randomnessCursor;

        g = gasleft();
        (claimedEval, foldingRandomness, randomnessCursor) = WhirVerifierCore4
            ._verifySumcheck(
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
        require(
            randomnessCursor == foldingRandomness.length,
            "PROFILE_RANDOMNESS_CURSOR"
        );
    }

    function profileObserveFinalPoly(
        bytes32 expectedCommitment,
        WhirStructs.WhirStatement calldata statement,
        WhirStructs.WhirProof calldata proof
    ) external view returns (uint256 gasObserveFinalPoly) {
        KeccakChallenger.State memory challenger;
        QuarticWhirFixedConfig.observePattern(challenger);
        WhirVerifierCore4.ParsedCommitment memory parsed = WhirVerifierCore4
            ._parseCommitment(
                challenger,
                proof.initialCommitment,
                proof.initialOodAnswers,
                QuarticWhirFixedConfig.NUM_VARIABLES,
                QuarticWhirFixedConfig.COMMITMENT_OOD_SAMPLES
            );
        if (parsed.root != expectedCommitment) {
            revert WhirVerifierCore4.CommitmentMismatch(
                expectedCommitment,
                parsed.root
            );
        }

        uint256 claimedEval = WhirVerifierCore4._combineConstraintEvals(
            0,
            WhirVerifierCore4.Constraint({
                challenge: WhirVerifierUtils4.sampleExt4(challenger),
                eqStatement: WhirVerifierCore4._concatenateEq(
                    WhirVerifierCore4._statementFromCalldata(
                        statement,
                        QuarticWhirFixedConfig.NUM_VARIABLES
                    ),
                    parsed.oodStatement
                ),
                selStatement: WhirVerifierCore4._emptySelect(
                    QuarticWhirFixedConfig.NUM_VARIABLES
                )
            })
        );
        uint256[] memory allRandomness = new uint256[](
            QuarticWhirFixedConfig.NUM_VARIABLES
        );
        (claimedEval, , ) = WhirVerifierCore4._verifySumcheck(
            proof.initialSumcheck,
            challenger,
            claimedEval,
            QuarticWhirFixedConfig.INITIAL_SUMCHECK_ROUNDS,
            QuarticWhirFixedConfig.STARTING_FOLDING_POW_BITS,
            allRandomness,
            0
        );

        uint256 g = gasleft();
        unchecked {
            for (uint256 i = 0; i < proof.finalPoly.length; ++i) {
                WhirVerifierUtils4.observeExt4(challenger, proof.finalPoly[i]);
            }
        }
        gasObserveFinalPoly = g - gasleft();
        require(claimedEval != 0, "PROFILE_ZERO_CLAIM");
    }

    function profileSyntheticEqConstraint(
        bytes32 expectedCommitment,
        WhirStructs.WhirStatement calldata statement,
        WhirStructs.WhirProof calldata proof
    )
        external
        view
        returns (uint256 gasEvaluateConstraints, uint256 eqPointCount)
    {
        uint256 g;

        KeccakChallenger.State memory challenger;
        QuarticWhirFixedConfig.observePattern(challenger);
        WhirVerifierCore4.ParsedCommitment memory parsed = WhirVerifierCore4
            ._parseCommitment(
                challenger,
                proof.initialCommitment,
                proof.initialOodAnswers,
                QuarticWhirFixedConfig.NUM_VARIABLES,
                QuarticWhirFixedConfig.COMMITMENT_OOD_SAMPLES
            );
        if (parsed.root != expectedCommitment) {
            revert WhirVerifierCore4.CommitmentMismatch(
                expectedCommitment,
                parsed.root
            );
        }

        WhirVerifierCore4.EqStatement memory initialEq = WhirVerifierCore4
            ._concatenateEq(
                WhirVerifierCore4._statementFromCalldata(
                    statement,
                    QuarticWhirFixedConfig.NUM_VARIABLES
                ),
                parsed.oodStatement
            );
        eqPointCount = initialEq.evaluations.length;

        WhirVerifierCore4.Constraint[]
            memory constraints = new WhirVerifierCore4.Constraint[](1);
        constraints[0] = WhirVerifierCore4.Constraint({
            challenge: KoalaBearExt4.fromBase(7),
            eqStatement: initialEq,
            selStatement: WhirVerifierCore4._emptySelect(
                QuarticWhirFixedConfig.NUM_VARIABLES
            )
        });

        uint256[] memory syntheticPoint = new uint256[](
            QuarticWhirFixedConfig.NUM_VARIABLES
        );
        unchecked {
            for (uint256 i = 0; i < QuarticWhirFixedConfig.NUM_VARIABLES; ++i) {
                syntheticPoint[i] = KoalaBearExt4.fromBase(i + 1);
            }
        }

        g = gasleft();
        WhirVerifierCore4._evaluateConstraints(constraints, 1, syntheticPoint);
        gasEvaluateConstraints = g - gasleft();
    }

    function profileSyntheticSelectConstraint()
        external
        view
        returns (uint256 gasEvaluateConstraints, uint256 selectCount)
    {
        WhirVerifierCore4.Constraint[]
            memory constraints = new WhirVerifierCore4.Constraint[](1);
        uint256[] memory vars = new uint256[](20);
        uint256[] memory evals = new uint256[](0);
        unchecked {
            for (uint256 i = 0; i < vars.length; ++i) {
                vars[i] = i + 2;
            }
        }

        constraints[0] = WhirVerifierCore4.Constraint({
            challenge: KoalaBearExt4.fromBase(11),
            eqStatement: WhirVerifierCore4.EqStatement({
                numVariables: QuarticWhirFixedConfig.NUM_VARIABLES,
                evaluations: evals,
                flatPoints: new uint256[](0)
            }),
            selStatement: WhirVerifierCore4.SelectStatement({
                numVariables: QuarticWhirFixedConfig.NUM_VARIABLES,
                evaluations: evals,
                vars: vars
            })
        });
        selectCount = vars.length;

        uint256[] memory syntheticPoint = new uint256[](
            QuarticWhirFixedConfig.NUM_VARIABLES
        );
        unchecked {
            for (uint256 i = 0; i < QuarticWhirFixedConfig.NUM_VARIABLES; ++i) {
                syntheticPoint[i] = KoalaBearExt4.fromBase(i + 1);
            }
        }

        uint256 g = gasleft();
        WhirVerifierCore4._evaluateConstraints(constraints, 1, syntheticPoint);
        gasEvaluateConstraints = g - gasleft();
    }

    function profileStandaloneFinalSumcheck(
        WhirStructs.WhirProof calldata proof
    ) external view returns (uint256 gasFinalSumcheck) {
        KeccakChallenger.State memory challenger;
        challenger.observeBytes(abi.encodePacked(bytes32(uint256(42))));
        uint256[] memory allRandomness = new uint256[](
            QuarticWhirFixedConfig.FINAL_SUMCHECK_ROUNDS
        );
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
        uint256 constraints;
        uint256 finalCheck;
    }

    function profileFullBreakdown(
        bytes32 expectedCommitment,
        WhirStructs.WhirStatement calldata statement,
        WhirStructs.WhirProof calldata proof
    ) external view returns (FullBreakdown memory bd) {
        uint256 g;
        KeccakChallenger.State memory challenger;
        WhirVerifierCore4.Constraint[]
            memory cArr = new WhirVerifierCore4.Constraint[](3);
        uint256 cCount;
        uint256 claimedEval;
        uint256[] memory foldingRandomness;
        uint256[] memory finalSumcheckRandomness;
        uint256[] memory allRandomness = new uint256[](
            QuarticWhirFixedConfig.NUM_VARIABLES
        );
        uint256 randomnessCursor;
        WhirVerifierCore4.ParsedCommitment memory prevCommitment;

        // --- Setup: observePattern + parseCommitment + statement + eq + constraint[0] ---
        g = gasleft();
        QuarticWhirFixedConfig.observePattern(challenger);
        prevCommitment = WhirVerifierCore4._parseCommitment(
            challenger,
            proof.initialCommitment,
            proof.initialOodAnswers,
            QuarticWhirFixedConfig.NUM_VARIABLES,
            QuarticWhirFixedConfig.COMMITMENT_OOD_SAMPLES
        );
        require(prevCommitment.root == expectedCommitment, "COMMITMENT");
        {
            WhirVerifierCore4.EqStatement memory initialEq = WhirVerifierCore4
                ._concatenateEq(
                    WhirVerifierCore4._statementFromCalldata(
                        statement,
                        QuarticWhirFixedConfig.NUM_VARIABLES
                    ),
                    prevCommitment.oodStatement
                );
            cArr[0] = WhirVerifierCore4.Constraint({
                challenge: WhirVerifierUtils4.sampleExt4(challenger),
                eqStatement: initialEq,
                selStatement: WhirVerifierCore4._emptySelect(
                    QuarticWhirFixedConfig.NUM_VARIABLES
                )
            });
        }
        claimedEval = WhirVerifierCore4._combineConstraintEvals(0, cArr[0]);
        cCount = 1;
        bd.setup = g - gasleft();

        // --- Initial Sumcheck ---
        g = gasleft();
        (claimedEval, foldingRandomness, randomnessCursor) = WhirVerifierCore4
            ._verifySumcheck(
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
            QuarticWhirFixedConfig.RoundConfig
                memory rc = QuarticWhirFixedConfig.roundConfig(0);
            WhirStructs.WhirRoundProof calldata rp = proof.rounds[0];

            g = gasleft();
            WhirVerifierCore4.ParsedCommitment memory nc = WhirVerifierCore4
                ._parseCommitment(
                    challenger,
                    rp.commitment,
                    rp.oodAnswers,
                    rc.numVariables,
                    rc.oodSamples
                );
            bd.round0Parse = g - gasleft();

            g = gasleft();
            WhirVerifierCore4.SelectStatement memory ss = WhirVerifierCore4
                ._verifyStirChallengesRaw(
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
            bd.round0Stir = g - gasleft();

            cArr[cCount] = WhirVerifierCore4.Constraint({
                challenge: WhirVerifierUtils4.sampleExt4(challenger),
                eqStatement: nc.oodStatement,
                selStatement: ss
            });
            claimedEval = WhirVerifierCore4._combineConstraintEvals(
                claimedEval,
                cArr[cCount]
            );
            cCount += 1;

            g = gasleft();
            (
                claimedEval,
                foldingRandomness,
                randomnessCursor
            ) = WhirVerifierCore4._verifySumcheck(
                rp.sumcheck,
                challenger,
                claimedEval,
                QuarticWhirFixedConfig.roundConfig(1).foldingFactor,
                rc.foldingPowBits,
                allRandomness,
                randomnessCursor
            );
            bd.round0Sumcheck = g - gasleft();

            prevCommitment = nc;
        }

        // --- Round 1 ---
        {
            QuarticWhirFixedConfig.RoundConfig
                memory rc = QuarticWhirFixedConfig.roundConfig(1);
            WhirStructs.WhirRoundProof calldata rp = proof.rounds[1];

            g = gasleft();
            WhirVerifierCore4.ParsedCommitment memory nc = WhirVerifierCore4
                ._parseCommitment(
                    challenger,
                    rp.commitment,
                    rp.oodAnswers,
                    rc.numVariables,
                    rc.oodSamples
                );
            bd.round1Parse = g - gasleft();

            g = gasleft();
            WhirVerifierCore4.SelectStatement memory ss = WhirVerifierCore4
                ._verifyStirChallengesRaw(
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
            bd.round1Stir = g - gasleft();

            cArr[cCount] = WhirVerifierCore4.Constraint({
                challenge: WhirVerifierUtils4.sampleExt4(challenger),
                eqStatement: nc.oodStatement,
                selStatement: ss
            });
            claimedEval = WhirVerifierCore4._combineConstraintEvals(
                claimedEval,
                cArr[cCount]
            );
            cCount += 1;

            g = gasleft();
            (
                claimedEval,
                foldingRandomness,
                randomnessCursor
            ) = WhirVerifierCore4._verifySumcheck(
                rp.sumcheck,
                challenger,
                claimedEval,
                QuarticWhirFixedConfig.FINAL_FOLDING_FACTOR,
                rc.foldingPowBits,
                allRandomness,
                randomnessCursor
            );
            bd.round1Sumcheck = g - gasleft();

            prevCommitment = nc;
        }

        // --- Observe Final Poly ---
        g = gasleft();
        WhirVerifierUtils4.validatePackedExt4Calldata(proof.finalPoly);
        unchecked {
            for (uint256 i = 0; i < proof.finalPoly.length; ++i) {
                WhirVerifierUtils4.observeExt4(challenger, proof.finalPoly[i]);
            }
        }
        bd.observeFinalPoly = g - gasleft();

        // --- Final STIR ---
        WhirVerifierCore4.SelectStatement memory finalSS;
        g = gasleft();
        finalSS = WhirVerifierCore4._verifyStirChallengesRaw(
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
            1,
            uint8(QuarticWhirFixedConfig.EFFECTIVE_DIGEST_BYTES)
        );
        bd.finalStir = g - gasleft();

        // --- Final Select ---
        g = gasleft();
        WhirVerifierCore4._verifySelectStatement(finalSS, proof.finalPoly);
        bd.finalSelect = g - gasleft();

        // --- Final Sumcheck ---
        g = gasleft();
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
        bd.finalSumcheck = g - gasleft();

        // --- Evaluate Constraints ---
        uint256 evaluationOfWeights;
        g = gasleft();
        evaluationOfWeights = WhirVerifierCore4._evaluateConstraints(
            cArr,
            cCount,
            allRandomness
        );
        bd.constraints = g - gasleft();

        // --- Final Check ---
        g = gasleft();
        {
            uint256 finalValue = WhirVerifierCore4._evaluateFinalValue(
                proof.finalPoly,
                finalSumcheckRandomness
            );
            uint256 expected = KoalaBearExt4.mul(
                evaluationOfWeights,
                finalValue
            );
            require(claimedEval == expected, "FINAL_CHECK");
        }
        bd.finalCheck = g - gasleft();
    }

    function profileStirMicro(
        uint256[] calldata baseValues16,
        uint256[] calldata extValues16
    )
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
            MerkleVerifier.compressNode(
                bytes32(uint256(i + 1)),
                bytes32(uint256(i + 42)),
                20
            );
        }
        gasCompressNode = (g - gasleft()) / 100;

        g = gasleft();
        uint256 powSink;
        for (uint256 i = 0; i < 100; ++i) {
            powSink += KoalaBear.pow(1848593786, 100000 + i * 2718);
        }
        gasPow = (g - gasleft()) / 100;
        require(powSink != 0, "SINK");

        g = gasleft();
        uint256 qsSink;
        for (uint256 i = 0; i < 10; ++i) {
            KeccakChallenger.State memory ch;
            ch.observeBytes(abi.encodePacked(bytes32(uint256(42 + i))));
            uint256[] memory qs = WhirVerifierUtils4.sampleStirQueries(
                ch,
                4194304,
                4,
                9
            );
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
        (
            WhirStructs.WhirStatement memory statement,
            WhirStructs.WhirProof memory proof
        ) = _loadSuccessFixture();

        uint256 gasParseCommitment = harness.profileParseCommitment(
            proof.initialCommitment,
            proof
        );

        uint256 g = gasleft();
        assertTrue(verifier.verify(proof.initialCommitment, statement, proof));
        uint256 gasVerify = g - gasleft();

        console.log("=== WHIR Verification Gas Profile ===");
        console.log("Parse commitment:     ", gasParseCommitment);
        console.log("Total verify:         ", gasVerify);
        console.log("Remainder:            ", gasVerify - gasParseCommitment);
    }

    function testProfileWhirHotspots() external view {
        (
            WhirStructs.WhirStatement memory statement,
            WhirStructs.WhirProof memory proof
        ) = _loadSuccessFixture();

        (
            uint256 gasParseCommitment,
            uint256 gasStatementFromCalldata,
            uint256 gasConcatEq
        ) = harness.profileConstraintPreparation(
                proof.initialCommitment,
                statement,
                proof
            );
        uint256 gasInitialSumcheck = harness.profileInitialSumcheck(
            proof.initialCommitment,
            statement,
            proof
        );
        uint256 gasObserveFinalPoly = harness.profileObserveFinalPoly(
            proof.initialCommitment,
            statement,
            proof
        );
        (uint256 gasEvaluateConstraints, uint256 eqPointCount) = harness
            .profileSyntheticEqConstraint(
                proof.initialCommitment,
                statement,
                proof
            );
        (uint256 gasSelectConstraints, uint256 selectCount) = harness
            .profileSyntheticSelectConstraint();
        uint256 gasFinalSumcheck = harness.profileStandaloneFinalSumcheck(
            proof
        );

        console.log("=== WHIR Hotspot Profile ===");
        console.log("Parse commitment:      ", gasParseCommitment);
        console.log("Statement copy:        ", gasStatementFromCalldata);
        console.log("Eq concat:             ", gasConcatEq);
        console.log("Initial sumcheck:      ", gasInitialSumcheck);
        console.log("Observe finalPoly:     ", gasObserveFinalPoly);
        console.log("Eq point count:        ", eqPointCount);
        console.log("Select count:          ", selectCount);
        console.log("Final sumcheck:        ", gasFinalSumcheck);
        console.log("Synthetic eq eval:     ", gasEvaluateConstraints);
        console.log("Synthetic select eval: ", gasSelectConstraints);
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
            mulSink |= KoalaBearExt4.mul(
                packedInputs[i & 7],
                packedInputs[(i + 3) & 7]
            );
        }
        uint256 gasMul100 = gasCheck - gasleft();

        gasCheck = gasleft();
        uint256 addSink;
        for (uint256 i = 0; i < 100; ++i) {
            addSink |= KoalaBearExt4.add(
                packedInputs[i & 7],
                packedInputs[(i + 3) & 7]
            );
        }
        uint256 gasAdd100 = gasCheck - gasleft();

        gasCheck = gasleft();
        uint256 subSink;
        for (uint256 i = 0; i < 100; ++i) {
            subSink |= KoalaBearExt4.sub(
                packedInputs[i & 7],
                packedInputs[(i + 3) & 7]
            );
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
            sampleBaseChallenger.observeBytes(
                abi.encodePacked(bytes32(uint256(42)))
            );
            sampleBaseSink += sampleBaseChallenger.sampleBase();
        }
        uint256 gasSampleBase100 = gasCheck - gasleft();

        gasCheck = gasleft();
        uint256 sampleExt4Sink;
        for (uint256 i = 0; i < 100; ++i) {
            KeccakChallenger.State memory sampleExt4Challenger;
            sampleExt4Challenger.observeBytes(
                abi.encodePacked(bytes32(uint256(42)))
            );
            sampleExt4Sink |= WhirVerifierUtils4.sampleExt4(
                sampleExt4Challenger
            );
        }
        uint256 gasSampleExt4_100 = gasCheck - gasleft();

        gasCheck = gasleft();
        uint256 sampleBitsSink;
        for (uint256 i = 0; i < 100; ++i) {
            KeccakChallenger.State memory sampleBitsChallenger;
            sampleBitsChallenger.observeBytes(
                abi.encodePacked(bytes32(uint256(42)))
            );
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
            observeExt4Challenger.observeBytes(
                abi.encodePacked(bytes32(uint256(42)))
            );
            WhirVerifierUtils4.observeExt4(
                observeExt4Challenger,
                packedInputs[i & 7]
            );
            observeExt4Sink |= observeExt4Challenger.outputIndex;
        }
        uint256 gasObserveExt4_100 = gasCheck - gasleft();

        gasCheck = gasleft();
        uint256 observeHashU64Sink;
        for (uint256 i = 0; i < 100; ++i) {
            KeccakChallenger.State memory observeDigestChallenger;
            observeDigestChallenger.observeBytes(
                abi.encodePacked(bytes32(uint256(42)))
            );
            observeDigestChallenger.observeHashU64Digest(
                bytes32(packedInputs[i & 7])
            );
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
            hypercube64Sink |= KoalaBearExt4.evaluate_hypercube(
                evals64,
                point6
            );
        }
        uint256 gasHypercube64_10 = gasCheck - gasleft();
        assertTrue(
            (mulSink |
                addSink |
                subSink |
                squareSink |
                eqSink |
                hypercube16Sink |
                sampleBaseSink |
                sampleExt4Sink |
                sampleBitsSink |
                observeExt4Sink |
                observeHashU64Sink |
                extrapolateSink |
                hypercube64Sink) != 0
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
        (
            WhirStructs.WhirStatement memory statement,
            WhirStructs.WhirProof memory proof
        ) = _loadSuccessFixture();

        WhirProfileHarness.FullBreakdown memory bd = harness
            .profileFullBreakdown(proof.initialCommitment, statement, proof);

        uint256 total = bd.setup +
            bd.initialSumcheck +
            bd.round0Parse +
            bd.round0Stir +
            bd.round0Sumcheck +
            bd.round1Parse +
            bd.round1Stir +
            bd.round1Sumcheck +
            bd.observeFinalPoly +
            bd.finalStir +
            bd.finalSelect +
            bd.finalSumcheck +
            bd.constraints +
            bd.finalCheck;

        console.log("=== Full Verification Breakdown ===");
        console.log("Setup (pattern+commit+eq):  ", bd.setup);
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
        console.log("Constraint evaluation:      ", bd.constraints);
        console.log("Final value check:          ", bd.finalCheck);
        console.log("---");
        console.log("Sum of phases:              ", total);
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

    function _makeRuntimeExt4Evals(
        uint256 salt,
        uint256 len
    ) internal pure returns (uint256[] memory evals) {
        evals = new uint256[](len);
        unchecked {
            for (uint256 i = 0; i < len; ++i) {
                evals[i] = _runtimePackedExt4(salt, i + 1);
            }
        }
    }

    function _runtimePackedExt4(
        uint256 salt,
        uint256 offset
    ) internal pure returns (uint256) {
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
        returns (
            WhirStructs.WhirStatement memory statement,
            WhirStructs.WhirProof memory proof
        )
    {
        statement = abi.decode(
            vm.readFileBinary(
                string.concat(TESTDATA, "quartic_whir_success_statement.abi")
            ),
            (WhirStructs.WhirStatement)
        );
        proof = abi.decode(
            vm.readFileBinary(
                string.concat(TESTDATA, "quartic_whir_success_proof.abi")
            ),
            (WhirStructs.WhirProof)
        );
    }
}
