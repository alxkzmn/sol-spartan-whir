// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";

import {KeccakChallenger} from "../src/transcript/KeccakChallenger.sol";
import {QuarticWhirFixedConfig} from "../src/generated/QuarticWhirFixedConfig.sol";
import {WhirStructs} from "../src/whir/WhirStructs.sol";
import {WhirVerifierCore4} from "../src/whir/WhirVerifierCore4.sol";
import {WhirVerifierUtils4} from "../src/whir/WhirVerifierUtils4.sol";
import {MerkleVerifier} from "../src/merkle/MerkleVerifier.sol";

contract WhirStirDetailHarness {
    using KeccakChallenger for KeccakChallenger.State;

    struct StirFrontierBreakdown {
        uint256 total;
        uint256 sampleQueries;
        uint256 frontierInit;
        uint256 merkleLoopOnly;
        uint256 overhead;
        uint256 queryCount;
        uint256 rowLen;
        uint256 depth;
    }

    struct FinalStirSplit {
        uint256 total;
        uint256 materialization;
        uint256 checkOnly;
        uint256 queryCount;
        uint256 polyLen;
    }

    function profileStirFrontierBreakdowns(
        bytes32 expectedCommitment,
        WhirStructs.WhirStatement calldata statement,
        WhirStructs.WhirProof calldata proof
    )
        external
        view
        returns (
            StirFrontierBreakdown memory round0,
            StirFrontierBreakdown memory round1,
            StirFrontierBreakdown memory finalBd
        )
    {
        round0 = _profileRound0Frontier(expectedCommitment, statement, proof);
        round1 = _profileRound1Frontier(expectedCommitment, statement, proof);
        finalBd = _profileFinalFrontier(expectedCommitment, statement, proof);
    }

    function profileFinalStirSplit(
        bytes32 expectedCommitment,
        WhirStructs.WhirStatement calldata statement,
        WhirStructs.WhirProof calldata proof
    ) external view returns (FinalStirSplit memory split) {
        KeccakChallenger.State memory challenger;
        QuarticWhirFixedConfig.observePattern(challenger);

        WhirVerifierCore4.ParsedCommitment
            memory prevCommitment = WhirVerifierCore4._parseCommitment(
                challenger,
                proof.initialCommitment,
                proof.initialOodAnswers,
                QuarticWhirFixedConfig.NUM_VARIABLES,
                QuarticWhirFixedConfig.COMMITMENT_OOD_SAMPLES
            );
        require(prevCommitment.root == expectedCommitment, "COMMITMENT");

        WhirVerifierCore4.Constraint[]
            memory constraints = new WhirVerifierCore4.Constraint[](3);
        uint256 constraintCount = 1;

        constraints[0] = WhirVerifierCore4.Constraint({
            challenge: WhirVerifierUtils4.sampleExt4(challenger),
            eqStatement: WhirVerifierCore4._concatenateEq(
                WhirVerifierCore4._statementFromCalldata(
                    statement,
                    QuarticWhirFixedConfig.NUM_VARIABLES
                ),
                prevCommitment.oodStatement
            ),
            selStatement: WhirVerifierCore4._emptySelect(
                QuarticWhirFixedConfig.NUM_VARIABLES
            )
        });

        uint256 claimedEval = WhirVerifierCore4._combineConstraintEvals(
            0,
            constraints[0]
        );
        uint256[] memory allRandomness = new uint256[](
            QuarticWhirFixedConfig.NUM_VARIABLES
        );
        uint256 randomnessCursor;
        uint256[] memory foldingRandomness;

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

        unchecked {
            for (
                uint256 roundIndex = 0;
                roundIndex < proof.rounds.length;
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
        }

        challenger.observeValidatedPackedExt4Slice(proof.finalPoly);

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
        split.materialization = g - gasleft();

        split.checkOnly = 0;
        split.total = split.materialization;
        split.polyLen = proof.finalPoly.length;
    }

    function _profileRound0Frontier(
        bytes32 expectedCommitment,
        WhirStructs.WhirStatement calldata statement,
        WhirStructs.WhirProof calldata proof
    ) internal view returns (StirFrontierBreakdown memory bd) {
        KeccakChallenger.State memory challenger;
        QuarticWhirFixedConfig.observePattern(challenger);

        WhirVerifierCore4.ParsedCommitment
            memory prevCommitment = WhirVerifierCore4._parseCommitment(
                challenger,
                proof.initialCommitment,
                proof.initialOodAnswers,
                QuarticWhirFixedConfig.NUM_VARIABLES,
                QuarticWhirFixedConfig.COMMITMENT_OOD_SAMPLES
            );
        require(prevCommitment.root == expectedCommitment, "COMMITMENT");

        WhirVerifierCore4.Constraint[]
            memory cArr = new WhirVerifierCore4.Constraint[](1);
        cArr[0] = WhirVerifierCore4.Constraint({
            challenge: WhirVerifierUtils4.sampleExt4(challenger),
            eqStatement: WhirVerifierCore4._concatenateEq(
                WhirVerifierCore4._statementFromCalldata(
                    statement,
                    QuarticWhirFixedConfig.NUM_VARIABLES
                ),
                prevCommitment.oodStatement
            ),
            selStatement: WhirVerifierCore4._emptySelect(
                QuarticWhirFixedConfig.NUM_VARIABLES
            )
        });

        uint256 claimedEval = WhirVerifierCore4._combineConstraintEvals(
            0,
            cArr[0]
        );
        uint256[] memory allRandomness = new uint256[](
            QuarticWhirFixedConfig.NUM_VARIABLES
        );
        uint256[] memory foldingRandomness;

        (claimedEval, foldingRandomness, ) = WhirVerifierCore4._verifySumcheck(
            proof.initialSumcheck,
            challenger,
            claimedEval,
            QuarticWhirFixedConfig.INITIAL_SUMCHECK_ROUNDS,
            QuarticWhirFixedConfig.STARTING_FOLDING_POW_BITS,
            allRandomness,
            0
        );

        QuarticWhirFixedConfig.RoundConfig memory rc = QuarticWhirFixedConfig
            .roundConfig(0);
        WhirStructs.WhirRoundProof calldata rp = proof.rounds[0];
        WhirVerifierCore4._parseCommitment(
            challenger,
            rp.commitment,
            rp.oodAnswers,
            rc.numVariables,
            rc.oodSamples
        );

        bd = _profileFrontierAndMerkleRaw(
            challenger,
            prevCommitment.root,
            rc.powBits,
            rc.numQueries,
            rc.foldingFactor,
            rc.domainSize,
            rp.queryBatch,
            true,
            rp.powWitness,
            true,
            0,
            uint8(QuarticWhirFixedConfig.EFFECTIVE_DIGEST_BYTES)
        );
    }

    function _profileRound1Frontier(
        bytes32 expectedCommitment,
        WhirStructs.WhirStatement calldata statement,
        WhirStructs.WhirProof calldata proof
    ) internal view returns (StirFrontierBreakdown memory bd) {
        KeccakChallenger.State memory challenger;
        QuarticWhirFixedConfig.observePattern(challenger);

        WhirVerifierCore4.ParsedCommitment
            memory prevCommitment = WhirVerifierCore4._parseCommitment(
                challenger,
                proof.initialCommitment,
                proof.initialOodAnswers,
                QuarticWhirFixedConfig.NUM_VARIABLES,
                QuarticWhirFixedConfig.COMMITMENT_OOD_SAMPLES
            );
        require(prevCommitment.root == expectedCommitment, "COMMITMENT");

        WhirVerifierCore4.Constraint[]
            memory cArr = new WhirVerifierCore4.Constraint[](2);
        cArr[0] = WhirVerifierCore4.Constraint({
            challenge: WhirVerifierUtils4.sampleExt4(challenger),
            eqStatement: WhirVerifierCore4._concatenateEq(
                WhirVerifierCore4._statementFromCalldata(
                    statement,
                    QuarticWhirFixedConfig.NUM_VARIABLES
                ),
                prevCommitment.oodStatement
            ),
            selStatement: WhirVerifierCore4._emptySelect(
                QuarticWhirFixedConfig.NUM_VARIABLES
            )
        });

        uint256 claimedEval = WhirVerifierCore4._combineConstraintEvals(
            0,
            cArr[0]
        );
        uint256[] memory allRandomness = new uint256[](
            QuarticWhirFixedConfig.NUM_VARIABLES
        );
        uint256 randomnessCursor;
        uint256[] memory foldingRandomness;

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

        {
            QuarticWhirFixedConfig.RoundConfig
                memory rc0 = QuarticWhirFixedConfig.roundConfig(0);
            WhirStructs.WhirRoundProof calldata rp0 = proof.rounds[0];
            WhirVerifierCore4.ParsedCommitment memory nc0 = WhirVerifierCore4
                ._parseCommitment(
                    challenger,
                    rp0.commitment,
                    rp0.oodAnswers,
                    rc0.numVariables,
                    rc0.oodSamples
                );
            WhirVerifierCore4.SelectStatement memory ss0 = WhirVerifierCore4
                ._verifyStirChallengesRaw(
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
            claimedEval = WhirVerifierCore4._combineConstraintEvals(
                claimedEval,
                cArr[1]
            );

            (
                claimedEval,
                foldingRandomness,
                randomnessCursor
            ) = WhirVerifierCore4._verifySumcheck(
                rp0.sumcheck,
                challenger,
                claimedEval,
                QuarticWhirFixedConfig.roundConfig(1).foldingFactor,
                rc0.foldingPowBits,
                allRandomness,
                randomnessCursor
            );

            prevCommitment = nc0;
        }

        QuarticWhirFixedConfig.RoundConfig memory rc1 = QuarticWhirFixedConfig
            .roundConfig(1);
        WhirStructs.WhirRoundProof calldata rp1 = proof.rounds[1];
        WhirVerifierCore4._parseCommitment(
            challenger,
            rp1.commitment,
            rp1.oodAnswers,
            rc1.numVariables,
            rc1.oodSamples
        );

        bd = _profileFrontierAndMerkleRaw(
            challenger,
            prevCommitment.root,
            rc1.powBits,
            rc1.numQueries,
            rc1.foldingFactor,
            rc1.domainSize,
            rp1.queryBatch,
            true,
            rp1.powWitness,
            true,
            1,
            uint8(QuarticWhirFixedConfig.EFFECTIVE_DIGEST_BYTES)
        );
    }

    function _profileFinalFrontier(
        bytes32 expectedCommitment,
        WhirStructs.WhirStatement calldata statement,
        WhirStructs.WhirProof calldata proof
    ) internal view returns (StirFrontierBreakdown memory bd) {
        KeccakChallenger.State memory challenger;
        QuarticWhirFixedConfig.observePattern(challenger);

        WhirVerifierCore4.ParsedCommitment
            memory prevCommitment = WhirVerifierCore4._parseCommitment(
                challenger,
                proof.initialCommitment,
                proof.initialOodAnswers,
                QuarticWhirFixedConfig.NUM_VARIABLES,
                QuarticWhirFixedConfig.COMMITMENT_OOD_SAMPLES
            );
        require(prevCommitment.root == expectedCommitment, "COMMITMENT");

        WhirVerifierCore4.Constraint[]
            memory constraints = new WhirVerifierCore4.Constraint[](3);
        uint256 constraintCount = 1;

        constraints[0] = WhirVerifierCore4.Constraint({
            challenge: WhirVerifierUtils4.sampleExt4(challenger),
            eqStatement: WhirVerifierCore4._concatenateEq(
                WhirVerifierCore4._statementFromCalldata(
                    statement,
                    QuarticWhirFixedConfig.NUM_VARIABLES
                ),
                prevCommitment.oodStatement
            ),
            selStatement: WhirVerifierCore4._emptySelect(
                QuarticWhirFixedConfig.NUM_VARIABLES
            )
        });

        uint256 claimedEval = WhirVerifierCore4._combineConstraintEvals(
            0,
            constraints[0]
        );
        uint256[] memory allRandomness = new uint256[](
            QuarticWhirFixedConfig.NUM_VARIABLES
        );
        uint256 randomnessCursor;
        uint256[] memory foldingRandomness;

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

        unchecked {
            for (
                uint256 roundIndex = 0;
                roundIndex < proof.rounds.length;
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
        }

        challenger.observeValidatedPackedExt4Slice(proof.finalPoly);

        bd = _profileFrontierAndMerkleRaw(
            challenger,
            prevCommitment.root,
            QuarticWhirFixedConfig.FINAL_POW_BITS,
            QuarticWhirFixedConfig.FINAL_NUM_QUERIES,
            QuarticWhirFixedConfig.FINAL_FOLDING_FACTOR,
            QuarticWhirFixedConfig.FINAL_DOMAIN_SIZE,
            proof.finalQueryBatch,
            proof.finalQueryBatchPresent,
            proof.finalPowWitness,
            false,
            QuarticWhirFixedConfig.ROUND_COUNT == 0 ? 0 : 1,
            uint8(QuarticWhirFixedConfig.EFFECTIVE_DIGEST_BYTES)
        );
    }

    function _profileFrontierAndMerkleRaw(
        KeccakChallenger.State memory challenger,
        bytes32 expectedRoot,
        uint256 powBits,
        uint256 numQueries,
        uint256 foldingFactor,
        uint256 domainSize,
        WhirStructs.QueryBatchOpening calldata queryBatch,
        bool queryBatchPresent,
        uint256 powWitness,
        bool checkpointAfterPow,
        uint8 expectedKind,
        uint8 effectiveDigestBytes
    ) internal view returns (StirFrontierBreakdown memory bd) {
        uint256 startGas = gasleft();

        if (powBits > 0 && !challenger.checkWitness(powBits, powWitness)) {
            revert WhirVerifierCore4.InvalidPowWitness();
        }

        if (checkpointAfterPow) {
            challenger.sampleBase();
        }

        if (!queryBatchPresent) {
            if (numQueries != 0) {
                revert WhirVerifierCore4.FinalQueryBatchPresenceMismatch(
                    true,
                    false
                );
            }
            bd.total = startGas - gasleft();
            bd.overhead = bd.total;
            return bd;
        }

        uint256 g = gasleft();
        uint256[] memory indices = WhirVerifierUtils4.sampleStirQueries(
            challenger,
            domainSize,
            foldingFactor,
            numQueries
        );
        bd.sampleQueries = g - gasleft();

        if (queryBatch.kind != expectedKind) {
            revert WhirVerifierCore4.QueryBatchKindMismatch(
                expectedKind,
                queryBatch.kind
            );
        }
        if (queryBatch.numQueries != indices.length) {
            revert WhirVerifierCore4.QueryBatchCountMismatch(
                indices.length,
                queryBatch.numQueries
            );
        }

        uint256 expectedRowLen = uint256(1) << foldingFactor;
        if (queryBatch.rowLen != expectedRowLen) {
            revert WhirVerifierCore4.QueryBatchRowLengthMismatch(
                expectedRowLen,
                queryBatch.rowLen
            );
        }

        uint256 depth = WhirVerifierUtils4.log2Strict(
            domainSize >> foldingFactor
        );
        bd.queryCount = indices.length;
        bd.rowLen = expectedRowLen;
        bd.depth = depth;

        bytes32[] memory leafHashes = new bytes32[](indices.length);
        g = gasleft();
        unchecked {
            for (uint256 i = 0; i < indices.length; ++i) {
                leafHashes[i] = expectedKind == 0
                    ? MerkleVerifier.hashLeafBaseSlice(
                        queryBatch.values,
                        i * queryBatch.rowLen,
                        queryBatch.rowLen,
                        effectiveDigestBytes
                    )
                    : MerkleVerifier.hashLeafExtensionSlice(
                        queryBatch.values,
                        i * queryBatch.rowLen,
                        queryBatch.rowLen,
                        effectiveDigestBytes
                    );
            }
        }
        bd.frontierInit = g - gasleft();

        g = gasleft();
        bytes32 computedRoot = _computeRootFromLeafHashesProfile(
            indices,
            leafHashes,
            depth,
            queryBatch.decommitments,
            effectiveDigestBytes
        );
        bd.merkleLoopOnly = g - gasleft();

        if (computedRoot != expectedRoot) {
            revert WhirVerifierCore4.MerkleRootMismatch(
                expectedRoot,
                computedRoot
            );
        }

        bd.total = startGas - gasleft();
        uint256 measured = bd.sampleQueries +
            bd.frontierInit +
            bd.merkleLoopOnly;
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

        uint256 expectedDecommitments = indices.length * depth;
        require(
            decommitments.length == expectedDecommitments,
            "DECOMMITMENT_LEN"
        );

        bytes32 root;
        unchecked {
            for (uint256 i = 0; i < indices.length; ++i) {
                uint256 node = indices[i];
                bytes32 hash = leafHashes[i];
                uint256 pathOffset = i * depth;

                for (uint256 level = 0; level < depth; ++level) {
                    bytes32 siblingHash = decommitments[pathOffset + level];
                    hash = (node & 1) == 0
                        ? MerkleVerifier.compressNode(
                            hash,
                            siblingHash,
                            effectiveDigestBytes
                        )
                        : MerkleVerifier.compressNode(
                            siblingHash,
                            hash,
                            effectiveDigestBytes
                        );
                    node >>= 1;
                }

                if (i == 0) {
                    root = hash;
                } else {
                    require(hash == root, "ROOT_MISMATCH");
                }
            }
        }

        return root;
    }
}

contract WhirStirDetailProfileTest is Test {
    string internal constant TESTDATA = "testdata/";
    WhirStirDetailHarness internal harness;

    function setUp() external {
        harness = new WhirStirDetailHarness();
    }

    function testProfileStirFrontierBreakdown() external view {
        (
            WhirStructs.WhirStatement memory statement,
            WhirStructs.WhirProof memory proof
        ) = _loadSuccessFixture();

        (
            WhirStirDetailHarness.StirFrontierBreakdown memory round0,
            WhirStirDetailHarness.StirFrontierBreakdown memory round1,
            WhirStirDetailHarness.StirFrontierBreakdown memory finalBd
        ) = harness.profileStirFrontierBreakdowns(
                proof.initialCommitment,
                statement,
                proof
            );

        _logStirFrontierBreakdown("Round0", round0);
        _logStirFrontierBreakdown("Round1", round1);
        _logStirFrontierBreakdown("Final", finalBd);
    }

    function testProfileFinalStirSplit() external view {
        (
            WhirStructs.WhirStatement memory statement,
            WhirStructs.WhirProof memory proof
        ) = _loadSuccessFixture();

        WhirStirDetailHarness.FinalStirSplit memory split = harness
            .profileFinalStirSplit(proof.initialCommitment, statement, proof);

        console.log("=== Final STIR Split ===");
        console.log("materialization:  ", split.materialization);
        console.log("checkOnly:        ", split.checkOnly);
        console.log("total:            ", split.total);
        console.log("queryCount:       ", split.queryCount);
        console.log("polyLen:          ", split.polyLen);
    }

    function _logStirFrontierBreakdown(
        string memory label,
        WhirStirDetailHarness.StirFrontierBreakdown memory bd
    ) internal pure {
        console.log("=== STIR Frontier Breakdown ===");
        console.log(label);
        console.log("total:            ", bd.total);
        console.log("sampleQueries:    ", bd.sampleQueries);
        console.log("frontierInit:     ", bd.frontierInit);
        console.log("merkleLoopOnly:   ", bd.merkleLoopOnly);
        console.log("overhead:         ", bd.overhead);
        console.log("queryCount:       ", bd.queryCount);
        console.log("rowLen:           ", bd.rowLen);
        console.log("depth:            ", bd.depth);
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
