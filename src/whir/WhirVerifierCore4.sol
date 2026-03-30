// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {KoalaBear} from "../field/KoalaBear.sol";
import {KoalaBearExt4} from "../field/KoalaBearExt4.sol";
import {MerkleVerifier} from "../merkle/MerkleVerifier.sol";
import {KeccakChallenger} from "../transcript/KeccakChallenger.sol";
import {WhirStructs} from "./WhirStructs.sol";
import {WhirVerifierUtils4} from "./WhirVerifierUtils4.sol";

library WhirVerifierCore4 {
    using KeccakChallenger for KeccakChallenger.State;

    struct EqStatement {
        uint256 numVariables;
        uint256[] flatPoints;
        uint256[] evaluations;
    }

    struct SelectStatement {
        uint256 numVariables;
        uint256[] vars;
        uint256[] evaluations;
    }

    struct Constraint {
        uint256 challenge;
        EqStatement eqStatement;
        SelectStatement selStatement;
    }

    struct ParsedCommitment {
        bytes32 root;
        EqStatement oodStatement;
    }

    error CommitmentMismatch(bytes32 expected, bytes32 actual);
    error ProofRoundCountMismatch(uint256 expected, uint256 actual);
    error StatementLengthMismatch(uint256 points, uint256 evaluations);
    error StatementPointArityMismatch(
        uint256 index,
        uint256 expected,
        uint256 actual
    );
    error OodAnswerCountMismatch(uint256 expected, uint256 actual);
    error FinalPolyLengthMismatch(uint256 expected, uint256 actual);
    error FinalQueryBatchPresenceMismatch(bool expected, bool actual);
    error FinalSumcheckPresenceMismatch(bool expected, bool actual);
    error QueryBatchKindMismatch(uint8 expected, uint8 actual);
    error QueryBatchCountMismatch(uint256 expected, uint256 actual);
    error QueryBatchRowLengthMismatch(uint256 expected, uint256 actual);
    error MerkleRootMismatch(bytes32 expected, bytes32 actual);
    error InvalidPowWitness();
    error SumcheckPolynomialLengthMismatch(uint256 expected, uint256 actual);
    error SumcheckPowWitnessLengthMismatch(uint256 expected, uint256 actual);
    error StirConstraintFailed(uint256 index);
    error FinalConstraintMismatch(uint256 expected, uint256 actual);
    error InconsistentConstraintArity(
        uint256 eqNumVariables,
        uint256 selNumVariables
    );
    error RandomnessLengthMismatch(uint256 expected, uint256 actual);

    function verify(
        bytes32 expectedCommitment,
        WhirStructs.ExpandedWhirConfig calldata config,
        WhirStructs.WhirStatement calldata statement,
        WhirStructs.WhirProof calldata proof
    ) internal pure returns (bool) {
        _validateProofShape(config, proof);

        KeccakChallenger.State memory challenger;
        ParsedCommitment memory parsed = parseCommitment(
            expectedCommitment,
            config,
            proof,
            challenger
        );

        finalize(config, statement, proof, challenger, parsed);
        return true;
    }

    function parseCommitment(
        bytes32 expectedCommitment,
        WhirStructs.ExpandedWhirConfig calldata config,
        WhirStructs.WhirProof calldata proof,
        KeccakChallenger.State memory challenger
    ) internal pure returns (ParsedCommitment memory parsed) {
        WhirVerifierUtils4.observePattern(challenger, config.whirFsPattern);
        parsed = _parseCommitment(
            challenger,
            proof.initialCommitment,
            proof.initialOodAnswers,
            config.numVariables,
            config.commitmentOodSamples
        );

        if (parsed.root != expectedCommitment) {
            revert CommitmentMismatch(expectedCommitment, parsed.root);
        }
    }

    function finalize(
        WhirStructs.ExpandedWhirConfig calldata config,
        WhirStructs.WhirStatement calldata statement,
        WhirStructs.WhirProof calldata proof,
        KeccakChallenger.State memory challenger,
        ParsedCommitment memory parsedCommitment
    ) internal pure {
        EqStatement memory userStatement = _statementFromCalldata(
            statement,
            config.numVariables
        );
        EqStatement memory initialEq = _concatenateEq(
            userStatement,
            parsedCommitment.oodStatement
        );

        Constraint[] memory constraints = new Constraint[](
            proof.rounds.length + 1
        );
        uint256 constraintCount = 0;
        uint256 claimedEval = 0;
        uint256[] memory foldingRandomness;
        uint256[] memory finalSumcheckRandomness;

        constraints[constraintCount] = Constraint({
            challenge: WhirVerifierUtils4.sampleExt4(challenger),
            eqStatement: initialEq,
            selStatement: _emptySelect(config.numVariables)
        });
        claimedEval = _combineConstraintEvals(
            claimedEval,
            constraints[constraintCount]
        );
        constraintCount += 1;

        uint256[] memory allRandomness = new uint256[](config.numVariables);
        uint256 randomnessCursor = 0;

        (claimedEval, foldingRandomness, randomnessCursor) = _verifySumcheck(
            proof.initialSumcheck,
            challenger,
            claimedEval,
            _initialSumcheckRounds(config),
            config.startingFoldingPowBits,
            allRandomness,
            randomnessCursor
        );

        ParsedCommitment memory prevCommitment = parsedCommitment;

        for (
            uint256 roundIndex = 0;
            roundIndex < proof.rounds.length;
            ++roundIndex
        ) {
            WhirStructs.RoundConfig calldata roundConfig = config
                .roundParameters[roundIndex];
            WhirStructs.WhirRoundProof calldata roundProof = proof.rounds[
                roundIndex
            ];

            ParsedCommitment memory newCommitment = _parseCommitment(
                challenger,
                roundProof.commitment,
                roundProof.oodAnswers,
                roundConfig.numVariables,
                roundConfig.oodSamples
            );

            SelectStatement memory stirStatement = _verifyStirChallenges(
                challenger,
                prevCommitment.root,
                roundConfig,
                roundProof.queryBatch,
                true,
                roundProof.powWitness,
                foldingRandomness,
                roundIndex == 0 ? 0 : 1,
                config.effectiveDigestBytes
            );

            constraints[constraintCount] = Constraint({
                challenge: WhirVerifierUtils4.sampleExt4(challenger),
                eqStatement: newCommitment.oodStatement,
                selStatement: stirStatement
            });
            claimedEval = _combineConstraintEvals(
                claimedEval,
                constraints[constraintCount]
            );
            constraintCount += 1;

            uint256 nextFoldingFactor = roundIndex + 1 <
                config.roundParameters.length
                ? config.roundParameters[roundIndex + 1].foldingFactor
                : config.finalRoundConfig.foldingFactor;

            (
                claimedEval,
                foldingRandomness,
                randomnessCursor
            ) = _verifySumcheck(
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
            proof.finalPoly.length != (uint256(1) << config.finalSumcheckRounds)
        ) {
            revert FinalPolyLengthMismatch(
                uint256(1) << config.finalSumcheckRounds,
                proof.finalPoly.length
            );
        }
        WhirVerifierUtils4.validatePackedExt4Calldata(proof.finalPoly);
        unchecked {
            for (uint256 i = 0; i < proof.finalPoly.length; ++i) {
                WhirVerifierUtils4.observeExt4(challenger, proof.finalPoly[i]);
            }
        }

        SelectStatement memory finalStirStatement = _verifyStirChallenges(
            challenger,
            prevCommitment.root,
            config.finalRoundConfig,
            proof.finalQueryBatch,
            proof.finalQueryBatchPresent,
            proof.finalPowWitness,
            foldingRandomness,
            proof.rounds.length == 0 ? 0 : 1,
            config.effectiveDigestBytes
        );
        _verifySelectStatement(finalStirStatement, proof.finalPoly);

        if (config.finalSumcheckRounds == 0) {
            if (proof.finalSumcheckPresent) {
                revert FinalSumcheckPresenceMismatch(false, true);
            }
        } else if (!proof.finalSumcheckPresent) {
            revert FinalSumcheckPresenceMismatch(true, false);
        }

        (
            claimedEval,
            finalSumcheckRandomness,
            randomnessCursor
        ) = _verifySumcheck(
            proof.finalSumcheck,
            challenger,
            claimedEval,
            config.finalSumcheckRounds,
            config.finalRoundConfig.foldingPowBits,
            allRandomness,
            randomnessCursor
        );

        if (randomnessCursor != allRandomness.length) {
            revert RandomnessLengthMismatch(
                allRandomness.length,
                randomnessCursor
            );
        }

        uint256 evaluationOfWeights = _evaluateConstraints(
            constraints,
            constraintCount,
            allRandomness
        );
        uint256 finalValue = _evaluateFinalValue(
            proof.finalPoly,
            finalSumcheckRandomness
        );
        uint256 expected = KoalaBearExt4.mul(evaluationOfWeights, finalValue);

        if (claimedEval != expected) {
            revert FinalConstraintMismatch(expected, claimedEval);
        }
    }

    function _validateProofShape(
        WhirStructs.ExpandedWhirConfig calldata config,
        WhirStructs.WhirProof calldata proof
    ) private pure {
        if (proof.rounds.length != config.roundParameters.length) {
            revert ProofRoundCountMismatch(
                config.roundParameters.length,
                proof.rounds.length
            );
        }

        bool expectFinalQueryBatch = config.finalRoundConfig.numQueries > 0;
        if (proof.finalQueryBatchPresent != expectFinalQueryBatch) {
            revert FinalQueryBatchPresenceMismatch(
                expectFinalQueryBatch,
                proof.finalQueryBatchPresent
            );
        }

        bool expectFinalSumcheck = config.finalSumcheckRounds > 0;
        if (proof.finalSumcheckPresent != expectFinalSumcheck) {
            revert FinalSumcheckPresenceMismatch(
                expectFinalSumcheck,
                proof.finalSumcheckPresent
            );
        }
    }

    function _statementFromCalldata(
        WhirStructs.WhirStatement calldata statement,
        uint256 numVariables
    ) private pure returns (EqStatement memory eqStatement) {
        if (statement.points.length != statement.evaluations.length) {
            revert StatementLengthMismatch(
                statement.points.length,
                statement.evaluations.length
            );
        }

        eqStatement.numVariables = numVariables;
        eqStatement.flatPoints = new uint256[](
            statement.points.length * numVariables
        );
        eqStatement.evaluations = new uint256[](statement.evaluations.length);

        unchecked {
            for (uint256 i = 0; i < statement.points.length; ++i) {
                if (statement.points[i].length != numVariables) {
                    revert StatementPointArityMismatch(
                        i,
                        numVariables,
                        statement.points[i].length
                    );
                }

                for (uint256 j = 0; j < numVariables; ++j) {
                    uint256 pointValue = statement.points[i][j];
                    WhirVerifierUtils4.validatePackedExt4(pointValue);
                    eqStatement.flatPoints[i * numVariables + j] = pointValue;
                }

                uint256 evalValue = statement.evaluations[i];
                WhirVerifierUtils4.validatePackedExt4(evalValue);
                eqStatement.evaluations[i] = evalValue;
            }
        }
    }

    function _parseCommitment(
        KeccakChallenger.State memory challenger,
        bytes32 root,
        uint256[] calldata oodAnswers,
        uint256 numVariables,
        uint256 oodSamples
    ) private pure returns (ParsedCommitment memory parsed) {
        if (oodAnswers.length != oodSamples) {
            revert OodAnswerCountMismatch(oodSamples, oodAnswers.length);
        }

        challenger.observeHashU64Digest(root);

        parsed.root = root;
        parsed.oodStatement.numVariables = numVariables;
        parsed.oodStatement.flatPoints = new uint256[](
            oodSamples * numVariables
        );
        parsed.oodStatement.evaluations = new uint256[](oodSamples);

        unchecked {
            for (uint256 i = 0; i < oodSamples; ++i) {
                uint256 point = WhirVerifierUtils4.sampleExt4(challenger);
                uint256[] memory expanded = WhirVerifierUtils4
                    .expandFromUnivariateExt(point, numVariables);
                for (uint256 j = 0; j < numVariables; ++j) {
                    parsed.oodStatement.flatPoints[
                        i * numVariables + j
                    ] = expanded[j];
                }

                uint256 evalValue = oodAnswers[i];
                WhirVerifierUtils4.validatePackedExt4(evalValue);
                WhirVerifierUtils4.observeExt4(challenger, evalValue);
                parsed.oodStatement.evaluations[i] = evalValue;
            }
        }
    }

    function _concatenateEq(
        EqStatement memory lhs,
        EqStatement memory rhs
    ) private pure returns (EqStatement memory out) {
        if (lhs.numVariables != rhs.numVariables) {
            revert InconsistentConstraintArity(
                lhs.numVariables,
                rhs.numVariables
            );
        }

        uint256 pointCountL = lhs.evaluations.length;
        uint256 pointCountR = rhs.evaluations.length;
        uint256 numVariables = lhs.numVariables;

        out.numVariables = numVariables;
        out.flatPoints = new uint256[](
            (pointCountL + pointCountR) * numVariables
        );
        out.evaluations = new uint256[](pointCountL + pointCountR);

        unchecked {
            for (uint256 i = 0; i < lhs.flatPoints.length; ++i) {
                out.flatPoints[i] = lhs.flatPoints[i];
            }
            for (uint256 i = 0; i < rhs.flatPoints.length; ++i) {
                out.flatPoints[lhs.flatPoints.length + i] = rhs.flatPoints[i];
            }
            for (uint256 i = 0; i < pointCountL; ++i) {
                out.evaluations[i] = lhs.evaluations[i];
            }
            for (uint256 i = 0; i < pointCountR; ++i) {
                out.evaluations[pointCountL + i] = rhs.evaluations[i];
            }
        }
    }

    function _emptySelect(
        uint256 numVariables
    ) private pure returns (SelectStatement memory sel) {
        sel.numVariables = numVariables;
        sel.vars = new uint256[](0);
        sel.evaluations = new uint256[](0);
    }

    function _verifySumcheck(
        WhirStructs.SumcheckData calldata sumcheck,
        KeccakChallenger.State memory challenger,
        uint256 claimedEval,
        uint256 expectedRounds,
        uint256 powBits,
        uint256[] memory allRandomness,
        uint256 randomnessCursor
    )
        private
        pure
        returns (
            uint256 updatedClaimedEval,
            uint256[] memory foldingRandomness,
            uint256 updatedCursor
        )
    {
        uint256 expectedPolyEvals = expectedRounds * 2;
        if (sumcheck.polynomialEvals.length != expectedPolyEvals) {
            revert SumcheckPolynomialLengthMismatch(
                expectedPolyEvals,
                sumcheck.polynomialEvals.length
            );
        }

        uint256 expectedWitnesses = powBits > 0 ? expectedRounds : 0;
        if (sumcheck.powWitnesses.length != expectedWitnesses) {
            revert SumcheckPowWitnessLengthMismatch(
                expectedWitnesses,
                sumcheck.powWitnesses.length
            );
        }

        updatedClaimedEval = claimedEval;
        updatedCursor = randomnessCursor;
        foldingRandomness = new uint256[](expectedRounds);

        unchecked {
            for (uint256 i = 0; i < expectedRounds; ++i) {
                uint256 c0 = sumcheck.polynomialEvals[2 * i];
                uint256 c2 = sumcheck.polynomialEvals[2 * i + 1];
                WhirVerifierUtils4.validatePackedExt4(c0);
                WhirVerifierUtils4.validatePackedExt4(c2);

                WhirVerifierUtils4.observeExt4(challenger, c0);
                WhirVerifierUtils4.observeExt4(challenger, c2);

                if (powBits > 0) {
                    if (
                        !challenger.checkWitness(
                            powBits,
                            sumcheck.powWitnesses[i]
                        )
                    ) {
                        revert InvalidPowWitness();
                    }
                }

                uint256 r = WhirVerifierUtils4.sampleExt4(challenger);
                foldingRandomness[i] = r;
                allRandomness[updatedCursor] = r;
                updatedCursor += 1;
                updatedClaimedEval = KoalaBearExt4.extrapolate_012(
                    c0,
                    KoalaBearExt4.sub(updatedClaimedEval, c0),
                    c2,
                    r
                );
            }
        }
    }

    function _verifyStirChallenges(
        KeccakChallenger.State memory challenger,
        bytes32 expectedRoot,
        WhirStructs.RoundConfig calldata params,
        WhirStructs.QueryBatchOpening calldata queryBatch,
        bool queryBatchPresent,
        uint256 powWitness,
        uint256[] memory foldingRandomness,
        uint8 expectedKind,
        uint8 effectiveDigestBytes
    ) private pure returns (SelectStatement memory statement) {
        if (
            params.powBits > 0 &&
            !challenger.checkWitness(params.powBits, powWitness)
        ) {
            revert InvalidPowWitness();
        }

        statement.numVariables = params.numVariables;

        if (!queryBatchPresent) {
            if (params.numQueries != 0) {
                revert FinalQueryBatchPresenceMismatch(true, false);
            }
            statement.vars = new uint256[](0);
            statement.evaluations = new uint256[](0);
            return statement;
        }

        uint256[] memory indices = WhirVerifierUtils4.sampleStirQueries(
            challenger,
            params.domainSize,
            params.foldingFactor,
            params.numQueries
        );

        if (queryBatch.kind != expectedKind) {
            revert QueryBatchKindMismatch(expectedKind, queryBatch.kind);
        }
        if (queryBatch.numQueries != indices.length) {
            revert QueryBatchCountMismatch(
                indices.length,
                queryBatch.numQueries
            );
        }

        uint256 expectedRowLen = uint256(1) << params.foldingFactor;
        if (queryBatch.rowLen != expectedRowLen) {
            revert QueryBatchRowLengthMismatch(
                expectedRowLen,
                queryBatch.rowLen
            );
        }

        uint256 depth = WhirVerifierUtils4.log2Strict(
            params.domainSize >> params.foldingFactor
        );

        bytes32 computedRoot;
        if (expectedKind == 0) {
            computedRoot = MerkleVerifier.computeRootFromFlatBaseRows(
                indices,
                queryBatch.values,
                queryBatch.rowLen,
                depth,
                queryBatch.decommitments,
                effectiveDigestBytes
            );
        } else {
            computedRoot = MerkleVerifier.computeRootFromFlatExtensionRows(
                indices,
                queryBatch.values,
                queryBatch.rowLen,
                depth,
                queryBatch.decommitments,
                effectiveDigestBytes
            );
        }

        if (computedRoot != expectedRoot) {
            revert MerkleRootMismatch(expectedRoot, computedRoot);
        }

        statement.vars = new uint256[](indices.length);
        statement.evaluations = new uint256[](indices.length);

        unchecked {
            for (uint256 i = 0; i < indices.length; ++i) {
                statement.vars[i] = KoalaBear.pow(
                    params.foldedDomainGen,
                    indices[i]
                );
                uint256 rowStart = i * queryBatch.rowLen;
                statement.evaluations[i] = expectedKind == 0
                    ? WhirVerifierUtils4.evaluateBaseRowAsExt4(
                        queryBatch.values,
                        rowStart,
                        queryBatch.rowLen,
                        foldingRandomness
                    )
                    : WhirVerifierUtils4.evaluateExtensionRowAsExt4(
                        queryBatch.values,
                        rowStart,
                        queryBatch.rowLen,
                        foldingRandomness
                    );
            }
        }
    }

    function _combineConstraintEvals(
        uint256 acc,
        Constraint memory constraint
    ) private pure returns (uint256 updated) {
        updated = acc;
        uint256 gammaPower = KoalaBearExt4.fromBase(1);

        unchecked {
            for (
                uint256 i = 0;
                i < constraint.eqStatement.evaluations.length;
                ++i
            ) {
                updated = KoalaBearExt4.add(
                    updated,
                    KoalaBearExt4.mul(
                        gammaPower,
                        constraint.eqStatement.evaluations[i]
                    )
                );
                gammaPower = KoalaBearExt4.mul(
                    gammaPower,
                    constraint.challenge
                );
            }
            for (
                uint256 i = 0;
                i < constraint.selStatement.evaluations.length;
                ++i
            ) {
                updated = KoalaBearExt4.add(
                    updated,
                    KoalaBearExt4.mul(
                        gammaPower,
                        constraint.selStatement.evaluations[i]
                    )
                );
                gammaPower = KoalaBearExt4.mul(
                    gammaPower,
                    constraint.challenge
                );
            }
        }
    }

    function _evaluateConstraints(
        Constraint[] memory constraints,
        uint256 constraintCount,
        uint256[] memory allRandomness
    ) private pure returns (uint256 acc) {
        unchecked {
            for (uint256 i = 0; i < constraintCount; ++i) {
                uint256 numVariables = constraints[i].eqStatement.numVariables;
                uint256 pointOffset = allRandomness.length - numVariables;
                acc = KoalaBearExt4.add(
                    acc,
                    _evaluateConstraint(
                        constraints[i],
                        allRandomness,
                        pointOffset
                    )
                );
            }
        }
    }

    function _evaluateConstraint(
        Constraint memory constraint,
        uint256[] memory fullPoint,
        uint256 pointOffset
    ) private pure returns (uint256 total) {
        if (
            constraint.eqStatement.numVariables !=
            constraint.selStatement.numVariables
        ) {
            revert InconsistentConstraintArity(
                constraint.eqStatement.numVariables,
                constraint.selStatement.numVariables
            );
        }

        uint256 numVariables = constraint.eqStatement.numVariables;
        uint256 gammaPower = KoalaBearExt4.fromBase(1);

        unchecked {
            for (
                uint256 i = 0;
                i < constraint.eqStatement.evaluations.length;
                ++i
            ) {
                uint256 weight = _eqPolyEvalAt(
                    constraint.eqStatement.flatPoints,
                    i * numVariables,
                    fullPoint,
                    pointOffset,
                    numVariables
                );
                total = KoalaBearExt4.add(
                    total,
                    KoalaBearExt4.mul(gammaPower, weight)
                );
                gammaPower = KoalaBearExt4.mul(
                    gammaPower,
                    constraint.challenge
                );
            }
            for (uint256 i = 0; i < constraint.selStatement.vars.length; ++i) {
                uint256 weight = _selectPolyEvalAt(
                    constraint.selStatement.vars[i],
                    fullPoint,
                    pointOffset,
                    numVariables
                );
                total = KoalaBearExt4.add(
                    total,
                    KoalaBearExt4.mul(gammaPower, weight)
                );
                gammaPower = KoalaBearExt4.mul(
                    gammaPower,
                    constraint.challenge
                );
            }
        }
    }

    function _eqPolyEvalAt(
        uint256[] memory flatPoints,
        uint256 pointStart,
        uint256[] memory fullPoint,
        uint256 pointOffset,
        uint256 numVariables
    ) private pure returns (uint256 acc) {
        acc = KoalaBearExt4.fromBase(1);

        unchecked {
            for (uint256 i = 0; i < numVariables; ++i) {
                uint256 p = flatPoints[pointStart + i];
                uint256 q = fullPoint[pointOffset + i];
                uint256 twoPQ = KoalaBearExt4.mulBase(
                    KoalaBearExt4.mul(p, q),
                    2
                );
                uint256 term = KoalaBearExt4.add(
                    KoalaBearExt4.fromBase(1),
                    KoalaBearExt4.sub(KoalaBearExt4.sub(twoPQ, p), q)
                );
                acc = KoalaBearExt4.mul(acc, term);
            }
        }
    }

    function _selectPolyEvalAt(
        uint256 var_,
        uint256[] memory fullPoint,
        uint256 pointOffset,
        uint256 numVariables
    ) private pure returns (uint256 acc) {
        acc = KoalaBearExt4.fromBase(1);
        uint256 current = var_;

        unchecked {
            for (uint256 i = numVariables; i > 0; --i) {
                uint256 pointValue = fullPoint[pointOffset + (i - 1)];
                uint256 scalar = KoalaBear.sub(current, 1);
                uint256 term = KoalaBearExt4.add(
                    KoalaBearExt4.fromBase(1),
                    KoalaBearExt4.mulBase(pointValue, scalar)
                );
                acc = KoalaBearExt4.mul(acc, term);
                current = KoalaBear.mul(current, current);
            }
        }
    }

    function _verifySelectStatement(
        SelectStatement memory statement,
        uint256[] calldata finalPoly
    ) private pure {
        unchecked {
            for (uint256 i = 0; i < statement.vars.length; ++i) {
                uint256 actual = WhirVerifierUtils4.hornerBase(
                    finalPoly,
                    statement.vars[i]
                );
                if (actual != statement.evaluations[i]) {
                    revert StirConstraintFailed(i);
                }
            }
        }
    }

    function _evaluateFinalValue(
        uint256[] calldata finalPoly,
        uint256[] memory finalSumcheckRandomness
    ) private pure returns (uint256) {
        if (finalSumcheckRandomness.length == 0) {
            return finalPoly[0];
        }

        uint256[] memory evals = new uint256[](finalPoly.length);
        unchecked {
            for (uint256 i = 0; i < finalPoly.length; ++i) {
                evals[i] = finalPoly[i];
            }
        }
        return KoalaBearExt4.evaluate_hypercube(evals, finalSumcheckRandomness);
    }

    function _initialSumcheckRounds(
        WhirStructs.ExpandedWhirConfig calldata config
    ) private pure returns (uint256) {
        if (config.roundParameters.length == 0) {
            return config.numVariables - config.finalRoundConfig.numVariables;
        }
        return config.numVariables - config.roundParameters[0].numVariables;
    }
}
