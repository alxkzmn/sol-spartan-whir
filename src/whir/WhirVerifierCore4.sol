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

    uint256 internal constant EXT4_ONE = uint256(1) << 224;

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

    function _statementFromCalldata(
        WhirStructs.WhirStatement calldata statement,
        uint256 numVariables
    ) internal pure returns (EqStatement memory eqStatement) {
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
    ) internal pure returns (ParsedCommitment memory parsed) {
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
    ) internal pure returns (EqStatement memory out) {
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
    ) internal pure returns (SelectStatement memory sel) {
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
        internal
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

    function _verifyStirChallengesRaw(
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
    ) internal pure returns (SelectStatement memory statement) {
        if (powBits > 0 && !challenger.checkWitness(powBits, powWitness)) {
            revert InvalidPowWitness();
        }

        if (checkpointAfterPow) {
            challenger.sampleBase();
        }

        statement.numVariables = numVariables;

        if (!queryBatchPresent) {
            if (numQueries != 0) {
                revert FinalQueryBatchPresenceMismatch(true, false);
            }
            statement.vars = new uint256[](0);
            statement.evaluations = new uint256[](0);
            return statement;
        }

        uint256[] memory indices = WhirVerifierUtils4.sampleStirQueries(
            challenger,
            domainSize,
            foldingFactor,
            numQueries
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

        uint256 expectedRowLen = uint256(1) << foldingFactor;
        if (queryBatch.rowLen != expectedRowLen) {
            revert QueryBatchRowLengthMismatch(
                expectedRowLen,
                queryBatch.rowLen
            );
        }

        uint256 depth = WhirVerifierUtils4.log2Strict(
            domainSize >> foldingFactor
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
                statement.vars[i] = KoalaBear.pow(foldedDomainGen, indices[i]);
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
    ) internal pure returns (uint256 updated) {
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
    ) internal pure returns (uint256 acc) {
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
    ) internal pure returns (uint256 total) {
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
    ) internal pure returns (uint256 acc) {
        acc = EXT4_ONE;

        unchecked {
            for (uint256 i = 0; i < numVariables; ++i) {
                uint256 p = flatPoints[pointStart + i];
                uint256 q = fullPoint[pointOffset + i];
                acc = _mulByEqTerm(acc, p, q, KoalaBearExt4.mul(p, q));
            }
        }
    }

    function _selectPolyEvalAt(
        uint256 var_,
        uint256[] memory fullPoint,
        uint256 pointOffset,
        uint256 numVariables
    ) internal pure returns (uint256 acc) {
        acc = EXT4_ONE;
        uint256 current = var_;

        unchecked {
            for (uint256 i = numVariables; i > 0; --i) {
                uint256 pointValue = fullPoint[pointOffset + (i - 1)];
                uint256 scalar = KoalaBear.sub(current, 1);
                acc = _mulBySelectTerm(acc, pointValue, scalar);
                current = KoalaBear.mul(current, current);
            }
        }
    }

    function _mulByEqTerm(
        uint256 acc,
        uint256 p,
        uint256 q,
        uint256 pq
    ) private pure returns (uint256 out) {
        uint256 modulus = KoalaBear.MODULUS;

        uint256 a0 = acc >> 224;
        uint256 a1 = (acc >> 192) & 0xffffffff;
        uint256 a2 = (acc >> 160) & 0xffffffff;
        uint256 a3 = (acc >> 128) & 0xffffffff;

        uint256 p0 = p >> 224;
        uint256 p1 = (p >> 192) & 0xffffffff;
        uint256 p2 = (p >> 160) & 0xffffffff;
        uint256 p3 = (p >> 128) & 0xffffffff;

        uint256 q0 = q >> 224;
        uint256 q1 = (q >> 192) & 0xffffffff;
        uint256 q2 = (q >> 160) & 0xffffffff;
        uint256 q3 = (q >> 128) & 0xffffffff;

        uint256 pq0 = pq >> 224;
        uint256 pq1 = (pq >> 192) & 0xffffffff;
        uint256 pq2 = (pq >> 160) & 0xffffffff;
        uint256 pq3 = (pq >> 128) & 0xffffffff;

        unchecked {
            uint256 t0 = _eqCoeff(p0, q0, pq0, true, modulus);
            uint256 t1 = _eqCoeff(p1, q1, pq1, false, modulus);
            uint256 t2 = _eqCoeff(p2, q2, pq2, false, modulus);
            uint256 t3 = _eqCoeff(p3, q3, pq3, false, modulus);

            uint256 c0 = a0 * t0 + KoalaBear.W * (a1 * t3 + a2 * t2 + a3 * t1);
            uint256 c1 = a0 * t1 + a1 * t0 + KoalaBear.W * (a2 * t3 + a3 * t2);
            uint256 c2 = a0 * t2 + a1 * t1 + a2 * t0 + KoalaBear.W * (a3 * t3);
            uint256 c3 = a0 * t3 + a1 * t2 + a2 * t1 + a3 * t0;

            c0 %= modulus;
            c1 %= modulus;
            c2 %= modulus;
            c3 %= modulus;

            out = (c0 << 224) | (c1 << 192) | (c2 << 160) | (c3 << 128);
        }
    }

    function _eqCoeff(
        uint256 p,
        uint256 q,
        uint256 pq,
        bool addOne,
        uint256 modulus
    ) private pure returns (uint256 t) {
        unchecked {
            t = pq + pq;
            if (t >= modulus) {
                t -= modulus;
            }

            if (t < p) {
                t += modulus;
            }
            t -= p;

            if (t < q) {
                t += modulus;
            }
            t -= q;

            if (addOne) {
                t += 1;
                if (t >= modulus) {
                    t -= modulus;
                }
            }
        }
    }

    function _selectTermPacked(
        uint256 pointValue,
        uint256 scalar
    ) private pure returns (uint256 term) {
        assembly ("memory-safe") {
            let modulus := 0x7f000001
            let mask := 0xffffffff

            let c0 := mulmod(shr(224, pointValue), scalar, modulus)
            let c1 := mulmod(and(shr(192, pointValue), mask), scalar, modulus)
            let c2 := mulmod(and(shr(160, pointValue), mask), scalar, modulus)
            let c3 := mulmod(and(shr(128, pointValue), mask), scalar, modulus)

            let t0 := add(c0, 1)
            if iszero(lt(t0, modulus)) {
                t0 := sub(t0, modulus)
            }

            term := or(
                or(shl(224, t0), shl(192, c1)),
                or(shl(160, c2), shl(128, c3))
            )
        }
    }

    function _mulBySelectTerm(
        uint256 acc,
        uint256 pointValue,
        uint256 scalar
    ) private pure returns (uint256 out) {
        uint256 a0 = acc >> 224;
        uint256 a1 = (acc >> 192) & 0xffffffff;
        uint256 a2 = (acc >> 160) & 0xffffffff;
        uint256 a3 = (acc >> 128) & 0xffffffff;

        uint256 p0 = pointValue >> 224;
        uint256 p1 = (pointValue >> 192) & 0xffffffff;
        uint256 p2 = (pointValue >> 160) & 0xffffffff;
        uint256 p3 = (pointValue >> 128) & 0xffffffff;

        unchecked {
            uint256 t0 = 1 + scalar * p0;
            uint256 t1 = scalar * p1;
            uint256 t2 = scalar * p2;
            uint256 t3 = scalar * p3;

            uint256 c0 = a0 * t0 + KoalaBear.W * (a1 * t3 + a2 * t2 + a3 * t1);
            uint256 c1 = a0 * t1 + a1 * t0 + KoalaBear.W * (a2 * t3 + a3 * t2);
            uint256 c2 = a0 * t2 + a1 * t1 + a2 * t0 + KoalaBear.W * (a3 * t3);
            uint256 c3 = a0 * t3 + a1 * t2 + a2 * t1 + a3 * t0;

            c0 %= KoalaBear.MODULUS;
            c1 %= KoalaBear.MODULUS;
            c2 %= KoalaBear.MODULUS;
            c3 %= KoalaBear.MODULUS;

            out = (c0 << 224) | (c1 << 192) | (c2 << 160) | (c3 << 128);
        }
    }

    function _verifySelectStatement(
        SelectStatement memory statement,
        uint256[] calldata finalPoly
    ) internal pure {
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
    ) internal pure returns (uint256) {
        if (finalSumcheckRandomness.length == 0) {
            return finalPoly[0];
        }
        return
            WhirVerifierUtils4.evaluateExtensionRowAsExt4(
                finalPoly,
                0,
                finalPoly.length,
                finalSumcheckRandomness
            );
    }
}
