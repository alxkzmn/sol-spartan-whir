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

                challenger.observePackedExt4Pair(c0, c2);

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
            computedRoot = MerkleVerifier.computeRootFromFlatBaseRows20(
                indices,
                queryBatch.values,
                queryBatch.rowLen,
                depth,
                queryBatch.decommitments
            );
        } else {
            computedRoot = MerkleVerifier.computeRootFromFlatExtensionRows20(
                indices,
                queryBatch.values,
                queryBatch.rowLen,
                depth,
                queryBatch.decommitments
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
        uint256 challenge = constraint.challenge;
        uint256[] memory eqEvals = constraint.eqStatement.evaluations;
        uint256 eqLen = eqEvals.length;
        uint256[] memory selEvals = constraint.selStatement.evaluations;
        uint256 selLen = selEvals.length;

        // Horner: Σ challenge^i * eval_i with fused mulAdd in assembly.
        // Pre-unpack challenge lanes (constant across all iterations).
        uint256 horner;
        assembly ("memory-safe") {
            let M := 0x7f000001
            let m := 0xffffffff
            let W := 3

            let ch0 := shr(224, challenge)
            let ch1 := and(shr(192, challenge), m)
            let ch2 := and(shr(160, challenge), m)
            let ch3 := and(shr(128, challenge), m)

            let h0 := 0
            let h1 := 0
            let h2 := 0
            let h3 := 0

            // selEvals: array data at selEvals + 0x20
            let selBase := add(selEvals, 0x20)
            for {
                let i := selLen
            } gt(i, 0) {
                i := sub(i, 1)
            } {
                let w := mload(add(selBase, shl(5, sub(i, 1))))
                let w0 := shr(224, w)
                let w1 := and(shr(192, w), m)
                let w2 := and(shr(160, w), m)
                let w3 := and(shr(128, w), m)

                let r0 := mod(
                    add(
                        add(
                            mul(h0, ch0),
                            mul(
                                W,
                                add(
                                    add(mul(h1, ch3), mul(h2, ch2)),
                                    mul(h3, ch1)
                                )
                            )
                        ),
                        w0
                    ),
                    M
                )
                let r1 := mod(
                    add(
                        add(
                            add(mul(h0, ch1), mul(h1, ch0)),
                            mul(W, add(mul(h2, ch3), mul(h3, ch2)))
                        ),
                        w1
                    ),
                    M
                )
                let r2 := mod(
                    add(
                        add(
                            add(add(mul(h0, ch2), mul(h1, ch1)), mul(h2, ch0)),
                            mul(W, mul(h3, ch3))
                        ),
                        w2
                    ),
                    M
                )
                let r3 := mod(
                    add(
                        add(
                            add(add(mul(h0, ch3), mul(h1, ch2)), mul(h2, ch1)),
                            mul(h3, ch0)
                        ),
                        w3
                    ),
                    M
                )
                h0 := r0
                h1 := r1
                h2 := r2
                h3 := r3
            }

            let eqBase := add(eqEvals, 0x20)
            for {
                let i := eqLen
            } gt(i, 0) {
                i := sub(i, 1)
            } {
                let w := mload(add(eqBase, shl(5, sub(i, 1))))
                let w0 := shr(224, w)
                let w1 := and(shr(192, w), m)
                let w2 := and(shr(160, w), m)
                let w3 := and(shr(128, w), m)

                let r0 := mod(
                    add(
                        add(
                            mul(h0, ch0),
                            mul(
                                W,
                                add(
                                    add(mul(h1, ch3), mul(h2, ch2)),
                                    mul(h3, ch1)
                                )
                            )
                        ),
                        w0
                    ),
                    M
                )
                let r1 := mod(
                    add(
                        add(
                            add(mul(h0, ch1), mul(h1, ch0)),
                            mul(W, add(mul(h2, ch3), mul(h3, ch2)))
                        ),
                        w1
                    ),
                    M
                )
                let r2 := mod(
                    add(
                        add(
                            add(add(mul(h0, ch2), mul(h1, ch1)), mul(h2, ch0)),
                            mul(W, mul(h3, ch3))
                        ),
                        w2
                    ),
                    M
                )
                let r3 := mod(
                    add(
                        add(
                            add(add(mul(h0, ch3), mul(h1, ch2)), mul(h2, ch1)),
                            mul(h3, ch0)
                        ),
                        w3
                    ),
                    M
                )
                h0 := r0
                h1 := r1
                h2 := r2
                h3 := r3
            }

            horner := or(
                or(shl(224, h0), shl(192, h1)),
                or(shl(160, h2), shl(128, h3))
            )
        }

        updated = KoalaBearExt4.add(acc, horner);
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
        uint256 challenge = constraint.challenge;
        uint256[] memory flatPoints = constraint.eqStatement.flatPoints;
        uint256 eqEvalCount = constraint.eqStatement.evaluations.length;
        uint256[] memory selVars = constraint.selStatement.vars;
        uint256 selVarCount = selVars.length;

        // Horner form: Σ γ^k × w_k = w_0 + γ·(w_1 + γ·(... + γ·w_{N-1}))
        // Eliminates one ext4 mul per weight vs explicit gamma-power tracking.
        // Process weights in reverse: selects last-to-first, then eq last-to-first.
        // The mulAdd step (total = total * challenge + weight) is fused in inline
        // assembly to avoid intermediate packing/unpacking of ext4 lanes.
        // Pre-unpack challenge lanes (constant across all iterations)
        uint256 ch0;
        uint256 ch1;
        uint256 ch2;
        uint256 ch3;
        assembly ("memory-safe") {
            ch0 := shr(224, challenge)
            ch1 := and(shr(192, challenge), 0xffffffff)
            ch2 := and(shr(160, challenge), 0xffffffff)
            ch3 := and(shr(128, challenge), 0xffffffff)
        }
        unchecked {
            for (uint256 i = selVarCount; i > 0; --i) {
                uint256 weight = _selectPolyEvalAt(
                    selVars[i - 1],
                    fullPoint,
                    pointOffset,
                    numVariables
                );
                // Fused: total = total * challenge + weight
                assembly ("memory-safe") {
                    let M := 0x7f000001
                    let m := 0xffffffff
                    let W := 3

                    let a0 := shr(224, total)
                    let a1 := and(shr(192, total), m)
                    let a2 := and(shr(160, total), m)
                    let a3 := and(shr(128, total), m)

                    let w0 := shr(224, weight)
                    let w1 := and(shr(192, weight), m)
                    let w2 := and(shr(160, weight), m)
                    let w3 := and(shr(128, weight), m)

                    let r0 := mod(
                        add(
                            add(
                                mul(a0, ch0),
                                mul(
                                    W,
                                    add(
                                        add(mul(a1, ch3), mul(a2, ch2)),
                                        mul(a3, ch1)
                                    )
                                )
                            ),
                            w0
                        ),
                        M
                    )
                    let r1 := mod(
                        add(
                            add(
                                add(mul(a0, ch1), mul(a1, ch0)),
                                mul(W, add(mul(a2, ch3), mul(a3, ch2)))
                            ),
                            w1
                        ),
                        M
                    )
                    let r2 := mod(
                        add(
                            add(
                                add(
                                    add(mul(a0, ch2), mul(a1, ch1)),
                                    mul(a2, ch0)
                                ),
                                mul(W, mul(a3, ch3))
                            ),
                            w2
                        ),
                        M
                    )
                    let r3 := mod(
                        add(
                            add(
                                add(
                                    add(mul(a0, ch3), mul(a1, ch2)),
                                    mul(a2, ch1)
                                ),
                                mul(a3, ch0)
                            ),
                            w3
                        ),
                        M
                    )

                    total := or(
                        or(shl(224, r0), shl(192, r1)),
                        or(shl(160, r2), shl(128, r3))
                    )
                }
            }
            for (uint256 i = eqEvalCount; i > 0; --i) {
                uint256 weight = _eqPolyEvalAt(
                    flatPoints,
                    (i - 1) * numVariables,
                    fullPoint,
                    pointOffset,
                    numVariables
                );
                // Fused: total = total * challenge + weight
                assembly ("memory-safe") {
                    let M := 0x7f000001
                    let m := 0xffffffff
                    let W := 3

                    let a0 := shr(224, total)
                    let a1 := and(shr(192, total), m)
                    let a2 := and(shr(160, total), m)
                    let a3 := and(shr(128, total), m)

                    let w0 := shr(224, weight)
                    let w1 := and(shr(192, weight), m)
                    let w2 := and(shr(160, weight), m)
                    let w3 := and(shr(128, weight), m)

                    let r0 := mod(
                        add(
                            add(
                                mul(a0, ch0),
                                mul(
                                    W,
                                    add(
                                        add(mul(a1, ch3), mul(a2, ch2)),
                                        mul(a3, ch1)
                                    )
                                )
                            ),
                            w0
                        ),
                        M
                    )
                    let r1 := mod(
                        add(
                            add(
                                add(mul(a0, ch1), mul(a1, ch0)),
                                mul(W, add(mul(a2, ch3), mul(a3, ch2)))
                            ),
                            w1
                        ),
                        M
                    )
                    let r2 := mod(
                        add(
                            add(
                                add(
                                    add(mul(a0, ch2), mul(a1, ch1)),
                                    mul(a2, ch0)
                                ),
                                mul(W, mul(a3, ch3))
                            ),
                            w2
                        ),
                        M
                    )
                    let r3 := mod(
                        add(
                            add(
                                add(
                                    add(mul(a0, ch3), mul(a1, ch2)),
                                    mul(a2, ch1)
                                ),
                                mul(a3, ch0)
                            ),
                            w3
                        ),
                        M
                    )

                    total := or(
                        or(shl(224, r0), shl(192, r1)),
                        or(shl(160, r2), shl(128, r3))
                    )
                }
            }
        }
    }

    function _evaluateConstraintsFixedSelect(
        Constraint[] memory constraints,
        uint256[] memory allRandomness
    ) internal pure returns (uint256 acc) {
        acc = KoalaBearExt4.add(
            _evaluateConstraint12Select(constraints[0], allRandomness),
            _evaluateConstraint8Select(constraints[1], allRandomness)
        );
    }

    function _evaluateConstraint12Select(
        Constraint memory constraint,
        uint256[] memory fullPoint
    ) internal pure returns (uint256 total) {
        if (
            constraint.eqStatement.numVariables != 12 ||
            constraint.selStatement.numVariables != 12
        ) {
            revert InconsistentConstraintArity(
                constraint.eqStatement.numVariables,
                constraint.selStatement.numVariables
            );
        }

        uint256 challenge = constraint.challenge;
        uint256[] memory flatPoints = constraint.eqStatement.flatPoints;
        uint256 eqEvalCount = constraint.eqStatement.evaluations.length;
        uint256[] memory selVars = constraint.selStatement.vars;
        uint256 selVarCount = selVars.length;
        uint256 ch0;
        uint256 ch1;
        uint256 ch2;
        uint256 ch3;
        assembly ("memory-safe") {
            ch0 := shr(224, challenge)
            ch1 := and(shr(192, challenge), 0xffffffff)
            ch2 := and(shr(160, challenge), 0xffffffff)
            ch3 := and(shr(128, challenge), 0xffffffff)
        }
        unchecked {
            for (uint256 i = selVarCount; i > 0; --i) {
                uint256 weight = _selectPolyEvalAt12At4(
                    selVars[i - 1],
                    fullPoint
                );
                assembly ("memory-safe") {
                    let M := 0x7f000001
                    let m := 0xffffffff
                    let W := 3

                    let a0 := shr(224, total)
                    let a1 := and(shr(192, total), m)
                    let a2 := and(shr(160, total), m)
                    let a3 := and(shr(128, total), m)

                    let w0 := shr(224, weight)
                    let w1 := and(shr(192, weight), m)
                    let w2 := and(shr(160, weight), m)
                    let w3 := and(shr(128, weight), m)

                    let r0 := mod(
                        add(
                            add(
                                mul(a0, ch0),
                                mul(
                                    W,
                                    add(
                                        add(mul(a1, ch3), mul(a2, ch2)),
                                        mul(a3, ch1)
                                    )
                                )
                            ),
                            w0
                        ),
                        M
                    )
                    let r1 := mod(
                        add(
                            add(
                                add(mul(a0, ch1), mul(a1, ch0)),
                                mul(W, add(mul(a2, ch3), mul(a3, ch2)))
                            ),
                            w1
                        ),
                        M
                    )
                    let r2 := mod(
                        add(
                            add(
                                add(
                                    add(mul(a0, ch2), mul(a1, ch1)),
                                    mul(a2, ch0)
                                ),
                                mul(W, mul(a3, ch3))
                            ),
                            w2
                        ),
                        M
                    )
                    let r3 := mod(
                        add(
                            add(
                                add(
                                    add(mul(a0, ch3), mul(a1, ch2)),
                                    mul(a2, ch1)
                                ),
                                mul(a3, ch0)
                            ),
                            w3
                        ),
                        M
                    )

                    total := or(
                        or(shl(224, r0), shl(192, r1)),
                        or(shl(160, r2), shl(128, r3))
                    )
                }
            }
            for (uint256 i = eqEvalCount; i > 0; --i) {
                uint256 weight = _eqPolyEvalAt(
                    flatPoints,
                    (i - 1) * 12,
                    fullPoint,
                    4,
                    12
                );
                assembly ("memory-safe") {
                    let M := 0x7f000001
                    let m := 0xffffffff
                    let W := 3

                    let a0 := shr(224, total)
                    let a1 := and(shr(192, total), m)
                    let a2 := and(shr(160, total), m)
                    let a3 := and(shr(128, total), m)

                    let w0 := shr(224, weight)
                    let w1 := and(shr(192, weight), m)
                    let w2 := and(shr(160, weight), m)
                    let w3 := and(shr(128, weight), m)

                    let r0 := mod(
                        add(
                            add(
                                mul(a0, ch0),
                                mul(
                                    W,
                                    add(
                                        add(mul(a1, ch3), mul(a2, ch2)),
                                        mul(a3, ch1)
                                    )
                                )
                            ),
                            w0
                        ),
                        M
                    )
                    let r1 := mod(
                        add(
                            add(
                                add(mul(a0, ch1), mul(a1, ch0)),
                                mul(W, add(mul(a2, ch3), mul(a3, ch2)))
                            ),
                            w1
                        ),
                        M
                    )
                    let r2 := mod(
                        add(
                            add(
                                add(
                                    add(mul(a0, ch2), mul(a1, ch1)),
                                    mul(a2, ch0)
                                ),
                                mul(W, mul(a3, ch3))
                            ),
                            w2
                        ),
                        M
                    )
                    let r3 := mod(
                        add(
                            add(
                                add(
                                    add(mul(a0, ch3), mul(a1, ch2)),
                                    mul(a2, ch1)
                                ),
                                mul(a3, ch0)
                            ),
                            w3
                        ),
                        M
                    )

                    total := or(
                        or(shl(224, r0), shl(192, r1)),
                        or(shl(160, r2), shl(128, r3))
                    )
                }
            }
        }
    }

    function _evaluateConstraint8Select(
        Constraint memory constraint,
        uint256[] memory fullPoint
    ) internal pure returns (uint256 total) {
        if (
            constraint.eqStatement.numVariables != 8 ||
            constraint.selStatement.numVariables != 8
        ) {
            revert InconsistentConstraintArity(
                constraint.eqStatement.numVariables,
                constraint.selStatement.numVariables
            );
        }

        uint256 challenge = constraint.challenge;
        uint256[] memory flatPoints = constraint.eqStatement.flatPoints;
        uint256 eqEvalCount = constraint.eqStatement.evaluations.length;
        uint256[] memory selVars = constraint.selStatement.vars;
        uint256 selVarCount = selVars.length;
        uint256 ch0;
        uint256 ch1;
        uint256 ch2;
        uint256 ch3;
        assembly ("memory-safe") {
            ch0 := shr(224, challenge)
            ch1 := and(shr(192, challenge), 0xffffffff)
            ch2 := and(shr(160, challenge), 0xffffffff)
            ch3 := and(shr(128, challenge), 0xffffffff)
        }
        unchecked {
            for (uint256 i = selVarCount; i > 0; --i) {
                uint256 weight = _selectPolyEvalAt8At8(
                    selVars[i - 1],
                    fullPoint
                );
                assembly ("memory-safe") {
                    let M := 0x7f000001
                    let m := 0xffffffff
                    let W := 3

                    let a0 := shr(224, total)
                    let a1 := and(shr(192, total), m)
                    let a2 := and(shr(160, total), m)
                    let a3 := and(shr(128, total), m)

                    let w0 := shr(224, weight)
                    let w1 := and(shr(192, weight), m)
                    let w2 := and(shr(160, weight), m)
                    let w3 := and(shr(128, weight), m)

                    let r0 := mod(
                        add(
                            add(
                                mul(a0, ch0),
                                mul(
                                    W,
                                    add(
                                        add(mul(a1, ch3), mul(a2, ch2)),
                                        mul(a3, ch1)
                                    )
                                )
                            ),
                            w0
                        ),
                        M
                    )
                    let r1 := mod(
                        add(
                            add(
                                add(mul(a0, ch1), mul(a1, ch0)),
                                mul(W, add(mul(a2, ch3), mul(a3, ch2)))
                            ),
                            w1
                        ),
                        M
                    )
                    let r2 := mod(
                        add(
                            add(
                                add(
                                    add(mul(a0, ch2), mul(a1, ch1)),
                                    mul(a2, ch0)
                                ),
                                mul(W, mul(a3, ch3))
                            ),
                            w2
                        ),
                        M
                    )
                    let r3 := mod(
                        add(
                            add(
                                add(
                                    add(mul(a0, ch3), mul(a1, ch2)),
                                    mul(a2, ch1)
                                ),
                                mul(a3, ch0)
                            ),
                            w3
                        ),
                        M
                    )

                    total := or(
                        or(shl(224, r0), shl(192, r1)),
                        or(shl(160, r2), shl(128, r3))
                    )
                }
            }
            for (uint256 i = eqEvalCount; i > 0; --i) {
                uint256 weight = _eqPolyEvalAt(
                    flatPoints,
                    (i - 1) * 8,
                    fullPoint,
                    8,
                    8
                );
                assembly ("memory-safe") {
                    let M := 0x7f000001
                    let m := 0xffffffff
                    let W := 3

                    let a0 := shr(224, total)
                    let a1 := and(shr(192, total), m)
                    let a2 := and(shr(160, total), m)
                    let a3 := and(shr(128, total), m)

                    let w0 := shr(224, weight)
                    let w1 := and(shr(192, weight), m)
                    let w2 := and(shr(160, weight), m)
                    let w3 := and(shr(128, weight), m)

                    let r0 := mod(
                        add(
                            add(
                                mul(a0, ch0),
                                mul(
                                    W,
                                    add(
                                        add(mul(a1, ch3), mul(a2, ch2)),
                                        mul(a3, ch1)
                                    )
                                )
                            ),
                            w0
                        ),
                        M
                    )
                    let r1 := mod(
                        add(
                            add(
                                add(mul(a0, ch1), mul(a1, ch0)),
                                mul(W, add(mul(a2, ch3), mul(a3, ch2)))
                            ),
                            w1
                        ),
                        M
                    )
                    let r2 := mod(
                        add(
                            add(
                                add(
                                    add(mul(a0, ch2), mul(a1, ch1)),
                                    mul(a2, ch0)
                                ),
                                mul(W, mul(a3, ch3))
                            ),
                            w2
                        ),
                        M
                    )
                    let r3 := mod(
                        add(
                            add(
                                add(
                                    add(mul(a0, ch3), mul(a1, ch2)),
                                    mul(a2, ch1)
                                ),
                                mul(a3, ch0)
                            ),
                            w3
                        ),
                        M
                    )

                    total := or(
                        or(shl(224, r0), shl(192, r1)),
                        or(shl(160, r2), shl(128, r3))
                    )
                }
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
        assembly ("memory-safe") {
            let M := 0x7f000001
            let m := 0xffffffff
            let W := 3

            let a0 := 1
            let a1 := 0
            let a2 := 0
            let a3 := 0

            let fpBase := add(add(flatPoints, 0x20), shl(5, pointStart))
            let fullBase := add(add(fullPoint, 0x20), shl(5, pointOffset))

            for {
                let i := 0
            } lt(i, numVariables) {
                i := add(i, 1)
            } {
                let off := shl(5, i)
                let p := mload(add(fpBase, off))
                let q := mload(add(fullBase, off))

                // Inline _computeEqTerm: eq(p,q) = 2·p·q + 1 - p - q  (per lane)
                let p0 := shr(224, p)
                let p1 := and(shr(192, p), m)
                let p2 := and(shr(160, p), m)
                let p3 := and(shr(128, p), m)

                let q0 := shr(224, q)
                let q1 := and(shr(192, q), m)
                let q2 := and(shr(160, q), m)
                let q3 := and(shr(128, q), m)

                // pq = p * q  (schoolbook ext4, X^4 - 3)
                let pq0 := add(
                    mul(p0, q0),
                    mul(W, add(add(mul(p1, q3), mul(p2, q2)), mul(p3, q1)))
                )
                let pq1 := add(
                    add(mul(p0, q1), mul(p1, q0)),
                    mul(W, add(mul(p2, q3), mul(p3, q2)))
                )
                let pq2 := add(
                    add(add(mul(p0, q2), mul(p1, q1)), mul(p2, q0)),
                    mul(W, mul(p3, q3))
                )
                let pq3 := add(
                    add(add(mul(p0, q3), mul(p1, q2)), mul(p2, q1)),
                    mul(p3, q0)
                )

                // t = 2*pq + 1 - p - q  (lane 0 gets +1)
                // Use 2*M as bias to avoid underflow.
                // mod is intentionally omitted: t_i < 2^67 and the subsequent
                // schoolbook acc*t products (< 2^31 * 2^67 = 2^98) fit in
                // uint256.  The final mod on acc gives the correct result.
                let t0 := sub(
                    add(add(pq0, pq0), add(0xfe000002, 1)),
                    add(p0, q0)
                )
                let t1 := sub(add(add(pq1, pq1), 0xfe000002), add(p1, q1))
                let t2 := sub(add(add(pq2, pq2), 0xfe000002), add(p2, q2))
                let t3 := sub(add(add(pq3, pq3), 0xfe000002), add(p3, q3))

                // acc = acc * t  (schoolbook ext4)
                let n0 := mod(
                    add(
                        mul(a0, t0),
                        mul(W, add(add(mul(a1, t3), mul(a2, t2)), mul(a3, t1)))
                    ),
                    M
                )
                let n1 := mod(
                    add(
                        add(mul(a0, t1), mul(a1, t0)),
                        mul(W, add(mul(a2, t3), mul(a3, t2)))
                    ),
                    M
                )
                let n2 := mod(
                    add(
                        add(add(mul(a0, t2), mul(a1, t1)), mul(a2, t0)),
                        mul(W, mul(a3, t3))
                    ),
                    M
                )
                let n3 := mod(
                    add(
                        add(add(mul(a0, t3), mul(a1, t2)), mul(a2, t1)),
                        mul(a3, t0)
                    ),
                    M
                )
                a0 := n0
                a1 := n1
                a2 := n2
                a3 := n3
            }

            acc := or(
                or(shl(224, a0), shl(192, a1)),
                or(shl(160, a2), shl(128, a3))
            )
        }
    }

    function _selectPolyEvalAt12At4(
        uint256 var_,
        uint256[] memory fullPoint
    ) internal pure returns (uint256 acc) {
        assembly ("memory-safe") {
            let modulus := 0x7f000001
            let mask := 0xffffffff
            let W := 3

            let a0 := 1
            let a1 := 0
            let a2 := 0
            let a3 := 0
            let current := var_
            let fpBase := add(add(fullPoint, 0x20), 0x80)

            for {
                let i := 12
            } gt(i, 0) {
                i := sub(i, 1)
            } {
                let pointValue := mload(add(fpBase, shl(5, sub(i, 1))))
                let scalar := sub(current, 1)
                if iszero(current) {
                    scalar := sub(modulus, 1)
                }

                let p0 := shr(224, pointValue)
                let p1 := and(shr(192, pointValue), mask)
                let p2 := and(shr(160, pointValue), mask)
                let p3 := and(shr(128, pointValue), mask)

                let t0 := add(1, mul(scalar, p0))
                let t1 := mul(scalar, p1)
                let t2 := mul(scalar, p2)
                let t3 := mul(scalar, p3)

                let n0 := mod(
                    add(
                        mul(a0, t0),
                        mul(W, add(add(mul(a1, t3), mul(a2, t2)), mul(a3, t1)))
                    ),
                    modulus
                )
                let n1 := mod(
                    add(
                        add(mul(a0, t1), mul(a1, t0)),
                        mul(W, add(mul(a2, t3), mul(a3, t2)))
                    ),
                    modulus
                )
                let n2 := mod(
                    add(
                        add(add(mul(a0, t2), mul(a1, t1)), mul(a2, t0)),
                        mul(W, mul(a3, t3))
                    ),
                    modulus
                )
                let n3 := mod(
                    add(
                        add(add(mul(a0, t3), mul(a1, t2)), mul(a2, t1)),
                        mul(a3, t0)
                    ),
                    modulus
                )

                a0 := n0
                a1 := n1
                a2 := n2
                a3 := n3
                current := mulmod(current, current, modulus)
            }

            acc := or(
                or(shl(224, a0), shl(192, a1)),
                or(shl(160, a2), shl(128, a3))
            )
        }
    }

    function _selectPolyEvalAt8At8(
        uint256 var_,
        uint256[] memory fullPoint
    ) internal pure returns (uint256 acc) {
        assembly ("memory-safe") {
            let modulus := 0x7f000001
            let mask := 0xffffffff
            let W := 3

            let a0 := 1
            let a1 := 0
            let a2 := 0
            let a3 := 0
            let current := var_
            let fpBase := add(add(fullPoint, 0x20), 0x100)

            for {
                let i := 8
            } gt(i, 0) {
                i := sub(i, 1)
            } {
                let pointValue := mload(add(fpBase, shl(5, sub(i, 1))))
                let scalar := sub(current, 1)
                if iszero(current) {
                    scalar := sub(modulus, 1)
                }

                let p0 := shr(224, pointValue)
                let p1 := and(shr(192, pointValue), mask)
                let p2 := and(shr(160, pointValue), mask)
                let p3 := and(shr(128, pointValue), mask)

                let t0 := add(1, mul(scalar, p0))
                let t1 := mul(scalar, p1)
                let t2 := mul(scalar, p2)
                let t3 := mul(scalar, p3)

                let n0 := mod(
                    add(
                        mul(a0, t0),
                        mul(W, add(add(mul(a1, t3), mul(a2, t2)), mul(a3, t1)))
                    ),
                    modulus
                )
                let n1 := mod(
                    add(
                        add(mul(a0, t1), mul(a1, t0)),
                        mul(W, add(mul(a2, t3), mul(a3, t2)))
                    ),
                    modulus
                )
                let n2 := mod(
                    add(
                        add(add(mul(a0, t2), mul(a1, t1)), mul(a2, t0)),
                        mul(W, mul(a3, t3))
                    ),
                    modulus
                )
                let n3 := mod(
                    add(
                        add(add(mul(a0, t3), mul(a1, t2)), mul(a2, t1)),
                        mul(a3, t0)
                    ),
                    modulus
                )

                a0 := n0
                a1 := n1
                a2 := n2
                a3 := n3
                current := mulmod(current, current, modulus)
            }

            acc := or(
                or(shl(224, a0), shl(192, a1)),
                or(shl(160, a2), shl(128, a3))
            )
        }
    }

    function _eqPolyEvalAtCalldata(
        uint256[] calldata point,
        uint256[] memory fullPoint,
        uint256 pointOffset,
        uint256 numVariables
    ) internal pure returns (uint256 acc) {
        if (point.length != numVariables) {
            revert StatementPointArityMismatch(0, numVariables, point.length);
        }

        assembly ("memory-safe") {
            let M := 0x7f000001
            let m := 0xffffffff
            let W := 3

            let a0 := 1
            let a1 := 0
            let a2 := 0
            let a3 := 0

            let fullBase := add(add(fullPoint, 0x20), shl(5, pointOffset))

            for {
                let i := 0
            } lt(i, numVariables) {
                i := add(i, 1)
            } {
                let off := shl(5, i)
                let p := calldataload(add(point.offset, off))
                let q := mload(add(fullBase, off))

                // Inline _computeEqTerm: eq(p,q) = 2·p·q + 1 - p - q  (per lane)
                let p0 := shr(224, p)
                let p1 := and(shr(192, p), m)
                let p2 := and(shr(160, p), m)
                let p3 := and(shr(128, p), m)

                let q0 := shr(224, q)
                let q1 := and(shr(192, q), m)
                let q2 := and(shr(160, q), m)
                let q3 := and(shr(128, q), m)

                // pq = p * q  (schoolbook ext4, X^4 - 3)
                let pq0 := add(
                    mul(p0, q0),
                    mul(W, add(add(mul(p1, q3), mul(p2, q2)), mul(p3, q1)))
                )
                let pq1 := add(
                    add(mul(p0, q1), mul(p1, q0)),
                    mul(W, add(mul(p2, q3), mul(p3, q2)))
                )
                let pq2 := add(
                    add(add(mul(p0, q2), mul(p1, q1)), mul(p2, q0)),
                    mul(W, mul(p3, q3))
                )
                let pq3 := add(
                    add(add(mul(p0, q3), mul(p1, q2)), mul(p2, q1)),
                    mul(p3, q0)
                )

                // t = 2*pq + 1 - p - q  (lane 0 gets +1)
                // Use 2*M as bias to avoid underflow.
                // mod is intentionally omitted (see _eqPolyEvalAt).
                let t0 := sub(
                    add(add(pq0, pq0), add(0xfe000002, 1)),
                    add(p0, q0)
                )
                let t1 := sub(add(add(pq1, pq1), 0xfe000002), add(p1, q1))
                let t2 := sub(add(add(pq2, pq2), 0xfe000002), add(p2, q2))
                let t3 := sub(add(add(pq3, pq3), 0xfe000002), add(p3, q3))

                // acc = acc * t  (schoolbook ext4)
                let n0 := mod(
                    add(
                        mul(a0, t0),
                        mul(W, add(add(mul(a1, t3), mul(a2, t2)), mul(a3, t1)))
                    ),
                    M
                )
                let n1 := mod(
                    add(
                        add(mul(a0, t1), mul(a1, t0)),
                        mul(W, add(mul(a2, t3), mul(a3, t2)))
                    ),
                    M
                )
                let n2 := mod(
                    add(
                        add(add(mul(a0, t2), mul(a1, t1)), mul(a2, t0)),
                        mul(W, mul(a3, t3))
                    ),
                    M
                )
                let n3 := mod(
                    add(
                        add(add(mul(a0, t3), mul(a1, t2)), mul(a2, t1)),
                        mul(a3, t0)
                    ),
                    M
                )
                a0 := n0
                a1 := n1
                a2 := n2
                a3 := n3
            }

            acc := or(
                or(shl(224, a0), shl(192, a1)),
                or(shl(160, a2), shl(128, a3))
            )
        }
    }

    function _selectPolyEvalAt(
        uint256 var_,
        uint256[] memory fullPoint,
        uint256 pointOffset,
        uint256 numVariables
    ) internal pure returns (uint256 acc) {
        assembly ("memory-safe") {
            let modulus := 0x7f000001
            let mask := 0xffffffff
            let W := 3

            let a0 := 1
            let a1 := 0
            let a2 := 0
            let a3 := 0
            let current := var_

            // fullPoint base: array data starts at fullPoint + 0x20
            // We iterate backwards: i from numVariables down to 1
            // fullPoint[pointOffset + (i-1)] is at base + (pointOffset + i - 1) * 0x20
            let fpBase := add(add(fullPoint, 0x20), shl(5, pointOffset))

            for {
                let i := numVariables
            } gt(i, 0) {
                i := sub(i, 1)
            } {
                let pointValue := mload(add(fpBase, shl(5, sub(i, 1))))

                // scalar = (current == 0) ? modulus - 1 : current - 1
                let scalar := sub(current, 1)
                if iszero(current) {
                    scalar := sub(modulus, 1)
                }

                let p0 := shr(224, pointValue)
                let p1 := and(shr(192, pointValue), mask)
                let p2 := and(shr(160, pointValue), mask)
                let p3 := and(shr(128, pointValue), mask)

                // select term: t = 1 + scalar * point (base scalar times ext4 point)
                let t0 := add(1, mul(scalar, p0))
                let t1 := mul(scalar, p1)
                let t2 := mul(scalar, p2)
                let t3 := mul(scalar, p3)

                // acc = acc * t (schoolbook over X^4 - 3)
                let n0 := mod(
                    add(
                        mul(a0, t0),
                        mul(W, add(add(mul(a1, t3), mul(a2, t2)), mul(a3, t1)))
                    ),
                    modulus
                )
                let n1 := mod(
                    add(
                        add(mul(a0, t1), mul(a1, t0)),
                        mul(W, add(mul(a2, t3), mul(a3, t2)))
                    ),
                    modulus
                )
                let n2 := mod(
                    add(
                        add(add(mul(a0, t2), mul(a1, t1)), mul(a2, t0)),
                        mul(W, mul(a3, t3))
                    ),
                    modulus
                )
                let n3 := mod(
                    add(
                        add(add(mul(a0, t3), mul(a1, t2)), mul(a2, t1)),
                        mul(a3, t0)
                    ),
                    modulus
                )

                a0 := n0
                a1 := n1
                a2 := n2
                a3 := n3

                // current = current^2 (base field squaring)
                current := mulmod(current, current, modulus)
            }

            acc := or(
                or(shl(224, a0), shl(192, a1)),
                or(shl(160, a2), shl(128, a3))
            )
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

    /// @dev Fused eq term: computes 2*p*q - p - q + (1,0,0,0) in ext4 without
    ///      intermediate packed pq. Replaces KoalaBearExt4.mul + 4x _eqCoeff.
    function _computeEqTerm(
        uint256 p,
        uint256 q
    ) private pure returns (uint256 result) {
        assembly {
            let M := 0x7f000001
            let m := 0xffffffff

            let p0 := shr(224, p)
            let p1 := and(shr(192, p), m)
            let p2 := and(shr(160, p), m)
            p := and(shr(128, p), m) // p3

            let q0 := shr(224, q)
            let q1 := and(shr(192, q), m)
            let q2 := and(shr(160, q), m)
            q := and(shr(128, q), m) // q3

            // Lane 0: pq0 = p0*q0 + W*(p1*q3 + p2*q2 + p3*q1)
            //          t0 = (2*pq0 + 2*M + 1 - p0 - q0) % M
            let tmp := add(
                mul(p0, q0),
                mul(3, add(add(mul(p1, q), mul(p2, q2)), mul(p, q1)))
            )
            result := shl(
                224,
                mod(sub(add(add(add(tmp, tmp), 0xfe000002), 1), add(p0, q0)), M)
            )

            // Lane 1: pq1 = p0*q1 + p1*q0 + W*(p2*q3 + p3*q2)
            tmp := add(
                add(mul(p0, q1), mul(p1, q0)),
                mul(3, add(mul(p2, q), mul(p, q2)))
            )
            result := or(
                result,
                shl(
                    192,
                    mod(sub(add(add(tmp, tmp), 0xfe000002), add(p1, q1)), M)
                )
            )

            // Lane 2: pq2 = p0*q2 + p1*q1 + p2*q0 + W*(p3*q3)
            tmp := add(
                add(add(mul(p0, q2), mul(p1, q1)), mul(p2, q0)),
                mul(3, mul(p, q))
            )
            result := or(
                result,
                shl(
                    160,
                    mod(sub(add(add(tmp, tmp), 0xfe000002), add(p2, q2)), M)
                )
            )

            // Lane 3: pq3 = p0*q3 + p1*q2 + p2*q1 + p3*q0
            tmp := add(
                add(add(mul(p0, q), mul(p1, q2)), mul(p2, q1)),
                mul(p, q0)
            )
            result := or(
                result,
                shl(128, mod(sub(add(add(tmp, tmp), 0xfe000002), add(p, q)), M))
            )
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
