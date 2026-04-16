// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { KoalaBear } from "../field/KoalaBear.sol";
import { KoalaBearExt4 } from "../field/KoalaBearExt4.sol";
import { MerkleVerifier } from "../merkle/MerkleVerifier.sol";
import { KeccakChallenger } from "../transcript/KeccakChallenger.sol";
import { WhirStructs } from "./WhirStructs.sol";
import { WhirBlobCodec4 } from "./WhirBlobCodec4_lir6_ff5_rsv1.sol";
import { WhirVerifierUtils4 } from "./WhirVerifierUtils4.sol";

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

    struct FixedConstraint {
        uint256 challenge;
        uint256[] eqFlatPoints;
        uint256[] selVars;
    }

    struct ParsedCommitment {
        bytes32 root;
        EqStatement oodStatement;
    }

    struct FixedParsedCommitment {
        bytes32 root;
        uint256[] oodFlatPoints;
    }

    error CommitmentMismatch(bytes32 expected, bytes32 actual);
    error ProofRoundCountMismatch(uint256 expected, uint256 actual);
    error StatementLengthMismatch(uint256 points, uint256 evaluations);
    error StatementPointArityMismatch(uint256 index, uint256 expected, uint256 actual);
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
    error InconsistentConstraintArity(uint256 eqNumVariables, uint256 selNumVariables);
    error RandomnessLengthMismatch(uint256 expected, uint256 actual);

    function _statementFromCalldata(
        WhirStructs.WhirStatement calldata statement,
        uint256 numVariables
    ) internal pure returns (EqStatement memory eqStatement) {
        if (statement.points.length != statement.evaluations.length) {
            revert StatementLengthMismatch(statement.points.length, statement.evaluations.length);
        }

        eqStatement.numVariables = numVariables;
        eqStatement.flatPoints = new uint256[](statement.points.length * numVariables);
        eqStatement.evaluations = new uint256[](statement.evaluations.length);

        unchecked {
            for (uint256 i = 0; i < statement.points.length; ++i) {
                if (statement.points[i].length != numVariables) {
                    revert StatementPointArityMismatch(i, numVariables, statement.points[i].length);
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
        parsed.oodStatement.flatPoints = new uint256[](oodSamples * numVariables);
        parsed.oodStatement.evaluations = new uint256[](oodSamples);

        unchecked {
            for (uint256 i = 0; i < oodSamples; ++i) {
                uint256 point = WhirVerifierUtils4.sampleExt4(challenger);
                WhirVerifierUtils4.expandFromUnivariateExtInto(
                    parsed.oodStatement.flatPoints, i * numVariables, point, numVariables
                );

                uint256 evalValue = oodAnswers[i];
                WhirVerifierUtils4.observeValidatedExt4(challenger, evalValue);
                parsed.oodStatement.evaluations[i] = evalValue;
            }
        }
    }

    function _parseFixedCommitment(
        KeccakChallenger.State memory challenger,
        bytes32 root,
        uint256[] calldata oodAnswers,
        uint256 numVariables,
        uint256 oodSamples
    ) internal pure returns (FixedParsedCommitment memory parsed) {
        if (oodAnswers.length != oodSamples) {
            revert OodAnswerCountMismatch(oodSamples, oodAnswers.length);
        }

        challenger.observeHashU64Digest(root);

        parsed.root = root;
        parsed.oodFlatPoints = new uint256[](oodSamples * numVariables);

        unchecked {
            for (uint256 i = 0; i < oodSamples; ++i) {
                uint256 point = WhirVerifierUtils4.sampleExt4(challenger);
                WhirVerifierUtils4.expandFromUnivariateExtInto(
                    parsed.oodFlatPoints, i * numVariables, point, numVariables
                );

                WhirVerifierUtils4.observeValidatedExt4(challenger, oodAnswers[i]);
            }
        }
    }

    function _parseFixedCommitment2(
        KeccakChallenger.State memory challenger,
        bytes32 root,
        uint256[] calldata oodAnswers,
        uint256 numVariables
    ) internal pure returns (FixedParsedCommitment memory parsed) {
        if (oodAnswers.length != 2) {
            revert OodAnswerCountMismatch(2, oodAnswers.length);
        }

        challenger.observeHashU64Digest(root);

        parsed.root = root;
        parsed.oodFlatPoints = new uint256[](numVariables << 1);

        uint256 point0 = WhirVerifierUtils4.sampleExt4(challenger);
        WhirVerifierUtils4.expandFromUnivariateExtInto(
            parsed.oodFlatPoints, 0, point0, numVariables
        );
        WhirVerifierUtils4.observeValidatedExt4(challenger, oodAnswers[0]);

        uint256 point1 = WhirVerifierUtils4.sampleExt4(challenger);
        WhirVerifierUtils4.expandFromUnivariateExtInto(
            parsed.oodFlatPoints, numVariables, point1, numVariables
        );
        WhirVerifierUtils4.observeValidatedExt4(challenger, oodAnswers[1]);
    }

    function _parseFixedCommitment16x2(
        KeccakChallenger.State memory challenger,
        bytes32 root,
        uint256[] calldata oodAnswers
    ) internal pure returns (FixedParsedCommitment memory parsed) {
        if (oodAnswers.length != 2) {
            revert OodAnswerCountMismatch(2, oodAnswers.length);
        }

        challenger.observeHashU64Digest(root);

        parsed.root = root;
        parsed.oodFlatPoints = new uint256[](32);

        uint256 point0 = WhirVerifierUtils4.sampleExt4(challenger);
        WhirVerifierUtils4.expandFromUnivariateExtInto(parsed.oodFlatPoints, 0, point0, 16);
        WhirVerifierUtils4.observeValidatedExt4(challenger, oodAnswers[0]);

        uint256 point1 = WhirVerifierUtils4.sampleExt4(challenger);
        WhirVerifierUtils4.expandFromUnivariateExtInto(parsed.oodFlatPoints, 16, point1, 16);
        WhirVerifierUtils4.observeValidatedExt4(challenger, oodAnswers[1]);
    }

    function _parseFixedCommitment2Blob(
        KeccakChallenger.State memory challenger,
        bytes calldata blob,
        uint256 offset,
        uint256 numVariables
    )
        internal
        pure
        returns (
            FixedParsedCommitment memory parsed,
            uint256 ood0,
            uint256 ood1,
            uint256 nextOffset
        )
    {
        (parsed.root, offset) = WhirBlobCodec4.readDigest20(blob, offset);
        challenger.observeHashU64Digest(parsed.root);

        parsed.oodFlatPoints = new uint256[](numVariables << 1);

        uint256 point0 = WhirVerifierUtils4.sampleExt4(challenger);
        WhirVerifierUtils4.expandFromUnivariateExtInto(
            parsed.oodFlatPoints, 0, point0, numVariables
        );
        ood0 = challenger.observeReadValidatedPackedExt4Le(blob, offset);
        offset += 16;

        uint256 point1 = WhirVerifierUtils4.sampleExt4(challenger);
        WhirVerifierUtils4.expandFromUnivariateExtInto(
            parsed.oodFlatPoints, numVariables, point1, numVariables
        );
        ood1 = challenger.observeReadValidatedPackedExt4Le(blob, offset);
        offset += 16;
        nextOffset = offset;
    }

    function _parseFixedCommitment16x2Blob(
        KeccakChallenger.State memory challenger,
        bytes calldata blob,
        uint256 offset
    )
        internal
        pure
        returns (
            FixedParsedCommitment memory parsed,
            uint256 ood0,
            uint256 ood1,
            uint256 nextOffset
        )
    {
        (parsed.root, offset) = WhirBlobCodec4.readDigest20(blob, offset);
        challenger.observeHashU64Digest(parsed.root);

        parsed.oodFlatPoints = new uint256[](32);

        uint256 point0 = WhirVerifierUtils4.sampleExt4(challenger);
        WhirVerifierUtils4.expandFromUnivariateExtInto(parsed.oodFlatPoints, 0, point0, 16);
        ood0 = challenger.observeReadValidatedPackedExt4Le(blob, offset);
        offset += 16;

        uint256 point1 = WhirVerifierUtils4.sampleExt4(challenger);
        WhirVerifierUtils4.expandFromUnivariateExtInto(parsed.oodFlatPoints, 16, point1, 16);
        ood1 = challenger.observeReadValidatedPackedExt4Le(blob, offset);
        offset += 16;
        nextOffset = offset;
    }

    function _parseFixedCommitment12x2Blob(
        KeccakChallenger.State memory challenger,
        bytes calldata blob,
        uint256 offset
    )
        internal
        pure
        returns (
            FixedParsedCommitment memory parsed,
            uint256 ood0,
            uint256 ood1,
            uint256 nextOffset
        )
    {
        (parsed.root, offset) = WhirBlobCodec4.readDigest20(blob, offset);
        challenger.observeHashU64Digest(parsed.root);

        parsed.oodFlatPoints = new uint256[](24);

        uint256 point0 = WhirVerifierUtils4.sampleExt4(challenger);
        WhirVerifierUtils4.expandFromUnivariateExtInto(parsed.oodFlatPoints, 0, point0, 12);
        ood0 = challenger.observeReadValidatedPackedExt4Le(blob, offset);
        offset += 16;

        uint256 point1 = WhirVerifierUtils4.sampleExt4(challenger);
        WhirVerifierUtils4.expandFromUnivariateExtInto(parsed.oodFlatPoints, 12, point1, 12);
        ood1 = challenger.observeReadValidatedPackedExt4Le(blob, offset);
        offset += 16;
        nextOffset = offset;
    }

    function _parseFixedCommitment8x2Blob(
        KeccakChallenger.State memory challenger,
        bytes calldata blob,
        uint256 offset
    )
        internal
        pure
        returns (
            FixedParsedCommitment memory parsed,
            uint256 ood0,
            uint256 ood1,
            uint256 nextOffset
        )
    {
        (parsed.root, offset) = WhirBlobCodec4.readDigest20(blob, offset);
        challenger.observeHashU64Digest(parsed.root);

        parsed.oodFlatPoints = new uint256[](16);

        uint256 point0 = WhirVerifierUtils4.sampleExt4(challenger);
        WhirVerifierUtils4.expandFromUnivariateExtInto(parsed.oodFlatPoints, 0, point0, 8);
        ood0 = challenger.observeReadValidatedPackedExt4Le(blob, offset);
        offset += 16;

        uint256 point1 = WhirVerifierUtils4.sampleExt4(challenger);
        WhirVerifierUtils4.expandFromUnivariateExtInto(parsed.oodFlatPoints, 8, point1, 8);
        ood1 = challenger.observeReadValidatedPackedExt4Le(blob, offset);
        offset += 16;
        nextOffset = offset;
    }

    function _checkWitnessBaseLeBlob(
        KeccakChallenger.State memory challenger,
        uint256 bits,
        bytes calldata blob,
        uint256 offset
    ) internal pure {
        if (bits == 0) {
            return;
        }

        challenger.observeBytesCalldata(blob, offset, 4);
        if (challenger.sampleBitsUnchecked(bits) != 0) {
            revert InvalidPowWitness();
        }
    }

    function _concatenateEq(EqStatement memory lhs, EqStatement memory rhs)
        internal
        pure
        returns (EqStatement memory out)
    {
        if (lhs.numVariables != rhs.numVariables) {
            revert InconsistentConstraintArity(lhs.numVariables, rhs.numVariables);
        }

        uint256 pointCountL = lhs.evaluations.length;
        uint256 pointCountR = rhs.evaluations.length;
        uint256 numVariables = lhs.numVariables;

        out.numVariables = numVariables;
        out.flatPoints = new uint256[]((pointCountL + pointCountR) * numVariables);
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

    function _emptySelect(uint256 numVariables) internal pure returns (SelectStatement memory sel) {
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
                expectedPolyEvals, sumcheck.polynomialEvals.length
            );
        }

        uint256 expectedWitnesses = powBits > 0 ? expectedRounds : 0;
        if (sumcheck.powWitnesses.length != expectedWitnesses) {
            revert SumcheckPowWitnessLengthMismatch(expectedWitnesses, sumcheck.powWitnesses.length);
        }

        updatedClaimedEval = claimedEval;
        updatedCursor = randomnessCursor;
        foldingRandomness = new uint256[](expectedRounds);

        unchecked {
            for (uint256 i = 0; i < expectedRounds; ++i) {
                uint256 c0 = sumcheck.polynomialEvals[2 * i];
                uint256 c2 = sumcheck.polynomialEvals[2 * i + 1];

                challenger.observeValidatedPackedExt4Pair(c0, c2);

                if (powBits > 0) {
                    if (!challenger.checkWitness(powBits, sumcheck.powWitnesses[i])) {
                        revert InvalidPowWitness();
                    }
                }

                uint256 r = WhirVerifierUtils4.sampleExt4(challenger);
                foldingRandomness[i] = r;
                allRandomness[updatedCursor] = r;
                updatedCursor += 1;
                updatedClaimedEval = KoalaBearExt4.extrapolate_012(
                    c0, KoalaBearExt4.sub(updatedClaimedEval, c0), c2, r
                );
            }
        }
    }

    function _verifySumcheckBlob(
        bytes calldata blob,
        uint256 offset,
        KeccakChallenger.State memory challenger,
        uint256 claimedEval,
        uint256 expectedRounds,
        uint256 powBits,
        uint256[] memory allRandomness,
        uint256 randomnessCursor
    )
        internal
        pure
        returns (uint256 updatedClaimedEval, uint256 updatedCursor, uint256 nextOffset)
    {
        updatedClaimedEval = claimedEval;
        updatedCursor = randomnessCursor;

        uint256 polyOffset = offset;
        uint256 powOffset = polyOffset + expectedRounds * 32;
        nextOffset = powOffset + (powBits > 0 ? expectedRounds * 4 : 0);

        unchecked {
            for (uint256 i = 0; i < expectedRounds; ++i) {
                (uint256 c0, uint256 c2) =
                    challenger.observeReadValidatedPackedExt4LePair(blob, polyOffset + i * 32);
                if (powBits > 0) {
                    _checkWitnessBaseLeBlob(challenger, powBits, blob, powOffset + i * 4);
                }

                uint256 r = WhirVerifierUtils4.sampleExt4(challenger);
                allRandomness[updatedCursor] = r;
                updatedCursor += 1;
                updatedClaimedEval = KoalaBearExt4.extrapolate_012(
                    c0, KoalaBearExt4.sub(updatedClaimedEval, c0), c2, r
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
        uint8 expectedKind
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
            challenger, domainSize, foldingFactor, numQueries
        );

        if (queryBatch.kind != expectedKind) {
            revert QueryBatchKindMismatch(expectedKind, queryBatch.kind);
        }
        if (queryBatch.numQueries != indices.length) {
            revert QueryBatchCountMismatch(indices.length, queryBatch.numQueries);
        }

        uint256 expectedRowLen = uint256(1) << foldingFactor;
        if (queryBatch.rowLen != expectedRowLen) {
            revert QueryBatchRowLengthMismatch(expectedRowLen, queryBatch.rowLen);
        }

        uint256 depth = WhirVerifierUtils4.log2Strict(domainSize >> foldingFactor);
        statement.vars = new uint256[](indices.length);
        statement.evaluations = new uint256[](indices.length);

        bytes32 computedRoot;
        if (expectedKind == 0) {
            computedRoot = MerkleVerifier.computeRootFromFlatBaseRows20(
                indices, queryBatch.values, queryBatch.rowLen, depth, queryBatch.decommitments
            );
        } else {
            computedRoot = MerkleVerifier.computeRootFromFlatExtensionRows20(
                indices, queryBatch.values, queryBatch.rowLen, depth, queryBatch.decommitments
            );
        }

        if (computedRoot != expectedRoot) {
            revert MerkleRootMismatch(expectedRoot, computedRoot);
        }

        unchecked {
            for (uint256 i = 0; i < indices.length; ++i) {
                statement.vars[i] = KoalaBear.pow(foldedDomainGen, indices[i]);
                uint256 rowStart = i * queryBatch.rowLen;
                statement.evaluations[i] = expectedKind == 0
                    ? WhirVerifierUtils4.evaluateBaseRowAsExt4(
                        queryBatch.values, rowStart, queryBatch.rowLen, foldingRandomness
                    )
                    : WhirVerifierUtils4.evaluateExtensionRowAsExt4(
                        queryBatch.values, rowStart, queryBatch.rowLen, foldingRandomness
                    );
            }
        }
    }

    function _combineConstraintEvals(uint256 acc, Constraint memory constraint)
        internal
        pure
        returns (uint256 updated)
    {
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

                let r0 :=
                    mod(
                        add(
                            add(
                                mul(h0, ch0),
                                mul(W, add(add(mul(h1, ch3), mul(h2, ch2)), mul(h3, ch1)))
                            ),
                            w0
                        ),
                        M
                    )
                let r1 :=
                    mod(
                        add(
                            add(
                                add(mul(h0, ch1), mul(h1, ch0)),
                                mul(W, add(mul(h2, ch3), mul(h3, ch2)))
                            ),
                            w1
                        ),
                        M
                    )
                let r2 :=
                    mod(
                        add(
                            add(
                                add(add(mul(h0, ch2), mul(h1, ch1)), mul(h2, ch0)),
                                mul(W, mul(h3, ch3))
                            ),
                            w2
                        ),
                        M
                    )
                let r3 :=
                    mod(
                        add(
                            add(add(add(mul(h0, ch3), mul(h1, ch2)), mul(h2, ch1)), mul(h3, ch0)),
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

                let r0 :=
                    mod(
                        add(
                            add(
                                mul(h0, ch0),
                                mul(W, add(add(mul(h1, ch3), mul(h2, ch2)), mul(h3, ch1)))
                            ),
                            w0
                        ),
                        M
                    )
                let r1 :=
                    mod(
                        add(
                            add(
                                add(mul(h0, ch1), mul(h1, ch0)),
                                mul(W, add(mul(h2, ch3), mul(h3, ch2)))
                            ),
                            w1
                        ),
                        M
                    )
                let r2 :=
                    mod(
                        add(
                            add(
                                add(add(mul(h0, ch2), mul(h1, ch1)), mul(h2, ch0)),
                                mul(W, mul(h3, ch3))
                            ),
                            w2
                        ),
                        M
                    )
                let r3 :=
                    mod(
                        add(
                            add(add(add(mul(h0, ch3), mul(h1, ch2)), mul(h2, ch1)), mul(h3, ch0)),
                            w3
                        ),
                        M
                    )
                h0 := r0
                h1 := r1
                h2 := r2
                h3 := r3
            }

            horner := or(or(shl(224, h0), shl(192, h1)), or(shl(160, h2), shl(128, h3)))
        }

        updated = KoalaBearExt4.add(acc, horner);
    }

    function _verifyFinalStirChallengesRaw(
        KeccakChallenger.State memory challenger,
        bytes32 expectedRoot,
        uint256 powBits,
        uint256 numQueries,
        uint256 foldingFactor,
        uint256 domainSize,
        uint256 foldedDomainGen,
        WhirStructs.QueryBatchOpening calldata queryBatch,
        bool queryBatchPresent,
        uint256 powWitness,
        uint256[] memory foldingRandomness,
        uint8 expectedKind,
        uint256[] calldata finalPoly
    ) internal pure {
        if (powBits > 0 && !challenger.checkWitness(powBits, powWitness)) {
            revert InvalidPowWitness();
        }

        if (!queryBatchPresent) {
            if (numQueries != 0) {
                revert FinalQueryBatchPresenceMismatch(true, false);
            }
            return;
        }

        uint256[] memory indices = WhirVerifierUtils4.sampleStirQueries(
            challenger, domainSize, foldingFactor, numQueries
        );

        if (queryBatch.kind != expectedKind) {
            revert QueryBatchKindMismatch(expectedKind, queryBatch.kind);
        }
        if (queryBatch.numQueries != indices.length) {
            revert QueryBatchCountMismatch(indices.length, queryBatch.numQueries);
        }

        uint256 expectedRowLen = uint256(1) << foldingFactor;
        if (queryBatch.rowLen != expectedRowLen) {
            revert QueryBatchRowLengthMismatch(expectedRowLen, queryBatch.rowLen);
        }

        uint256 depth = WhirVerifierUtils4.log2Strict(domainSize >> foldingFactor);
        bytes32 computedRoot;
        if (expectedKind == 0) {
            computedRoot = MerkleVerifier.computeRootFromFlatBaseRows20(
                indices, queryBatch.values, queryBatch.rowLen, depth, queryBatch.decommitments
            );
        } else {
            computedRoot = MerkleVerifier.computeRootFromFlatExtensionRows20(
                indices, queryBatch.values, queryBatch.rowLen, depth, queryBatch.decommitments
            );
        }

        if (computedRoot != expectedRoot) {
            revert MerkleRootMismatch(expectedRoot, computedRoot);
        }

        unchecked {
            for (uint256 i = 0; i < indices.length; ++i) {
                uint256 point = KoalaBear.pow(foldedDomainGen, indices[i]);
                uint256 rowStart = i * queryBatch.rowLen;
                uint256 expectedEval = expectedKind == 0
                    ? WhirVerifierUtils4.evaluateBaseRowAsExt4(
                        queryBatch.values, rowStart, queryBatch.rowLen, foldingRandomness
                    )
                    : WhirVerifierUtils4.evaluateExtensionRowAsExt4(
                        queryBatch.values, rowStart, queryBatch.rowLen, foldingRandomness
                    );
                if (WhirVerifierUtils4.hornerBase(finalPoly, point) != expectedEval) {
                    revert StirConstraintFailed(i);
                }
            }
        }
    }

    function _verifyStirAndCombineConstraint(
        KeccakChallenger.State memory challenger,
        bytes32 expectedRoot,
        uint256 powBits,
        uint256 numQueries,
        uint256 foldingFactor,
        uint256 domainSize,
        uint256 foldedDomainGen,
        WhirStructs.QueryBatchOpening calldata queryBatch,
        bool queryBatchPresent,
        uint256 powWitness,
        uint256[] memory foldingRandomness,
        uint8 expectedKind,
        uint256[] calldata oodAnswers
    )
        internal
        pure
        returns (uint256 challenge, uint256 claimedContribution, uint256[] memory selVars)
    {
        if (powBits > 0 && !challenger.checkWitness(powBits, powWitness)) {
            revert InvalidPowWitness();
        }

        challenger.sampleBase();

        if (!queryBatchPresent) {
            if (numQueries != 0) {
                revert FinalQueryBatchPresenceMismatch(true, false);
            }
            challenge = WhirVerifierUtils4.sampleExt4(challenger);
            unchecked {
                for (uint256 i = oodAnswers.length; i > 0; --i) {
                    claimedContribution =
                        _hornerStep(claimedContribution, challenge, oodAnswers[i - 1]);
                }
            }
            selVars = new uint256[](0);
            return (challenge, claimedContribution, selVars);
        }

        uint256[] memory indices = WhirVerifierUtils4.sampleStirQueries(
            challenger, domainSize, foldingFactor, numQueries
        );

        if (queryBatch.kind != expectedKind) {
            revert QueryBatchKindMismatch(expectedKind, queryBatch.kind);
        }
        if (queryBatch.numQueries != indices.length) {
            revert QueryBatchCountMismatch(indices.length, queryBatch.numQueries);
        }

        uint256 expectedRowLen = uint256(1) << foldingFactor;
        if (queryBatch.rowLen != expectedRowLen) {
            revert QueryBatchRowLengthMismatch(expectedRowLen, queryBatch.rowLen);
        }

        uint256 depth = WhirVerifierUtils4.log2Strict(domainSize >> foldingFactor);

        bytes32 computedRoot;
        if (expectedKind == 0) {
            computedRoot = MerkleVerifier.computeRootFromFlatBaseRows20(
                indices, queryBatch.values, queryBatch.rowLen, depth, queryBatch.decommitments
            );
        } else {
            computedRoot = MerkleVerifier.computeRootFromFlatExtensionRows20(
                indices, queryBatch.values, queryBatch.rowLen, depth, queryBatch.decommitments
            );
        }

        if (computedRoot != expectedRoot) {
            revert MerkleRootMismatch(expectedRoot, computedRoot);
        }

        challenge = WhirVerifierUtils4.sampleExt4(challenger);
        selVars = new uint256[](indices.length);

        unchecked {
            for (uint256 i = indices.length; i > 0; --i) {
                uint256 idx = i - 1;
                uint256 point = KoalaBear.pow(foldedDomainGen, indices[idx]);
                selVars[idx] = point;

                uint256 rowStart = idx * queryBatch.rowLen;
                uint256 evalValue = expectedKind == 0
                    ? WhirVerifierUtils4.evaluateBaseRowAsExt4(
                        queryBatch.values, rowStart, queryBatch.rowLen, foldingRandomness
                    )
                    : WhirVerifierUtils4.evaluateExtensionRowAsExt4(
                        queryBatch.values, rowStart, queryBatch.rowLen, foldingRandomness
                    );
                claimedContribution = _hornerStep(claimedContribution, challenge, evalValue);
            }

            for (uint256 i = oodAnswers.length; i > 0; --i) {
                claimedContribution = _hornerStep(claimedContribution, challenge, oodAnswers[i - 1]);
            }
        }
    }

    function _computeBaseRootAndEvalsBlob16(
        uint256[] memory indices,
        bytes calldata blob,
        uint256 valuesOffset,
        uint256 depth,
        uint256 decommOffset,
        uint256 decommLen,
        uint256 p0,
        uint256 p1,
        uint256 p2,
        uint256 p3
    ) private pure returns (bytes32 root, uint256[] memory rowEvals) {
        uint256 count = indices.length;
        if (count == 0) {
            revert MerkleVerifier.EmptyIndices();
        }

        bytes memory frontier;
        assembly ("memory-safe") {
            let frontierBytes := shl(6, count)
            frontier := mload(0x40)
            mstore(frontier, frontierBytes)

            rowEvals := add(add(frontier, 0x20), frontierBytes)
            mstore(rowEvals, count)
            mstore(0x40, add(add(rowEvals, 0x20), shl(5, count)))
        }

        unchecked {
            uint256 prevIdx;
            for (uint256 i = 0; i < count; ++i) {
                uint256 idx = indices[i];
                if (i != 0 && prevIdx >= idx) {
                    revert MerkleVerifier.IndicesNotStrictlyIncreasing(prevIdx, idx);
                }
                prevIdx = idx;

                uint256 rowOffset = valuesOffset + i * 64;
                (bytes32 hash, uint256 evalValue) = WhirVerifierUtils4._hashAndEvaluateBaseRowDim4BlobPackedPoints(
                    blob, rowOffset, p0, p1, p2, p3
                );
                rowEvals[i] = evalValue;

                assembly ("memory-safe") {
                    let dst := add(add(frontier, 0x20), shl(6, i))
                    mstore(dst, idx)
                    mstore(add(dst, 0x20), hash)
                }
            }
        }

        root = MerkleVerifier.computeRootFromFrontier20Blob(
            frontier, count, depth, blob, decommOffset, decommLen
        );
    }

    function _computeBaseRootAndEvalsBlob32(
        uint256[] memory indices,
        bytes calldata blob,
        uint256 valuesOffset,
        uint256 depth,
        uint256 decommOffset,
        uint256 decommLen,
        uint256 p0,
        uint256 p1,
        uint256 p2,
        uint256 p3,
        uint256 p4
    ) private pure returns (bytes32 root, uint256[] memory rowEvals) {
        uint256 count = indices.length;
        if (count == 0) {
            revert MerkleVerifier.EmptyIndices();
        }

        bytes memory frontier;
        assembly ("memory-safe") {
            let frontierBytes := shl(6, count)
            frontier := mload(0x40)
            mstore(frontier, frontierBytes)

            rowEvals := add(add(frontier, 0x20), frontierBytes)
            mstore(rowEvals, count)
            mstore(0x40, add(add(rowEvals, 0x20), shl(5, count)))
        }

        unchecked {
            uint256 prevIdx;
            for (uint256 i = 0; i < count; ++i) {
                uint256 idx = indices[i];
                if (i != 0 && prevIdx >= idx) {
                    revert MerkleVerifier.IndicesNotStrictlyIncreasing(prevIdx, idx);
                }
                prevIdx = idx;

                uint256 rowOffset = valuesOffset + i * 128;
                (bytes32 hash, uint256 evalValue) = WhirVerifierUtils4._hashAndEvaluateBaseRowDim5BlobPackedPoints(
                    blob, rowOffset, p0, p1, p2, p3, p4
                );
                rowEvals[i] = evalValue;

                assembly ("memory-safe") {
                    let dst := add(add(frontier, 0x20), shl(6, i))
                    mstore(dst, idx)
                    mstore(add(dst, 0x20), hash)
                }
            }
        }

        root = MerkleVerifier.computeRootFromFrontier20Blob(
            frontier, count, depth, blob, decommOffset, decommLen
        );
    }

    function _computeExtensionRootAndEvalsBlob16(
        uint256[] memory indices,
        bytes calldata blob,
        uint256 valuesOffset,
        uint256 depth,
        uint256 decommOffset,
        uint256 decommLen,
        uint256 p0,
        uint256 p1,
        uint256 p2,
        uint256 p3
    ) private pure returns (bytes32 root, uint256[] memory rowEvals) {
        uint256 count = indices.length;
        if (count == 0) {
            revert MerkleVerifier.EmptyIndices();
        }

        bytes memory frontier;
        assembly ("memory-safe") {
            let frontierBytes := shl(6, count)
            frontier := mload(0x40)
            mstore(frontier, frontierBytes)

            rowEvals := add(add(frontier, 0x20), frontierBytes)
            mstore(rowEvals, count)
            mstore(0x40, add(add(rowEvals, 0x20), shl(5, count)))
        }

        unchecked {
            uint256 prevIdx;
            for (uint256 i = 0; i < count; ++i) {
                uint256 idx = indices[i];
                if (i != 0 && prevIdx >= idx) {
                    revert MerkleVerifier.IndicesNotStrictlyIncreasing(prevIdx, idx);
                }
                prevIdx = idx;

                uint256 rowOffset = valuesOffset + i * 256;
                (bytes32 hash, uint256 evalValue) = WhirVerifierUtils4._hashAndEvaluateExtensionRowDim4BlobPackedPoints(
                    blob, rowOffset, p0, p1, p2, p3
                );
                rowEvals[i] = evalValue;

                assembly ("memory-safe") {
                    let dst := add(add(frontier, 0x20), shl(6, i))
                    mstore(dst, idx)
                    mstore(add(dst, 0x20), hash)
                }
            }
        }

        root = MerkleVerifier.computeRootFromFrontier20Blob(
            frontier, count, depth, blob, decommOffset, decommLen
        );
    }

    function _computeExtensionRootAndEvalsBlob32(
        uint256[] memory indices,
        bytes calldata blob,
        uint256 valuesOffset,
        uint256 depth,
        uint256 decommOffset,
        uint256 decommLen,
        uint256 p0,
        uint256 p1,
        uint256 p2,
        uint256 p3,
        uint256 p4
    ) private pure returns (bytes32 root, uint256[] memory rowEvals) {
        uint256 count = indices.length;
        if (count == 0) {
            revert MerkleVerifier.EmptyIndices();
        }

        bytes memory frontier;
        assembly ("memory-safe") {
            let frontierBytes := shl(6, count)
            frontier := mload(0x40)
            mstore(frontier, frontierBytes)

            rowEvals := add(add(frontier, 0x20), frontierBytes)
            mstore(rowEvals, count)
            mstore(0x40, add(add(rowEvals, 0x20), shl(5, count)))
        }

        unchecked {
            uint256 prevIdx;
            for (uint256 i = 0; i < count; ++i) {
                uint256 idx = indices[i];
                if (i != 0 && prevIdx >= idx) {
                    revert MerkleVerifier.IndicesNotStrictlyIncreasing(prevIdx, idx);
                }
                prevIdx = idx;

                uint256 rowOffset = valuesOffset + i * 512;
                (bytes32 hash, uint256 evalValue) = WhirVerifierUtils4._hashAndEvaluateExtensionRowDim5BlobPackedPoints(
                    blob, rowOffset, p0, p1, p2, p3, p4
                );
                rowEvals[i] = evalValue;

                assembly ("memory-safe") {
                    let dst := add(add(frontier, 0x20), shl(6, i))
                    mstore(dst, idx)
                    mstore(add(dst, 0x20), hash)
                }
            }
        }

        root = MerkleVerifier.computeRootFromFrontier20Blob(
            frontier, count, depth, blob, decommOffset, decommLen
        );
    }

    function _computeBlobRootAndEvals(
        uint256[] memory indices,
        bytes calldata blob,
        uint256 valuesOffset,
        uint256 rowLen,
        uint256 depth,
        uint256 decommOffset,
        uint256 decommLen,
        uint256[] memory allRandomness,
        uint256 randomnessOffset,
        uint8 expectedKind
    ) private pure returns (bytes32 computedRoot, uint256[] memory rowEvals) {
        uint256 p0 = allRandomness[randomnessOffset];
        uint256 p1 = allRandomness[randomnessOffset + 1];
        uint256 p2 = allRandomness[randomnessOffset + 2];
        uint256 p3 = allRandomness[randomnessOffset + 3];

        if (rowLen == 16) {
            if (expectedKind == 0) {
                return _computeBaseRootAndEvalsBlob16(
                    indices, blob, valuesOffset, depth, decommOffset, decommLen, p0, p1, p2, p3
                );
            }

            return _computeExtensionRootAndEvalsBlob16(
                indices, blob, valuesOffset, depth, decommOffset, decommLen, p0, p1, p2, p3
            );
        }

        if (rowLen == 32) {
            uint256 p4 = allRandomness[randomnessOffset + 4];

            if (expectedKind == 0) {
                return _computeBaseRootAndEvalsBlob32(
                    indices, blob, valuesOffset, depth, decommOffset, decommLen, p0, p1, p2, p3, p4
                );
            }

            return _computeExtensionRootAndEvalsBlob32(
                indices, blob, valuesOffset, depth, decommOffset, decommLen, p0, p1, p2, p3, p4
            );
        }

        uint256 count = indices.length;
        rowEvals = new uint256[](count);
        if (expectedKind == 0) {
            computedRoot = MerkleVerifier.computeRootFromFlatBaseRows20Blob(
                indices, blob, valuesOffset, rowLen, depth, decommOffset, decommLen
            );
            unchecked {
                for (uint256 i = 0; i < count; ++i) {
                    rowEvals[i] = WhirVerifierUtils4.evaluateBaseRowBlobAsExt4(
                        blob,
                        valuesOffset + i * rowLen * 4,
                        rowLen,
                        allRandomness,
                        randomnessOffset,
                        WhirVerifierUtils4.log2Strict(rowLen)
                    );
                }
            }
            return (computedRoot, rowEvals);
        }

        computedRoot = MerkleVerifier.computeRootFromFlatExtensionRows20Blob(
            indices, blob, valuesOffset, rowLen, depth, decommOffset, decommLen
        );
        unchecked {
            for (uint256 i = 0; i < count; ++i) {
                rowEvals[i] = WhirVerifierUtils4.evaluateExtensionRowBlobAsExt4(
                    blob,
                    valuesOffset + i * rowLen * 16,
                    rowLen,
                    allRandomness,
                    randomnessOffset,
                    WhirVerifierUtils4.log2Strict(rowLen)
                );
            }
        }
        return (computedRoot, rowEvals);
    }

    function _verifyStirAndCombineConstraintBlob(
        KeccakChallenger.State memory challenger,
        bytes32 expectedRoot,
        uint256 powBits,
        uint256 numQueries,
        uint256 rowLen,
        uint256 depth,
        uint256 foldedDomainGen,
        bytes calldata blob,
        uint256 valuesOffset,
        uint256 decommLen,
        uint256 powWitnessOffset,
        uint256[] memory allRandomness,
        uint256 randomnessOffset,
        uint8 expectedKind,
        uint256 ood0,
        uint256 ood1
    )
        internal
        pure
        returns (
            uint256 challenge,
            uint256 claimedContribution,
            uint256[] memory selVars,
            uint256 nextOffset
        )
    {
        _checkWitnessBaseLeBlob(challenger, powBits, blob, powWitnessOffset);

        challenger.sampleBase();

        uint256[] memory indices =
            WhirVerifierUtils4.sampleStirQueriesPow2(challenger, depth, numQueries);
        if (indices.length != numQueries) {
            revert QueryBatchCountMismatch(numQueries, indices.length);
        }

        uint256 stride = expectedKind == 0 ? 4 : 16;
        uint256 decommOffset = valuesOffset + numQueries * rowLen * stride;
        nextOffset = decommOffset + decommLen * 20;

        unchecked {
            (bytes32 computedRoot, uint256[] memory rowEvals) = _computeBlobRootAndEvals(
                indices,
                blob,
                valuesOffset,
                rowLen,
                depth,
                decommOffset,
                decommLen,
                allRandomness,
                randomnessOffset,
                expectedKind
            );

            if (computedRoot != expectedRoot) {
                revert MerkleRootMismatch(expectedRoot, computedRoot);
            }

            challenge = WhirVerifierUtils4.sampleExt4(challenger);
            // Reuse the sampled query-index buffer as the select-variable output to avoid
            // a second allocation; the loop below overwrites each sorted index with g^index
            // only after Merkle verification has already consumed the original indices.
            selVars = indices;

            for (uint256 i = numQueries; i > 0; --i) {
                uint256 idx = i - 1;
                uint256 point = KoalaBear.pow(foldedDomainGen, indices[idx]);
                selVars[idx] = point;
                claimedContribution = _hornerStep(claimedContribution, challenge, rowEvals[idx]);
            }

            claimedContribution = _hornerStep(claimedContribution, challenge, ood1);
            claimedContribution = _hornerStep(claimedContribution, challenge, ood0);
        }
    }

    function _verifyFinalStirChallengesBlob(
        KeccakChallenger.State memory challenger,
        bytes32 expectedRoot,
        uint256 powBits,
        uint256 numQueries,
        uint256 rowLen,
        uint256 depth,
        uint256 foldedDomainGen,
        bytes calldata blob,
        uint256 valuesOffset,
        uint256 decommLen,
        uint256 powWitnessOffset,
        uint256[] memory allRandomness,
        uint256 randomnessOffset,
        uint8 expectedKind,
        uint256 finalPolyOffset,
        uint256 finalPolyLen
    ) internal pure returns (uint256 nextOffset) {
        _checkWitnessBaseLeBlob(challenger, powBits, blob, powWitnessOffset);

        uint256[] memory indices =
            WhirVerifierUtils4.sampleStirQueriesPow2(challenger, depth, numQueries);
        if (indices.length != numQueries) {
            revert QueryBatchCountMismatch(numQueries, indices.length);
        }

        uint256 stride = expectedKind == 0 ? 4 : 16;
        uint256 decommOffset = valuesOffset + numQueries * rowLen * stride;
        nextOffset = decommOffset + decommLen * 20;

        unchecked {
            (bytes32 computedRoot, uint256[] memory rowEvals) = _computeBlobRootAndEvals(
                indices,
                blob,
                valuesOffset,
                rowLen,
                depth,
                decommOffset,
                decommLen,
                allRandomness,
                randomnessOffset,
                expectedKind
            );

            if (computedRoot != expectedRoot) {
                revert MerkleRootMismatch(expectedRoot, computedRoot);
            }

            for (uint256 i = 0; i < numQueries; ++i) {
                indices[i] = KoalaBear.pow(foldedDomainGen, indices[i]);
            }

            for (uint256 i = 0; i < numQueries; ++i) {
                if (
                    WhirVerifierUtils4.hornerBaseBlob(
                            blob, finalPolyOffset, finalPolyLen, indices[i]
                        ) != rowEvals[i]
                ) {
                    revert StirConstraintFailed(i);
                }
            }
        }
    }

    function _evaluateConstraintsFixedSelect(
        Constraint[] memory constraints,
        uint256[] memory allRandomness
    ) internal pure returns (uint256 acc) {
        FixedConstraint[] memory fixedConstraints = new FixedConstraint[](constraints.length);
        unchecked {
            for (uint256 i = 0; i < constraints.length; ++i) {
                fixedConstraints[i] = FixedConstraint({
                    challenge: constraints[i].challenge,
                    eqFlatPoints: constraints[i].eqStatement.flatPoints,
                    selVars: constraints[i].selStatement.vars
                });
            }
        }
        return _evaluateConstraintsFixedSelectRaw(
            constraints[0].challenge,
            fixedConstraints[0].eqFlatPoints,
            fixedConstraints[0].selVars,
            constraints[1].challenge,
            fixedConstraints[1].eqFlatPoints,
            fixedConstraints[1].selVars,
            allRandomness
        );
    }

    function _evaluateConstraintsFixedSelectRaw(
        uint256 round0Challenge,
        uint256[] memory round0EqFlatPoints,
        uint256[] memory round0SelVars,
        uint256 round1Challenge,
        uint256[] memory round1EqFlatPoints,
        uint256[] memory round1SelVars,
        uint256[] memory allRandomness
    ) internal pure returns (uint256 acc) {
        acc = KoalaBearExt4.add(
            _evaluateConstraint12SelectRaw(
                round0Challenge, round0EqFlatPoints, round0SelVars, allRandomness
            ),
            _evaluateConstraint8SelectRaw(
                round1Challenge, round1EqFlatPoints, round1SelVars, allRandomness
            )
        );
    }

    function _evaluateConstraintGenericRaw(
        uint256 challenge,
        uint256[] memory flatPoints,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) internal pure returns (uint256 total) {
        uint256 numVariables = flatPoints.length / 2;
        uint256 eqCount = numVariables == 0 ? 0 : flatPoints.length / numVariables;
        uint256 pointOffset = fullPoint.length - numVariables;

        unchecked {
            for (uint256 i = selVars.length; i > 0; --i) {
                total = _hornerStep(
                    total,
                    challenge,
                    _selectPolyEvalAtTail(selVars[i - 1], fullPoint, pointOffset, numVariables)
                );
            }
            for (uint256 i = eqCount; i > 0; --i) {
                total = _hornerStep(
                    total,
                    challenge,
                    _eqPolyEvalAt(
                        flatPoints, (i - 1) * numVariables, fullPoint, pointOffset, numVariables
                    )
                );
            }
        }
    }

    function _evaluateConstraint12SelectRaw(
        uint256 challenge,
        uint256[] memory flatPoints,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) internal pure returns (uint256 total) {
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
            for (uint256 i = 9; i > 0; --i) {
                uint256 weight = _selectPolyEvalAt12At4(selVars[i - 1], fullPoint);
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

                    let r0 :=
                        mod(
                            add(
                                add(
                                    mul(a0, ch0),
                                    mul(W, add(add(mul(a1, ch3), mul(a2, ch2)), mul(a3, ch1)))
                                ),
                                w0
                            ),
                            M
                        )
                    let r1 :=
                        mod(
                            add(
                                add(
                                    add(mul(a0, ch1), mul(a1, ch0)),
                                    mul(W, add(mul(a2, ch3), mul(a3, ch2)))
                                ),
                                w1
                            ),
                            M
                        )
                    let r2 :=
                        mod(
                            add(
                                add(
                                    add(add(mul(a0, ch2), mul(a1, ch1)), mul(a2, ch0)),
                                    mul(W, mul(a3, ch3))
                                ),
                                w2
                            ),
                            M
                        )
                    let r3 :=
                        mod(
                            add(
                                add(
                                    add(add(mul(a0, ch3), mul(a1, ch2)), mul(a2, ch1)),
                                    mul(a3, ch0)
                                ),
                                w3
                            ),
                            M
                        )

                    total := or(or(shl(224, r0), shl(192, r1)), or(shl(160, r2), shl(128, r3)))
                }
            }
            for (uint256 i = 2; i > 0; --i) {
                uint256 weight = _eqPolyEvalAt(flatPoints, (i - 1) * 12, fullPoint, 4, 12);
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

                    let r0 :=
                        mod(
                            add(
                                add(
                                    mul(a0, ch0),
                                    mul(W, add(add(mul(a1, ch3), mul(a2, ch2)), mul(a3, ch1)))
                                ),
                                w0
                            ),
                            M
                        )
                    let r1 :=
                        mod(
                            add(
                                add(
                                    add(mul(a0, ch1), mul(a1, ch0)),
                                    mul(W, add(mul(a2, ch3), mul(a3, ch2)))
                                ),
                                w1
                            ),
                            M
                        )
                    let r2 :=
                        mod(
                            add(
                                add(
                                    add(add(mul(a0, ch2), mul(a1, ch1)), mul(a2, ch0)),
                                    mul(W, mul(a3, ch3))
                                ),
                                w2
                            ),
                            M
                        )
                    let r3 :=
                        mod(
                            add(
                                add(
                                    add(add(mul(a0, ch3), mul(a1, ch2)), mul(a2, ch1)),
                                    mul(a3, ch0)
                                ),
                                w3
                            ),
                            M
                        )

                    total := or(or(shl(224, r0), shl(192, r1)), or(shl(160, r2), shl(128, r3)))
                }
            }
        }
    }

    function _evaluateConstraint8SelectRaw(
        uint256 challenge,
        uint256[] memory flatPoints,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) internal pure returns (uint256 total) {
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
            for (uint256 i = 6; i > 0; --i) {
                uint256 weight = _selectPolyEvalAt8At8(selVars[i - 1], fullPoint);
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

                    let r0 :=
                        mod(
                            add(
                                add(
                                    mul(a0, ch0),
                                    mul(W, add(add(mul(a1, ch3), mul(a2, ch2)), mul(a3, ch1)))
                                ),
                                w0
                            ),
                            M
                        )
                    let r1 :=
                        mod(
                            add(
                                add(
                                    add(mul(a0, ch1), mul(a1, ch0)),
                                    mul(W, add(mul(a2, ch3), mul(a3, ch2)))
                                ),
                                w1
                            ),
                            M
                        )
                    let r2 :=
                        mod(
                            add(
                                add(
                                    add(add(mul(a0, ch2), mul(a1, ch1)), mul(a2, ch0)),
                                    mul(W, mul(a3, ch3))
                                ),
                                w2
                            ),
                            M
                        )
                    let r3 :=
                        mod(
                            add(
                                add(
                                    add(add(mul(a0, ch3), mul(a1, ch2)), mul(a2, ch1)),
                                    mul(a3, ch0)
                                ),
                                w3
                            ),
                            M
                        )

                    total := or(or(shl(224, r0), shl(192, r1)), or(shl(160, r2), shl(128, r3)))
                }
            }
            for (uint256 i = 2; i > 0; --i) {
                uint256 weight = _eqPolyEvalAt(flatPoints, (i - 1) * 8, fullPoint, 8, 8);
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

                    let r0 :=
                        mod(
                            add(
                                add(
                                    mul(a0, ch0),
                                    mul(W, add(add(mul(a1, ch3), mul(a2, ch2)), mul(a3, ch1)))
                                ),
                                w0
                            ),
                            M
                        )
                    let r1 :=
                        mod(
                            add(
                                add(
                                    add(mul(a0, ch1), mul(a1, ch0)),
                                    mul(W, add(mul(a2, ch3), mul(a3, ch2)))
                                ),
                                w1
                            ),
                            M
                        )
                    let r2 :=
                        mod(
                            add(
                                add(
                                    add(add(mul(a0, ch2), mul(a1, ch1)), mul(a2, ch0)),
                                    mul(W, mul(a3, ch3))
                                ),
                                w2
                            ),
                            M
                        )
                    let r3 :=
                        mod(
                            add(
                                add(
                                    add(add(mul(a0, ch3), mul(a1, ch2)), mul(a2, ch1)),
                                    mul(a3, ch0)
                                ),
                                w3
                            ),
                            M
                        )

                    total := or(or(shl(224, r0), shl(192, r1)), or(shl(160, r2), shl(128, r3)))
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
                let pq0 := add(mul(p0, q0), mul(W, add(add(mul(p1, q3), mul(p2, q2)), mul(p3, q1))))
                let pq1 := add(add(mul(p0, q1), mul(p1, q0)), mul(W, add(mul(p2, q3), mul(p3, q2))))
                let pq2 := add(add(add(mul(p0, q2), mul(p1, q1)), mul(p2, q0)), mul(W, mul(p3, q3)))
                let pq3 := add(add(add(mul(p0, q3), mul(p1, q2)), mul(p2, q1)), mul(p3, q0))

                // t = 2*pq + 1 - p - q  (lane 0 gets +1)
                // Use 2*M as bias to avoid underflow.
                // mod is intentionally omitted: t_i < 2^67 and the subsequent
                // schoolbook acc*t products (< 2^31 * 2^67 = 2^98) fit in
                // uint256.  The final mod on acc gives the correct result.
                let t0 := sub(add(add(pq0, pq0), add(0xfe000002, 1)), add(p0, q0))
                let t1 := sub(add(add(pq1, pq1), 0xfe000002), add(p1, q1))
                let t2 := sub(add(add(pq2, pq2), 0xfe000002), add(p2, q2))
                let t3 := sub(add(add(pq3, pq3), 0xfe000002), add(p3, q3))

                // acc = acc * t  (schoolbook ext4)
                let n0 :=
                    mod(
                        add(mul(a0, t0), mul(W, add(add(mul(a1, t3), mul(a2, t2)), mul(a3, t1)))),
                        M
                    )
                let n1 :=
                    mod(
                        add(add(mul(a0, t1), mul(a1, t0)), mul(W, add(mul(a2, t3), mul(a3, t2)))),
                        M
                    )
                let n2 :=
                    mod(
                        add(add(add(mul(a0, t2), mul(a1, t1)), mul(a2, t0)), mul(W, mul(a3, t3))),
                        M
                    )
                let n3 := mod(add(add(add(mul(a0, t3), mul(a1, t2)), mul(a2, t1)), mul(a3, t0)), M)
                a0 := n0
                a1 := n1
                a2 := n2
                a3 := n3
            }

            acc := or(or(shl(224, a0), shl(192, a1)), or(shl(160, a2), shl(128, a3)))
        }
    }

    function _selectPolyEvalAt12At4(uint256 var_, uint256[] memory fullPoint)
        internal
        pure
        returns (uint256 acc)
    {
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

                let n0 :=
                    mod(
                        add(mul(a0, t0), mul(W, add(add(mul(a1, t3), mul(a2, t2)), mul(a3, t1)))),
                        modulus
                    )
                let n1 :=
                    mod(
                        add(add(mul(a0, t1), mul(a1, t0)), mul(W, add(mul(a2, t3), mul(a3, t2)))),
                        modulus
                    )
                let n2 :=
                    mod(
                        add(add(add(mul(a0, t2), mul(a1, t1)), mul(a2, t0)), mul(W, mul(a3, t3))),
                        modulus
                    )
                let n3 :=
                    mod(add(add(add(mul(a0, t3), mul(a1, t2)), mul(a2, t1)), mul(a3, t0)), modulus)

                a0 := n0
                a1 := n1
                a2 := n2
                a3 := n3
                current := mulmod(current, current, modulus)
            }

            acc := or(or(shl(224, a0), shl(192, a1)), or(shl(160, a2), shl(128, a3)))
        }
    }

    function _selectPolyEvalAt8At8(uint256 var_, uint256[] memory fullPoint)
        internal
        pure
        returns (uint256 acc)
    {
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

                let n0 :=
                    mod(
                        add(mul(a0, t0), mul(W, add(add(mul(a1, t3), mul(a2, t2)), mul(a3, t1)))),
                        modulus
                    )
                let n1 :=
                    mod(
                        add(add(mul(a0, t1), mul(a1, t0)), mul(W, add(mul(a2, t3), mul(a3, t2)))),
                        modulus
                    )
                let n2 :=
                    mod(
                        add(add(add(mul(a0, t2), mul(a1, t1)), mul(a2, t0)), mul(W, mul(a3, t3))),
                        modulus
                    )
                let n3 :=
                    mod(add(add(add(mul(a0, t3), mul(a1, t2)), mul(a2, t1)), mul(a3, t0)), modulus)

                a0 := n0
                a1 := n1
                a2 := n2
                a3 := n3
                current := mulmod(current, current, modulus)
            }

            acc := or(or(shl(224, a0), shl(192, a1)), or(shl(160, a2), shl(128, a3)))
        }
    }

    function _selectPolyEvalAtTail(
        uint256 var_,
        uint256[] memory fullPoint,
        uint256 pointOffset,
        uint256 numVariables
    ) internal pure returns (uint256 acc) {
        acc = EXT4_ONE;
        uint256 current = var_;

        unchecked {
            for (uint256 i = numVariables; i > 0; --i) {
                uint256 pointValue = fullPoint[pointOffset + i - 1];
                uint256 scalar = current == 0 ? KoalaBear.MODULUS - 1 : current - 1;
                uint256 term = scalar == 0
                    ? EXT4_ONE
                    : KoalaBearExt4.add(
                        EXT4_ONE, KoalaBearExt4.mul(pointValue, KoalaBearExt4.fromBase(scalar))
                    );
                acc = KoalaBearExt4.mul(acc, term);
                current = mulmod(current, current, KoalaBear.MODULUS);
            }
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
                let pq0 := add(mul(p0, q0), mul(W, add(add(mul(p1, q3), mul(p2, q2)), mul(p3, q1))))
                let pq1 := add(add(mul(p0, q1), mul(p1, q0)), mul(W, add(mul(p2, q3), mul(p3, q2))))
                let pq2 := add(add(add(mul(p0, q2), mul(p1, q1)), mul(p2, q0)), mul(W, mul(p3, q3)))
                let pq3 := add(add(add(mul(p0, q3), mul(p1, q2)), mul(p2, q1)), mul(p3, q0))

                // t = 2*pq + 1 - p - q  (lane 0 gets +1)
                // Use 2*M as bias to avoid underflow.
                // mod is intentionally omitted (see _eqPolyEvalAt).
                let t0 := sub(add(add(pq0, pq0), add(0xfe000002, 1)), add(p0, q0))
                let t1 := sub(add(add(pq1, pq1), 0xfe000002), add(p1, q1))
                let t2 := sub(add(add(pq2, pq2), 0xfe000002), add(p2, q2))
                let t3 := sub(add(add(pq3, pq3), 0xfe000002), add(p3, q3))

                // acc = acc * t  (schoolbook ext4)
                let n0 :=
                    mod(
                        add(mul(a0, t0), mul(W, add(add(mul(a1, t3), mul(a2, t2)), mul(a3, t1)))),
                        M
                    )
                let n1 :=
                    mod(
                        add(add(mul(a0, t1), mul(a1, t0)), mul(W, add(mul(a2, t3), mul(a3, t2)))),
                        M
                    )
                let n2 :=
                    mod(
                        add(add(add(mul(a0, t2), mul(a1, t1)), mul(a2, t0)), mul(W, mul(a3, t3))),
                        M
                    )
                let n3 := mod(add(add(add(mul(a0, t3), mul(a1, t2)), mul(a2, t1)), mul(a3, t0)), M)
                a0 := n0
                a1 := n1
                a2 := n2
                a3 := n3
            }

            acc := or(or(shl(224, a0), shl(192, a1)), or(shl(160, a2), shl(128, a3)))
        }
    }

    function _eqPolyEvalAtMemory(
        uint256[] memory point,
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

            let pointBase := add(point, 0x20)
            let fullBase := add(add(fullPoint, 0x20), shl(5, pointOffset))

            for {
                let i := 0
            } lt(i, numVariables) {
                i := add(i, 1)
            } {
                let off := shl(5, i)
                let p := mload(add(pointBase, off))
                let q := mload(add(fullBase, off))

                let p0 := shr(224, p)
                let p1 := and(shr(192, p), m)
                let p2 := and(shr(160, p), m)
                let p3 := and(shr(128, p), m)

                let q0 := shr(224, q)
                let q1 := and(shr(192, q), m)
                let q2 := and(shr(160, q), m)
                let q3 := and(shr(128, q), m)

                let pq0 := add(mul(p0, q0), mul(W, add(add(mul(p1, q3), mul(p2, q2)), mul(p3, q1))))
                let pq1 := add(add(mul(p0, q1), mul(p1, q0)), mul(W, add(mul(p2, q3), mul(p3, q2))))
                let pq2 := add(add(add(mul(p0, q2), mul(p1, q1)), mul(p2, q0)), mul(W, mul(p3, q3)))
                let pq3 := add(add(add(mul(p0, q3), mul(p1, q2)), mul(p2, q1)), mul(p3, q0))

                let t0 := sub(add(add(pq0, pq0), add(0xfe000002, 1)), add(p0, q0))
                let t1 := sub(add(add(pq1, pq1), 0xfe000002), add(p1, q1))
                let t2 := sub(add(add(pq2, pq2), 0xfe000002), add(p2, q2))
                let t3 := sub(add(add(pq3, pq3), 0xfe000002), add(p3, q3))

                let n0 :=
                    mod(
                        add(mul(a0, t0), mul(W, add(add(mul(a1, t3), mul(a2, t2)), mul(a3, t1)))),
                        M
                    )
                let n1 :=
                    mod(
                        add(add(mul(a0, t1), mul(a1, t0)), mul(W, add(mul(a2, t3), mul(a3, t2)))),
                        M
                    )
                let n2 :=
                    mod(
                        add(add(add(mul(a0, t2), mul(a1, t1)), mul(a2, t0)), mul(W, mul(a3, t3))),
                        M
                    )
                let n3 := mod(add(add(add(mul(a0, t3), mul(a1, t2)), mul(a2, t1)), mul(a3, t0)), M)
                a0 := n0
                a1 := n1
                a2 := n2
                a3 := n3
            }

            acc := or(or(shl(224, a0), shl(192, a1)), or(shl(160, a2), shl(128, a3)))
        }
    }

    function _eqPolyEvalAtBlob(
        bytes calldata blob,
        uint256 blobOffset,
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

            let pointBase := add(blob.offset, blobOffset)
            let fullBase := add(add(fullPoint, 0x20), shl(5, pointOffset))

            for {
                let i := 0
            } lt(i, numVariables) {
                i := add(i, 1)
            } {
                let poff := shl(4, i)
                let foff := shl(5, i)
                let p := and(calldataload(add(pointBase, poff)), not(sub(shl(128, 1), 1)))
                let q := mload(add(fullBase, foff))

                let p0 := shr(224, p)
                let p1 := and(shr(192, p), m)
                let p2 := and(shr(160, p), m)
                let p3 := and(shr(128, p), m)

                let q0 := shr(224, q)
                let q1 := and(shr(192, q), m)
                let q2 := and(shr(160, q), m)
                let q3 := and(shr(128, q), m)

                let pq0 := add(mul(p0, q0), mul(W, add(add(mul(p1, q3), mul(p2, q2)), mul(p3, q1))))
                let pq1 := add(add(mul(p0, q1), mul(p1, q0)), mul(W, add(mul(p2, q3), mul(p3, q2))))
                let pq2 := add(add(add(mul(p0, q2), mul(p1, q1)), mul(p2, q0)), mul(W, mul(p3, q3)))
                let pq3 := add(add(add(mul(p0, q3), mul(p1, q2)), mul(p2, q1)), mul(p3, q0))

                let t0 := sub(add(add(pq0, pq0), add(0xfe000002, 1)), add(p0, q0))
                let t1 := sub(add(add(pq1, pq1), 0xfe000002), add(p1, q1))
                let t2 := sub(add(add(pq2, pq2), 0xfe000002), add(p2, q2))
                let t3 := sub(add(add(pq3, pq3), 0xfe000002), add(p3, q3))

                let n0 :=
                    mod(
                        add(mul(a0, t0), mul(W, add(add(mul(a1, t3), mul(a2, t2)), mul(a3, t1)))),
                        M
                    )
                let n1 :=
                    mod(
                        add(add(mul(a0, t1), mul(a1, t0)), mul(W, add(mul(a2, t3), mul(a3, t2)))),
                        M
                    )
                let n2 :=
                    mod(
                        add(add(add(mul(a0, t2), mul(a1, t1)), mul(a2, t0)), mul(W, mul(a3, t3))),
                        M
                    )
                let n3 := mod(add(add(add(mul(a0, t3), mul(a1, t2)), mul(a2, t1)), mul(a3, t0)), M)
                a0 := n0
                a1 := n1
                a2 := n2
                a3 := n3
            }

            acc := or(or(shl(224, a0), shl(192, a1)), or(shl(160, a2), shl(128, a3)))
        }
    }

    function _evaluateFinalValue(
        uint256[] calldata finalPoly,
        uint256[] memory finalSumcheckRandomness
    ) internal pure returns (uint256) {
        if (finalSumcheckRandomness.length == 0) {
            return finalPoly[0];
        }
        return WhirVerifierUtils4.evaluateExtensionRowAsExt4(
            finalPoly, 0, finalPoly.length, finalSumcheckRandomness
        );
    }

    function _evaluateFinalValueMemory(
        uint256[] memory finalPoly,
        uint256[] memory finalSumcheckRandomness
    ) internal pure returns (uint256) {
        if (finalSumcheckRandomness.length == 0) {
            return finalPoly[0];
        }
        return KoalaBearExt4.evaluate_hypercube(finalPoly, finalSumcheckRandomness);
    }

    function _hornerStep(uint256 total, uint256 challenge, uint256 weight)
        internal
        pure
        returns (uint256 updated)
    {
        assembly ("memory-safe") {
            let M := 0x7f000001
            let m := 0xffffffff
            let W := 3

            let ch0 := shr(224, challenge)
            let ch1 := and(shr(192, challenge), m)
            let ch2 := and(shr(160, challenge), m)
            let ch3 := and(shr(128, challenge), m)

            let a0 := shr(224, total)
            let a1 := and(shr(192, total), m)
            let a2 := and(shr(160, total), m)
            let a3 := and(shr(128, total), m)

            let w0 := shr(224, weight)
            let w1 := and(shr(192, weight), m)
            let w2 := and(shr(160, weight), m)
            let w3 := and(shr(128, weight), m)

            let r0 :=
                mod(
                    add(
                        add(
                            mul(a0, ch0),
                            mul(W, add(add(mul(a1, ch3), mul(a2, ch2)), mul(a3, ch1)))
                        ),
                        w0
                    ),
                    M
                )
            let r1 :=
                mod(
                    add(
                        add(
                            add(mul(a0, ch1), mul(a1, ch0)),
                            mul(W, add(mul(a2, ch3), mul(a3, ch2)))
                        ),
                        w1
                    ),
                    M
                )
            let r2 :=
                mod(
                    add(
                        add(
                            add(add(mul(a0, ch2), mul(a1, ch1)), mul(a2, ch0)),
                            mul(W, mul(a3, ch3))
                        ),
                        w2
                    ),
                    M
                )
            let r3 :=
                mod(
                    add(add(add(add(mul(a0, ch3), mul(a1, ch2)), mul(a2, ch1)), mul(a3, ch0)), w3),
                    M
                )

            updated := or(or(shl(224, r0), shl(192, r1)), or(shl(160, r2), shl(128, r3)))
        }
    }
}
