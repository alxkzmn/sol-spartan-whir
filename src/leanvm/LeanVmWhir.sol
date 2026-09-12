// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import { KoalaBearExt5 as EF } from "../field/KoalaBearExt5.sol";
import { KoalaBearPackedField as Packed } from "../field/KoalaBearPackedField.sol";
import { LeanVmTranscript as Transcript } from "./LeanVmTranscript.sol";
import { LeanVmPolynomial as Poly } from "./LeanVmPolynomial.sol";
import { LeanVmWhirArithmetic as Arithmetic } from "./LeanVmWhirArithmetic.sol";
import { LeanVmWhirWeight as Weight } from "./LeanVmWhirWeight.sol";
import { LeanVmWhirFolding as Folding } from "./LeanVmWhirFolding.sol";
import { LeanVmMerkle as Merkle } from "./LeanVmMerkle.sol";

/// @dev Configuration is supplied by the application-selected verifier, never by the proof.
library LeanVmWhir {
    using Transcript for Transcript.State;
    uint256 internal constant ONE = uint256(1) << 224;
    uint256 internal constant MODULUS = 2_130_706_433;

    struct Round {
        uint256 variables;
        uint256 fold;
        uint256 domainSize;
        uint256 generator;
        uint256 queries;
        uint256 ood;
        uint256 queryPow;
        uint256 foldingPow;
    }

    struct Config {
        uint256 variables;
        uint256 firstFold;
        uint256 nextFold;
        uint256 commitmentOod;
        uint256 firstPow;
        uint256 finalRounds;
        Round[] rounds;
        Round finalRound;
        uint256 openingsCodec;
    }

    struct Statement {
        uint256 variables;
        uint256[] point;
        uint256[] selectors;
        uint256[] values;
        bool isNext;
    }

    struct Commitment {
        uint256 variables;
        bytes32 root;
        Statement[] ood;
    }

    struct Constraints {
        uint256 gamma;
        Statement[] statements;
        uint256[] basePoints;
    }

    struct VerificationState {
        Commitment commitment;
        Constraints[] constraints;
        uint256[][] folding;
        uint256 target;
    }

    struct TwoCommitmentInitial {
        uint256 target;
        uint256 polynomialRandomness;
        uint256 gamma;
        uint256 theta;
        Statement[] oodStatements;
    }

    struct CommonCache {
        uint256[] referencePoint;
        uint256[] suffixProducts;
    }

    struct Queries {
        uint256[] points;
        uint256[] values;
    }

    struct Cursor {
        uint256 offset;
        uint256 codec;
    }

    function dense(uint256 variables, uint256[] memory point, uint256 value)
        internal
        pure
        returns (Statement memory statement)
    {
        statement.variables = variables;
        statement.point = point;
        statement.selectors = new uint256[](1);
        statement.values = new uint256[](1);
        statement.values[0] = value;
    }

    function parse(
        Transcript.State memory state,
        bytes calldata transcript,
        uint256 variables,
        uint256 oodCount
    ) internal pure returns (Commitment memory commitment) {
        commitment.variables = variables;
        commitment.root = Transcript.digest(state.readBase(transcript, 8));
        uint256[] memory points = state.sampleMany(oodCount);
        uint256[] memory answers = state.readExtension(transcript, oodCount);
        commitment.ood = new Statement[](oodCount);
        for (uint256 i; i < oodCount; ++i) {
            commitment.ood[i] = dense(variables, Poly.expand(points[i], variables), answers[i]);
        }
    }

    /// @dev Parses and observes a commitment root without sampling or reading
    /// an individual OOD answer. Both C1 roots must be parsed before gamma.
    function parseRoot(Transcript.State memory state, bytes calldata transcript, uint256 variables)
        internal
        pure
        returns (Commitment memory commitment)
    {
        commitment.variables = variables;
        commitment.root = Transcript.digest(state.readBase(transcript, 8));
        commitment.ood = new Statement[](0);
    }

    function join(Statement[] memory a, Statement[] memory b)
        internal
        pure
        returns (Statement[] memory out)
    {
        out = new Statement[](a.length + b.length);
        for (uint256 i; i < a.length; ++i) {
            out[i] = a[i];
        }
        for (uint256 i; i < b.length; ++i) {
            out[a.length + i] = b[i];
        }
    }

    function combine(
        Transcript.State memory state,
        Statement[] memory statements,
        uint256 target,
        uint256[] memory queryValues
    ) internal pure returns (Constraints memory constraints, uint256 out) {
        state.duplex();
        uint256 gamma = state.sample();
        for (uint256 i = queryValues.length; i != 0; --i) {
            out = EF.add(Packed.mul(out, gamma), queryValues[i - 1]);
        }
        for (uint256 i = statements.length; i != 0; --i) {
            Statement memory statement = statements[i - 1];
            require(statement.selectors.length == statement.values.length, "STATEMENT_LENGTH");
            for (uint256 j = statement.values.length; j != 0; --j) {
                out = EF.add(Packed.mul(out, gamma), statement.values[j - 1]);
            }
        }
        out = EF.add(target, out);
        constraints = Constraints(gamma, statements, new uint256[](0));
    }

    function powBase(uint256 value, uint256 exponent) internal pure returns (uint256 result) {
        result = 1;
        while (exponent != 0) {
            if (exponent & 1 != 0) result = mulmod(result, value, MODULUS);
            value = mulmod(value, value, MODULUS);
            exponent >>= 1;
        }
    }

    function stir(
        Transcript.State memory state,
        bytes calldata transcript,
        bytes calldata openings,
        Cursor memory cursor,
        Round memory params,
        Commitment memory commitment,
        uint256[] memory foldPoint,
        bool baseLeaf
    ) internal pure returns (Queries memory queries) {
        require(
            params.fold == foldPoint.length
                && params.variables + params.fold == commitment.variables,
            "ROUND_DIM"
        );
        uint256 width = uint256(1) << params.fold;
        uint256 height = Poly.log2(params.domainSize / width);
        state.checkPow(transcript, params.queryPow);
        uint256[] memory indices = new uint256[](params.queries);
        for (uint256 i; i < indices.length; ++i) {
            indices[i] = state.sampleIndex(height);
        }
        queries.points = new uint256[](params.queries);
        queries.values = new uint256[](params.queries);
        uint256 weightsPtr;
        if (params.fold == 4) weightsPtr = Folding.prepare16(foldPoint, baseLeaf);
        else if (params.fold == 5) weightsPtr = Folding.prepare32(foldPoint, baseLeaf);
        if (cursor.codec == 1) {
            uint256[] memory leafOffsets;
            (leafOffsets, cursor.offset) = Merkle.openBatch(
                openings,
                cursor.offset,
                width * (baseLeaf ? 1 : 5),
                height,
                indices,
                commitment.root
            );
            for (uint256 i; i < indices.length; ++i) {
                queries.points[i] = powBase(params.generator, indices[i]);
                queries.values[i] =
                    foldLeaf(openings, leafOffsets[i], width, foldPoint, baseLeaf, weightsPtr);
            }
        } else {
            for (uint256 i; i < indices.length; ++i) {
                uint256 value = foldOpening(
                    openings,
                    cursor,
                    width,
                    height,
                    indices[i],
                    commitment.root,
                    foldPoint,
                    baseLeaf,
                    weightsPtr
                );
                queries.points[i] = powBase(params.generator, indices[i]);
                queries.values[i] = value;
            }
        }
    }

    /// @dev A fixed batch-codec argument lets the C1 verifier omit the full-path
    /// decoder. Query sampling, authentication, and folding keep their order.
    function stirWithCodec(
        Transcript.State memory state,
        bytes calldata transcript,
        bytes calldata openings,
        Cursor memory cursor,
        Round memory params,
        Commitment memory commitment,
        uint256[] memory foldPoint,
        bool baseLeaf,
        bool batchCodec
    ) private pure returns (Queries memory queries) {
        require(
            params.fold == foldPoint.length
                && params.variables + params.fold == commitment.variables,
            "ROUND_DIM"
        );
        uint256 width = uint256(1) << params.fold;
        uint256 height = Poly.log2(params.domainSize / width);
        state.checkPow(transcript, params.queryPow);
        uint256[] memory indices = new uint256[](params.queries);
        for (uint256 i; i < indices.length; ++i) {
            indices[i] = state.sampleIndex(height);
        }
        queries.points = new uint256[](params.queries);
        queries.values = new uint256[](params.queries);
        uint256 weightsPtr;
        if (params.fold == 4) weightsPtr = Folding.prepare16(foldPoint, baseLeaf);
        else if (params.fold == 5) weightsPtr = Folding.prepare32(foldPoint, baseLeaf);
        if (batchCodec) {
            uint256[] memory leafOffsets;
            (leafOffsets, cursor.offset) = Merkle.openBatch(
                openings,
                cursor.offset,
                width * (baseLeaf ? 1 : 5),
                height,
                indices,
                commitment.root
            );
            for (uint256 i; i < indices.length; ++i) {
                queries.points[i] = powBase(params.generator, indices[i]);
                queries.values[i] =
                    foldLeaf(openings, leafOffsets[i], width, foldPoint, baseLeaf, weightsPtr);
            }
        } else {
            for (uint256 i; i < indices.length; ++i) {
                uint256 value = foldOpening(
                    openings,
                    cursor,
                    width,
                    height,
                    indices[i],
                    commitment.root,
                    foldPoint,
                    baseLeaf,
                    weightsPtr
                );
                queries.points[i] = powBase(params.generator, indices[i]);
                queries.values[i] = value;
            }
        }
    }

    /// @dev The first C1 STIR query set authenticates two base-field trees.
    /// Openings are encoded as the complete primary batch followed by the
    /// complete secondary batch.
    function stirTwoCommitments(
        Transcript.State memory state,
        bytes calldata transcript,
        bytes calldata openings,
        Cursor memory cursor,
        Round memory params,
        Commitment memory primaryCommitment,
        Commitment memory secondaryCommitment,
        uint256[] memory foldPoint,
        uint256 polynomialRandomness
    ) internal pure returns (Queries memory queries) {
        require(cursor.codec == 1, "OPENINGS_CODEC");
        require(
            params.fold == foldPoint.length
                && params.variables + params.fold == primaryCommitment.variables
                && secondaryCommitment.variables == primaryCommitment.variables,
            "ROUND_DIM"
        );
        uint256 width = uint256(1) << params.fold;
        uint256 height = Poly.log2(params.domainSize / width);
        state.checkPow(transcript, params.queryPow);
        uint256[] memory indices = new uint256[](params.queries);
        for (uint256 i; i < indices.length; ++i) {
            indices[i] = state.sampleIndex(height);
        }
        uint256 weightsPtr;
        if (params.fold == 4) {
            weightsPtr = Folding.prepare16(foldPoint, true);
        } else if (params.fold == 5) {
            weightsPtr = Folding.prepare32(foldPoint, true);
        }
        uint256 primaryOffset = cursor.offset;
        uint256[] memory rowNumbers;
        uint256 secondaryOffset;
        (rowNumbers, secondaryOffset, cursor.offset) = Merkle.openTwoBatches(
            openings,
            cursor.offset,
            width,
            height,
            indices,
            primaryCommitment.root,
            secondaryCommitment.root
        );
        queries.points = new uint256[](params.queries);
        queries.values = new uint256[](params.queries);
        for (uint256 i; i < indices.length; ++i) {
            uint256 rowOffset = rowNumbers[i] * width * 4;
            uint256 primary =
                foldLeaf(openings, primaryOffset + rowOffset, width, foldPoint, true, weightsPtr);
            uint256 secondary =
                foldLeaf(openings, secondaryOffset + rowOffset, width, foldPoint, true, weightsPtr);
            queries.points[i] = powBase(params.generator, indices[i]);
            queries.values[i] = EF.add(primary, Packed.mul(polynomialRandomness, secondary));
        }
    }

    /// @dev The Merkle decoder has authenticated and range-checked the entire row.
    function foldLeaf(
        bytes calldata openings,
        uint256 offset,
        uint256 width,
        uint256[] memory foldPoint,
        bool baseLeaf,
        uint256 weightsPtr
    ) private pure returns (uint256 value) {
        if (width == 16) {
            return Folding.fold16(openings, offset, weightsPtr, baseLeaf);
        }
        if (width == 32) {
            return Folding.fold32(openings, offset, weightsPtr, baseLeaf, foldPoint[0]);
        }
        uint256 scratch;
        assembly ("memory-safe") { scratch := mload(0x40) }
        uint256[] memory values = new uint256[](width);
        if (baseLeaf) {
            for (uint256 j; j < width; ++j) {
                uint256 scalar;
                assembly ("memory-safe") {
                    scalar := shr(224, calldataload(add(add(openings.offset, offset), mul(j, 4))))
                }
                values[j] = EF.fromBase(scalar);
            }
        } else {
            for (uint256 j; j < width; ++j) {
                uint256 packed;
                assembly ("memory-safe") {
                    packed := and(
                        calldataload(add(add(openings.offset, offset), mul(j, 20))),
                        not(sub(shl(96, 1), 1))
                    )
                }
                values[j] = packed;
            }
        }
        value = EF.evaluate_hypercube(values, foldPoint);
        assembly ("memory-safe") { mstore(0x40, scratch) }
    }

    function foldOpening(
        bytes calldata openings,
        Cursor memory cursor,
        uint256 width,
        uint256 height,
        uint256 index,
        bytes32 root,
        uint256[] memory foldPoint,
        bool baseLeaf,
        uint256 weightsPtr
    ) private pure returns (uint256 value) {
        uint256 scratch;
        assembly ("memory-safe") { scratch := mload(0x40) }
        uint256 leafOffset = cursor.offset;
        (, cursor.offset) =
            Merkle.open(openings, cursor.offset, width * (baseLeaf ? 1 : 5), height, index, root);
        value = foldLeaf(openings, leafOffset, width, foldPoint, baseLeaf, weightsPtr);
        // Merkle buffers and any generic folding array are temporary. Prepared
        // weights and the cursor predate scratch; only the scalar result escapes.
        assembly ("memory-safe") { mstore(0x40, scratch) }
    }

    function weight(Statement memory statement, uint256[] memory point)
        internal
        pure
        returns (uint256[] memory weights)
    {
        require(statement.point.length <= point.length, "WEIGHT_DIM");
        uint256 depth = statement.values.length > 1 ? point.length - statement.point.length : 0;
        if (depth > 10) depth = 10;
        return weightWithCache(statement, point, Weight.initialize(depth));
    }

    function weightCache(Statement[] memory statements, uint256[] memory point)
        internal
        pure
        returns (Weight.Cache memory cache)
    {
        uint256 depth;
        for (uint256 i; i < statements.length; ++i) {
            Statement memory statement = statements[i];
            require(
                statement.variables == point.length && statement.point.length <= point.length,
                "WEIGHT_DIM"
            );
            if (statement.values.length > 1) {
                uint256 candidate = point.length - statement.point.length;
                if (candidate > depth) depth = candidate;
            }
        }
        if (depth > 10) depth = 10;
        cache = Weight.initialize(depth);
    }

    function weightWithCache(
        Statement memory statement,
        uint256[] memory point,
        Weight.Cache memory cache
    ) internal pure returns (uint256[] memory weights) {
        require(
            statement.variables == point.length && statement.point.length <= point.length,
            "WEIGHT_DIM"
        );
        require(statement.selectors.length == statement.values.length, "STATEMENT_LENGTH");
        uint256[] memory suffix =
            Poly.slice(point, point.length - statement.point.length, statement.point.length);
        uint256 common = statement.isNext
            ? Poly.next(statement.point, suffix)
            : EF.eq_poly_eval(statement.point, suffix);
        weights = new uint256[](statement.values.length);
        for (uint256 i; i < weights.length; ++i) {
            weights[i] = EF.mul(
                common,
                Weight.selector(
                    cache, point, statement.selectors[i], point.length - statement.point.length
                )
            );
        }
    }

    function validInitialStatements(Statement[] memory statements, uint256 variables)
        private
        pure
        returns (bool)
    {
        if (statements.length == 0) {
            return false;
        }
        for (uint256 i; i < statements.length; ++i) {
            Statement memory statement = statements[i];
            if (
                statement.variables != variables || statement.point.length > variables
                    || statement.values.length == 0
                    || statement.selectors.length != statement.values.length
            ) {
                return false;
            }
            uint256 selectorVariables = variables - statement.point.length;
            if (selectorVariables >= 256) {
                return false;
            }
            uint256 selectorLimit = uint256(1) << selectorVariables;
            for (uint256 j; j < statement.selectors.length; ++j) {
                if (statement.selectors[j] >= selectorLimit) {
                    return false;
                }
            }
        }
        return true;
    }

    /// @dev Reverse Horner over every statement value: the i-th value of the
    /// group, in forward order, receives the coefficient gamma^i.
    function statementValuesGammaSum(Statement[] memory statements, uint256 gamma)
        private
        pure
        returns (uint256 sum)
    {
        for (uint256 i = statements.length; i != 0; --i) {
            uint256[] memory values = statements[i - 1].values;
            for (uint256 j = values.length; j != 0; --j) {
                sum = EF.add(Packed.mul(sum, gamma), values[j - 1]);
            }
        }
    }

    function initializeTwoCommitments(
        Transcript.State memory state,
        bytes calldata transcript,
        uint256 variables,
        uint256 oodCount,
        uint256 batchingPowBits,
        Statement[] memory primaryStatements,
        Statement[] memory secondaryStatements
    ) internal pure returns (TwoCommitmentInitial memory initial) {
        state.duplex();
        initial.gamma = state.sample();
        uint256 primarySum = statementValuesGammaSum(primaryStatements, initial.gamma);
        uint256 secondarySum = statementValuesGammaSum(secondaryStatements, initial.gamma);

        uint256[] memory crossValues = state.readExtension(transcript, 2);
        state.checkPow(transcript, batchingPowBits);
        state.duplex();
        initial.polynomialRandomness = state.sample();

        state.duplex();
        uint256[] memory oodPoints = state.sampleMany(oodCount);
        uint256[] memory oodAnswers = state.readExtension(transcript, oodCount);
        initial.oodStatements = new Statement[](oodCount);
        for (uint256 i; i < oodCount; ++i) {
            initial.oodStatements[i] =
                dense(variables, Poly.expand(oodPoints[i], variables), oodAnswers[i]);
        }

        state.duplex();
        initial.theta = state.sample();
        uint256 thetaPower = ONE;
        for (uint256 i; i < oodCount; ++i) {
            initial.target = EF.add(initial.target, Packed.mul(thetaPower, oodAnswers[i]));
            thetaPower = Packed.mul(thetaPower, initial.theta);
        }
        initial.target = EF.add(
            initial.target,
            Packed.mul(
                thetaPower,
                EF.add(primarySum, Packed.mul(initial.polynomialRandomness, crossValues[0]))
            )
        );
        thetaPower = Packed.mul(thetaPower, initial.theta);
        initial.target = EF.add(
            initial.target,
            Packed.mul(
                thetaPower,
                EF.add(crossValues[1], Packed.mul(initial.polynomialRandomness, secondarySum))
            )
        );
    }

    function evaluateConstraintWeights(Constraints memory constraints, uint256[] memory point)
        private
        pure
        returns (uint256 contribution)
    {
        if (constraints.basePoints.length != 0) {
            uint256[] memory cache = Arithmetic.prepareBaseEq(point, 0, point.length);
            for (uint256 j = constraints.basePoints.length; j != 0; --j) {
                uint256 w =
                    Arithmetic.evaluateBaseEq(cache, point.length, constraints.basePoints[j - 1]);
                contribution = EF.add(Packed.mul(contribution, constraints.gamma), w);
            }
        }
        Weight.Cache memory selectorCache = weightCache(constraints.statements, point);
        for (uint256 j = constraints.statements.length; j != 0; --j) {
            uint256[] memory weights =
                weightWithCache(constraints.statements[j - 1], point, selectorCache);
            for (uint256 k = weights.length; k != 0; --k) {
                contribution = EF.add(Packed.mul(contribution, constraints.gamma), weights[k - 1]);
            }
        }
    }

    /// @dev C1 continuation rounds contain only dense OOD claims and base-field queries.
    function evaluateContinuationWeights(Constraints memory constraints, uint256[] memory point)
        private
        pure
        returns (uint256 contribution)
    {
        if (constraints.basePoints.length != 0) {
            uint256[] memory cache = Arithmetic.prepareBaseEq(point, 0, point.length);
            for (uint256 j = constraints.basePoints.length; j != 0; --j) {
                uint256 w =
                    Arithmetic.evaluateBaseEq(cache, point.length, constraints.basePoints[j - 1]);
                contribution = EF.add(Packed.mul(contribution, constraints.gamma), w);
            }
        }
        // Every statement comes from parse(), which constructs one dense OOD claim.
        for (uint256 j = constraints.statements.length; j != 0; --j) {
            require(constraints.statements[j - 1].variables == point.length, "WEIGHT_DIM");
            uint256 w = statementCommon(constraints.statements[j - 1], point);
            contribution = EF.add(Packed.mul(contribution, constraints.gamma), w);
        }
    }

    /// @dev Shared statement factor eq(statement.point, point suffix) without slicing.
    /// The caller has checked the statement dimensions against the point.
    function statementCommon(Statement memory statement, uint256[] memory point)
        private
        pure
        returns (uint256 common)
    {
        uint256 offset = point.length - statement.point.length;
        if (statement.isNext) {
            return Poly.next(statement.point, Poly.slice(point, offset, statement.point.length));
        }
        if (statement.point.length == 0) return ONE;
        common = Packed.eq(statement.point[0], point[offset]);
        for (uint256 k = 1; k < statement.point.length; ++k) {
            common = Packed.mul(common, Packed.eq(statement.point[k], point[offset + k]));
        }
    }

    /// @dev Cache suffix equality products for the longest ordinary statement point.
    function prepareCommonCache(Statement[] memory statements, uint256[] memory point)
        private
        pure
        returns (CommonCache memory cache)
    {
        for (uint256 i; i < statements.length; ++i) {
            Statement memory statement = statements[i];
            if (!statement.isNext && statement.point.length > cache.referencePoint.length) {
                cache.referencePoint = statement.point;
            }
        }
        uint256 length = cache.referencePoint.length;
        cache.suffixProducts = new uint256[](length + 1);
        cache.suffixProducts[0] = ONE;
        if (length != 0) {
            cache.suffixProducts[1] =
                Packed.eq(cache.referencePoint[length - 1], point[point.length - 1]);
        }
        for (uint256 i = 2; i <= length; ++i) {
            cache.suffixProducts[i] = Packed.mul(
                cache.suffixProducts[i - 1],
                Packed.eq(cache.referencePoint[length - i], point[point.length - i])
            );
        }
    }

    function commonWithCache(
        Statement memory statement,
        uint256[] memory point,
        CommonCache memory cache
    ) private pure returns (uint256) {
        uint256[] memory referencePoint = cache.referencePoint;
        uint256[] memory candidate = statement.point;
        if (statement.isNext || candidate.length > referencePoint.length) {
            return statementCommon(statement, point);
        }
        bool same = true;
        assembly ("memory-safe") {
            let length := mload(candidate)
            let source := add(candidate, 32)
            let reference :=
                add(add(referencePoint, 32), shl(5, sub(mload(referencePoint), length)))
            // Lengths bound both array reads; compare every canonical word exactly.
            for { let i := 0 } lt(i, length) { i := add(i, 1) } {
                if iszero(eq(mload(add(source, shl(5, i))), mload(add(reference, shl(5, i))))) {
                    same := false
                    break
                }
            }
        }
        if (same) return cache.suffixProducts[candidate.length];
        return statementCommon(statement, point);
    }

    /// @dev Group weight with the i-th value of the group, in forward order,
    /// weighted by gamma^i, matching statementValuesGammaSum. The shared eq
    /// factor of each statement multiplies its selector Horner sum once.
    function evaluateGammaStatementWeights(
        Statement[] memory statements,
        uint256 gamma,
        uint256[] memory point
    ) internal pure returns (uint256 contribution) {
        Weight.Cache memory selectorCache = weightCache(statements, point);
        CommonCache memory commonCache = prepareCommonCache(statements, point);
        uint256[8] memory gammaSquares;
        gammaSquares[0] = gamma;
        for (uint256 k = 1; k < 8; ++k) {
            gammaSquares[k] = Packed.mul(gammaSquares[k - 1], gammaSquares[k - 1]);
        }
        uint256 runningGamma = ONE;
        for (uint256 i; i < statements.length; ++i) {
            Statement memory statement = statements[i];
            require(statement.selectors.length == statement.values.length, "STATEMENT_LENGTH");
            uint256 count = statement.selectors.length;
            require(count < 256, "STATEMENT_LENGTH");
            uint256 depth = point.length - statement.point.length;
            uint256 inner;
            bool consecutive = count >= 16;
            for (uint256 j = 1; consecutive && j < count; ++j) {
                consecutive = statement.selectors[j] == statement.selectors[0] + j;
            }
            if (consecutive) {
                inner = Weight.rangeSum(
                    selectorCache, point, statement.selectors[0], count, depth, gammaSquares
                );
            } else {
                for (uint256 j = count; j != 0; --j) {
                    inner = EF.add(
                        Packed.mul(inner, gamma),
                        Weight.selector(selectorCache, point, statement.selectors[j - 1], depth)
                    );
                }
            }
            contribution = EF.add(
                contribution,
                Packed.mul(
                    runningGamma, Packed.mul(inner, commonWithCache(statement, point, commonCache))
                )
            );
            for (uint256 k; count != 0; ++k) {
                if (count & 1 != 0) runningGamma = Packed.mul(runningGamma, gammaSquares[k]);
                count >>= 1;
            }
        }
    }

    /// @dev Complete a round after its openings have been consumed. Keeping the
    /// opening cursor and calldata out of this phase limits live compiler state.
    function finishRound(
        Transcript.State memory state,
        bytes calldata transcript,
        Config memory config,
        VerificationState memory proofState,
        uint256 index,
        Commitment memory nextCommitment,
        Queries memory queried
    ) private pure {
        (proofState.constraints[index + 1], proofState.target) =
            combine(state, nextCommitment.ood, proofState.target, queried.values);
        proofState.constraints[index + 1].basePoints = queried.points;
        (proofState.folding[index + 1], proofState.target) = Poly.sumcheck(
            state,
            transcript,
            proofState.target,
            config.nextFold,
            2,
            config.rounds[index].foldingPow
        );
        proofState.commitment = nextCommitment;
    }

    function verify(
        Transcript.State memory state,
        bytes calldata transcript,
        bytes calldata openings,
        Cursor memory cursor,
        Config memory config,
        Commitment memory commitment,
        Statement[] memory statements
    ) internal pure {
        require(config.openingsCodec <= 1, "OPENINGS_CODEC");
        cursor.codec = config.openingsCodec;
        VerificationState memory proofState;
        proofState.commitment = commitment;
        proofState.constraints = new Constraints[](config.rounds.length + 1);
        proofState.folding = new uint256[][](config.rounds.length + 2);
        (proofState.constraints[0], proofState.target) =
            combine(state, join(proofState.commitment.ood, statements), 0, new uint256[](0));
        (proofState.folding[0], proofState.target) = Poly.sumcheck(
            state, transcript, proofState.target, config.firstFold, 2, config.firstPow
        );
        for (uint256 i; i < config.rounds.length; ++i) {
            Round memory params = config.rounds[i];
            Commitment memory nextCommitment =
                parse(state, transcript, params.variables, params.ood);
            Queries memory queried = stir(
                state,
                transcript,
                openings,
                cursor,
                params,
                proofState.commitment,
                proofState.folding[i],
                i == 0
            );
            finishRound(state, transcript, config, proofState, i, nextCommitment, queried);
        }
        uint256[] memory coefficients =
            state.readExtension(transcript, uint256(1) << config.finalRounds);
        Queries memory finalQueries = stir(
            state,
            transcript,
            openings,
            cursor,
            config.finalRound,
            proofState.commitment,
            proofState.folding[config.rounds.length],
            config.rounds.length == 0
        );
        for (uint256 i; i < finalQueries.points.length; ++i) {
            uint256 answer = Poly.hornerBase(coefficients, finalQueries.points[i]);
            require(answer == finalQueries.values[i], "FINAL_STIR");
        }
        (proofState.folding[proofState.folding.length - 1], proofState.target) =
            Poly.sumcheck(state, transcript, proofState.target, config.finalRounds, 2, 0);
        uint256[] memory allPoint = new uint256[](config.variables);
        uint256 written;
        for (uint256 i; i < proofState.folding.length; ++i) {
            for (uint256 j; j < proofState.folding[i].length; ++j) {
                allPoint[written++] = proofState.folding[i][j];
            }
        }
        require(written == config.variables, "FOLDING_DIM");
        uint256 evaluatedWeights;
        uint256 skipped;
        for (uint256 i; i < proofState.constraints.length; ++i) {
            uint256[] memory point = Poly.slice(allPoint, skipped, allPoint.length - skipped);
            evaluatedWeights = EF.add(
                evaluatedWeights, evaluateConstraintWeights(proofState.constraints[i], point)
            );
            skipped += proofState.folding[i].length;
        }
        uint256 finalValue = Poly.coefficients(
            coefficients, Poly.reverse(proofState.folding[proofState.folding.length - 1])
        );
        require(proofState.target == EF.mul(evaluatedWeights, finalValue), "WHIR_FINAL");
    }

    /// @dev Verifies C1's shared WHIR continuation for two separately committed
    /// base-field polynomials. The caller must bind the proof mode, statement
    /// layouts, and batchingPowBits before parsing both roots.
    function verifyTwoCommitments(
        Transcript.State memory state,
        bytes calldata transcript,
        bytes calldata openings,
        Cursor memory cursor,
        Config memory config,
        uint256 batchingPowBits,
        Commitment memory primaryCommitment,
        Statement[] memory primaryStatements,
        Commitment memory secondaryCommitment,
        Statement[] memory secondaryStatements
    ) internal pure {
        require(config.openingsCodec == 1, "OPENINGS_CODEC");
        require(
            config.rounds.length != 0 && config.commitmentOod != 0
                && primaryCommitment.variables == config.variables
                && secondaryCommitment.variables == config.variables
                && primaryCommitment.ood.length == 0 && secondaryCommitment.ood.length == 0,
            "TWO_COMMITMENT_CONFIG"
        );
        require(
            validInitialStatements(primaryStatements, config.variables)
                && validInitialStatements(secondaryStatements, config.variables),
            "INITIAL_STATEMENT"
        );
        cursor.codec = 1;
        TwoCommitmentInitial memory initial = initializeTwoCommitments(
            state,
            transcript,
            config.variables,
            config.commitmentOod,
            batchingPowBits,
            primaryStatements,
            secondaryStatements
        );

        Constraints[] memory constraints = new Constraints[](config.rounds.length);
        uint256[][] memory folding = new uint256[][](config.rounds.length + 2);
        uint256 target = initial.target;
        (folding[0], target) =
            Poly.sumcheck(state, transcript, target, config.firstFold, 2, config.firstPow);

        Commitment memory commitment;
        for (uint256 i; i < config.rounds.length; ++i) {
            Round memory params = config.rounds[i];
            Commitment memory nextCommitment =
                parse(state, transcript, params.variables, params.ood);
            Queries memory queried;
            if (i == 0) {
                queried = stirTwoCommitments(
                    state,
                    transcript,
                    openings,
                    cursor,
                    params,
                    primaryCommitment,
                    secondaryCommitment,
                    folding[0],
                    initial.polynomialRandomness
                );
            } else {
                queried = stirWithCodec(
                    state, transcript, openings, cursor, params, commitment, folding[i], false, true
                );
            }
            (constraints[i], target) = combine(state, nextCommitment.ood, target, queried.values);
            constraints[i].basePoints = queried.points;
            (folding[i + 1], target) =
                Poly.sumcheck(state, transcript, target, config.nextFold, 2, params.foldingPow);
            commitment = nextCommitment;
        }

        uint256[] memory coefficients =
            state.readExtension(transcript, uint256(1) << config.finalRounds);
        Queries memory finalQueries = stirWithCodec(
            state,
            transcript,
            openings,
            cursor,
            config.finalRound,
            commitment,
            folding[config.rounds.length],
            false,
            true
        );
        for (uint256 i; i < finalQueries.points.length; ++i) {
            uint256 answer = Poly.hornerBase(coefficients, finalQueries.points[i]);
            require(answer == finalQueries.values[i], "FINAL_STIR");
        }
        (folding[folding.length - 1], target) =
            Poly.sumcheck(state, transcript, target, config.finalRounds, 2, 0);

        uint256[] memory allPoint = new uint256[](config.variables);
        uint256 written;
        for (uint256 i; i < folding.length; ++i) {
            for (uint256 j; j < folding[i].length; ++j) {
                allPoint[written++] = folding[i][j];
            }
        }
        require(written == config.variables, "FOLDING_DIM");

        uint256 evaluatedWeights;
        {
            uint256 thetaPower = ONE;
            for (uint256 i; i < initial.oodStatements.length; ++i) {
                evaluatedWeights = EF.add(
                    evaluatedWeights,
                    Packed.mul(thetaPower, statementCommon(initial.oodStatements[i], allPoint))
                );
                thetaPower = Packed.mul(thetaPower, initial.theta);
            }
            evaluatedWeights = EF.add(
                evaluatedWeights,
                Packed.mul(
                    thetaPower,
                    evaluateGammaStatementWeights(primaryStatements, initial.gamma, allPoint)
                )
            );
            thetaPower = Packed.mul(thetaPower, initial.theta);
            evaluatedWeights = EF.add(
                evaluatedWeights,
                Packed.mul(
                    thetaPower,
                    evaluateGammaStatementWeights(secondaryStatements, initial.gamma, allPoint)
                )
            );
        }
        uint256 skipped = folding[0].length;
        for (uint256 i; i < constraints.length; ++i) {
            uint256[] memory point = Poly.slice(allPoint, skipped, allPoint.length - skipped);
            evaluatedWeights =
                EF.add(evaluatedWeights, evaluateContinuationWeights(constraints[i], point));
            skipped += folding[i + 1].length;
        }
        uint256 finalValue =
            Poly.coefficients(coefficients, Poly.reverse(folding[folding.length - 1]));
        require(target == EF.mul(evaluatedWeights, finalValue), "WHIR_FINAL");
    }
}
