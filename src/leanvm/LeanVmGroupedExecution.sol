// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import { KoalaBearExt5 as EF } from "../field/KoalaBearExt5.sol";
import { LeanVmTranscript as Transcript } from "./LeanVmTranscript.sol";
import { LeanVmPolynomial as Poly } from "./LeanVmPolynomial.sol";
import { LeanVmPackedPolynomial as PackedPoly } from "./LeanVmPackedPolynomial.sol";
import { LeanVmWhir as Whir } from "./LeanVmWhir.sol";
import { LeanVmGroupedLogUp as Grouped } from "./LeanVmGroupedLogUp.sol";
import { LeanVmTwoCommitmentExecution as Core } from "./LeanVmTwoCommitmentExecution.sol";

/// @dev Experimental grouped LogUp execution mode. The mode observation binds the
/// inverse group width, three commitments and four-bit batching work before challenges.
library LeanVmGroupedExecution {
    using Transcript for Transcript.State;
    uint256 internal constant ONE = uint256(1) << 224;

    function consecutive(uint256 start, uint256 count) private pure returns (uint256[] memory out) {
        out = new uint256[](count);
        for (uint256 i; i < count; ++i) {
            out[i] = start + i;
        }
    }

    function single(uint256 value) private pure returns (uint256[] memory out) {
        out = new uint256[](1);
        out[0] = value;
    }

    function buildStatements(
        Grouped.Layout memory l,
        Grouped.Claims memory claims,
        uint256[] memory beta,
        Core.FixedProgramClaims memory fixedClaims,
        Whir.Statement memory publicStatement,
        Whir.Statement memory regionStatement,
        uint256 endingPc
    ) internal pure returns (Whir.Statement[][3] memory groups) {
        uint256 n = l.variables;
        groups[0] = new Whir.Statement[](11);
        groups[1] = new Whir.Statement[](3);
        groups[2] = new Whir.Statement[](5);
        groups[0][0] = publicStatement;
        groups[0][1] = regionStatement;
        uint256 at = 2;
        for (uint256 i; i < 5; ++i) {
            uint256 kind = l.order[i];
            uint256 h = l.heights[kind];
            uint256[] memory point = claims.points[kind];
            uint256[] memory values = claims.values[kind];
            if (kind == 0) {
                uint256[] memory selectors = new uint256[](16);
                for (uint256 j; j < 8; ++j) {
                    selectors[2 * j] = j;
                    selectors[2 * j + 1] = 8 + j;
                }
                groups[0][at++] =
                    Whir.Statement(n, point, selectors, Poly.slice(values, 0, 16), false);
            } else if (kind == 1) {
                uint256[] memory acc = new uint256[](8);
                uint256[] memory instructions = new uint256[](8);
                for (uint256 j; j < 8; ++j) {
                    instructions[j] = values[2 * j];
                    acc[j] = values[2 * j + 1];
                }
                groups[0][at++] = Whir.Statement(
                    n, point, consecutive((uint256(2) << l.memoryLog) >> h, 8), acc, false
                );
                uint256[] memory fixedPoint = new uint256[](h + 4);
                for (uint256 j; j < h; ++j) {
                    fixedPoint[j] = point[j];
                }
                for (uint256 j; j < 4; ++j) {
                    fixedPoint[h + j] = beta[j];
                }
                // The validated fixed layout places the root program at prefix [1,1].
                uint256 fixedOffset = uint256(3) << (l.bytecodeLog + 4);
                require(l.bytecodeLog + 6 == n, "GROUPED_FIXED_DIM");
                groups[1][2] = Whir.Statement(
                    n, fixedPoint, consecutive(fixedOffset >> (h + 4), 8), instructions, false
                );
            }
            groups[2][i] = Whir.Statement(
                n,
                point,
                consecutive(l.helperOffsets[kind] >> h, 5 * Grouped.groups(kind)),
                Poly.slice(values, Grouped.helperStart(kind), 5 * Grouped.groups(kind)),
                false
            );
        }
        for (uint256 table; table < 3; ++table) {
            uint256 kind = table + 2;
            uint256 h = l.heights[kind];
            uint256 base = l.tableOffsets[table] >> h;
            if (table == 0) {
                for (uint256 boundary; boundary < 2; ++boundary) {
                    groups[0][at++] = Whir.Statement(
                        n,
                        new uint256[](0),
                        single(l.tableOffsets[0] + (boundary == 0 ? 0 : (uint256(1) << h) - 1)),
                        single(EF.fromBase(boundary == 0 ? 0 : endingPc)),
                        false
                    );
                }
            }
            uint256 count = Grouped.columns(table);
            uint256 shifted = Grouped.shifts(table);
            if (shifted != 0) {
                groups[0][at++] = Whir.Statement(
                    n,
                    claims.points[kind],
                    consecutive(base, shifted),
                    Poly.slice(claims.values[kind], count + 5 * Grouped.groups(kind), shifted),
                    true
                );
            }
            groups[0][at++] = Whir.Statement(
                n,
                claims.points[kind],
                consecutive(base, count),
                Poly.slice(claims.values[kind], 0, count),
                false
            );
        }
        require(at == groups[0].length, "GROUPED_STATEMENTS");
        uint256[] memory spark = new uint256[](n);
        for (uint256 i; i < fixedClaims.sparkPoint.length; ++i) {
            spark[i + 1] = fixedClaims.sparkPoint[i];
        }
        groups[1][0] = Whir.dense(n, spark, fixedClaims.sparkValue);
        uint256[] memory lift = new uint256[](n);
        lift[0] = ONE;
        for (uint256 i; i < fixedClaims.liftPoint.length; ++i) {
            lift[i + 2] = fixedClaims.liftPoint[i];
        }
        groups[1][1] = Whir.dense(n, lift, fixedClaims.liftValue);
    }

    function verifyWithPublicMemory(
        bytes calldata transcript,
        bytes calldata openings,
        uint256[8] memory publicInput,
        Core.Config memory config,
        uint256 fixedBytecodeValue,
        uint256[] memory publicMemory,
        uint256 publicMemoryOffset,
        Core.TwoCommitmentConfig memory fixedConfig,
        Core.FixedProgramClaims memory fixedClaims
    ) internal pure {
        require(publicMemory.length != 0, "PUBLIC_MEMORY_EMPTY");
        Core.validateTwoCommitmentConfig(config, fixedConfig);
        Core.validateFixedProgramPublicMemory(publicMemory, fixedConfig, fixedClaims);
        EF.validatePacked(fixedBytecodeValue);
        Transcript.State memory state = Transcript.initialize(config.capacity);
        state.observeDigest([uint256(0x474c5531), 1, 8, 3, 5, 11, 4, 0]);
        state.observeDigest(publicInput);
        uint256 regionLog = Poly.log2(publicMemory.length);
        require((publicMemoryOffset & (publicMemory.length - 1)) == 0, "PUBLIC_MEMORY_ALIGNMENT");
        uint256[8] memory header;
        header[0] = 0x50554d31;
        header[1] = publicMemoryOffset;
        header[2] = publicMemory.length;
        state.observeDigest(header);
        state.observe(publicMemory);
        state.observe(Core.twoCommitmentStatementObservation(config.whir.variables, fixedClaims));
        uint256[] memory dimensions = state.readBase(transcript, 5);
        require(dimensions[0] == config.rate, "EXECUTION_CONFIG");
        Grouped.Layout memory l =
            Grouped.layout(dimensions, config.bytecodeLog, config.whir.variables);
        uint256 memorySize = uint256(1) << l.memoryLog;
        require(
            publicMemoryOffset <= memorySize
                && publicMemory.length <= memorySize - publicMemoryOffset,
            "PUBLIC_MEMORY_RANGE"
        );
        Whir.Commitment[3] memory commitments;
        commitments[0] = Whir.parseRoot(state, transcript, l.variables);
        commitments[1] = Whir.parseRoot(state, transcript, l.variables);
        uint256[] memory root = new uint256[](8);
        for (uint256 i; i < 8; ++i) {
            root[i] = fixedConfig.expectedSecondaryRoot[i];
        }
        require(commitments[1].root == Transcript.digest(root), "FIXED_PROGRAM_ROOT");
        Grouped.Challenges memory challenges;
        challenges.gamma = state.sample();
        state.duplex();
        uint256[] memory beta = state.sampleMany(4);
        challenges.betaEq = Grouped.eqValues(beta);
        commitments[2] = Whir.parseRoot(state, transcript, l.variables);
        state.duplex();
        challenges.equality = state.sampleMany(l.maximum);
        challenges.alpha = state.sample();
        challenges.balance = state.sample();
        (uint256[] memory point, uint256 value) =
            Poly.sumcheck(state, transcript, 0, l.maximum, 11, 0);
        Grouped.Claims memory claims;
        for (uint256 i; i < 5; ++i) {
            uint256 kind = l.order[i];
            uint256 h = l.heights[kind];
            claims.values[kind] = state.readExtension(transcript, Grouped.claimCount(kind));
            claims.points[kind] = Poly.reverse(Poly.slice(point, point.length - h, h));
        }
        require(Grouped.evaluate(l, claims, challenges, point) == value, "GROUPED_AIR_EVALUATION");
        require(fixedBytecodeValue == claims.values[1][0], "GROUPED_BYTECODE_VALUE");
        uint256[] memory publicValues = new uint256[](8);
        for (uint256 i; i < 8; ++i) {
            publicValues[i] = publicInput[i];
        }
        uint256[] memory publicPoint = state.sampleMany(3);
        Whir.Statement memory publicStatement = Whir.dense(
            l.variables, publicPoint, PackedPoly.evaluateBaseHypercube(publicValues, publicPoint)
        );
        uint256[] memory regionPoint = state.sampleMany(regionLog);
        Whir.Statement memory regionStatement = Whir.Statement(
            l.variables,
            regionPoint,
            single(publicMemoryOffset >> regionLog),
            single(PackedPoly.evaluateBaseHypercube(publicMemory, regionPoint)),
            false
        );
        Whir.Statement[][3] memory groups = buildStatements(
            l, claims, beta, fixedClaims, publicStatement, regionStatement, config.endingPc
        );
        Whir.Cursor memory cursor;
        Whir.verifyThreeCommitments(
            state, transcript, openings, cursor, config.whir, 4, commitments, groups
        );
        state.finish(transcript);
        require(cursor.offset == openings.length, "UNUSED_OPENINGS");
    }
}
