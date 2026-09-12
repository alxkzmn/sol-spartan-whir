// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import { KoalaBearExt5 as EF } from "../field/KoalaBearExt5.sol";
import { KoalaBearPackedField as Packed } from "../field/KoalaBearPackedField.sol";
import { LeanVmTranscript as Transcript } from "./LeanVmTranscript.sol";
import { LeanVmPolynomial as Poly } from "./LeanVmPolynomial.sol";
import { LeanVmPackedPolynomial as PackedPoly } from "./LeanVmPackedPolynomial.sol";
import { LeanVmWhir as Whir } from "./LeanVmWhir.sol";
import { LeanVmAir as Air } from "./LeanVmAir.sol";
import { LeanVmLogUp as LogUp } from "./LeanVmLogUp.sol";

library LeanVmTwoCommitmentExecution {
    using Transcript for Transcript.State;
    uint256 internal constant ONE = uint256(1) << 224;
    uint256 internal constant TWO_COMMITMENT_MODE_TAG = 0x32570001;
    uint256 internal constant TWO_COMMITMENT_BATCHING_POW_BITS = 2;

    struct Config {
        uint256 bytecodeLog;
        uint256 endingPc;
        uint256 rate;
        uint256[8] capacity;
        Whir.Config whir;
    }

    struct Result {
        uint256[] bytecodePoint;
        uint256 bytecodeValue;
    }

    /// @dev Application-pinned metadata included in the generated C1 Fiat-Shamir capacity.
    struct TwoCommitmentConfig {
        uint256 modeTag;
        uint256 batchingPowBits;
        uint256[3] programDimensions;
        uint256 secondaryActualDataLength;
        uint256[2] secondaryStatementPublicMemoryOffsets;
        uint256[2] secondaryStatementPointPrefixLengths;
        uint256[3] secondaryStatementPointPrefixes;
        uint256[2] executionBytecodePointPrefix;
        uint256[8] expectedSecondaryRoot;
    }

    struct FixedProgramClaims {
        uint256[] sparkPoint;
        uint256 sparkValue;
        uint256[] liftPoint;
        uint256 liftValue;
    }

    function columns(uint256 table) private pure returns (uint256) {
        return table == 0 ? 20 : (table == 1 ? 29 : 110);
    }

    function constraints(uint256 table) private pure returns (uint256) {
        return table == 0 ? 14 : (table == 1 ? 35 : 96);
    }

    function shifts(uint256 table) private pure returns (uint256) {
        return table == 0 ? 2 : (table == 1 ? 13 : 0);
    }

    function max(uint256 a, uint256 b) private pure returns (uint256) {
        return a > b ? a : b;
    }

    function ceilLog2(uint256 value) private pure returns (uint256 out) {
        require(value != 0, "ZERO_SIZE");
        --value;
        while (value != 0) {
            value >>= 1;
            out += 1;
        }
    }

    function product(uint256[] memory values) private pure returns (uint256 out) {
        out = ONE;
        for (uint256 i; i < values.length; ++i) {
            out = Packed.mul(out, values[i]);
        }
    }

    function powers(uint256 value, uint256 count) private pure returns (uint256[] memory out) {
        out = new uint256[](count);
        uint256 power = ONE;
        for (uint256 i; i < count; ++i) {
            out[i] = power;
            power = Packed.mul(power, value);
        }
    }

    function eqValues(uint256[] memory point) private pure returns (uint256[] memory out) {
        out = new uint256[](uint256(1) << point.length);
        out[0] = ONE;
        uint256 size = 1;
        for (uint256 i; i < point.length; ++i) {
            for (uint256 j = size; j != 0; --j) {
                uint256 value = out[j - 1];
                out[2 * j - 2] = Packed.mul(value, EF.sub(ONE, point[i]));
                out[2 * j - 1] = Packed.mul(value, point[i]);
            }
            size <<= 1;
        }
    }

    function suffix(uint256[] memory point, uint256 length)
        private
        pure
        returns (uint256[] memory)
    {
        return Poly.slice(point, point.length - length, length);
    }

    function statement(
        uint256 variables,
        uint256[] memory point,
        uint256[] memory selectors,
        uint256[] memory values,
        bool isNext
    ) private pure returns (Whir.Statement memory) {
        return Whir.Statement(variables, point, selectors, values, isNext);
    }

    function validateTwoCommitmentConfig(
        Config memory config,
        TwoCommitmentConfig memory twoCommitment
    ) internal pure {
        uint256 variables = config.whir.variables;
        uint256[3] memory dimensions = twoCommitment.programDimensions;
        require(
            twoCommitment.modeTag == TWO_COMMITMENT_MODE_TAG
                && twoCommitment.batchingPowBits == TWO_COMMITMENT_BATCHING_POW_BITS,
            "TWO_COMMITMENT_MODE"
        );
        require(
            variables != 0 && variables < 256 && dimensions[0] + 1 == variables
                && dimensions[1] + 1 == dimensions[0] && dimensions[2] == dimensions[1],
            "TWO_COMMITMENT_LAYOUT"
        );
        uint256 fullLength = uint256(1) << variables;
        require(
            twoCommitment.secondaryActualDataLength == fullLength
                && (uint256(1) << dimensions[0]) + (uint256(1) << dimensions[1])
                        + (uint256(1) << dimensions[2]) == fullLength,
            "TWO_COMMITMENT_LENGTH"
        );
        uint256 liftClaimLength = (dimensions[1] + 1) * 5;
        uint256 liftClaimPaddedLength = (liftClaimLength + 7) & ~uint256(7);
        require(
            twoCommitment.secondaryStatementPublicMemoryOffsets[0] == 16 + liftClaimPaddedLength
                && twoCommitment.secondaryStatementPublicMemoryOffsets[1] == 8
                && twoCommitment.secondaryStatementPointPrefixLengths[0] == 1
                && twoCommitment.secondaryStatementPointPrefixLengths[1] == 2
                && twoCommitment.secondaryStatementPointPrefixes[0] == 0
                && twoCommitment.secondaryStatementPointPrefixes[1] == ONE
                && twoCommitment.secondaryStatementPointPrefixes[2] == 0
                && twoCommitment.executionBytecodePointPrefix[0] == ONE
                && twoCommitment.executionBytecodePointPrefix[1] == ONE,
            "TWO_COMMITMENT_MEMORY"
        );
    }

    function appendExtension(uint256[] memory encoded, uint256 at, uint256 value)
        private
        pure
        returns (uint256)
    {
        EF.validatePacked(value);
        require(at <= encoded.length && 5 <= encoded.length - at, "FIXED_PROGRAM_OBSERVATION");
        assembly ("memory-safe") {
            let destination := add(add(encoded, 32), shl(5, at))
            mstore(destination, shr(224, value))
            mstore(add(destination, 32), and(shr(192, value), 0xffffffff))
            mstore(add(destination, 64), and(shr(160, value), 0xffffffff))
            mstore(add(destination, 96), and(shr(128, value), 0xffffffff))
            mstore(add(destination, 128), and(shr(96, value), 0xffffffff))
        }
        return at + 5;
    }

    /// @dev Canonical Rust-compatible observation of the two application-supplied
    /// fixed-program claims. The root-program claim is derived later by LogUp.
    function twoCommitmentStatementObservation(uint256 variables, FixedProgramClaims memory claims)
        internal
        pure
        returns (uint256[] memory encoded)
    {
        require(
            claims.sparkPoint.length + 1 == variables && claims.liftPoint.length + 2 == variables,
            "FIXED_PROGRAM_CLAIM_DIM"
        );
        encoded = new uint256[](24 + 10 * variables);
        encoded[0] = 0x32574f31;
        encoded[1] = 2;
        encoded[2] = encoded.length;
        uint256 at = 4;

        encoded[at++] = variables;
        encoded[at++] = claims.sparkPoint.length + 1;
        encoded[at++] = 1;
        encoded[at++] = 0;
        at = appendExtension(encoded, at, 0);
        for (uint256 i; i < claims.sparkPoint.length; ++i) {
            at = appendExtension(encoded, at, claims.sparkPoint[i]);
        }
        encoded[at++] = 0;
        at = appendExtension(encoded, at, claims.sparkValue);

        encoded[at++] = variables;
        encoded[at++] = claims.liftPoint.length + 2;
        encoded[at++] = 1;
        encoded[at++] = 0;
        at = appendExtension(encoded, at, ONE);
        at = appendExtension(encoded, at, 0);
        for (uint256 i; i < claims.liftPoint.length; ++i) {
            at = appendExtension(encoded, at, claims.liftPoint[i]);
        }
        encoded[at++] = 0;
        at = appendExtension(encoded, at, claims.liftValue);
        require(at == encoded.length, "FIXED_PROGRAM_OBSERVATION");
    }

    function matchPublicMemoryExtension(uint256[] memory publicMemory, uint256 at, uint256 value)
        private
        pure
        returns (uint256)
    {
        require(at <= publicMemory.length && 5 <= publicMemory.length - at, "FIXED_PROGRAM_MEMORY");
        for (uint256 i; i < 5; ++i) {
            uint256 coefficient = (value >> (224 - 32 * i)) & 0xffffffff;
            require(publicMemory[at++] == coefficient, "FIXED_PROGRAM_MEMORY");
        }
        return at;
    }

    function validateFixedProgramPublicMemory(
        uint256[] memory publicMemory,
        TwoCommitmentConfig memory twoCommitment,
        FixedProgramClaims memory claims
    ) internal pure {
        uint256 at = twoCommitment.secondaryStatementPublicMemoryOffsets[0];
        for (uint256 i; i < claims.sparkPoint.length; ++i) {
            at = matchPublicMemoryExtension(publicMemory, at, claims.sparkPoint[i]);
        }
        matchPublicMemoryExtension(publicMemory, at, claims.sparkValue);

        at = twoCommitment.secondaryStatementPublicMemoryOffsets[1];
        for (uint256 i; i < claims.liftPoint.length; ++i) {
            at = matchPublicMemoryExtension(publicMemory, at, claims.liftPoint[i]);
        }
        matchPublicMemoryExtension(publicMemory, at, claims.liftValue);
    }

    /// @dev Verifies the terminal C1 proof with a separately committed fixed-program
    /// polynomial. The generated capacity pins every field in twoCommitment.
    function verifyTwoCommitmentsWithPublicMemory(
        bytes calldata transcript,
        bytes calldata openings,
        uint256[8] memory publicInput,
        Config memory config,
        uint256 fixedBytecodeValue,
        uint256[] memory publicMemory,
        uint256 publicMemoryOffset,
        TwoCommitmentConfig memory twoCommitmentConfig,
        FixedProgramClaims memory fixedProgramClaims
    ) internal pure returns (Result memory result) {
        require(publicMemory.length != 0, "PUBLIC_MEMORY_EMPTY");
        validateTwoCommitmentConfig(config, twoCommitmentConfig);
        require(
            fixedProgramClaims.sparkPoint.length == twoCommitmentConfig.programDimensions[0]
                && fixedProgramClaims.liftPoint.length == twoCommitmentConfig.programDimensions[1],
            "FIXED_PROGRAM_CLAIM_DIM"
        );
        EF.validatePacked(fixedProgramClaims.sparkValue);
        EF.validatePacked(fixedProgramClaims.liftValue);
        for (uint256 i; i < fixedProgramClaims.sparkPoint.length; ++i) {
            EF.validatePacked(fixedProgramClaims.sparkPoint[i]);
        }
        for (uint256 i; i < fixedProgramClaims.liftPoint.length; ++i) {
            EF.validatePacked(fixedProgramClaims.liftPoint[i]);
        }
        validateFixedProgramPublicMemory(publicMemory, twoCommitmentConfig, fixedProgramClaims);
        return verifyCore(
            transcript,
            openings,
            publicInput,
            config,
            fixedBytecodeValue,
            publicMemory,
            publicMemoryOffset,
            twoCommitmentConfig,
            fixedProgramClaims
        );
    }

    function verifyCore(
        bytes calldata transcript,
        bytes calldata openings,
        uint256[8] memory publicInput,
        Config memory config,
        uint256 fixedBytecodeValue,
        uint256[] memory publicMemory,
        uint256 publicMemoryOffset,
        TwoCommitmentConfig memory twoCommitmentConfig,
        FixedProgramClaims memory fixedProgramClaims
    ) private pure returns (Result memory result) {
        EF.validatePacked(fixedBytecodeValue);
        Transcript.State memory state = Transcript.initialize(config.capacity);
        state.observeDigest(publicInput);
        uint256 publicMemoryLog;
        if (publicMemory.length != 0) {
            publicMemoryLog = Poly.log2(publicMemory.length);
            require(
                (publicMemoryOffset & (publicMemory.length - 1)) == 0, "PUBLIC_MEMORY_ALIGNMENT"
            );
            uint256[8] memory regionHeader;
            regionHeader[0] = 0x50554d31;
            regionHeader[1] = publicMemoryOffset;
            regionHeader[2] = publicMemory.length;
            state.observeDigest(regionHeader);
            state.observe(publicMemory);
        }
        state.observe(twoCommitmentStatementObservation(config.whir.variables, fixedProgramClaims));
        uint256[] memory dimensions = state.readBase(transcript, 5);
        require(
            dimensions[0] == config.rate && config.bytecodeLog >= 8 && config.bytecodeLog <= 22,
            "EXECUTION_CONFIG"
        );
        LogUp.Layout memory layout;
        layout.memoryLog = dimensions[1];
        require(layout.memoryLog >= 16 && layout.memoryLog <= 26, "MEMORY_DIM");
        if (publicMemory.length != 0) {
            uint256 memorySize = uint256(1) << layout.memoryLog;
            require(
                publicMemoryOffset <= memorySize
                    && publicMemory.length <= memorySize - publicMemoryOffset,
                "PUBLIC_MEMORY_RANGE"
            );
        }
        for (uint256 t; t < 3; ++t) {
            layout.heights[t] = dimensions[t + 2];
            layout.sorted[t] = t;
            require(layout.heights[t] >= 8 && layout.heights[t] <= (t == 0 ? 26 : 22), "TABLE_DIM");
            layout.maximum = max(layout.maximum, layout.heights[t]);
        }
        require(layout.memoryLog >= max(config.bytecodeLog, layout.maximum), "MEMORY_HEIGHT");
        for (uint256 i; i < 3; ++i) {
            for (uint256 j = i + 1; j < 3; ++j) {
                if (
                    layout.heights[layout.sorted[j]] > layout.heights[layout.sorted[i]]
                        || (layout.heights[layout.sorted[j]] == layout.heights[layout.sorted[i]]
                            && layout.sorted[j] < layout.sorted[i])
                ) (layout.sorted[i], layout.sorted[j]) = (layout.sorted[j], layout.sorted[i]);
            }
        }
        uint256 entries = (uint256(2) << layout.memoryLog)
            + (uint256(1) << max(config.bytecodeLog, layout.maximum));
        for (uint256 t; t < 3; ++t) {
            entries += columns(t) << layout.heights[t];
        }
        layout.stacked = ceilLog2(entries);
        require(layout.stacked == config.whir.variables, "STACKED_DIM");
        Whir.Commitment memory commitment = Whir.parseRoot(state, transcript, layout.stacked);
        Whir.Commitment memory secondaryCommitment =
            Whir.parseRoot(state, transcript, layout.stacked);
        uint256[] memory expectedRoot = new uint256[](8);
        for (uint256 i; i < 8; ++i) {
            expectedRoot[i] = twoCommitmentConfig.expectedSecondaryRoot[i];
        }
        require(secondaryCommitment.root == Transcript.digest(expectedRoot), "FIXED_PROGRAM_ROOT");
        uint256 gamma = state.sample();
        state.duplex();
        uint256[] memory beta = state.sampleMany(4);
        uint256[] memory betaEq = eqValues(beta);
        LogUp.Result memory logup = LogUp.verify(
            state, transcript, config.bytecodeLog, layout, gamma, beta, betaEq, fixedBytecodeValue
        );
        uint256[] memory alphas = powers(state.sample(), 145);
        uint256 initial;
        uint256 alphaOffset;
        for (uint256 t; t < 3; ++t) {
            initial = EF.add(
                initial,
                Packed.mul(
                    alphas[alphaOffset],
                    t == 0 ? logup.numerators[t] : EF.sub(0, logup.numerators[t])
                )
            );
            initial = EF.add(
                initial, Packed.mul(alphas[alphaOffset + 1], EF.sub(gamma, logup.denominators[t]))
            );
            alphaOffset += constraints(t);
        }
        (uint256[] memory airPoint, uint256 airValue) =
            Poly.sumcheck(state, transcript, initial, layout.maximum, 11, 0);
        uint256[][3] memory airColumns;
        uint256[][3] memory airPoints;
        uint256 actualAir;
        alphaOffset = 0;
        for (uint256 t; t < 3; ++t) {
            airColumns[t] = state.readExtension(transcript, columns(t) + shifts(t));
            uint256[] memory flat = Poly.slice(airColumns[t], 0, columns(t));
            uint256[] memory shifted = Poly.slice(airColumns[t], columns(t), shifts(t));
            uint256[] memory tableAlphas = Poly.slice(alphas, alphaOffset, constraints(t));
            alphaOffset += constraints(t);
            uint256 evaluation = t == 0
                ? Air.evalExecutionTrusted(flat, shifted, tableAlphas, betaEq)
                : (t == 1
                        ? Air.evalExtensionTrusted(flat, shifted, tableAlphas, betaEq)
                        : Air.evalPoseidonTrusted(flat, shifted, tableAlphas, betaEq));
            airPoints[t] = Poly.reverse(suffix(airPoint, layout.heights[t]));
            uint256 factor = Packed.mul(
                product(Poly.slice(airPoint, 0, airPoint.length - layout.heights[t])),
                PackedPoly.eqPolynomial(suffix(logup.point, layout.heights[t]), airPoints[t])
            );
            actualAir = EF.add(actualAir, Packed.mul(factor, evaluation));
        }
        require(actualAir == airValue, "AIR_EVALUATION");
        uint256[] memory publicPoint = state.sampleMany(3);
        uint256[] memory publicValues = new uint256[](8);
        for (uint256 i; i < 8; ++i) {
            publicValues[i] = publicInput[i];
        }
        uint256[] memory regionPoint;
        uint256 regionValue;
        if (publicMemory.length != 0) {
            regionPoint = state.sampleMany(publicMemoryLog);
            regionValue = PackedPoly.evaluateBaseHypercube(publicMemory, regionPoint);
        }
        Whir.Statement[] memory statements =
            new Whir.Statement[](publicMemory.length == 0 ? 14 : 15);
        uint256 count;
        uint256[] memory selectors = new uint256[](2);
        selectors[1] = 1;
        uint256[] memory values = new uint256[](2);
        values[0] = logup.memoryValue;
        values[1] = logup.memoryAcc;
        statements[count++] = statement(
            layout.stacked, suffix(logup.point, layout.memoryLog), selectors, values, false
        );
        statements[count++] = Whir.dense(
            layout.stacked, publicPoint, PackedPoly.evaluateBaseHypercube(publicValues, publicPoint)
        );
        selectors = new uint256[](1);
        selectors[0] = (uint256(2) << layout.memoryLog) >> config.bytecodeLog;
        values = new uint256[](1);
        values[0] = logup.bytecodeAcc;
        statements[count++] = statement(
            layout.stacked, suffix(logup.point, config.bytecodeLog), selectors, values, false
        );
        if (publicMemory.length != 0) {
            selectors = new uint256[](1);
            selectors[0] = publicMemoryOffset >> publicMemoryLog;
            values = new uint256[](1);
            values[0] = regionValue;
            statements[count++] = statement(layout.stacked, regionPoint, selectors, values, false);
        }
        uint256[3] memory offsets;
        uint256 offset = (uint256(2) << layout.memoryLog)
            + (uint256(1) << max(config.bytecodeLog, layout.maximum));
        for (uint256 i; i < 3; ++i) {
            uint256 t = layout.sorted[i];
            offsets[t] = offset;
            offset += columns(t) << layout.heights[t];
        }
        for (uint256 t; t < 3; ++t) {
            uint256 base = offsets[t] >> layout.heights[t];
            if (t == 0) {
                for (uint256 boundary; boundary < 2; ++boundary) {
                    selectors = new uint256[](1);
                    selectors[0] =
                        offsets[t] + (boundary == 0 ? 0 : (uint256(1) << layout.heights[t]) - 1);
                    values = new uint256[](1);
                    values[0] = EF.fromBase(boundary == 0 ? 0 : config.endingPc);
                    statements[count++] =
                        statement(layout.stacked, new uint256[](0), selectors, values, false);
                }
            }
            uint256 known;
            for (uint256 i; i < columns(t); ++i) {
                if ((logup.seen[t] & (uint256(1) << i)) != 0) ++known;
            }
            selectors = new uint256[](known);
            values = new uint256[](known);
            uint256 at;
            for (uint256 i; i < columns(t); ++i) {
                if ((logup.seen[t] & (uint256(1) << i)) != 0) {
                    selectors[at] = base + i;
                    values[at++] = logup.columns[t][i];
                }
            }
            statements[count++] = statement(
                layout.stacked, suffix(logup.point, layout.heights[t]), selectors, values, false
            );
            if (shifts(t) != 0) {
                selectors = new uint256[](shifts(t));
                for (uint256 i; i < shifts(t); ++i) {
                    selectors[i] = base + i;
                }
                statements[count++] = statement(
                    layout.stacked,
                    airPoints[t],
                    selectors,
                    Poly.slice(airColumns[t], columns(t), shifts(t)),
                    true
                );
            }
            selectors = new uint256[](columns(t));
            for (uint256 i; i < columns(t); ++i) {
                selectors[i] = base + i;
            }
            statements[count++] = statement(
                layout.stacked,
                airPoints[t],
                selectors,
                Poly.slice(airColumns[t], 0, columns(t)),
                false
            );
        }
        assembly ("memory-safe") { mstore(statements, count) }
        Whir.Cursor memory cursor;
        Whir.Statement[] memory secondaryStatements = new Whir.Statement[](3);
        uint256[] memory sparkPoint = new uint256[](fixedProgramClaims.sparkPoint.length + 1);
        for (uint256 i; i < fixedProgramClaims.sparkPoint.length; ++i) {
            sparkPoint[i + 1] = fixedProgramClaims.sparkPoint[i];
        }
        secondaryStatements[0] =
            Whir.dense(layout.stacked, sparkPoint, fixedProgramClaims.sparkValue);
        uint256[] memory liftPoint = new uint256[](fixedProgramClaims.liftPoint.length + 2);
        liftPoint[0] = ONE;
        for (uint256 i; i < fixedProgramClaims.liftPoint.length; ++i) {
            liftPoint[i + 2] = fixedProgramClaims.liftPoint[i];
        }
        secondaryStatements[1] = Whir.dense(layout.stacked, liftPoint, fixedProgramClaims.liftValue);
        uint256[] memory rootPoint = new uint256[](logup.bytecodePoint.length + 2);
        rootPoint[0] = twoCommitmentConfig.executionBytecodePointPrefix[0];
        rootPoint[1] = twoCommitmentConfig.executionBytecodePointPrefix[1];
        for (uint256 i; i < logup.bytecodePoint.length; ++i) {
            rootPoint[i + 2] = logup.bytecodePoint[i];
        }
        secondaryStatements[2] = Whir.dense(layout.stacked, rootPoint, fixedBytecodeValue);
        Whir.verifyTwoCommitments(
            state,
            transcript,
            openings,
            cursor,
            config.whir,
            twoCommitmentConfig.batchingPowBits,
            commitment,
            statements,
            secondaryCommitment,
            secondaryStatements
        );
        state.finish(transcript);
        require(cursor.offset == openings.length, "UNUSED_OPENINGS");
        result = Result(logup.bytecodePoint, fixedBytecodeValue);
    }
}
