// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { KoalaBearExt5 as EF } from "../field/KoalaBearExt5.sol";
import { KoalaBearPackedField as Packed } from "../field/KoalaBearPackedField.sol";
import { LeanVmTranscript as Transcript } from "./LeanVmTranscript.sol";
import { LeanVmPolynomial as Poly } from "./LeanVmPolynomial.sol";
import { LeanVmGkrSumcheck as Cubic } from "./LeanVmGkrSumcheck.sol";
import { LeanVmPackedPolynomial as PackedPoly } from "./LeanVmPackedPolynomial.sol";

/// @notice Verifies the quotient GKR reduction and reconstructs every LogUp section.
/// @dev The caller authenticates fixedBytecodeValue at the returned bytecodePoint.
/// All sampled claims are read and observed by the transcript before their dependent challenges.
library LeanVmLogUp {
    using Transcript for Transcript.State;
    uint256 internal constant ONE = uint256(1) << 224;

    struct Layout {
        uint256 memoryLog;
        uint256[3] heights;
        uint256[3] sorted;
        uint256 maximum;
        uint256 stacked;
    }

    struct Result {
        uint256 memoryValue;
        uint256 memoryAcc;
        uint256 bytecodeAcc;
        uint256[3] numerators;
        uint256[3] denominators;
        uint256[] point;
        uint256[3] seen;
        uint256[][3] columns;
        uint256[] bytecodePoint;
    }

    struct Gkr {
        uint256 balance;
        uint256[] point;
        uint256 numerator;
        uint256 denominator;
    }

    function columns(uint256 table) private pure returns (uint256) {
        return table == 0 ? 20 : (table == 1 ? 29 : 110);
    }

    function buses(uint256 table) private pure returns (uint256) {
        return table == 0 ? 5 : (table == 1 ? 16 : 33);
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

    function zerosThenOnes(uint256 zeros, uint256[] memory point) private pure returns (uint256) {
        require(zeros <= (uint256(1) << point.length), "ZERO_BOUND");
        if (zeros == 0) return ONE;
        if (zeros == (uint256(1) << point.length)) return 0;
        return zerosThenOnesAt(zeros, point, 0);
    }

    function zerosThenOnesAt(uint256 zeros, uint256[] memory point, uint256 offset)
        private
        pure
        returns (uint256)
    {
        if (zeros == 0) return ONE;
        uint256 remaining = point.length - offset;
        uint256 half = uint256(1) << (remaining - 1);
        uint256 coordinate = point[offset];
        if (zeros < half) {
            return EF.add(
                Packed.mul(EF.sub(ONE, coordinate), zerosThenOnesAt(zeros, point, offset + 1)),
                coordinate
            );
        }
        return Packed.mul(coordinate, zerosThenOnesAt(zeros - half, point, offset + 1));
    }

    function integerMle(uint256[] memory point) private pure returns (uint256 out) {
        for (uint256 i; i < point.length; ++i) {
            out = EF.add(out, EF.mulBase(point[i], uint256(1) << (point.length - 1 - i)));
        }
    }

    function fingerprint(uint256 domain, uint256[] memory values, uint256[] memory betaEq)
        private
        pure
        returns (uint256 out)
    {
        require(betaEq.length > values.length, "FINGERPRINT");
        for (uint256 i; i < values.length; ++i) {
            out = EF.add(out, Packed.mul(betaEq[i], values[i]));
        }
        out = EF.add(out, EF.mulBase(betaEq[betaEq.length - 1], domain));
    }

    function suffix(uint256[] memory point, uint256 length)
        private
        pure
        returns (uint256[] memory)
    {
        return Poly.slice(point, point.length - length, length);
    }

    function verifyGkr(Transcript.State memory state, bytes calldata transcript, uint256 variables)
        internal
        pure
        returns (Gkr memory result)
    {
        require(variables > 5, "GKR_DIM");
        uint256[] memory numerators = state.readExtension(transcript, 32);
        uint256[] memory denominators = state.readExtension(transcript, 32);
        // The fraction sum is zero iff the combined numerator is, so no inverse is needed.
        uint256 denominator;
        (result.balance, denominator) = combinedFraction(numerators, denominators);
        require(denominator != 0, "LOGUP_DENOMINATOR");
        result.point = state.sampleMany(5);
        result.numerator = PackedPoly.evaluateHypercube(numerators, result.point);
        result.denominator = PackedPoly.evaluateHypercube(denominators, result.point);
        for (uint256 layer = 5; layer < variables; ++layer) {
            state.duplex();
            uint256 alpha = state.sample();
            (uint256[] memory point, uint256 value) = Cubic.verifyReversedWithTail(
                state,
                transcript,
                EF.add(result.numerator, Packed.mul(alpha, result.denominator)),
                layer
            );
            uint256[] memory child = state.readExtension(transcript, 4);
            uint256 step = EF.add(
                Packed.mul(alpha, Packed.mul(child[2], child[3])),
                EF.add(Packed.mul(child[0], child[3]), Packed.mul(child[1], child[2]))
            );
            require(value == Packed.mul(eqPrefix(result.point, point), step), "GKR_STEP");
            uint256 beta = state.sample();
            result.numerator = EF.add(child[0], Packed.mul(beta, EF.sub(child[1], child[0])));
            result.denominator = EF.add(child[2], Packed.mul(beta, EF.sub(child[3], child[2])));
            point[point.length - 1] = beta;
            result.point = point;
        }
    }

    /// @dev `point` holds one reserved trailing word that is written only after
    /// this equality check, so its prefix has the prior layer's dimension.
    function eqPrefix(uint256[] memory prior, uint256[] memory point)
        private
        pure
        returns (uint256 out)
    {
        if (prior.length == 0) return ONE;
        out = Packed.eq(prior[0], point[0]);
        for (uint256 i = 1; i < prior.length; ++i) {
            out = Packed.mul(out, Packed.eq(prior[i], point[i]));
        }
    }

    /// @dev Accumulate the fractions over one common denominator without inverting.
    function combinedFraction(uint256[] memory numerators, uint256[] memory denominators)
        internal
        pure
        returns (uint256 numerator, uint256 denominator)
    {
        require(numerators.length == 32 && denominators.length == 32, "GKR_TOP");
        numerator = numerators[0];
        denominator = denominators[0];
        for (uint256 i = 1; i < 32; ++i) {
            // Padding contributes the neutral fraction 0/1.
            if (numerators[i] == 0 && denominators[i] == ONE) continue;
            numerator = EF.add(
                Packed.mul(numerator, denominators[i]), Packed.mul(numerators[i], denominator)
            );
            denominator = Packed.mul(denominator, denominators[i]);
        }
    }

    /// @dev Reference quotient over the common denominator, requiring one extension inverse.
    /// A zero input denominator makes the product zero and is rejected by EF.inv.
    function sumQuotients(uint256[] memory numerators, uint256[] memory denominators)
        internal
        pure
        returns (uint256)
    {
        (uint256 numerator, uint256 denominator) = combinedFraction(numerators, denominators);
        return Packed.mul(numerator, EF.inv(denominator));
    }

    function pref(uint256[] memory point, uint256 offset, uint256 height)
        private
        pure
        returns (uint256)
    {
        return Poly.eqIndex(point, offset >> height, point.length - height);
    }

    function requestColumns(
        Transcript.State memory state,
        bytes calldata transcript,
        Result memory logup,
        uint256 table,
        uint256[] memory indices
    ) private pure returns (uint256[] memory out) {
        uint256 count;
        uint256 oldSeen = logup.seen[table];
        for (uint256 i; i < indices.length; ++i) {
            if ((oldSeen & (uint256(1) << indices[i])) == 0) ++count;
        }
        uint256[] memory received = state.readExtension(transcript, count);
        out = new uint256[](indices.length);
        count = 0;
        for (uint256 i; i < indices.length; ++i) {
            uint256 index = indices[i];
            if ((oldSeen & (uint256(1) << index)) == 0) {
                logup.columns[table][index] = received[count++];
                logup.seen[table] |= uint256(1) << index;
            }
            out[i] = logup.columns[table][index];
        }
    }

    /// @dev Reads a two-column request as one transcript group, matching the
    /// generic requestColumns read/absorption boundary without allocating the
    /// temporary indices and tuple arrays.
    function requestTwoColumns(
        Transcript.State memory state,
        bytes calldata transcript,
        Result memory logup,
        uint256 table,
        uint256 first,
        uint256 second
    ) private pure returns (uint256 firstValue, uint256 secondValue) {
        uint256 oldSeen = logup.seen[table];
        uint256 firstMask = uint256(1) << first;
        uint256 secondMask = uint256(1) << second;
        uint256 count = (oldSeen & firstMask) == 0 ? 1 : 0;
        if ((oldSeen & secondMask) == 0) ++count;
        uint256[] memory received = state.readExtension(transcript, count);
        uint256 at;
        if ((oldSeen & firstMask) == 0) {
            firstValue = received[at++];
            logup.columns[table][first] = firstValue;
            logup.seen[table] |= firstMask;
        } else {
            firstValue = logup.columns[table][first];
        }
        if ((oldSeen & secondMask) == 0) {
            secondValue = received[at];
            logup.columns[table][second] = secondValue;
            logup.seen[table] |= secondMask;
        } else {
            secondValue = logup.columns[table][second];
        }
    }

    function fingerprintTwo(uint256 domain, uint256 first, uint256 second, uint256[] memory betaEq)
        private
        pure
        returns (uint256 out)
    {
        out = EF.add(Packed.mul(betaEq[0], first), Packed.mul(betaEq[1], second));
        return EF.add(out, EF.mulBase(betaEq[betaEq.length - 1], domain));
    }

    function poseidonBusColumns()
        private
        pure
        returns (uint256[] memory indices, uint256 domain, uint256 terms)
    {
        indices = new uint256[](13);
        for (uint256 i; i < 12; ++i) {
            indices[i] = i + 8;
        }
        indices[12] = 0;
        return (indices, 2, 1);
    }

    function verify(
        Transcript.State memory state,
        bytes calldata transcript,
        uint256 bytecodeLog,
        Layout memory layout,
        uint256 gamma,
        uint256[] memory beta,
        uint256[] memory betaEq,
        uint256 fixedBytecodeValue
    ) internal pure returns (Result memory out) {
        validateLayout(bytecodeLog, layout);
        require(beta.length == 4 && betaEq.length == 16, "LOGUP_BETA");
        EF.validatePacked(gamma);
        EF.validatePacked(fixedBytecodeValue);
        for (uint256 i; i < beta.length; ++i) {
            EF.validatePacked(beta[i]);
        }
        for (uint256 i; i < betaEq.length; ++i) {
            EF.validatePacked(betaEq[i]);
        }
        uint256 active =
            (uint256(1) << layout.memoryLog) + (uint256(1) << max(bytecodeLog, layout.maximum));
        for (uint256 t; t < 3; ++t) {
            active += buses(t) << layout.heights[t];
        }
        Gkr memory result = verifyGkr(state, transcript, ceilLog2(active));
        require(result.balance == 0, "LOGUP_BALANCE");
        out.point = result.point;
        uint256 numerator;
        uint256 denominator;
        uint256[] memory memoryPoint = suffix(result.point, layout.memoryLog);
        uint256 weight = pref(result.point, 0, layout.memoryLog);
        out.memoryAcc = state.readOneExtension(transcript);
        out.memoryValue = state.readOneExtension(transcript);
        numerator = EF.sub(0, Packed.mul(weight, out.memoryAcc));
        uint256[] memory tuple = new uint256[](2);
        tuple[0] = integerMle(memoryPoint);
        tuple[1] = out.memoryValue;
        denominator = Packed.mul(weight, EF.sub(gamma, fingerprint(1, tuple, betaEq)));
        uint256 offset = uint256(1) << layout.memoryLog;
        uint256[] memory bytecodePoint = suffix(result.point, bytecodeLog);
        out.bytecodePoint = new uint256[](bytecodeLog + 4);
        for (uint256 i; i < bytecodePoint.length; ++i) {
            out.bytecodePoint[i] = bytecodePoint[i];
        }
        for (uint256 i; i < 4; ++i) {
            out.bytecodePoint[bytecodePoint.length + i] = beta[i];
        }
        out.bytecodeAcc = state.readOneExtension(transcript);
        uint256 codeFingerprint = EF.add(
            fixedBytecodeValue,
            EF.add(
                Packed.mul(integerMle(bytecodePoint), betaEq[12]),
                EF.mulBase(betaEq[betaEq.length - 1], 2)
            )
        );
        weight = pref(result.point, offset, bytecodeLog);
        numerator = EF.sub(numerator, Packed.mul(weight, out.bytecodeAcc));
        denominator = EF.add(denominator, Packed.mul(weight, EF.sub(gamma, codeFingerprint)));
        uint256 padded = max(bytecodeLog, layout.maximum);
        denominator = EF.add(
            denominator,
            Packed.mul(
                pref(result.point, offset, padded),
                zerosThenOnes(uint256(1) << bytecodeLog, suffix(result.point, padded))
            )
        );
        offset += uint256(1) << padded;
        uint256[3] memory tableOffsets;
        for (uint256 i; i < 3; ++i) {
            uint256 table = layout.sorted[i];
            tableOffsets[table] = offset;
            offset += buses(table) << layout.heights[table];
        }
        uint256 finalOffset = offset;
        uint256 weightedAddresses;
        uint256 weightedValues;
        uint256 busWeightSum;
        for (uint256 table; table < 3; ++table) {
            out.columns[table] = new uint256[](columns(table));
            offset = tableOffsets[table];
            uint256[] memory busWeights = PackedPoly.eqIndexRange(
                result.point,
                offset >> layout.heights[table],
                buses(table),
                result.point.length - layout.heights[table]
            );
            uint256 weightIndex;
            weight = busWeights[weightIndex++];
            out.numerators[table] = state.readOneExtension(transcript);
            out.denominators[table] = state.readOneExtension(transcript);
            numerator = EF.add(numerator, Packed.mul(weight, out.numerators[table]));
            denominator = EF.add(denominator, Packed.mul(weight, out.denominators[table]));
            offset += uint256(1) << layout.heights[table];
            uint256 busCount = table == 1 ? 4 : 5;
            for (uint256 bus = 1; bus < busCount; ++bus) {
                if (table == 0 && bus == 1) {
                    (uint256[] memory base, uint256 domain, uint256 specialTerms) =
                        poseidonBusColumns();
                    for (uint256 term; term < specialTerms; ++term) {
                        uint256[] memory indices = Poly.slice(base, 0, base.length);
                        for (uint256 i = 1; i < indices.length; ++i) {
                            indices[i] += term;
                        }
                        tuple = requestColumns(state, transcript, out, table, indices);
                        tuple[0] = EF.add(tuple[0], EF.fromBase(term));
                        weight = busWeights[weightIndex++];
                        numerator = EF.add(numerator, weight);
                        denominator = EF.add(
                            denominator,
                            Packed.mul(weight, EF.sub(gamma, fingerprint(domain, tuple, betaEq)))
                        );
                        offset += uint256(1) << layout.heights[table];
                    }
                    continue;
                }
                uint256 first;
                uint256 second;
                uint256 terms;
                if (table == 0) {
                    first = bus;
                    second = bus + 3;
                    terms = 1;
                } else if (table == 1) {
                    first = bus == 1 ? 6 : (bus == 2 ? 7 : 13);
                    second = 14 + (bus - 1) * 5;
                    terms = 5;
                } else {
                    first = bus == 1 ? 7 : (bus == 2 ? 8 : (bus == 3 ? 1 : 2));
                    second = bus == 1 ? 10 : (bus == 2 ? 14 : (bus == 3 ? 18 : 94));
                    terms = bus == 4 ? 16 : (bus == 3 ? 8 : 4);
                }
                uint256 firstValue;
                uint256 busWeight;
                for (uint256 term; term < terms; ++term) {
                    uint256 secondValue;
                    (firstValue, secondValue) =
                        requestTwoColumns(state, transcript, out, table, first, second + term);
                    weight = busWeights[weightIndex++];
                    busWeight = EF.add(busWeight, weight);
                    weightedAddresses = EF.add(weightedAddresses, EF.mulBase(weight, term));
                    weightedValues = EF.add(weightedValues, Packed.mul(weight, secondValue));
                }
                weightedAddresses = EF.add(weightedAddresses, Packed.mul(busWeight, firstValue));
                busWeightSum = EF.add(busWeightSum, busWeight);
            }
        }
        numerator = EF.add(numerator, busWeightSum);
        denominator = EF.add(denominator, Packed.mul(busWeightSum, EF.sub(gamma, betaEq[15])));
        denominator = EF.sub(denominator, Packed.mul(betaEq[0], weightedAddresses));
        denominator = EF.sub(denominator, Packed.mul(betaEq[1], weightedValues));
        denominator = EF.add(denominator, zerosThenOnes(finalOffset, result.point));
        require(
            numerator == result.numerator && denominator == result.denominator, "LOGUP_EVALUATION"
        );
    }

    function validateLayout(uint256 bytecodeLog, Layout memory layout) private pure {
        require(bytecodeLog <= 26 && layout.memoryLog <= 30, "LOGUP_LAYOUT");
        uint256 seen;
        uint256 maximum;
        for (uint256 i; i < 3; ++i) {
            uint256 table = layout.sorted[i];
            require(table < 3 && (seen & (uint256(1) << table)) == 0, "LOGUP_SORT");
            seen |= uint256(1) << table;
            require(layout.heights[table] <= layout.memoryLog, "LOGUP_HEIGHT");
            maximum = max(maximum, layout.heights[table]);
            if (i != 0) {
                uint256 prior = layout.sorted[i - 1];
                require(
                    layout.heights[prior] > layout.heights[table]
                        || (layout.heights[prior] == layout.heights[table] && prior < table),
                    "LOGUP_SORT"
                );
            }
        }
        require(layout.maximum == maximum && layout.memoryLog >= bytecodeLog, "LOGUP_LAYOUT");
    }
}
