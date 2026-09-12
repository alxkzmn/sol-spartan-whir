// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { KoalaBearExt5 as EF } from "../field/KoalaBearExt5.sol";
import { KoalaBearPackedField as Packed } from "../field/KoalaBearPackedField.sol";
import { KeccakChallenger } from "../transcript/KeccakChallenger.sol";
import { LeanVmTranscript as Transcript } from "./LeanVmTranscript.sol";

/// @dev GKR's cubic coefficient-form sumcheck has no grinding witness.
/// Each round consumes four quintic coefficients and four zero recorder words.
library LeanVmGkrSumcheck {
    using KeccakChallenger for KeccakChallenger.State;

    function samplePacked(Transcript.State memory state) internal pure returns (uint256 value) {
        // Keep calls in separate statements: expression evaluation order must
        // not change the challenger sequence or coefficient order.
        value = state.challenger.sampleBase() << 224;
        // Consume four remaining coefficients together only when all pass the
        // same rejection test. Otherwise leave the output cursor untouched.
        uint256 available = state.challenger.outputIndex;
        if (available >= 16) {
            uint256 candidates = (uint256(state.challenger.outputBlock) >> ((32 - available) * 8))
                & 0x7fffffff7fffffff7fffffff7fffffff;
            if (
                ((candidates + 0x00ffffff00ffffff00ffffff00ffffff)
                            & 0x80000000800000008000000080000000) == 0
            ) {
                state.challenger.outputIndex =
                    available - 16;
                return value | ((candidates & 0xffffffff) << 192)
                    | (((candidates >> 32) & 0xffffffff) << 160)
                    | (((candidates >> 64) & 0xffffffff) << 128) | ((candidates >> 96) << 96);
            }
        }
        value |= state.challenger.sampleBase() << 192;
        value |= state.challenger.sampleBase() << 160;
        value |= state.challenger.sampleBase() << 128;
        value |= state.challenger.sampleBase() << 96;
    }

    function readCoefficients(Transcript.State memory state, bytes calldata transcript)
        internal
        pure
        returns (uint256 c0, uint256 c1, uint256 c2, uint256 c3)
    {
        uint256 start = state.offset;
        uint256 end = start + 96;
        require(end <= transcript.length, "TRANSCRIPT_END");
        c0 = decode(transcript, start);
        c1 = decode(transcript, start + 20);
        c2 = decode(transcript, start + 40);
        c3 = decode(transcript, start + 60);
        require(bytes16(transcript[start + 80:end]) == bytes16(0), "TRANSCRIPT_PADDING");
        state.challenger.observeBytesCalldata(transcript, start, 80);
        state.offset = end;
    }

    function decode(bytes calldata transcript, uint256 offset)
        private
        pure
        returns (uint256 packed)
    {
        assembly ("memory-safe") {
            let raw := calldataload(add(transcript.offset, offset))
            let pairs :=
                or(
                    shl(
                        8,
                        and(raw, 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff)
                    ),
                    shr(
                        8,
                        and(raw, 0xff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00)
                    )
                )
            packed := and(
                or(
                    shl(
                        16,
                        and(
                            pairs,
                            0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff
                        )
                    ),
                    shr(
                        16,
                        and(
                            pairs,
                            0xffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000
                        )
                    )
                ),
                0xffffffffffffffffffffffffffffffffffffffff000000000000000000000000
            )
        }
        EF.validatePacked(packed);
    }

    /// @dev Returns 2*c0+c1+c2+c3 for canonical packed quintic coefficients.
    /// Each addition reduces before the next, keeping every 32-bit lane canonical.
    function sumAtZeroAndOne(uint256 c0, uint256 c1, uint256 c2, uint256 c3)
        internal
        pure
        returns (uint256 out)
    {
        assembly ("memory-safe") {
            let p := 0x7f000001
            let bias := 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000
            let high := 0x8000000080000000800000008000000080000000000000000000000000000000
            let sum := add(c0, c0)
            let carry := and(add(sum, bias), high)
            sum := add(sub(sum, mul(shr(31, carry), p)), c1)
            carry := and(add(sum, bias), high)
            sum := add(sub(sum, mul(shr(31, carry), p)), c2)
            carry := and(add(sum, bias), high)
            sum := add(sub(sum, mul(shr(31, carry), p)), c3)
            carry := and(add(sum, bias), high)
            out := sub(sum, mul(shr(31, carry), p))
        }
    }

    function verify(
        Transcript.State memory state,
        bytes calldata transcript,
        uint256 target,
        uint256 rounds
    ) internal pure returns (uint256[] memory point, uint256 finalValue) {
        point = new uint256[](rounds);
        for (uint256 i; i < rounds; ++i) {
            (uint256 c0, uint256 c1, uint256 c2, uint256 c3) = readCoefficients(state, transcript);
            uint256 sum = sumAtZeroAndOne(c0, c1, c2, c3);
            require(sum == target, "SUMCHECK_IDENTITY");
            uint256 challenge = samplePacked(state);
            point[i] = challenge;
            target = EF.add(c2, Packed.mul(c3, challenge));
            target = EF.add(c1, Packed.mul(target, challenge));
            target = EF.add(c0, Packed.mul(target, challenge));
        }
        finalValue = target;
    }

    /// @dev Produces the same sampled point in reverse coordinate order, with one
    /// trailing word reserved for the caller's next-layer challenge.
    function verifyReversedWithTail(
        Transcript.State memory state,
        bytes calldata transcript,
        uint256 target,
        uint256 rounds
    ) internal pure returns (uint256[] memory point, uint256 finalValue) {
        point = new uint256[](rounds + 1);
        for (uint256 i; i < rounds; ++i) {
            (uint256 c0, uint256 c1, uint256 c2, uint256 c3) = readCoefficients(state, transcript);
            uint256 sum = sumAtZeroAndOne(c0, c1, c2, c3);
            require(sum == target, "SUMCHECK_IDENTITY");
            uint256 challenge = samplePacked(state);
            point[rounds - 1 - i] = challenge;
            target = EF.add(c2, Packed.mul(c3, challenge));
            target = EF.add(c1, Packed.mul(target, challenge));
            target = EF.add(c0, Packed.mul(target, challenge));
        }
        finalValue = target;
    }
}
