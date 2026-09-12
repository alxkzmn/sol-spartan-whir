// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { KeccakChallenger } from "../../src/transcript/KeccakChallenger.sol";
import { KoalaBearExt5 } from "../../src/field/KoalaBearExt5.sol";

/// @dev The raw transcript contains LE-u32 scalars in padded eight-scalar blocks.
/// The Keccak transcript observes the actual protocol scalar count before padding.
library LeanVmTranscriptReference {
    using KeccakChallenger for KeccakChallenger.State;
    uint256 internal constant MODULUS = 2_130_706_433;

    struct State {
        KeccakChallenger.State challenger;
        uint256 offset;
    }

    function initialize(uint256[8] memory capacity) internal pure returns (State memory state) {
        state.challenger.observeBytes(bytes("leanvm-keccak240-v1"));
        for (uint256 i; i < 8; ++i) {
            state.challenger.observeBase(capacity[i]);
        }
    }

    function observe(State memory state, uint256[] memory values) internal pure {
        for (uint256 i; i < values.length; ++i) {
            state.challenger.observeBase(values[i]);
        }
    }

    function observeDigest(State memory state, uint256[8] memory values) internal pure {
        for (uint256 i; i < 8; ++i) {
            state.challenger.observeBase(values[i]);
        }
    }

    function duplex(State memory state) internal pure {
        for (uint256 i; i < 8; ++i) {
            state.challenger.observeBase(0);
        }
    }

    function sample(State memory state) internal pure returns (uint256) {
        return KoalaBearExt5.pack(state.challenger.sampleExt5Coeffs());
    }

    function sampleMany(State memory state, uint256 count)
        internal
        pure
        returns (uint256[] memory values)
    {
        values = new uint256[](count);
        for (uint256 i; i < count; ++i) {
            values[i] = sample(state);
        }
    }

    function sampleIndex(State memory state, uint256 bits) internal pure returns (uint256) {
        return state.challenger.sampleBits(bits);
    }

    function readBase(State memory state, bytes calldata transcript, uint256 count)
        internal
        pure
        returns (uint256[] memory values)
    {
        uint256 paddedCount = (count + 7) & ~uint256(7);
        require(state.offset + paddedCount * 4 <= transcript.length, "TRANSCRIPT_END");
        values = new uint256[](count);
        for (uint256 i; i < paddedCount; ++i) {
            uint256 value =
                uint32(bytes4(transcript[state.offset + i * 4:state.offset + i * 4 + 4]));
            value = ((value & 0xff) << 24) | ((value & 0xff00) << 8) | ((value >> 8) & 0xff00)
                | (value >> 24);
            if (i < count) {
                require(value < MODULUS, "BASE_RANGE");
                values[i] = value;
                state.challenger.observeBase(value);
            } else {
                require(value == 0, "TRANSCRIPT_PADDING");
            }
        }
        state.offset += paddedCount * 4;
    }

    function readExtension(State memory state, bytes calldata transcript, uint256 count)
        internal
        pure
        returns (uint256[] memory values)
    {
        uint256[] memory scalars = readBase(state, transcript, count * 5);
        values = new uint256[](count);
        for (uint256 i; i < count; ++i) {
            values[i] = (scalars[5 * i] << 224) | (scalars[5 * i + 1] << 192)
                | (scalars[5 * i + 2] << 160) | (scalars[5 * i + 3] << 128)
                | (scalars[5 * i + 4] << 96);
        }
    }

    function readOneExtension(State memory state, bytes calldata transcript)
        internal
        pure
        returns (uint256)
    {
        return readExtension(state, transcript, 1)[0];
    }

    function checkPow(State memory state, bytes calldata transcript, uint256 bits) internal pure {
        if (bits != 0) {
            readBase(state, transcript, 1);
            require(state.challenger.sampleBits(bits) == 0, "GRINDING");
        }
    }

    function digest(uint256[] memory limbs) internal pure returns (bytes32 result) {
        require(limbs.length == 8, "DIGEST_LENGTH");
        uint256 packed;
        for (uint256 i; i < 8; ++i) {
            require(limbs[i] < 1 << 30, "DIGEST_LIMB");
            packed = (packed << 30) | limbs[i];
        }
        result = bytes32(packed << 16);
    }

    function finish(State memory state, bytes calldata transcript) internal pure {
        require(state.offset == transcript.length, "UNUSED_TRANSCRIPT");
    }
}
