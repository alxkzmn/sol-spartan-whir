// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { KeccakChallenger } from "../transcript/KeccakChallenger.sol";
import { KoalaBearExt5 } from "../field/KoalaBearExt5.sol";

/// @dev The raw transcript contains LE-u32 scalars in padded eight-scalar blocks.
/// The Keccak transcript observes the actual protocol scalar count before padding.
library LeanVmTranscript {
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
        if (values.length == 0) return;
        uint256 length = values.length * 4;
        // Reserve the trailing 28 bytes written by the last full-word store.
        bytes memory encoded = new bytes(length + 28);
        for (uint256 i; i < values.length; ++i) {
            uint256 value = values[i];
            require(value < MODULUS, "BASE_RANGE");
            uint256 swapped = ((value & 0xff) << 24) | ((value & 0xff00) << 8)
                | ((value >> 8) & 0xff00) | (value >> 24);
            assembly ("memory-safe") {
                mstore(add(add(encoded, 32), shl(2, i)), shl(224, swapped))
            }
        }
        assembly ("memory-safe") { mstore(encoded, length) }
        state.challenger.observeBytes(encoded);
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

    function sample(State memory state) internal pure returns (uint256 value) {
        // Five canonical 31-bit coefficients occupy at most 160 bits before
        // being shifted into the transport representation.
        for (uint256 i; i < 5; ++i) {
            value = (value << 32) | state.challenger.sampleBase();
        }
        return value << 96;
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
        uint256 fieldCount = count * 5;
        uint256 paddedCount = (fieldCount + 7) & ~uint256(7);
        uint256 start = state.offset;
        uint256 end = start + paddedCount * 4;
        require(end <= transcript.length, "TRANSCRIPT_END");
        values = new uint256[](count);
        for (uint256 i; i < count; ++i) {
            uint256 packed;
            uint256 offset = start + i * 20;
            assembly ("memory-safe") {
                // Reverse bytes within every u32 lane without changing lane order.
                let raw := calldataload(add(transcript.offset, offset))
                let pairs :=
                    or(
                        shl(
                            8,
                            and(
                                raw,
                                0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff
                            )
                        ),
                        shr(
                            8,
                            and(
                                raw,
                                0xff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00
                            )
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
            KoalaBearExt5.validatePacked(packed);
            values[i] = packed;
        }
        for (uint256 i = start + fieldCount * 4; i < end; i += 4) {
            require(bytes4(transcript[i:i + 4]) == 0, "TRANSCRIPT_PADDING");
        }
        // These bytes are the exact concatenation of the validated LE-u32
        // coefficients. Padding is checked above and excluded from absorption.
        // An empty read must preserve any partially consumed output block.
        if (count != 0) state.challenger.observeBytesCalldata(transcript, start, fieldCount * 4);
        state.offset = end;
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
