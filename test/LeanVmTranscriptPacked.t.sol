// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {LeanVmTranscript} from "../src/leanvm/LeanVmTranscript.sol";
import {LeanVmTranscriptReference} from "./helpers/LeanVmTranscriptReference.sol";

contract LeanVmTranscriptPackedTest is Test {
    using LeanVmTranscript for LeanVmTranscript.State;
    using LeanVmTranscriptReference for LeanVmTranscriptReference.State;
    uint256 private constant P = 2_130_706_433;

    function appendBlock(bytes memory raw, uint256 count, uint256 seed) private pure returns (bytes memory) {
        bytes memory blockData = new bytes(((count + 7) & ~uint256(7)) * 4);
        for (uint256 i; i < count; ++i) {
            uint256 value = uint256(keccak256(abi.encode(seed, i))) % P;
            if (i % 7 == 0) value = P - 1;
            if (i % 11 == 0) value = 0;
            for (uint256 j; j < 4; ++j) {
                blockData[4 * i + j] = bytes1(uint8(value >> (8 * j)));
            }
        }
        return bytes.concat(raw, blockData);
    }

    function compareSequence(bytes calldata raw, uint256 count, uint256 seed) external pure {
        uint256[8] memory capacity;
        for (uint256 i; i < 8; ++i) {
            capacity[i] = (seed % P + i) % P;
        }
        LeanVmTranscript.State memory actual = LeanVmTranscript.initialize(capacity);
        LeanVmTranscriptReference.State memory expected = LeanVmTranscriptReference.initialize(capacity);
        // Leave a partially consumed output block before a zero read.
        require(actual.sampleIndex(13) == expected.sampleIndex(13), "INITIAL_SAMPLE");
        require(actual.readExtension(raw, 0).length == 0, "ZERO_READ");
        require(expected.readExtension(raw, 0).length == 0, "REFERENCE_ZERO");
        require(actual.offset == expected.offset, "ZERO_OFFSET");
        require(actual.sampleIndex(13) == expected.sampleIndex(13), "ZERO_SAMPLE");
        require(
            keccak256(abi.encode(actual.readBase(raw, 3))) == keccak256(abi.encode(expected.readBase(raw, 3))), "BASE"
        );
        require(
            keccak256(abi.encode(actual.readExtension(raw, count)))
                == keccak256(abi.encode(expected.readExtension(raw, count))),
            "PACKED_VALUES"
        );
        require(actual.offset == expected.offset, "EXTENSION_OFFSET");
        for (uint256 i; i < 12; ++i) {
            require(actual.sample() == expected.sample(), "EXTENSION_SAMPLE");
        }
        actual.duplex();
        expected.duplex();
        require(actual.sampleIndex(20) == expected.sampleIndex(20), "DUPLEX");
        require(
            keccak256(abi.encode(actual.readBase(raw, 1))) == keccak256(abi.encode(expected.readBase(raw, 1))),
            "SECOND_BASE"
        );
        require(actual.readOneExtension(raw) == expected.readOneExtension(raw), "ONE_EXTENSION");
        require(
            keccak256(abi.encode(actual.sampleMany(9))) == keccak256(abi.encode(expected.sampleMany(9))),
            "FINAL_SAMPLES"
        );
        actual.finish(raw);
        expected.finish(raw);
    }

    function testFuzzPackedReadParity(uint8 encodedCount, uint256 seed) external view {
        uint256 count = uint256(encodedCount) % 33;
        bytes memory raw = appendBlock(hex"", 3, seed);
        raw = appendBlock(raw, count * 5, seed);
        raw = appendBlock(raw, 1, seed);
        raw = appendBlock(raw, 5, seed);
        this.compareSequence(raw, count, seed);
    }

    function testEveryPaddingLength() external view {
        for (uint256 count; count <= 8; ++count) {
            bytes memory raw = appendBlock(hex"", 3, count);
            raw = appendBlock(raw, count * 5, count);
            raw = appendBlock(raw, 1, count);
            raw = appendBlock(raw, 5, count);
            this.compareSequence(raw, count, count);
        }
    }

    function readOnly(bytes calldata raw, uint256 count, bool useReference)
        external
        pure
        returns (bytes32 digest, uint256 offset)
    {
        uint256[8] memory capacity;
        if (useReference) {
            LeanVmTranscriptReference.State memory state = LeanVmTranscriptReference.initialize(capacity);
            uint256[] memory values = state.readExtension(raw, count);
            digest = keccak256(abi.encode(values, state.sampleMany(3)));
            state.finish(raw);
            offset = state.offset;
        } else {
            LeanVmTranscript.State memory state = LeanVmTranscript.initialize(capacity);
            uint256[] memory values = state.readExtension(raw, count);
            digest = keccak256(abi.encode(values, state.sampleMany(3)));
            state.finish(raw);
            offset = state.offset;
        }
    }

    function testMaxAndZeroCoefficients() external view {
        bytes memory raw = new bytes(32);
        for (uint256 i; i < 5; ++i) {
            uint256 value = i % 2 == 0 ? P - 1 : 0;
            for (uint256 j; j < 4; ++j) {
                raw[4 * i + j] = bytes1(uint8(value >> (8 * j)));
            }
        }
        (bytes32 actual,) = this.readOnly(raw, 1, false);
        (bytes32 expected,) = this.readOnly(raw, 1, true);
        assertEq(actual, expected);
    }

    function testRejectEachNoncanonicalCoefficient() external {
        for (uint256 i; i < 5; ++i) {
            bytes memory raw = new bytes(32);
            for (uint256 j; j < 4; ++j) {
                raw[4 * i + j] = bytes1(uint8(P >> (8 * j)));
            }
            vm.expectRevert();
            this.readOnly(raw, 1, false);
            vm.expectRevert("BASE_RANGE");
            this.readOnly(raw, 1, true);
        }
    }

    function testRejectEveryPaddingByte() external {
        for (uint256 i = 20; i < 32; ++i) {
            bytes memory raw = new bytes(32);
            raw[i] = 0x01;
            vm.expectRevert("TRANSCRIPT_PADDING");
            this.readOnly(raw, 1, false);
        }
    }

    function testRejectTruncatedBlock() external {
        vm.expectRevert("TRANSCRIPT_END");
        this.readOnly(new bytes(31), 1, false);
    }

    function testRejectExtraData() external {
        vm.expectRevert("UNUSED_TRANSCRIPT");
        this.readOnly(new bytes(33), 1, false);
    }

    function testZeroCountEmptyTranscript() external view {
        (bytes32 actual, uint256 offset) = this.readOnly(hex"", 0, false);
        (bytes32 expected,) = this.readOnly(hex"", 0, true);
        assertEq(actual, expected);
        assertEq(offset, 0);
    }

    function challengeAfterRead(bytes calldata raw) external pure returns (uint256) {
        uint256[8] memory capacity;
        LeanVmTranscript.State memory state = LeanVmTranscript.initialize(capacity);
        state.readExtension(raw, 1);
        state.finish(raw);
        return state.sample();
    }

    function testChangedValueChangesChallenge() external view {
        bytes memory raw = new bytes(32);
        uint256 beforeMutation = this.challengeAfterRead(raw);
        raw[0] = 0x01;
        uint256 afterMutation = this.challengeAfterRead(raw);
        assertNotEq(beforeMutation, afterMutation);
    }

    function testGasPackedRead() external {
        bytes memory raw = appendBlock(hex"", 160, 77);
        uint256 start = gasleft();
        (bytes32 candidate,) = this.readOnly(raw, 32, false);
        uint256 candidateGas = start - gasleft();
        start = gasleft();
        (bytes32 expected,) = this.readOnly(raw, 32, true);
        uint256 referenceGas = start - gasleft();
        assertEq(candidate, expected);
        emit log_named_uint("packed extension read gas", candidateGas);
        emit log_named_uint("scalar reference read gas", referenceGas);
    }
}
