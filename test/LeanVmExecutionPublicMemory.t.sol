// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import { Test } from "forge-std/Test.sol";
import { LeanVmExecution as Execution } from "../src/leanvm/LeanVmExecution.sol";

contract LeanVmExecutionPublicMemoryHarness {
    function verify(bytes calldata transcript, uint256[] memory words, uint256 offset) external pure {
        uint256[8] memory publicInput;
        Execution.Config memory config;
        config.bytecodeLog = 8;
        config.rate = 5;
        Execution.verifyWithPublicMemory(transcript, transcript[0:0], publicInput, config, 0, words, offset);
    }
}

contract LeanVmExecutionPublicMemoryTest is Test {
    LeanVmExecutionPublicMemoryHarness harness;
    function setUp() external { harness = new LeanVmExecutionPublicMemoryHarness(); }

    // Valid padded dimensions: rate5, memory2^16, and all three tables2^8.
    function dimensions() internal pure returns (bytes memory) {
        return hex"0500000010000000080000000800000008000000000000000000000000000000";
    }

    function testRejectEmptyRegion() external {
        vm.expectRevert("PUBLIC_MEMORY_EMPTY");
        harness.verify(bytes(""), new uint256[](0), 4096);
    }

    function testRejectNonPowerOfTwoRegion() external {
        vm.expectRevert("POWER_OF_TWO");
        harness.verify(bytes(""), new uint256[](255), 4096);
    }

    function testRejectUnalignedRegion() external {
        vm.expectRevert("PUBLIC_MEMORY_ALIGNMENT");
        harness.verify(bytes(""), new uint256[](256), 4097);
    }

    function testRejectRegionPastMemory() external {
        vm.expectRevert("PUBLIC_MEMORY_RANGE");
        harness.verify(dimensions(), new uint256[](256), 65536);
    }

    function testRejectRegionOffsetPastMemoryEnd() external {
        vm.expectRevert("PUBLIC_MEMORY_RANGE");
        harness.verify(dimensions(), new uint256[](256), 65792);
    }

    function testRejectNoncanonicalPublicWord() external {
        uint256[] memory words = new uint256[](256);
        words[255] = 2_130_706_433;
        vm.expectRevert("BASE_RANGE");
        harness.verify(bytes(""), words, 4096);
    }

    function testRejectNoncanonicalHeaderOffset() external {
        vm.expectRevert("BASE_RANGE");
        harness.verify(bytes(""), new uint256[](256), uint256(1) << 32);
    }

    function testValidRegionReachesCommitmentGeometryCheck() external {
        vm.expectRevert("STACKED_DIM");
        harness.verify(dimensions(), new uint256[](256), 4096);
    }
}
