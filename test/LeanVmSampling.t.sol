// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { KeccakChallenger } from "../src/transcript/KeccakChallenger.sol";
import { KoalaBearExt5 as EF } from "../src/field/KoalaBearExt5.sol";
import { LeanVmTranscript as Transcript } from "../src/leanvm/LeanVmTranscript.sol";
import { LeanVmGkrSumcheck as Cubic } from "../src/leanvm/LeanVmGkrSumcheck.sol";

contract LeanVmSamplingHarness {
    using KeccakChallenger for KeccakChallenger.State;

    struct Result {
        uint256[] values;
        uint256 inputLength;
        bytes32 inputHash;
        bytes32 outputBlock;
        uint256 outputIndex;
    }

    function observeSequence(
        bool candidate,
        uint256[] memory values,
        uint256 prefix,
        uint256 warmups
    ) external pure returns (Result memory result) {
        uint256[8] memory cap = [uint256(7), 9, 11, 13, 17, 19, 23, 29];
        Transcript.State memory state = Transcript.initialize(cap);
        for (uint256 i; i < prefix; ++i) {
            state.challenger.observeBase(i);
        }
        for (uint256 i; i < warmups; ++i) {
            state.challenger.sampleBase();
        }
        bytes32 inputValues = keccak256(abi.encode(values));
        if (candidate) {
            Transcript.observe(state, values);
        } else {
            for (uint256 i; i < values.length; ++i) {
                state.challenger.observeBase(values[i]);
            }
        }
        require(inputValues == keccak256(abi.encode(values)), "INPUT_CHANGED");
        result.inputLength = state.challenger.inputLen;
        result.inputHash = state.challenger.debugInputHash();
        result.outputBlock = state.challenger.outputBlock;
        result.outputIndex = state.challenger.outputIndex;
        result.values = new uint256[](6);
        for (uint256 i; i < result.values.length; ++i) {
            result.values[i] = EF.pack(state.challenger.sampleExt5Coeffs());
        }
    }

    function sequence(
        uint256 mode,
        bytes32 blockValue,
        uint256 index,
        uint256 count,
        bool interleave
    ) external pure returns (Result memory result) {
        require(index <= 32 && index % 4 == 0, "TEST_INDEX");
        uint256[8] memory cap = [uint256(7), 9, 11, 13, 17, 19, 23, 29];
        Transcript.State memory state = Transcript.initialize(cap);
        state.challenger.outputBlock = blockValue;
        state.challenger.outputIndex = index;
        result.values = new uint256[](count);
        for (uint256 i; i < count; ++i) {
            if (interleave && i % 3 == 2) state.challenger.observeBase(i);
            // The reference retains the unchanged scalar rejection sampler and
            // array packing, independently of both optimized entry points.
            if (mode == 0) result.values[i] = EF.pack(state.challenger.sampleExt5Coeffs());
            else if (mode == 1) result.values[i] = Transcript.sample(state);
            else result.values[i] = Cubic.samplePacked(state);
            EF.validatePacked(result.values[i]);
        }
        result.inputLength = state.challenger.inputLen;
        result.inputHash = state.challenger.debugInputHash();
        result.outputBlock = state.challenger.outputBlock;
        result.outputIndex = state.challenger.outputIndex;
    }
}

contract LeanVmSamplingTest is Test {
    uint256 private constant P = 2_130_706_433;
    LeanVmSamplingHarness private harness = new LeanVmSamplingHarness();

    function compare(bytes32 blockValue, uint256 index, uint256 count, bool interleave)
        private
        view
    {
        bytes memory expected =
            abi.encode(harness.sequence(0, blockValue, index, count, interleave));
        assertEq(abi.encode(harness.sequence(1, blockValue, index, count, interleave)), expected);
        assertEq(abi.encode(harness.sequence(2, blockValue, index, count, interleave)), expected);
    }

    function testFuzzBatchedObservationPreservesStateAndInput(
        bytes32 seed,
        uint16 rawLength,
        uint8 prefix
    ) external view {
        uint256[] memory values = new uint256[](rawLength % 301);
        for (uint256 i; i < values.length; ++i) {
            values[i] = uint256(keccak256(abi.encode(seed, i))) % P;
        }
        assertEq(
            abi.encode(harness.observeSequence(true, values, prefix % 40, prefix % 9)),
            abi.encode(harness.observeSequence(false, values, prefix % 40, prefix % 9))
        );
    }

    function testObservationCapacityBoundariesAndEmptyInput() external view {
        uint256[9] memory lengths = [uint256(0), 1, 7, 8, 9, 16, 17, 254, 256];
        for (uint256 n; n < lengths.length; ++n) {
            uint256[] memory values = new uint256[](lengths[n]);
            for (uint256 i; i < values.length; ++i) {
                values[i] = i % 2 == 0 ? P - 1 : 0;
            }
            for (uint256 warmups; warmups <= 8; ++warmups) {
                assertEq(
                    abi.encode(harness.observeSequence(true, values, 13, warmups)),
                    abi.encode(harness.observeSequence(false, values, 13, warmups))
                );
            }
        }
    }

    function testObservationRejectsNoncanonicalFieldAtEveryPosition() external {
        uint256[] memory values = new uint256[](17);
        for (uint256 i; i < values.length; ++i) {
            values[i] = P;
            vm.expectRevert(bytes("BASE_RANGE"));
            harness.observeSequence(true, values, 5, 3);
            values[i] = type(uint256).max;
            vm.expectRevert(bytes("BASE_RANGE"));
            harness.observeSequence(true, values, 5, 3);
            values[i] = P - 1;
        }
    }

    function testFuzzSamplingPreservesCompleteState(
        bytes32 blockValue,
        uint8 rawIndex,
        uint8 rawCount
    ) external view {
        compare(blockValue, uint256(rawIndex % 9) * 4, rawCount % 13, rawIndex >= 128);
    }

    function testEveryRejectionLaneAndCursor() external view {
        uint256[6] memory boundary = [uint256(0), P - 1, P, 0x7fffffff, 0x80000000, 0xffffffff];
        uint256 ordinary;
        for (uint256 i; i < 8; ++i) {
            ordinary |= (i + 1) << (32 * i);
        }
        for (uint256 lane; lane < 8; ++lane) {
            for (uint256 b; b < boundary.length; ++b) {
                uint256 blockValue = (ordinary & ~(uint256(0xffffffff) << (32 * lane)))
                    | (boundary[b] << (32 * lane));
                for (uint256 index; index <= 32; index += 4) {
                    compare(bytes32(blockValue), index, 4, false);
                }
            }
        }
    }

    function testAllRejectedBlockAndEmptySequence() external view {
        for (uint256 index; index <= 32; index += 4) {
            compare(bytes32(type(uint256).max), index, 12, true);
            compare(bytes32(type(uint256).max), index, 0, false);
        }
    }
}
