// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import { Test } from "forge-std/Test.sol";
import { KoalaBearExt5 as EF } from "../src/field/KoalaBearExt5.sol";
import { KeccakChallenger } from "../src/transcript/KeccakChallenger.sol";
import { LeanVmTranscript as Transcript } from "../src/leanvm/LeanVmTranscript.sol";
import { LeanVmPolynomial as Poly } from "../src/leanvm/LeanVmPolynomial.sol";
import { LeanVmGkrSumcheck as Cubic } from "../src/leanvm/LeanVmGkrSumcheck.sol";

library GkrSumcheckTestSetup {
    using Transcript for Transcript.State;

    function initial(uint256 warmups) internal pure returns (Transcript.State memory state) {
        uint256[8] memory capacity = [uint256(7), 9, 11, 13, 17, 19, 23, 29];
        state = Transcript.initialize(capacity);
        for (uint256 i; i < warmups; ++i) state.sample();
    }
}

contract LeanVmGkrSumcheckHarness {
    using Transcript for Transcript.State;
    using KeccakChallenger for KeccakChallenger.State;

    struct Result {
        uint256[] point;
        uint256 finalValue;
        uint256 offset;
        uint256 inputLength;
        bytes32 inputHash;
        bytes32 outputBlock;
        uint256 outputIndex;
        uint256[4] continuation;
    }

    function run(bool candidate, bytes calldata raw, uint256 target, uint256 rounds, uint256 offset, uint256 warmups)
        external pure returns (Result memory result)
    {
        Transcript.State memory state = GkrSumcheckTestSetup.initial(warmups);
        state.offset = offset;
        if (candidate) (result.point, result.finalValue) = Cubic.verify(state, raw, target, rounds);
        else (result.point, result.finalValue) = Poly.sumcheck(state, raw, target, rounds, 3, 0);
        result.offset = state.offset;
        result.inputLength = state.challenger.inputLen;
        result.inputHash = state.challenger.debugInputHash();
        result.outputBlock = state.challenger.outputBlock;
        result.outputIndex = state.challenger.outputIndex;
        result.continuation[0] = state.sample();
        result.continuation[1] = state.sample();
        result.continuation[2] = state.sampleIndex(17);
        result.continuation[3] = state.sample();
    }

    function runReversedWithTail(
        bytes calldata raw,
        uint256 target,
        uint256 rounds,
        uint256 offset,
        uint256 warmups
    ) external pure returns (Result memory result) {
        Transcript.State memory state = GkrSumcheckTestSetup.initial(warmups);
        state.offset = offset;
        (result.point, result.finalValue) = Cubic.verifyReversedWithTail(state, raw, target, rounds);
        result.offset = state.offset;
        result.inputLength = state.challenger.inputLen;
        result.inputHash = state.challenger.debugInputHash();
        result.outputBlock = state.challenger.outputBlock;
        result.outputIndex = state.challenger.outputIndex;
        result.continuation[0] = state.sample();
        result.continuation[1] = state.sample();
        result.continuation[2] = state.sampleIndex(17);
        result.continuation[3] = state.sample();
    }

    function sampleSequence(bool candidate, bytes32 outputBlock, uint256 outputIndex, uint256 count)
        external pure returns (uint256[] memory values, uint256 finalIndex, bytes32 finalBlock, bytes32 inputHash)
    {
        require(outputIndex <= 32 && outputIndex % 4 == 0, "TEST_INDEX");
        Transcript.State memory state = GkrSumcheckTestSetup.initial(0);
        state.challenger.outputBlock = outputBlock;
        state.challenger.outputIndex = outputIndex;
        values = new uint256[](count);
        for (uint256 i; i < count; ++i) values[i] = candidate ? Cubic.samplePacked(state) : state.sample();
        return (values, state.challenger.outputIndex, state.challenger.outputBlock, state.challenger.debugInputHash());
    }
}

contract LeanVmGkrSumcheckTest is Test {
    using Transcript for Transcript.State;
    using KeccakChallenger for KeccakChallenger.State;
    uint256 constant P = 2_130_706_433;
    LeanVmGkrSumcheckHarness harness = new LeanVmGkrSumcheckHarness();

    function randomElement(bytes32 seed, uint256 round, uint256 coefficient) private pure returns (uint256) {
        uint256[5] memory limbs;
        for (uint256 i; i < 5; ++i) limbs[i] = uint256(keccak256(abi.encode(seed, round, coefficient, i))) % P;
        return EF.pack(limbs);
    }

    function writeLe(bytes memory out, uint256 offset, uint256 value) private pure {
        out[offset] = bytes1(uint8(value));
        out[offset + 1] = bytes1(uint8(value >> 8));
        out[offset + 2] = bytes1(uint8(value >> 16));
        out[offset + 3] = bytes1(uint8(value >> 24));
    }

    function readLe(bytes memory input, uint256 offset) private pure returns (uint256) {
        return uint8(input[offset]) | (uint256(uint8(input[offset + 1])) << 8)
            | (uint256(uint8(input[offset + 2])) << 16) | (uint256(uint8(input[offset + 3])) << 24);
    }

    // Construct valid rounds using the unchanged generic challenger and Horner
    // evaluator. c1 is chosen to satisfy 2*c0+c1+c2+c3=the previous target.
    function makeProof(bytes32 seed, uint256 rounds, uint256 warmups)
        private pure returns (bytes memory raw, uint256 initialTarget, uint256 finalValue, uint256[] memory point)
    {
        raw = new bytes(rounds * 96);
        point = new uint256[](rounds);
        Transcript.State memory state = GkrSumcheckTestSetup.initial(warmups);
        initialTarget = randomElement(seed, 99, 7);
        finalValue = initialTarget;
        for (uint256 round; round < rounds; ++round) {
            uint256[] memory coefficients = new uint256[](4);
            coefficients[0] = randomElement(seed, round, 0);
            coefficients[2] = randomElement(seed, round, 2);
            coefficients[3] = randomElement(seed, round, 3);
            coefficients[1] = EF.sub(EF.sub(EF.sub(finalValue, EF.add(coefficients[0], coefficients[0])), coefficients[2]), coefficients[3]);
            bytes memory observed = new bytes(80);
            for (uint256 c; c < 4; ++c) {
                uint256[5] memory limbs = EF.unpack(coefficients[c]);
                for (uint256 j; j < 5; ++j) {
                    writeLe(raw, round * 96 + c * 20 + j * 4, limbs[j]);
                    writeLe(observed, c * 20 + j * 4, limbs[j]);
                }
            }
            state.challenger.observeBytes(observed);
            point[round] = state.sample();
            finalValue = Poly.horner(coefficients, point[round]);
        }
    }

    function checkProof(bytes32 seed, uint256 rounds, uint256 warmups) private view {
        (bytes memory raw, uint256 target, uint256 expected, uint256[] memory point) = makeProof(seed, rounds, warmups);
        LeanVmGkrSumcheckHarness.Result memory generic = harness.run(false, raw, target, rounds, 0, warmups);
        LeanVmGkrSumcheckHarness.Result memory candidate = harness.run(true, raw, target, rounds, 0, warmups);
        assertEq(abi.encode(candidate), abi.encode(generic));
        assertEq(candidate.finalValue, expected);
        assertEq(candidate.point, point);
        assertEq(candidate.offset, raw.length);
    }

    function testFuzzGenericParity(bytes32 seed, uint8 rawRounds, uint8 rawWarmups) external view {
        checkProof(seed, rawRounds % 7, rawWarmups % 8);
    }

    function testAllSelectedGkrLayerSizes() external view {
        for (uint256 rounds = 5; rounds <= 21; ++rounds) checkProof(bytes32(rounds), rounds, 1);
    }

    function testReversedPointWithTailPreservesTranscript() external view {
        (bytes memory raw, uint256 target,,) = makeProof(bytes32(uint256(91)), 5, 2);
        LeanVmGkrSumcheckHarness.Result memory forward = harness.run(true, raw, target, 5, 0, 2);
        LeanVmGkrSumcheckHarness.Result memory reversed =
            harness.runReversedWithTail(raw, target, 5, 0, 2);
        assertEq(reversed.finalValue, forward.finalValue);
        assertEq(reversed.offset, forward.offset);
        assertEq(reversed.inputLength, forward.inputLength);
        assertEq(reversed.inputHash, forward.inputHash);
        assertEq(reversed.outputBlock, forward.outputBlock);
        assertEq(reversed.outputIndex, forward.outputIndex);
        for (uint256 i; i < forward.continuation.length; ++i) {
            assertEq(reversed.continuation[i], forward.continuation[i]);
        }
        assertEq(reversed.point.length, forward.point.length + 1);
        for (uint256 i; i < forward.point.length; ++i) {
            assertEq(reversed.point[i], forward.point[forward.point.length - 1 - i]);
        }
        assertEq(reversed.point[reversed.point.length - 1], 0);
    }

    function testZeroRoundsPreserveTargetAndTranscript() external view {
        (bytes memory raw, uint256 target,,) = makeProof(bytes32(uint256(13)), 0, 3);
        LeanVmGkrSumcheckHarness.Result memory generic = harness.run(false, raw, target, 0, 0, 3);
        LeanVmGkrSumcheckHarness.Result memory candidate = harness.run(true, raw, target, 0, 0, 3);
        assertEq(abi.encode(candidate), abi.encode(generic));
        assertEq(candidate.offset, 0);
        assertEq(candidate.finalValue, target);
        assertEq(candidate.point.length, 0);
    }

    function testOffsetAndUnconsumedSuffix() external view {
        (bytes memory raw, uint256 target,,) = makeProof(bytes32(uint256(72)), 3, 2);
        bytes memory wrapped = abi.encodePacked(hex"01020304050607", raw, hex"89abcdef");
        LeanVmGkrSumcheckHarness.Result memory generic = harness.run(false, wrapped, target, 3, 7, 2);
        LeanVmGkrSumcheckHarness.Result memory candidate = harness.run(true, wrapped, target, 3, 7, 2);
        assertEq(abi.encode(candidate), abi.encode(generic));
        assertEq(candidate.offset, 7 + raw.length);
    }

    function testEveryCoefficientAndLimbMutationIsRejected() external {
        (bytes memory raw, uint256 target,,) = makeProof(bytes32(uint256(2)), 3, 0);
        for (uint256 round; round < 3; ++round) {
            for (uint256 scalar; scalar < 20; ++scalar) {
                uint256 offset = round * 96 + scalar * 4;
                uint256 saved = readLe(raw, offset);
                writeLe(raw, offset, (saved + 1) % P);
                vm.expectRevert("SUMCHECK_IDENTITY");
                harness.run(false, raw, target, 3, 0, 0);
                vm.expectRevert("SUMCHECK_IDENTITY");
                harness.run(true, raw, target, 3, 0, 0);
                writeLe(raw, offset, saved);
            }
        }
    }

    function testEveryPaddingByteIsRejected() external {
        (bytes memory raw, uint256 target,,) = makeProof(bytes32(uint256(2)), 1, 0);
        for (uint256 i = 80; i < 96; ++i) {
            raw[i] = 0x01;
            vm.expectRevert("TRANSCRIPT_PADDING");
            harness.run(false, raw, target, 1, 0, 0);
            vm.expectRevert("TRANSCRIPT_PADDING");
            harness.run(true, raw, target, 1, 0, 0);
            raw[i] = 0;
        }
    }

    function testShortRoundIsRejected() external {
        (bytes memory raw, uint256 target,,) = makeProof(bytes32(uint256(2)), 1, 0);
        uint256[8] memory lengths = [uint256(0), 1, 19, 20, 79, 80, 92, 95];
        for (uint256 i; i < lengths.length; ++i) {
            bytes memory truncated = new bytes(lengths[i]);
            for (uint256 j; j < truncated.length; ++j) truncated[j] = raw[j];
            vm.expectRevert("TRANSCRIPT_END");
            harness.run(false, truncated, target, 1, 0, 0);
            vm.expectRevert("TRANSCRIPT_END");
            harness.run(true, truncated, target, 1, 0, 0);
        }
    }

    function testNoncanonicalCoefficientIsRejected() external {
        (bytes memory raw, uint256 target,,) = makeProof(bytes32(uint256(2)), 1, 0);
        for (uint256 c; c < 4; ++c) {
            uint256 offset = c * 20 + 16;
            uint256 saved = readLe(raw, offset);
            writeLe(raw, offset, P);
            vm.expectPartialRevert(EF.PackedExtensionElementOutOfRange.selector);
            harness.run(false, raw, target, 1, 0, 0);
            vm.expectPartialRevert(EF.PackedExtensionElementOutOfRange.selector);
            harness.run(true, raw, target, 1, 0, 0);
            writeLe(raw, offset, saved);
        }
    }

    function testPackedSamplingRejectsAndMasksExactly() external view {
        uint256 blockValue = uint256(0x7fffffff) | (P << 32) | (uint256(0x80000007) << 64)
            | ((P - 1) << 96) | (uint256(1) << 160) | (uint256(2) << 192);
        (uint256[] memory first, uint256 remaining,,) = harness.sampleSequence(true, bytes32(blockValue), 32, 1);
        uint256[5] memory expected = [uint256(7), P - 1, 0, 1, 2];
        assertEq(first[0], EF.pack(expected));
        assertEq(remaining, 4);
        for (uint256 index; index <= 32; index += 4) {
            (uint256[] memory a, uint256 ai, bytes32 ab, bytes32 ah) = harness.sampleSequence(false, bytes32(blockValue), index, 12);
            (uint256[] memory b, uint256 bi, bytes32 bb, bytes32 bh) = harness.sampleSequence(true, bytes32(blockValue), index, 12);
            assertEq(abi.encode(a, ai, ab, ah), abi.encode(b, bi, bb, bh));
        }
    }
}
