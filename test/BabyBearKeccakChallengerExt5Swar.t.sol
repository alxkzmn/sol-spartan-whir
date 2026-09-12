// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";

import { BabyBearKeccakChallenger } from "../src/transcript/BabyBearKeccakChallenger.sol";

contract BabyBearKeccakChallengerExt5SwarHarness {
    using BabyBearKeccakChallenger for BabyBearKeccakChallenger.State;

    function observeRead(bytes calldata data, uint256 offset)
        external
        pure
        returns (uint256 packed, bytes memory observed)
    {
        BabyBearKeccakChallenger.State memory challenger;
        packed = challenger.observeReadValidatedPackedExt5Le(data, offset);
        observed = _observedBytes(challenger);
    }

    function observePair(uint256 first, uint256 second)
        external
        pure
        returns (bytes memory observed)
    {
        BabyBearKeccakChallenger.State memory challenger;
        challenger.observeValidatedPackedExt5Pair(first, second);
        observed = _observedBytes(challenger);
    }

    function _observedBytes(BabyBearKeccakChallenger.State memory challenger)
        private
        pure
        returns (bytes memory observed)
    {
        observed = new bytes(challenger.inputLen);
        bytes memory buffer = challenger.inputBuffer;
        unchecked {
            for (uint256 i = 0; i < challenger.inputLen; ++i) {
                observed[i] = buffer[i];
            }
        }
    }
}

contract BabyBearKeccakChallengerExt5SwarTest is Test {
    uint256 internal constant MODULUS = 0x78000001;
    bytes4 internal constant PACKED_RANGE_ERROR = bytes4(0xd53cfe5c);

    BabyBearKeccakChallengerExt5SwarHarness internal harness;

    function setUp() external {
        harness = new BabyBearKeccakChallengerExt5SwarHarness();
    }

    function testObserveReadCanonicalBoundariesAndTranscriptByteOrder() external view {
        uint256[5] memory lanes =
            [uint256(0), uint256(1), MODULUS - 1, uint256(0x01020304), uint256(0x10203040)];
        bytes memory encoded = _encodeLittleEndian(lanes);
        bytes memory data = bytes.concat(hex"a1b2c3", encoded, hex"d4e5f60718293a4b5c6d7e8f");

        (uint256 packed, bytes memory observed) = harness.observeRead(data, 3);

        assertEq(packed, _pack(lanes));
        assertEq(observed, encoded);
        assertEq(observed, hex"0000000001000000000000780403020140302010");
    }

    function testObservePairCanonicalBoundariesAndTranscriptByteOrder() external view {
        uint256[5] memory firstLanes =
            [uint256(0), MODULUS - 1, uint256(0x01020304), uint256(1), uint256(0x10203040)];
        uint256[5] memory secondLanes =
            [MODULUS - 1, uint256(0), uint256(0x11223344), uint256(2), uint256(0x55667700)];

        bytes memory observed = harness.observePair(_pack(firstLanes), _pack(secondLanes));
        bytes memory expected =
            bytes.concat(_encodeLittleEndian(firstLanes), _encodeLittleEndian(secondLanes));

        assertEq(observed, expected);
        assertEq(
            observed,
            hex"00000000000000780403020101000000403020100000007800000000443322110200000000776655"
        );
    }

    function testFuzzCanonicalLanesMatchReferenceEncoding(
        uint256[5] memory rawFirst,
        uint256[5] memory rawSecond
    ) external view {
        uint256[5] memory firstLanes;
        uint256[5] memory secondLanes;
        unchecked {
            for (uint256 i = 0; i < 5; ++i) {
                firstLanes[i] = rawFirst[i] % MODULUS;
                secondLanes[i] = rawSecond[i] % MODULUS;
            }
        }

        bytes memory firstEncoded = _encodeLittleEndian(firstLanes);
        bytes memory secondEncoded = _encodeLittleEndian(secondLanes);
        bytes memory readData = bytes.concat(hex"cafe", firstEncoded, hex"decafbad0102030405060708");

        (uint256 packed, bytes memory readObserved) = harness.observeRead(readData, 2);
        bytes memory pairObserved = harness.observePair(_pack(firstLanes), _pack(secondLanes));

        assertEq(packed, _pack(firstLanes));
        assertEq(readObserved, firstEncoded);
        assertEq(pairObserved, bytes.concat(firstEncoded, secondEncoded));
    }

    function testObserveReadRejectsModulusInEveryLane() external {
        uint256[5] memory lanes;
        unchecked {
            for (uint256 i = 0; i < 5; ++i) {
                lanes[i] = MODULUS;
                vm.expectPartialRevert(PACKED_RANGE_ERROR);
                harness.observeRead(_encodeLittleEndian(lanes), 0);
                lanes[i] = 0;
            }
        }
    }

    function testObservePairRejectsModulusInEveryLaneAndEitherArgument() external {
        uint256[5] memory lanes;
        uint256 canonical = _pack(lanes);
        unchecked {
            for (uint256 i = 0; i < 5; ++i) {
                lanes[i] = MODULUS;
                uint256 malformed = _pack(lanes);

                vm.expectRevert(abi.encodeWithSelector(PACKED_RANGE_ERROR, malformed));
                harness.observePair(malformed, canonical);

                vm.expectRevert(abi.encodeWithSelector(PACKED_RANGE_ERROR, malformed));
                harness.observePair(canonical, malformed);
                lanes[i] = 0;
            }
        }
    }

    function testObservePairRejectsNonzeroLowGarbage() external {
        uint256[5] memory lanes = [uint256(1), uint256(2), uint256(3), uint256(4), uint256(5)];
        uint256 canonical = _pack(lanes);
        uint256[4] memory garbage =
            [uint256(1), uint256(1) << 31, uint256(1) << 64, uint256(1) << 95];

        unchecked {
            for (uint256 i = 0; i < garbage.length; ++i) {
                uint256 malformed = canonical | garbage[i];

                vm.expectRevert(abi.encodeWithSelector(PACKED_RANGE_ERROR, malformed));
                harness.observePair(malformed, canonical);

                vm.expectRevert(abi.encodeWithSelector(PACKED_RANGE_ERROR, malformed));
                harness.observePair(canonical, malformed);
            }
        }
    }

    function _pack(uint256[5] memory lanes) internal pure returns (uint256 packed) {
        packed = (lanes[0] << 224) | (lanes[1] << 192) | (lanes[2] << 160) | (lanes[3] << 128)
            | (lanes[4] << 96);
    }

    function _encodeLittleEndian(uint256[5] memory lanes)
        internal
        pure
        returns (bytes memory encoded)
    {
        encoded = new bytes(20);
        unchecked {
            for (uint256 i = 0; i < 5; ++i) {
                uint256 value = lanes[i];
                uint256 offset = i * 4;
                encoded[offset] = bytes1(uint8(value));
                encoded[offset + 1] = bytes1(uint8(value >> 8));
                encoded[offset + 2] = bytes1(uint8(value >> 16));
                encoded[offset + 3] = bytes1(uint8(value >> 24));
            }
        }
    }
}
