// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";

import { KeccakChallenger } from "../src/transcript/KeccakChallenger.sol";

contract KoalaBearKeccakChallengerExt8SwarHarness {
    using KeccakChallenger for KeccakChallenger.State;

    function observePair(uint256 first, uint256 second)
        external
        pure
        returns (bytes memory observed)
    {
        KeccakChallenger.State memory challenger;
        challenger.observeValidatedPackedExt8Pair(first, second);
        observed = _observedBytes(challenger);
    }

    function observeRead(bytes calldata data, uint256 offset)
        external
        pure
        returns (uint256 packed, bytes memory observed)
    {
        KeccakChallenger.State memory challenger;
        packed = challenger.observeReadValidatedPackedExt8Le(data, offset);
        observed = _observedBytes(challenger);
    }

    function observeReadPair(bytes calldata data, uint256 offset)
        external
        pure
        returns (uint256 first, uint256 second, bytes memory observed)
    {
        KeccakChallenger.State memory challenger;
        (first, second) = challenger.observeReadValidatedPackedExt8LePair(data, offset);
        observed = _observedBytes(challenger);
    }

    function _observedBytes(KeccakChallenger.State memory challenger)
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

contract KoalaBearKeccakChallengerExt8SwarTest is Test {
    uint256 internal constant MODULUS = 0x7f000001;
    bytes4 internal constant PACKED_RANGE_ERROR = bytes4(0xd53cfe5c);

    KoalaBearKeccakChallengerExt8SwarHarness internal harness;

    function setUp() external {
        harness = new KoalaBearKeccakChallengerExt8SwarHarness();
    }

    function testCanonicalBoundariesAndTranscriptByteOrder() external view {
        uint256[8] memory firstLanes = [
            uint256(0),
            uint256(1),
            MODULUS - 1,
            uint256(0x01020304),
            uint256(0x10203040),
            uint256(2),
            uint256(0x11223344),
            uint256(0x55667700)
        ];
        uint256[8] memory secondLanes;
        unchecked {
            for (uint256 i = 0; i < 8; ++i) {
                secondLanes[i] = MODULUS - 1;
            }
        }

        bytes memory firstEncoded = _encodeLittleEndian(firstLanes);
        bytes memory secondEncoded = _encodeLittleEndian(secondLanes);
        bytes memory data = bytes.concat(hex"a1b2c3", firstEncoded, secondEncoded, hex"d4e5");

        bytes memory pairObserved = harness.observePair(_pack(firstLanes), _pack(secondLanes));
        (uint256 single, bytes memory singleObserved) = harness.observeRead(data, 3);
        (uint256 first, uint256 second, bytes memory readPairObserved) =
            harness.observeReadPair(data, 3);

        assertEq(single, _pack(firstLanes));
        assertEq(first, _pack(firstLanes));
        assertEq(second, _pack(secondLanes));
        assertEq(singleObserved, firstEncoded);
        assertEq(pairObserved, bytes.concat(firstEncoded, secondEncoded));
        assertEq(readPairObserved, pairObserved);
        assertEq(
            firstEncoded, hex"00000000010000000000007f0403020140302010020000004433221100776655"
        );
    }

    function testFuzzCanonicalLanesMatchReferenceEncoding(
        uint256[8] memory rawFirst,
        uint256[8] memory rawSecond
    ) external view {
        uint256[8] memory firstLanes;
        uint256[8] memory secondLanes;
        unchecked {
            for (uint256 i = 0; i < 8; ++i) {
                firstLanes[i] = rawFirst[i] % MODULUS;
                secondLanes[i] = rawSecond[i] % MODULUS;
            }
        }

        bytes memory firstEncoded = _encodeLittleEndian(firstLanes);
        bytes memory secondEncoded = _encodeLittleEndian(secondLanes);
        bytes memory data = bytes.concat(hex"cafe", firstEncoded, secondEncoded, hex"decafbad");

        bytes memory pairObserved = harness.observePair(_pack(firstLanes), _pack(secondLanes));
        (uint256 single, bytes memory singleObserved) = harness.observeRead(data, 2);
        (uint256 first, uint256 second, bytes memory readPairObserved) =
            harness.observeReadPair(data, 2);

        assertEq(single, _pack(firstLanes));
        assertEq(first, _pack(firstLanes));
        assertEq(second, _pack(secondLanes));
        assertEq(singleObserved, firstEncoded);
        assertEq(pairObserved, bytes.concat(firstEncoded, secondEncoded));
        assertEq(readPairObserved, pairObserved);
    }

    function testRejectsEveryInvalidBoundaryInEveryLane() external {
        uint256[4] memory invalids =
            [MODULUS, uint256(0x7fffffff), uint256(0x80000000), uint256(0xffffffff)];
        uint256[8] memory lanes;
        uint256 canonical = _pack(lanes);

        unchecked {
            for (uint256 valueIndex = 0; valueIndex < invalids.length; ++valueIndex) {
                for (uint256 lane = 0; lane < 8; ++lane) {
                    lanes[lane] = invalids[valueIndex];
                    uint256 malformed = _pack(lanes);
                    bytes memory malformedLe = _encodeLittleEndian(lanes);
                    uint256 raw = _word(malformedLe);

                    vm.expectRevert(abi.encodeWithSelector(PACKED_RANGE_ERROR, malformed));
                    harness.observePair(malformed, canonical);

                    vm.expectRevert(abi.encodeWithSelector(PACKED_RANGE_ERROR, malformed));
                    harness.observePair(canonical, malformed);

                    vm.expectRevert(abi.encodeWithSelector(PACKED_RANGE_ERROR, raw));
                    harness.observeRead(malformedLe, 0);

                    vm.expectRevert(abi.encodeWithSelector(PACKED_RANGE_ERROR, raw));
                    harness.observeReadPair(bytes.concat(malformedLe, new bytes(32)), 0);

                    vm.expectRevert(abi.encodeWithSelector(PACKED_RANGE_ERROR, raw));
                    harness.observeReadPair(bytes.concat(new bytes(32), malformedLe), 0);

                    lanes[lane] = 0;
                }
            }
        }
    }

    function _pack(uint256[8] memory lanes) internal pure returns (uint256 packed) {
        unchecked {
            for (uint256 i = 0; i < 8; ++i) {
                packed |= lanes[i] << (224 - 32 * i);
            }
        }
    }

    function _encodeLittleEndian(uint256[8] memory lanes)
        internal
        pure
        returns (bytes memory encoded)
    {
        encoded = new bytes(32);
        unchecked {
            for (uint256 i = 0; i < 8; ++i) {
                uint256 value = lanes[i];
                uint256 offset = i * 4;
                encoded[offset] = bytes1(uint8(value));
                encoded[offset + 1] = bytes1(uint8(value >> 8));
                encoded[offset + 2] = bytes1(uint8(value >> 16));
                encoded[offset + 3] = bytes1(uint8(value >> 24));
            }
        }
    }

    function _word(bytes memory data) internal pure returns (uint256 word) {
        assembly ("memory-safe") {
            word := mload(add(data, 0x20))
        }
    }
}
