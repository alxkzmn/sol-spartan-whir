// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { KoalaBearExt5Precompile } from "../src/field/KoalaBearExt5Precompile.sol";
import { Ext5PrecompileHarness } from "./helpers/Ext5PrecompileHarness.sol";

contract Ext5PrecompileHarnessTest is Test {
    Ext5PrecompileHarness internal harness;

    uint256 internal constant A0 =
        0x0000000100000002000000030000000400000005000000000000000000000000;
    uint256 internal constant A1 =
        0x000000070000000b0000000d0000001100000013000000000000000000000000;
    uint256 internal constant B0 =
        0x000000170000001d0000001f0000002500000029000000000000000000000000;
    uint256 internal constant B1 =
        0x0000002b0000002f000000350000003b0000003d000000000000000000000000;
    uint256 internal constant ACC =
        0x0000004300000047000000490000004f00000053000000000000000000000000;

    function setUp() public {
        harness = new Ext5PrecompileHarness();
    }

    function testPackMacInputEmptyWithoutAccumulator() external view {
        uint256[] memory packedA = new uint256[](0);
        uint256[] memory packedB = new uint256[](0);

        bytes memory expected = _macHeader(0, 0);
        bytes memory actual = harness.packMacInputForTest(0, false, packedA, packedB);

        assertEq(actual, expected);
    }

    function testPackMacInputEmptyWithAccumulator() external view {
        uint256[] memory packedA = new uint256[](0);
        uint256[] memory packedB = new uint256[](0);

        bytes memory expected = bytes.concat(_macHeader(0, 1), bytes32(ACC));
        bytes memory actual = harness.packMacInputForTest(ACC, true, packedA, packedB);

        assertEq(actual, expected);
    }

    function testPackMacInputTwoPairsWithoutAccumulator() external view {
        uint256[] memory packedA = new uint256[](2);
        uint256[] memory packedB = new uint256[](2);
        packedA[0] = A0;
        packedA[1] = A1;
        packedB[0] = B0;
        packedB[1] = B1;

        bytes memory expected =
            bytes.concat(_macHeader(2, 0), bytes32(A0), bytes32(B0), bytes32(A1), bytes32(B1));
        bytes memory actual = harness.packMacInputForTest(0, false, packedA, packedB);

        assertEq(actual, expected);
    }

    function testPackMacInputTwoPairsWithAccumulator() external view {
        uint256[] memory packedA = new uint256[](2);
        uint256[] memory packedB = new uint256[](2);
        packedA[0] = A0;
        packedA[1] = A1;
        packedB[0] = B0;
        packedB[1] = B1;

        bytes memory expected = bytes.concat(
            _macHeader(2, 1), bytes32(ACC), bytes32(A0), bytes32(B0), bytes32(A1), bytes32(B1)
        );
        bytes memory actual = harness.packMacInputForTest(ACC, true, packedA, packedB);

        assertEq(actual, expected);
    }

    function testPackMacInputRejectsLengthMismatch() external {
        uint256[] memory packedA = new uint256[](1);
        uint256[] memory packedB = new uint256[](0);
        packedA[0] = A0;

        vm.expectRevert(bytes("LEN_MAC"));
        harness.packMacInputForTest(0, false, packedA, packedB);
    }

    function testPackMacInputRejectsOversizedLength() external {
        uint256[] memory packedA = new uint256[](1025);
        uint256[] memory packedB = new uint256[](1025);

        vm.expectRevert(bytes("MAC_N"));
        harness.packMacInputForTest(0, false, packedA, packedB);
    }

    function _macHeader(uint256 n, uint256 flags) internal pure returns (bytes memory out) {
        uint256 fieldId = KoalaBearExt5Precompile.EXTFIELD_MAC_FIELD_ID_KOALABEAR_EXT5;
        out = new bytes(8);
        assembly ("memory-safe") {
            let ptr := add(out, 0x20)
            mstore8(ptr, shr(8, fieldId))
            mstore8(add(ptr, 0x01), fieldId)
            mstore8(add(ptr, 0x02), shr(8, n))
            mstore8(add(ptr, 0x03), n)
            mstore8(add(ptr, 0x04), shr(24, flags))
            mstore8(add(ptr, 0x05), shr(16, flags))
            mstore8(add(ptr, 0x06), shr(8, flags))
            mstore8(add(ptr, 0x07), flags)
        }
    }
}
