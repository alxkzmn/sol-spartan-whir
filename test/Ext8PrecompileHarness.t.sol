// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { KoalaBearExt8Precompile } from "../src/field/KoalaBearExt8Precompile.sol";
import { Ext8PrecompileHarness } from "./helpers/Ext8PrecompileHarness.sol";

contract Ext8PrecompileHarnessTest is Test {
    Ext8PrecompileHarness internal harness;

    uint256 internal constant P = 0x7f000001;
    uint256 internal constant A0 =
        0x0000000100000002000000030000000400000005000000060000000700000008;
    uint256 internal constant A1 =
        0x0000000b0000000d0000001100000013000000170000001d0000001f00000025;
    uint256 internal constant B0 =
        0x000000290000002b0000002f000000350000003b0000003d0000004300000047;
    uint256 internal constant B1 =
        0x000000490000004f00000053000000590000006100000065000000670000006b;
    uint256 internal constant ACC =
        0x0000006d000000710000007f00000083000000890000008b0000009500000097;

    function setUp() public {
        harness = new Ext8PrecompileHarness();
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

    function testPackLinProdInputExplicitTerms() external view {
        uint256[] memory alpha = _pair(A0, A1);
        uint256[] memory beta = _pair(B0, B1);
        uint256[] memory scalars = new uint256[](0);
        uint256[] memory x = _pair(ACC, A0);

        bytes memory expected = bytes.concat(
            _linProdHeader(2, 0),
            bytes32(A0),
            bytes32(B0),
            bytes32(ACC),
            bytes32(A1),
            bytes32(B1),
            bytes32(A0)
        );
        bytes memory actual = harness.packLinProdInputForTest(0, alpha, beta, scalars, x);

        assertEq(actual, expected);
    }

    function testPackLinProdInputImplicitAlphaExtBeta() external view {
        uint256[] memory beta = _pair(B0, B1);
        uint256[] memory x = _pair(A0, A1);

        bytes memory expected =
            bytes.concat(_linProdHeader(2, 1), bytes32(B0), bytes32(A0), bytes32(B1), bytes32(A1));
        bytes memory actual =
            harness.packLinProdInputForTest(1, new uint256[](0), beta, new uint256[](0), x);

        assertEq(actual, expected);
    }

    function testPackLinProdInputImplicitAlphaBaseBeta() external view {
        uint256[] memory scalars = _pair(0x01020304, 0x05060708);
        uint256[] memory x = _pair(A0, A1);

        bytes memory expected = bytes.concat(
            _linProdHeader(2, 3), bytes4(0x01020304), bytes32(A0), bytes4(0x05060708), bytes32(A1)
        );
        bytes memory actual =
            harness.packLinProdInputForTest(3, new uint256[](0), new uint256[](0), scalars, x);

        assertEq(actual, expected);
    }

    function testPackLinProdInputRejectsFlags2() external {
        vm.expectRevert(bytes("FLAGS"));
        harness.packLinProdInputForTest(
            2, new uint256[](0), new uint256[](0), new uint256[](0), new uint256[](0)
        );
    }

    function testDotProductMatchesFoldFixedVector() external view {
        uint256[16] memory row = _fixedRow();
        uint256 p0 = _ext8FromSeed(1000);
        uint256 p1 = _ext8FromSeed(1001);
        uint256 p2 = _ext8FromSeed(1002);
        uint256 p3 = _ext8FromSeed(1003);

        assertEq(
            harness.dotRowForTest(row, p0, p1, p2, p3), harness.foldRowForTest(row, p0, p1, p2, p3)
        );
    }

    function testFuzz_DotProductMatchesFold(uint256 seed) external view {
        uint256[16] memory row;
        for (uint256 i = 0; i < 16; ++i) {
            row[i] = _ext8FromSeed(uint256(keccak256(abi.encode(seed, i))));
        }
        uint256 p0 = _ext8FromSeed(uint256(keccak256(abi.encode(seed, uint256(1000)))));
        uint256 p1 = _ext8FromSeed(uint256(keccak256(abi.encode(seed, uint256(1001)))));
        uint256 p2 = _ext8FromSeed(uint256(keccak256(abi.encode(seed, uint256(1002)))));
        uint256 p3 = _ext8FromSeed(uint256(keccak256(abi.encode(seed, uint256(1003)))));

        assertEq(
            harness.dotRowForTest(row, p0, p1, p2, p3), harness.foldRowForTest(row, p0, p1, p2, p3)
        );
    }

    function _fixedRow() internal pure returns (uint256[16] memory row) {
        for (uint256 i = 0; i < 16; ++i) {
            row[i] = _ext8FromSeed(i + 1);
        }
    }

    function _ext8FromSeed(uint256 seed) internal pure returns (uint256 packed) {
        for (uint256 i = 0; i < 8; ++i) {
            uint256 coeff = uint256(keccak256(abi.encode(seed, i))) % P;
            packed |= coeff << (224 - (i << 5));
        }
    }

    function _macHeader(uint256 n, uint256 flags) internal pure returns (bytes memory out) {
        uint256 fieldId = KoalaBearExt8Precompile.EXTFIELD_MAC_FIELD_ID_KOALABEAR_EXT8;
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

    function _linProdHeader(uint256 n, uint256 flags) internal pure returns (bytes memory out) {
        uint256 fieldId = KoalaBearExt8Precompile.EXTFIELD_MAC_FIELD_ID_KOALABEAR_EXT8;
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

    function _pair(uint256 a, uint256 b) internal pure returns (uint256[] memory out) {
        out = new uint256[](2);
        out[0] = a;
        out[1] = b;
    }
}
