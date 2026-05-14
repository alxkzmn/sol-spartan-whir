// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { KoalaBear } from "../src/field/KoalaBear.sol";
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

    function testSelectEvalLinProdMatchesSoftwareFixed() external view {
        uint256[] memory fullPoint = new uint256[](22);
        for (uint256 i = 0; i < fullPoint.length; ++i) {
            fullPoint[i] = _packExt5(i + 1, i + 2, i + 3, i + 4, i + 5);
        }
        uint256 var_ = 1_234_567;
        assertEq(
            harness.selectEvalLinProdSoftware(var_, fullPoint, 4, 18),
            harness.selectEvalSoftware(var_, fullPoint, 4, 18)
        );
        assertEq(
            harness.selectEvalLinProdSoftware(var_, fullPoint, 8, 14),
            harness.selectEvalSoftware(var_, fullPoint, 8, 14)
        );
        assertEq(
            harness.selectEvalLinProdSoftware(var_, fullPoint, 12, 10),
            harness.selectEvalSoftware(var_, fullPoint, 12, 10)
        );
    }

    function testFuzzSelectEvalLinProdMatchesSoftware(uint256 seed) external view {
        uint256[] memory fullPoint = new uint256[](22);
        for (uint256 i = 0; i < fullPoint.length; ++i) {
            uint256 s = uint256(keccak256(abi.encode(seed, i)));
            fullPoint[i] = _packExt5(
                s % KoalaBear.MODULUS,
                (s >> 32) % KoalaBear.MODULUS,
                (s >> 64) % KoalaBear.MODULUS,
                (s >> 96) % KoalaBear.MODULUS,
                (s >> 128) % KoalaBear.MODULUS
            );
        }
        uint256 var_ = uint256(keccak256(abi.encode(seed, "var"))) % KoalaBear.MODULUS;
        assertEq(
            harness.selectEvalLinProdSoftware(var_, fullPoint, 4, 18),
            harness.selectEvalSoftware(var_, fullPoint, 4, 18)
        );
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

    function _linProdHeader(uint256 n, uint256 flags) internal pure returns (bytes memory out) {
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

    function _pair(uint256 a, uint256 b) internal pure returns (uint256[] memory out) {
        out = new uint256[](2);
        out[0] = a;
        out[1] = b;
    }

    function _packExt5(uint256 c0, uint256 c1, uint256 c2, uint256 c3, uint256 c4)
        internal
        pure
        returns (uint256)
    {
        return (c0 << 224) | (c1 << 192) | (c2 << 160) | (c3 << 128) | (c4 << 96);
    }
}
