// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import { Test } from "forge-std/Test.sol";
import { KoalaBearExt5 as EF } from "../src/field/KoalaBearExt5.sol";
import { LeanVmWhirFolding as Folding } from "../src/leanvm/LeanVmWhirFolding.sol";

contract LeanVmWhirFoldingHarness {
    function fold(bytes calldata rows, uint256[] calldata offsets, uint256[] memory point, bool baseLeaf)
        external pure returns (uint256[] memory out)
    {
        for (uint256 i; i < point.length; ++i) EF.validatePacked(point[i]);
        uint256 ptr = point.length == 5 ? Folding.prepare32(point, baseLeaf) : Folding.prepare16(point, baseLeaf);
        out = new uint256[](offsets.length);
        for (uint256 i; i < offsets.length; ++i) {
            out[i] = point.length == 5 ? Folding.fold32(rows, offsets[i], ptr, baseLeaf, point[0]) : Folding.fold16(rows, offsets[i], ptr, baseLeaf);
        }
    }
}

contract LeanVmWhirFoldingTest is Test {
    uint256 constant P = 2_130_706_433;
    uint256 constant ONE = uint256(1) << 224;
    LeanVmWhirFoldingHarness harness;

    function setUp() external { harness = new LeanVmWhirFoldingHarness(); }

    function generate(bytes32 seed, uint256 count, bool baseOnly) internal pure returns (uint256[] memory out) {
        out = new uint256[](count);
        for (uint256 i; i < count; ++i) {
            uint256[5] memory coefficients;
            for (uint256 j; j < (baseOnly ? 1 : 5); ++j) {
                coefficients[j] = uint256(keccak256(abi.encode(seed, i, j))) % P;
            }
            out[i] = EF.pack(coefficients);
        }
    }

    function encode(uint256[] memory values, bool baseOnly) internal pure returns (bytes memory out) {
        for (uint256 i; i < values.length; ++i) {
            uint256[5] memory coefficients = EF.unpack(values[i]);
            for (uint256 j; j < (baseOnly ? 1 : 5); ++j) out = bytes.concat(out, bytes4(uint32(coefficients[j])));
        }
    }

    // Multilinear row order: point[0] is the most significant bit.
    // Use independent schoolbook products, without the prepared dot kernel.
    function referenceFold(uint256[] memory values, uint256[] memory point) internal pure returns (uint256 out) {
        for (uint256 i; i < values.length; ++i) {
            uint256 weight = ONE;
            for (uint256 j; j < point.length; ++j) {
                uint256 factor = (i >> (point.length-1-j)) & 1 == 1 ? point[j] : EF.sub(ONE, point[j]);
                weight = EF.mulReference(weight, factor);
            }
            out = EF.add(out, EF.mulReference(weight, values[i]));
        }
    }

    function check(uint256[] memory values, uint256[] memory point, bool baseOnly) internal view {
        bytes memory row = encode(values, baseOnly);
        bytes memory rows = bytes.concat(hex"11223344556677", row, hex"ff00aabb", row, hex"ffffffffffffffffffffffffffffffff");
        uint256[] memory offsets = new uint256[](3);
        offsets[0] = 7 + row.length + 4;
        offsets[1] = 7;
        offsets[2] = offsets[0];
        uint256[] memory got = harness.fold(rows, offsets, point, baseOnly);
        uint256 expected = referenceFold(values, point);
        for (uint256 i; i < got.length; ++i) { EF.validatePacked(got[i]); assertEq(got[i], expected); }
    }

    function testFuzzPreparedRowsMatchSchoolbook(bytes32 seed, bool baseOnly) external view {
        check(generate(seed, 16, baseOnly), generate(keccak256(abi.encode(seed)), 4, false), baseOnly);
    }

    function testFuzzPreparedRows32MatchSchoolbook(bytes32 seed, bool baseOnly) external view {
        check(generate(seed, 32, baseOnly), generate(keccak256(abi.encode(seed)), 5, false), baseOnly);
    }

    function testMaximum32AndFirstCoordinate() external view {
        uint256[5] memory maximum = [P-1,P-1,P-1,P-1,P-1];
        uint256[] memory point = new uint256[](5);
        for (uint256 i; i < 5; ++i) point[i] = EF.pack(maximum);
        for (uint256 kind; kind < 2; ++kind) {
            bool baseOnly = kind == 0;
            uint256[] memory values = new uint256[](32);
            for (uint256 i; i < 32; ++i) values[i] = baseOnly ? (P-1) << 224 : EF.pack(maximum);
            check(values, point, baseOnly);
            values = generate(bytes32(uint256(33)), 32, baseOnly);
            point[0] = 0;
            check(values, point, baseOnly);
            point[0] = ONE;
            check(values, point, baseOnly);
            point[0] = EF.pack(maximum);
        }
    }

    function testBooleanPointsSelectExactRow() external view {
        for (uint256 kind; kind < 2; ++kind) {
            bool baseOnly = kind == 0;
            uint256[] memory values = generate(bytes32(uint256(123)), 16, baseOnly);
            bytes memory row = encode(values, baseOnly);
            uint256[] memory offsets = new uint256[](1);
            for (uint256 index; index < 16; ++index) {
                uint256[] memory point = new uint256[](4);
                for (uint256 j; j < 4; ++j) point[j] = ((index >> (3-j)) & 1) * ONE;
                assertEq(harness.fold(row, offsets, point, baseOnly)[0], values[index]);
            }
        }
    }

    function testMaximumCoefficientsAndZeroRows() external view {
        uint256[] memory point = new uint256[](4);
        uint256[5] memory maximum = [P-1,P-1,P-1,P-1,P-1];
        for (uint256 i; i < 4; ++i) point[i] = EF.pack(maximum);
        for (uint256 kind; kind < 2; ++kind) {
            bool baseOnly = kind == 0;
            uint256[] memory values = new uint256[](16);
            check(values, point, baseOnly);
            for (uint256 i; i < 16; ++i) values[i] = baseOnly ? (P-1) << 224 : EF.pack(maximum);
            check(values, point, baseOnly);
        }
    }

    function testRejectShortRowsAndInvalidDimension() external {
        uint256[] memory offsets = new uint256[](1);
        vm.expectRevert("FOLD_ROW");
        harness.fold(new bytes(63), offsets, new uint256[](4), true);
        vm.expectRevert("FOLD_ROW");
        harness.fold(new bytes(319), offsets, new uint256[](4), false);
        offsets[0] = 321;
        vm.expectRevert("FOLD_ROW");
        harness.fold(new bytes(320), offsets, new uint256[](4), false);
        vm.expectRevert("FOLD_POINT");
        harness.fold(new bytes(320), offsets, new uint256[](3), false);
        offsets[0] = 0;
        vm.expectRevert("FOLD_ROW");
        harness.fold(new bytes(127), offsets, new uint256[](5), true);
        vm.expectRevert("FOLD_ROW");
        harness.fold(new bytes(639), offsets, new uint256[](5), false);
    }
}
