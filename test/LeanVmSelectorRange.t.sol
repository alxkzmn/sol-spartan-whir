// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { KoalaBearExt5 as EF } from "../src/field/KoalaBearExt5.sol";
import { LeanVmPackedPolynomial as Poly } from "../src/leanvm/LeanVmPackedPolynomial.sol";

contract LeanVmSelectorRangeHarness {
    function evaluate(uint256[] memory point, uint256 first, uint256 count, uint256 depth)
        external
        pure
        returns (uint256[] memory)
    {
        return Poly.eqIndexRange(point, first, count, depth);
    }
}

contract LeanVmSelectorRangeTest is Test {
    uint256 constant P = 2_130_706_433;
    uint256 constant ONE = uint256(1) << 224;

    function checkRange(uint256[] memory point, uint256 first, uint256 count, uint256 depth)
        internal
        pure
    {
        uint256[] memory actual = Poly.eqIndexRange(point, first, count, depth);
        assertEq(actual.length, count);
        for (uint256 i; i < count; ++i) {
            uint256 expected = ONE;
            for (uint256 j; j < depth; ++j) {
                uint256 factor =
                    ((first + i) >> (depth - 1 - j)) & 1 == 0 ? EF.sub(ONE, point[j]) : point[j];
                // The oracle uses schoolbook convolution, independent of the
                // packed multiplication and incremental selector traversal.
                expected = EF.mulReference(expected, factor);
            }
            EF.validatePacked(actual[i]);
            assertEq(actual[i], expected);
        }
    }

    function testFuzzConsecutiveSelectors(bytes32 seed, uint256 depth, uint256 first, uint256 count)
        external
        pure
    {
        depth %= 13;
        uint256 limit = uint256(1) << depth;
        first %= limit + 1;
        count %= 65;
        if (count > limit - first) count = limit - first;
        uint256[] memory point = new uint256[](depth + 2);
        for (uint256 i; i < point.length; ++i) {
            uint256[5] memory coefficients;
            for (uint256 j; j < 5; ++j) {
                coefficients[j] = uint256(keccak256(abi.encode(seed, i, j))) % P;
            }
            point[i] = EF.pack(coefficients);
        }
        checkRange(point, first, count, depth);
    }

    function testLongCarriesAndMaximumCoefficients() external pure {
        uint256[] memory point = new uint256[](9);
        uint256 maximum = EF.pack([P - 1, P - 1, P - 1, P - 1, P - 1]);
        for (uint256 i; i < point.length; ++i) {
            point[i] = maximum;
        }
        checkRange(point, 224, 33, 9);
        checkRange(point, 127, 3, 9);
        checkRange(point, 510, 2, 9);
    }

    function testZeroAndOneCoordinatesAndCompleteRange() external pure {
        uint256[] memory point = new uint256[](8);
        for (uint256 pattern; pattern < 3; ++pattern) {
            for (uint256 i; i < point.length; ++i) {
                point[i] = pattern == 0 ? 0 : (pattern == 1 || i & 1 != 0 ? ONE : 0);
            }
            checkRange(point, 0, 256, 8);
        }
        checkRange(new uint256[](0), 0, 1, 0);
        checkRange(new uint256[](0), 1, 0, 0);
    }

    function testRejectInvalidRanges() external {
        LeanVmSelectorRangeHarness harness = new LeanVmSelectorRangeHarness();
        uint256[] memory point = new uint256[](3);
        vm.expectRevert("SELECTOR");
        harness.evaluate(point, 0, 1, 4);
        vm.expectRevert("SELECTOR");
        harness.evaluate(point, 9, 0, 3);
        vm.expectRevert("SELECTOR");
        harness.evaluate(point, 7, 2, 3);
        vm.expectRevert("SELECTOR");
        harness.evaluate(point, 0, type(uint256).max, 3);
    }
}
