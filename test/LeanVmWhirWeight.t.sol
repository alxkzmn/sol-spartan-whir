// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import { Test } from "forge-std/Test.sol";
import { KoalaBearExt5 as EF } from "../src/field/KoalaBearExt5.sol";
import { LeanVmWhir as Whir } from "../src/leanvm/LeanVmWhir.sol";
import { LeanVmWhirWeight as Weight } from "../src/leanvm/LeanVmWhirWeight.sol";

contract LeanVmWhirWeightHarness {
    function selector(uint256[] memory point, uint256 depth, uint256 index, uint256 count)
        external pure returns (uint256)
    {
        return Weight.selector(Weight.initialize(depth), point, index, count);
    }
}

contract LeanVmWhirWeightTest is Test {
    uint256 constant P = 2_130_706_433;
    uint256 constant ONE = uint256(1) << 224;

    function pointFromSeed(bytes32 seed, uint256 count) internal pure returns (uint256[] memory p) {
        p = new uint256[](count);
        for (uint256 i; i < count; ++i) {
            uint256[5] memory a;
            for (uint256 j; j < 5; ++j) a[j] = uint256(keccak256(abi.encode(seed, i, j))) % P;
            p[i] = EF.pack(a);
        }
    }

    function indicator(uint256[] memory point, uint256 start, uint256 count, uint256 index)
        internal pure returns (uint256 value)
    {
        value = ONE;
        for (uint256 i; i < count; ++i) {
            uint256 term = (index >> (count - i - 1)) & 1 == 0
                ? EF.sub(ONE, point[start + i]) : point[start + i];
            value = EF.mulReference(value, term);
        }
    }

    function testFuzzCachedSelectorsMatchSchoolbook(bytes32 seed, uint256 rawDepth, uint256 rawCount) external pure {
        uint256 depth = rawDepth % 11;
        uint256 count = rawCount % 28;
        uint256[] memory point = pointFromSeed(seed, 27);
        Weight.Cache memory cache = Weight.initialize(depth);
        uint256 mask = (uint256(1) << count) - 1;
        uint256[6] memory indices = [uint256(0), mask, uint256(seed) & mask, uint256(11) & mask, mask, uint256(0)];
        for (uint256 i; i < indices.length; ++i) {
            uint256 got = Weight.selector(cache, point, indices[i], count);
            EF.validatePacked(got);
            assertEq(got, indicator(point, 0, count, indices[i]));
        }
    }

    function testMixedPrefixLengthsAndDuplicateSelectors() external pure {
        uint256[] memory point = pointFromSeed(bytes32(uint256(52)), 27);
        Weight.Cache memory cache = Weight.initialize(10);
        uint256[8] memory counts = [uint256(10), 6, 23, 8, 4, 0, 15, 10];
        uint256[8] memory indices = [uint256(580), 9, 1_179_648, 116, 1, 0, 16, 580];
        for (uint256 i; i < counts.length; ++i) {
            assertEq(Weight.selector(cache, point, indices[i], counts[i]), indicator(point, 0, counts[i], indices[i]));
        }
    }

    function testZeroWeightsAreCachedAndPointCachesAreSeparate() external pure {
        uint256[] memory point = new uint256[](12);
        Weight.Cache memory cache = Weight.initialize(10);
        assertEq(Weight.selector(cache, point, 1, 10), 0);
        assertEq(cache.nodes[1025], 1);
        assertEq(Weight.selector(cache, point, 1, 10), 0);
        assertEq(Weight.selector(cache, point, 0, 10), ONE);
        for (uint256 i; i < point.length; ++i) point[i] = ONE;
        Weight.Cache memory other = Weight.initialize(10);
        assertEq(Weight.selector(other, point, 0, 10), 0);
        assertEq(Weight.selector(other, point, 1023, 10), ONE);
    }

    function testMaximumCanonicalCoefficients() external pure {
        uint256[] memory point = new uint256[](27);
        uint256[5] memory a = [P - 1, P - 1, P - 1, P - 1, P - 1];
        for (uint256 i; i < point.length; ++i) point[i] = EF.pack(a);
        Weight.Cache memory cache = Weight.initialize(10);
        for (uint256 count; count <= 27; ++count) {
            uint256 index = (uint256(1) << count) - 1;
            assertEq(Weight.selector(cache, point, index, count), indicator(point, 0, count, index));
        }
    }

    function testFullWeightUsesExactEqualityAndSaturatingNext() external pure {
        uint256[] memory point = pointFromSeed(bytes32(uint256(7)), 8);
        Whir.Statement[] memory statements = new Whir.Statement[](2);
        for (uint256 s; s < 2; ++s) {
            uint256[] memory selectors = new uint256[](3);
            selectors[0] = 17; selectors[1] = 0; selectors[2] = 17;
            statements[s] = Whir.Statement(8, pointFromSeed(bytes32(s + 44), 3), selectors, new uint256[](3), s == 1);
        }
        Weight.Cache memory cache = Whir.weightCache(statements, point);
        assertEq(cache.depth, 5);
        for (uint256 s; s < statements.length; ++s) {
            uint256 common;
            for (uint256 row; row < 8; ++row) {
                uint256 rightRow = s == 0 ? row : (row == 7 ? 7 : row + 1);
                common = EF.add(common, EF.mulReference(
                    indicator(statements[s].point, 0, 3, row), indicator(point, 5, 3, rightRow)
                ));
            }
            uint256[] memory weights = Whir.weightWithCache(statements[s], point, cache);
            for (uint256 j; j < weights.length; ++j) {
                assertEq(weights[j], EF.mulReference(common, indicator(point, 0, 5, statements[s].selectors[j])));
            }
        }
    }

    function testDenseStatementsDoNotAllocatePrefixTree() external pure {
        uint256[] memory point = pointFromSeed(bytes32(uint256(5)), 23);
        Whir.Statement[] memory statements = new Whir.Statement[](3);
        for (uint256 i; i < 3; ++i) statements[i] = Whir.dense(23, point, 0);
        Weight.Cache memory cache = Whir.weightCache(statements, point);
        assertEq(cache.depth, 0);
        assertEq(cache.nodes.length, 0);
    }

    function testRejectOutOfRangeSelectorAndCacheDepth() external {
        LeanVmWhirWeightHarness harness = new LeanVmWhirWeightHarness();
        vm.expectRevert("SELECTOR");
        harness.selector(new uint256[](10), 10, 1024, 10);
        vm.expectRevert("SELECTOR");
        harness.selector(new uint256[](9), 10, 0, 10);
        vm.expectRevert("WEIGHT_CACHE_DEPTH");
        harness.selector(new uint256[](11), 11, 0, 11);
    }
}
