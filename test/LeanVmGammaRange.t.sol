// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { KoalaBearExt5 as EF } from "../src/field/KoalaBearExt5.sol";
import { LeanVmWhirWeight as Weight } from "../src/leanvm/LeanVmWhirWeight.sol";
import { LeanVmWhir as Whir } from "../src/leanvm/LeanVmWhir.sol";

contract LeanVmGammaRangeTest is Test {
    uint256 constant P = 2_130_706_433;
    uint256 constant ONE = uint256(1) << 224;

    function element(bytes32 seed, uint256 i) private pure returns (uint256) {
        uint256[5] memory coefficients;
        for (uint256 j; j < 5; ++j) {
            coefficients[j] = uint256(keccak256(abi.encode(seed, i, j))) % P;
        }
        return EF.pack(coefficients);
    }

    function referenceSelector(uint256[] memory point, uint256 index, uint256 depth)
        private
        pure
        returns (uint256 result)
    {
        result = ONE;
        for (uint256 i; i < depth; ++i) {
            uint256 factor = (index >> (depth - 1 - i)) & 1 == 0 ? EF.sub(ONE, point[i]) : point[i];
            result = EF.mulReference(result, factor);
        }
    }

    function checkRange(
        uint256[] memory point,
        uint256 first,
        uint256 count,
        uint256 depth,
        uint256 gamma
    ) private pure {
        uint256[8] memory squares;
        squares[0] = gamma;
        for (uint256 i = 1; i < 8; ++i) {
            squares[i] = EF.mulReference(squares[i - 1], squares[i - 1]);
        }
        Weight.Cache memory cache = Weight.initialize(depth > 10 ? 10 : depth);
        uint256 actual = Weight.rangeSum(cache, point, first, count, depth, squares);
        uint256 expected;
        uint256 power = ONE;
        for (uint256 i; i < count; ++i) {
            expected = EF.add(
                expected, EF.mulReference(power, referenceSelector(point, first + i, depth))
            );
            power = EF.mulReference(power, gamma);
        }
        EF.validatePacked(actual);
        assertEq(actual, expected);
    }

    function testFuzzFactoredRange(bytes32 seed, uint256 depth, uint256 first, uint256 count)
        external
        pure
    {
        depth %= 14;
        uint256 limit = uint256(1) << depth;
        first %= limit + 1;
        count %= 256;
        if (count > limit - first) count = limit - first;
        uint256[] memory point = new uint256[](depth + 1);
        for (uint256 i; i < point.length; ++i) {
            point[i] = element(seed, i);
        }
        checkRange(point, first, count, depth, element(seed, 100));
    }

    function testDegenerateChallengesAndCoordinates() external pure {
        uint256[] memory point = new uint256[](10);
        uint256 maximum = EF.pack([P - 1, P - 1, P - 1, P - 1, P - 1]);
        uint256[3] memory challenges = [uint256(0), ONE, maximum];
        for (uint256 pattern; pattern < 3; ++pattern) {
            for (uint256 i; i < point.length; ++i) {
                point[i] = pattern == 0 ? 0 : (pattern == 1 ? ONE : maximum);
            }
            for (uint256 i; i < 3; ++i) {
                checkRange(point, 580, 110, 10, challenges[i]);
                checkRange(point, 255, 17, 10, challenges[i]);
                checkRange(point, 0, 128, 10, challenges[i]);
            }
        }
        checkRange(new uint256[](0), 0, 1, 0, 0);
        checkRange(new uint256[](0), 1, 0, 0, ONE);
    }

    function testMixedStatementsPreserveGammaExponentAndCommonFactor() external pure {
        uint256[] memory point = new uint256[](12);
        for (uint256 i; i < point.length; ++i) {
            point[i] = element(bytes32(uint256(17)), i);
        }
        Whir.Statement[] memory statements = new Whir.Statement[](3);
        uint256 gamma = element(bytes32(uint256(29)), 0);
        uint256 power = ONE;
        uint256 expected;
        for (uint256 group; group < 3; ++group) {
            uint256 depth = group == 0 ? 10 : 8;
            uint256 count = group == 0 ? 110 : (group == 1 ? 20 : 29);
            uint256 first = group == 0 ? 580 : 17;
            uint256[] memory selectors = new uint256[](count);
            uint256[] memory values = new uint256[](count);
            uint256[] memory suffixPoint = new uint256[](point.length - depth);
            uint256 common = ONE;
            for (uint256 j; j < suffixPoint.length; ++j) {
                suffixPoint[j] = element(bytes32(group + 100), j);
                uint256 p = suffixPoint[j];
                uint256 q = point[depth + j];
                common = EF.mulReference(
                    common,
                    EF.add(EF.mulReference(p, q), EF.mulReference(EF.sub(ONE, p), EF.sub(ONE, q)))
                );
            }
            for (uint256 j; j < count; ++j) {
                // The last group exercises the sparse fallback after two ranges.
                selectors[j] = first + (group == 2 ? 2 * j : j);
                uint256 weight =
                    EF.mulReference(common, referenceSelector(point, selectors[j], depth));
                expected = EF.add(expected, EF.mulReference(power, weight));
                power = EF.mulReference(power, gamma);
            }
            statements[group] = Whir.Statement(12, suffixPoint, selectors, values, false);
        }
        uint256 actual = Whir.evaluateGammaStatementWeights(statements, gamma, point);
        EF.validatePacked(actual);
        assertEq(actual, expected);
    }
}
