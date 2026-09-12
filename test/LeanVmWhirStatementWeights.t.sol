// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { KoalaBearExt5 as EF } from "../src/field/KoalaBearExt5.sol";
import { LeanVmWhir as Whir } from "../src/leanvm/LeanVmWhir.sol";

contract LeanVmWhirStatementWeightsHarness {
    function evaluate(Whir.Statement[] memory statements, uint256 gamma, uint256[] memory point)
        external
        pure
        returns (uint256)
    {
        return Whir.evaluateGammaStatementWeights(statements, gamma, point);
    }

    // The general per-statement evaluator uses its original equality polynomial
    // and selector calculations, independently of the shared suffix cache.
    function evaluateReference(
        Whir.Statement[] memory statements,
        uint256 gamma,
        uint256[] memory point
    ) external pure returns (uint256 result) {
        uint256 power = uint256(1) << 224;
        for (uint256 i; i < statements.length; ++i) {
            uint256[] memory weights = Whir.weight(statements[i], point);
            for (uint256 j; j < weights.length; ++j) {
                result = EF.add(result, EF.mulReference(power, weights[j]));
                power = EF.mulReference(power, gamma);
            }
        }
    }
}

contract LeanVmWhirStatementWeightsTest is Test {
    uint256 private constant P = 2_130_706_433;
    uint256 private constant ONE = uint256(1) << 224;
    LeanVmWhirStatementWeightsHarness private harness;

    function setUp() public {
        harness = new LeanVmWhirStatementWeightsHarness();
    }

    function testFuzzMixedSuffixesMatchOriginalWeights(uint256 seed) public view {
        uint256[] memory point = _point(seed, 10);
        Whir.Statement[] memory statements = _statements(_point(seed ^ 0xabc, 8));
        uint256 gamma = _word(seed, 100);
        _compare(statements, gamma, point);
        for (uint256 i; i < statements.length / 2; ++i) {
            Whir.Statement memory swap = statements[i];
            statements[i] = statements[statements.length - 1 - i];
            statements[statements.length - 1 - i] = swap;
        }
        _compare(statements, gamma, point);
    }

    function testZeroOneAndMaximumCoefficients() public view {
        uint256 maximum = EF.pack([P - 1, P - 1, P - 1, P - 1, P - 1]);
        for (uint256 mode; mode < 3; ++mode) {
            uint256 value = mode == 0 ? 0 : (mode == 1 ? ONE : maximum);
            uint256[] memory referencePoint = new uint256[](8);
            uint256[] memory point = new uint256[](10);
            for (uint256 i; i < point.length; ++i) {
                point[i] = value;
                if (i < referencePoint.length) {
                    referencePoint[i] = value;
                }
            }
            Whir.Statement[] memory statements = _statements(referencePoint);
            _compare(statements, 0, point);
            _compare(statements, ONE, point);
            _compare(statements, maximum, point);
        }
    }

    function testMismatchAtEveryCoordinateAndCoefficient() public view {
        uint256[] memory point = _point(101, 10);
        uint256[] memory referencePoint = _point(202, 8);
        Whir.Statement[] memory statements = new Whir.Statement[](2);
        statements[0] = _statement(referencePoint, false, 3);
        for (uint256 length = 1; length <= referencePoint.length; ++length) {
            statements[1] = _statement(_suffix(referencePoint, length), false, 3);
            for (uint256 i; i < length; ++i) {
                uint256 original = statements[1].point[i];
                for (uint256 coefficient; coefficient < 5; ++coefficient) {
                    statements[1].point[i] =
                        EF.add(original, uint256(1) << (224 - 32 * coefficient));
                    _compare(statements, EF.fromBase(37), point);
                }
                statements[1].point[i] = original;
            }
        }
    }

    function testOnlySuccessorClaimsAndEmptyLists() public view {
        uint256[] memory point = _point(303, 10);
        Whir.Statement[] memory empty = new Whir.Statement[](0);
        assertEq(harness.evaluate(empty, ONE, point), 0);
        Whir.Statement[] memory statements = new Whir.Statement[](2);
        statements[0] = _statement(_point(404, 8), true, 3);
        statements[1] = _statement(_point(505, 6), true, 2);
        _compare(statements, EF.fromBase(43), point);
        statements[1] = _statement(new uint256[](0), false, 2);
        _compare(statements, ONE, point);
    }

    function testMalformedDimensionsAndSelectorsRemainRejected() public {
        uint256[] memory point = _point(606, 10);
        Whir.Statement[] memory statements = _statements(_point(707, 8));
        statements[1].variables = 9;
        vm.expectRevert(bytes("WEIGHT_DIM"));
        harness.evaluate(statements, ONE, point);
        statements[1].variables = 10;
        statements[1].point = new uint256[](11);
        vm.expectRevert(bytes("WEIGHT_DIM"));
        harness.evaluate(statements, ONE, point);
        statements[1].point = new uint256[](0);
        statements[1].selectors = new uint256[](2);
        vm.expectRevert(bytes("STATEMENT_LENGTH"));
        harness.evaluate(statements, ONE, point);
        statements[1].values = new uint256[](2);
        statements[1].selectors[0] = 1 << 10;
        vm.expectRevert(bytes("SELECTOR"));
        harness.evaluate(statements, ONE, point);
    }

    function _compare(Whir.Statement[] memory statements, uint256 gamma, uint256[] memory point)
        private
        view
    {
        uint256 actual = harness.evaluate(statements, gamma, point);
        EF.validatePacked(actual);
        assertEq(actual, harness.evaluateReference(statements, gamma, point));
    }

    function _statements(uint256[] memory referencePoint)
        private
        pure
        returns (Whir.Statement[] memory statements)
    {
        statements = new Whir.Statement[](8);
        statements[0] = _statement(referencePoint, false, 3);
        statements[1] = _statement(new uint256[](0), false, 1);
        statements[2] = _statement(_suffix(referencePoint, 7), false, 3);
        statements[3] = _statement(_suffix(referencePoint, 4), false, 17);
        statements[4] = _statement(_suffix(referencePoint, 8), false, 3);
        statements[4].point[3] = EF.add(statements[4].point[3], ONE);
        statements[5] = _statement(_suffix(referencePoint, 6), true, 3);
        statements[6] = _statement(_point(808, 3), false, 3);
        statements[7] = _statement(_suffix(referencePoint, 8), false, 3);
    }

    function _statement(uint256[] memory point, bool isNext, uint256 count)
        private
        pure
        returns (Whir.Statement memory statement)
    {
        statement.variables = 10;
        statement.point = point;
        statement.isNext = isNext;
        statement.values = new uint256[](count);
        statement.selectors = new uint256[](count);
        for (uint256 i; i < count; ++i) {
            statement.selectors[i] = count >= 16 ? i : (i % 2);
        }
    }

    function _suffix(uint256[] memory point, uint256 length)
        private
        pure
        returns (uint256[] memory result)
    {
        result = new uint256[](length);
        for (uint256 i; i < length; ++i) {
            result[i] = point[point.length - length + i];
        }
    }

    function _point(uint256 seed, uint256 length) private pure returns (uint256[] memory result) {
        result = new uint256[](length);
        for (uint256 i; i < length; ++i) {
            result[i] = _word(seed, i);
        }
    }

    function _word(uint256 seed, uint256 index) private pure returns (uint256) {
        uint256[5] memory coefficients;
        for (uint256 i; i < 5; ++i) {
            coefficients[i] = uint256(keccak256(abi.encode(seed, index, i))) % P;
        }
        return EF.pack(coefficients);
    }
}
