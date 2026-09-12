// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { KoalaBearExt5 as EF } from "../src/field/KoalaBearExt5.sol";
import { LeanVmPolynomial as Poly } from "../src/leanvm/LeanVmPolynomial.sol";

contract LeanVmNextPolynomialTest is Test {
    uint256 constant P = 2_130_706_433;
    uint256 constant ONE = uint256(1) << 224;

    function selector(uint256[] memory point, uint256 index) private pure returns (uint256 value) {
        value = ONE;
        for (uint256 i; i < point.length; ++i) {
            uint256 factor =
                (index >> (point.length - 1 - i)) & 1 == 0 ? EF.sub(ONE, point[i]) : point[i];
            value = EF.mulReference(value, factor);
        }
    }

    function matrixOracle(uint256[] memory x, uint256[] memory y)
        private
        pure
        returns (uint256 value)
    {
        uint256 size = uint256(1) << x.length;
        // Multilinear extension of the native successor matrix: the last row
        // remains at the last column. This oracle does not use the recurrence.
        for (uint256 i; i < size; ++i) {
            value = EF.add(
                value, EF.mulReference(selector(x, i), selector(y, i + 1 < size ? i + 1 : i))
            );
        }
    }

    function testFuzzSuccessorMatrix(bytes32 seed, uint256 depth) external pure {
        depth %= 6;
        uint256[] memory x = new uint256[](depth);
        uint256[] memory y = new uint256[](depth);
        for (uint256 i; i < depth; ++i) {
            uint256[5] memory a;
            uint256[5] memory b;
            for (uint256 j; j < 5; ++j) {
                a[j] = uint256(keccak256(abi.encode(seed, i, j, 0))) % P;
                b[j] = uint256(keccak256(abi.encode(seed, i, j, 1))) % P;
            }
            x[i] = EF.pack(a);
            y[i] = EF.pack(b);
        }
        uint256 actual = Poly.next(x, y);
        EF.validatePacked(actual);
        assertEq(actual, matrixOracle(x, y));
    }

    function testAllBooleanEntriesAndLastRow() external pure {
        for (uint256 depth; depth <= 4; ++depth) {
            uint256 size = uint256(1) << depth;
            uint256[] memory x = new uint256[](depth);
            uint256[] memory y = new uint256[](depth);
            for (uint256 a; a < size; ++a) {
                for (uint256 b; b < size; ++b) {
                    for (uint256 i; i < depth; ++i) {
                        x[i] = ((a >> (depth - 1 - i)) & 1) == 0 ? 0 : ONE;
                        y[i] = ((b >> (depth - 1 - i)) & 1) == 0 ? 0 : ONE;
                    }
                    bool expected = a + 1 == b || (a == size - 1 && b == size - 1);
                    assertEq(Poly.next(x, y), expected ? ONE : 0);
                }
            }
        }
    }

    function testMaximumCoefficients() external pure {
        uint256[] memory x = new uint256[](5);
        uint256 maximum = EF.pack([P - 1, P - 1, P - 1, P - 1, P - 1]);
        for (uint256 i; i < x.length; ++i) {
            x[i] = maximum;
        }
        assertEq(Poly.next(x, x), matrixOracle(x, x));
    }
}
