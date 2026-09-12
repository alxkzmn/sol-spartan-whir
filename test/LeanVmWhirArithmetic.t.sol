// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import { Test } from "forge-std/Test.sol";
import { KoalaBearExt5 as EF } from "../src/field/KoalaBearExt5.sol";
import { LeanVmWhirArithmetic as Arithmetic } from "../src/leanvm/LeanVmWhirArithmetic.sol";

contract LeanVmWhirArithmeticHarness {
    function evaluate(uint256[] memory point, uint256 offset, uint256 count, uint256 x)
        external
        pure
        returns (uint256)
    {
        return Arithmetic.evaluateBaseEq(Arithmetic.prepareBaseEq(point, offset, count), count, x);
    }
}

contract LeanVmWhirArithmeticTest is Test {
    uint256 constant P = 2_130_706_433;
    uint256 constant ONE = uint256(1) << 224;

    function referenceEq(uint256[] memory point, uint256 offset, uint256 count, uint256 x)
        internal
        pure
        returns (uint256 out)
    {
        out = ONE;
        for (uint256 i; i < count; ++i) {
            uint256[5] memory r = EF.unpack(point[offset + i]);
            uint256 scalar = addmod(mulmod(2, x, P), P - 1, P);
            uint256[5] memory term;
            for (uint256 j; j < 5; ++j) {
                term[j] = mulmod(r[j], scalar, P);
            }
            term[0] = addmod(term[0], P + 1 - x, P);
            out = EF.mulReference(out, EF.pack(term));
            x = mulmod(x, x, P);
        }
    }

    function pointFromSeed(bytes32 seed, uint256 count)
        internal
        pure
        returns (uint256[] memory point)
    {
        point = new uint256[](count);
        for (uint256 i; i < count; ++i) {
            uint256[5] memory r;
            for (uint256 j; j < 5; ++j) {
                r[j] = uint256(keccak256(abi.encode(seed, i, j))) % P;
            }
            point[i] = EF.pack(r);
        }
    }

    function check(uint256[] memory point, uint256 offset, uint256 count, uint256 x) internal pure {
        uint256[] memory cache = Arithmetic.prepareBaseEq(point, offset, count);
        uint256 got = Arithmetic.evaluateBaseEq(cache, count, x);
        EF.validatePacked(got);
        assertEq(got, referenceEq(point, offset, count, x));
    }

    function testFuzzPreparedEqMatchesSchoolbook(
        bytes32 seed,
        uint256 rawCount,
        uint256 rawOffset,
        uint256 x
    ) external pure {
        uint256 count = rawCount % 28;
        uint256 offset = rawOffset % 4;
        check(pointFromSeed(seed, offset + count + 2), offset, count, x % P);
    }

    function testAllDimensionsAndBaseBoundaries() external pure {
        uint256[] memory point = pointFromSeed(bytes32(uint256(11)), 30);
        for (uint256 count; count <= 27; ++count) {
            check(point, 2, count, 0);
            check(point, 2, count, 1);
            check(point, 2, count, P - 1);
        }
    }

    function testMaximumExtensionCoefficientsAndReusedCache() external pure {
        uint256[5] memory maximum = [P - 1, P - 1, P - 1, P - 1, P - 1];
        uint256[] memory point = new uint256[](25);
        for (uint256 i; i < point.length; ++i) {
            point[i] = EF.pack(maximum);
        }
        for (uint256 count = 21; count <= 23; ++count) {
            uint256[] memory cache = Arithmetic.prepareBaseEq(point, 1, count);
            uint256[5] memory queries = [uint256(0), P - 1, uint256(19), uint256(1), uint256(19)];
            for (uint256 i; i < queries.length; ++i) {
                uint256 got = Arithmetic.evaluateBaseEq(cache, count, queries[i]);
                EF.validatePacked(got);
                assertEq(got, referenceEq(point, 1, count, queries[i]));
            }
        }
    }

    function testRejectInvalidPointWindow() external {
        LeanVmWhirArithmeticHarness harness = new LeanVmWhirArithmeticHarness();
        vm.expectRevert("EQ_POINT");
        harness.evaluate(new uint256[](2), 1, 2, 1);
    }

    function testRejectNoncanonicalBasePoint() external {
        LeanVmWhirArithmeticHarness harness = new LeanVmWhirArithmeticHarness();
        vm.expectRevert("EQ_CACHE");
        harness.evaluate(new uint256[](2), 0, 2, P);
    }
}
