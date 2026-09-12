// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import { Test } from "forge-std/Test.sol";
import { KoalaBearExt5 as EF } from "../src/field/KoalaBearExt5.sol";
import { LeanVmPackedPolynomial as Poly } from "../src/leanvm/LeanVmPackedPolynomial.sol";

contract LeanVmPackedPolynomialHarness {
    function eqPolynomial(uint256[] memory p, uint256[] memory q) external pure returns (uint256) {
        return Poly.eqPolynomial(p, q);
    }

    function evaluateHypercube(uint256[] memory values, uint256[] memory p)
        external
        pure
        returns (uint256)
    {
        return Poly.evaluateHypercube(values, p);
    }

    function evaluateBaseHypercube(uint256[] memory values, uint256[] memory p)
        external
        pure
        returns (uint256)
    {
        return Poly.evaluateBaseHypercube(values, p);
    }
}

contract LeanVmPackedPolynomialTest is Test {
    uint256 constant P = 2_130_706_433;
    uint256 constant ONE = uint256(1) << 224;

    function generate(bytes32 seed, uint256 count) internal pure returns (uint256[] memory out) {
        out = new uint256[](count);
        for (uint256 i; i < count; ++i) {
            uint256[5] memory coefficients;
            for (uint256 j; j < 5; ++j) {
                coefficients[j] = uint256(keccak256(abi.encode(seed, i, j))) % P;
            }
            out[i] = EF.pack(coefficients);
        }
    }

    function schoolbookEq(uint256[] memory p, uint256[] memory q)
        internal
        pure
        returns (uint256 out)
    {
        out = ONE;
        for (uint256 i; i < p.length; ++i) {
            uint256 term = EF.add(
                EF.mulReference(p[i], q[i]), EF.mulReference(EF.sub(ONE, p[i]), EF.sub(ONE, q[i]))
            );
            out = EF.mulReference(out, term);
        }
    }

    function schoolbookMle(uint256[] memory values, uint256[] memory point)
        internal
        pure
        returns (uint256 out)
    {
        for (uint256 i; i < values.length; ++i) {
            uint256 weight = ONE;
            for (uint256 j; j < point.length; ++j) {
                uint256 factor =
                    ((i >> (point.length - j - 1)) & 1) == 0 ? EF.sub(ONE, point[j]) : point[j];
                weight = EF.mulReference(weight, factor);
            }
            out = EF.add(out, EF.mulReference(weight, values[i]));
        }
    }

    function testFuzzEqMatchesSchoolbook(bytes32 seed, uint256 n) external pure {
        n %= 28;
        uint256[] memory p = generate(seed, n);
        uint256[] memory q = generate(keccak256(abi.encode(seed)), n);
        uint256 got = Poly.eqPolynomial(p, q);
        EF.validatePacked(got);
        assertEq(got, schoolbookEq(p, q));
    }

    function testFuzzMleMatchesSchoolbook(bytes32 seed, uint256 n) external pure {
        n %= 9;
        uint256[] memory point = generate(seed, n);
        uint256[] memory values = generate(keccak256(abi.encode(seed)), uint256(1) << n);
        uint256 expected = schoolbookMle(values, point);
        uint256 got = Poly.evaluateHypercube(values, point);
        EF.validatePacked(got);
        assertEq(got, expected);
    }

    function testFuzzBaseMleMatchesSchoolbookAndPreservesInput(bytes32 seed, uint256 n)
        external
        pure
    {
        n %= 9;
        uint256[] memory point = generate(seed, n);
        uint256[] memory values = new uint256[](uint256(1) << n);
        uint256[] memory packed = new uint256[](values.length);
        for (uint256 i; i < values.length; ++i) {
            values[i] = uint256(keccak256(abi.encode(seed, i))) % P;
            packed[i] = EF.fromBase(values[i]);
        }
        bytes32 beforeHash = keccak256(abi.encode(values));
        uint256 actual = Poly.evaluateBaseHypercube(values, point);
        EF.validatePacked(actual);
        assertEq(actual, schoolbookMle(packed, point));
        assertEq(beforeHash, keccak256(abi.encode(values)));
    }

    function testBaseMleRejectsNoncanonicalInputs() external {
        LeanVmPackedPolynomialHarness harness = new LeanVmPackedPolynomialHarness();
        uint256[] memory values = new uint256[](2);
        uint256[] memory point = new uint256[](1);
        point[0] = ONE;
        values[1] = P;
        vm.expectRevert();
        harness.evaluateBaseHypercube(values, point);
        values[1] = 0;
        values[0] = P;
        vm.expectRevert();
        harness.evaluateBaseHypercube(values, point);
        vm.expectRevert("BAD_EVALS");
        harness.evaluateBaseHypercube(new uint256[](0), point);
        vm.expectRevert(bytes("DIM"));
        harness.evaluateBaseHypercube(values, new uint256[](0));
    }

    function testMaximumCoefficientsAndEmptyPoint() external pure {
        uint256[5] memory maximum = [P - 1, P - 1, P - 1, P - 1, P - 1];
        uint256[] memory point = new uint256[](8);
        for (uint256 i; i < point.length; ++i) {
            point[i] = EF.pack(maximum);
        }
        uint256[] memory values = new uint256[](256);
        for (uint256 i; i < values.length; ++i) {
            values[i] = EF.pack(maximum);
        }
        assertEq(Poly.eqPolynomial(point, point), schoolbookEq(point, point));
        assertEq(Poly.evaluateHypercube(values, point), EF.pack(maximum));
        assertEq(Poly.eqPolynomial(new uint256[](0), new uint256[](0)), ONE);
        values = new uint256[](1);
        values[0] = EF.pack(maximum);
        assertEq(Poly.evaluateHypercube(values, new uint256[](0)), values[0]);
    }

    function testRejectWrongDimensions() external {
        LeanVmPackedPolynomialHarness harness = new LeanVmPackedPolynomialHarness();
        vm.expectRevert(bytes("LEN"));
        harness.eqPolynomial(new uint256[](1), new uint256[](2));
        vm.expectRevert("BAD_EVALS");
        harness.evaluateHypercube(new uint256[](0), new uint256[](0));
        vm.expectRevert("BAD_EVALS");
        harness.evaluateHypercube(new uint256[](3), new uint256[](2));
        vm.expectRevert(bytes("DIM"));
        harness.evaluateHypercube(new uint256[](4), new uint256[](1));
    }
}
