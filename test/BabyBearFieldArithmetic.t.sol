// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { BabyBear } from "../src/field/BabyBear.sol";
import { BabyBearExt5 } from "../src/field/BabyBearExt5.sol";
import { BabyBearReference as Ref } from "./helpers/BabyBearReference.sol";

contract BabyBearFieldHarness {
    function baseAdd(uint256 a, uint256 b) external pure returns (uint256) {
        return BabyBear.add(a, b);
    }

    function baseSub(uint256 a, uint256 b) external pure returns (uint256) {
        return BabyBear.sub(a, b);
    }

    function baseMul(uint256 a, uint256 b) external pure returns (uint256) {
        return BabyBear.mul(a, b);
    }

    function basePow(uint256 a, uint256 exponent) external pure returns (uint256) {
        return BabyBear.pow(a, exponent);
    }

    function baseInv(uint256 a) external pure returns (uint256) {
        return BabyBear.inv(a);
    }

    function extPack(uint256[5] memory coeffs) external pure returns (uint256) {
        return BabyBearExt5.pack(coeffs);
    }

    function extUnpack(uint256 packed) external pure returns (uint256[5] memory) {
        return BabyBearExt5.unpack(packed);
    }

    function extValidate(uint256 packed) external pure {
        BabyBearExt5.validatePacked(packed);
    }

    function extAdd(uint256 a, uint256 b) external pure returns (uint256) {
        return BabyBearExt5.add(a, b);
    }

    function extSub(uint256 a, uint256 b) external pure returns (uint256) {
        return BabyBearExt5.sub(a, b);
    }

    function extMul(uint256 a, uint256 b) external pure returns (uint256) {
        return BabyBearExt5.mul(a, b);
    }

    function extSquare(uint256 a) external pure returns (uint256) {
        return BabyBearExt5.square(a);
    }

    function extInv(uint256 a) external pure returns (uint256) {
        return BabyBearExt5.inv(a);
    }
}

contract BabyBearFieldArithmeticTest is Test {
    uint256 internal constant Q = 0x78000001;
    uint256 internal constant ONE = uint256(1) << 224;
    uint256 internal constant LOW_96_MASK = (uint256(1) << 96) - 1;

    BabyBearFieldHarness internal harness;

    function setUp() external {
        harness = new BabyBearFieldHarness();
    }

    function testBabyBearBaseBoundaryArithmetic() external view {
        assertEq(harness.baseAdd(0, 0), 0);
        assertEq(harness.baseAdd(Q - 1, 1), 0);
        assertEq(harness.baseAdd(Q - 1, Q - 1), Q - 2);

        assertEq(harness.baseSub(0, 0), 0);
        assertEq(harness.baseSub(0, 1), Q - 1);
        assertEq(harness.baseSub(Q - 1, Q - 1), 0);

        assertEq(harness.baseMul(0, Q - 1), 0);
        assertEq(harness.baseMul(Q - 1, Q - 1), 1);

        assertEq(harness.basePow(0, 0), 1);
        assertEq(harness.basePow(0, 1), 0);
        assertEq(harness.basePow(Q - 1, 2), 1);
        assertEq(harness.basePow(7, Q - 1), 1);

        assertEq(harness.baseInv(1), 1);
        assertEq(harness.baseInv(Q - 1), Q - 1);
    }

    function testBabyBearBaseInverseRejectsZeroRepresentatives() external {
        vm.expectRevert(bytes("ZERO_INV"));
        harness.baseInv(0);

        vm.expectRevert(bytes("ZERO_INV"));
        harness.baseInv(Q);

        vm.expectRevert(bytes("ZERO_INV"));
        harness.baseInv(3 * Q);
    }

    function testFuzzBabyBearBaseArithmetic(uint256 rawA, uint256 rawB, uint256 exponent)
        external
        view
    {
        uint256 a = rawA % Q;
        uint256 b = rawB % Q;

        assertEq(harness.baseAdd(a, b), addmod(a, b, Q));
        assertEq(harness.baseSub(a, b), addmod(a, Q - b, Q));
        assertEq(harness.baseMul(a, b), mulmod(a, b, Q));
        assertEq(harness.basePow(a, exponent), _basePowReference(a, exponent));

        if (a != 0) {
            uint256 inverse = harness.baseInv(a);
            assertEq(mulmod(a, inverse, Q), 1);
            assertEq(inverse, _basePowReference(a, Q - 2));
        }
    }

    function testBabyBearExt5BasisProducts() external view {
        for (uint256 i; i < 5; ++i) {
            uint256 a = (Q - 1) << (224 - 32 * i);
            for (uint256 j; j < 5; ++j) {
                uint256 b = (Q - 1) << (224 - 32 * j);
                uint256 actual = harness.extMul(a, b);
                assertEq(actual, Ref.mul(a, b, Q, 1), "basis product");
                _assertCanonical(actual);
            }
        }
    }

    function testBabyBearExt5MaximumCoefficients() external view {
        uint256 max = Ref.pack([Q - 1, Q - 1, Q - 1, Q - 1, Q - 1]);

        assertEq(harness.extAdd(max, max), Ref.add(max, max, Q));
        assertEq(harness.extSub(max, max), 0);
        assertEq(harness.extMul(max, max), Ref.mul(max, max, Q, 1));
        assertEq(harness.extSquare(max), Ref.mul(max, max, Q, 1));

        _assertCanonical(harness.extAdd(max, max));
        _assertCanonical(harness.extMul(max, max));
        _assertCanonical(harness.extSquare(max));
    }

    function testFuzzBabyBearExt5PackedArithmetic(uint256[5] memory rawA, uint256[5] memory rawB)
        external
        view
    {
        uint256[5] memory coeffsA = _canonicalCoeffs(rawA);
        uint256[5] memory coeffsB = _canonicalCoeffs(rawB);
        uint256 a = Ref.pack(coeffsA);
        uint256 b = Ref.pack(coeffsB);

        assertEq(harness.extPack(coeffsA), a);
        assertEq(harness.extPack(coeffsB), b);
        assertEq(abi.encode(harness.extUnpack(a)), abi.encode(coeffsA));
        assertEq(abi.encode(harness.extUnpack(b)), abi.encode(coeffsB));

        uint256 sum = harness.extAdd(a, b);
        uint256 difference = harness.extSub(a, b);
        uint256 product = harness.extMul(a, b);
        uint256 square = harness.extSquare(a);

        assertEq(sum, Ref.add(a, b, Q));
        assertEq(difference, _referenceSub(a, b));
        assertEq(product, Ref.mul(a, b, Q, 1));
        assertEq(square, Ref.mul(a, a, Q, 1));
        assertEq(square, harness.extMul(a, a));

        _assertCanonical(sum);
        _assertCanonical(difference);
        _assertCanonical(product);
        _assertCanonical(square);
    }

    function testBabyBearExt5ValidationChecksEveryLane() external {
        uint256 allMaximum = Ref.pack([Q - 1, Q - 1, Q - 1, Q - 1, Q - 1]);
        harness.extValidate(allMaximum);

        for (uint256 i; i < 5; ++i) {
            uint256 shift = 224 - 32 * i;
            uint256 canonical = (Q - 1) << shift;
            harness.extValidate(canonical);

            uint256 nonCanonical = Q << shift;
            vm.expectRevert(
                abi.encodeWithSignature("PackedExtensionElementOutOfRange(uint256)", nonCanonical)
            );
            harness.extValidate(nonCanonical);
        }
    }

    function testBabyBearExt5ValidationRejectsEveryLowPaddingBit() external {
        for (uint256 i; i < 96; ++i) {
            uint256 malformed = ONE | (uint256(1) << i);
            vm.expectRevert(
                abi.encodeWithSignature("PackedExtensionElementOutOfRange(uint256)", malformed)
            );
            harness.extValidate(malformed);
        }
    }

    function testBabyBearExt5InverseRejectsZero() external {
        vm.expectRevert(bytes("ZERO_INV"));
        harness.extInv(0);
    }

    function testFuzzBabyBearExt5InverseProduct(uint256[5] memory rawA) external view {
        uint256 a = Ref.pack(_canonicalCoeffs(rawA));
        if (a == 0) {
            return;
        }

        uint256 inverse = harness.extInv(a);
        assertEq(harness.extMul(a, inverse), ONE);
        assertEq(Ref.mul(a, inverse, Q, 1), ONE);
        _assertCanonical(inverse);
    }

    function _canonicalCoeffs(uint256[5] memory raw)
        private
        pure
        returns (uint256[5] memory coeffs)
    {
        for (uint256 i; i < 5; ++i) {
            coeffs[i] = raw[i] % Q;
        }
    }

    function _referenceSub(uint256 a, uint256 b) private pure returns (uint256) {
        return Ref.add(a, Ref.scale(b, Q - 1, Q), Q);
    }

    function _basePowReference(uint256 a, uint256 exponent) private pure returns (uint256 out) {
        out = 1;
        while (exponent != 0) {
            if ((exponent & 1) != 0) {
                out = mulmod(out, a, Q);
            }
            a = mulmod(a, a, Q);
            exponent >>= 1;
        }
    }

    function _assertCanonical(uint256 packed) private pure {
        assertEq(packed & LOW_96_MASK, 0, "nonzero padding");
        uint256[5] memory coeffs = Ref.unpack(packed);
        for (uint256 i; i < 5; ++i) {
            assertLt(coeffs[i], Q, "noncanonical coefficient");
        }
    }
}
