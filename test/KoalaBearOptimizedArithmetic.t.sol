// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { KoalaBearExt5 as F } from "../src/field/KoalaBearExt5.sol";
import { KoalaBearPackedField as PackedF } from "../src/field/KoalaBearPackedField.sol";
import {
    WhirVerifierUtils5 as U
} from "../src/whir/k22_jb100_ext5_lir4_ff4_rsv3_pow28/WhirVerifierUtils5.sol";

contract KoalaBearOptimizedArithmeticHarness {
    function mul(uint256 a, uint256 b) external pure returns (uint256) {
        return PackedF.mul(a, b);
    }

    function extensionDot(uint256[16] memory weights, uint256[16] memory values)
        external
        pure
        returns (uint256)
    {
        uint256 packedWeightsPtr;
        assembly ("memory-safe") {
            packedWeightsPtr := weights
        }
        uint256 weightsPtr = U._prepareRowWeights(packedWeightsPtr);
        return U._dotExt5Weights16Unpacked(
            weightsPtr,
            values[0],
            values[1],
            values[2],
            values[3],
            values[4],
            values[5],
            values[6],
            values[7],
            values[8],
            values[9],
            values[10],
            values[11],
            values[12],
            values[13],
            values[14],
            values[15]
        );
    }

    function baseDot(uint256[16] memory weights, uint256 w0, uint256 w1)
        external
        pure
        returns (uint256)
    {
        uint256 packedWeightsPtr;
        assembly ("memory-safe") {
            packedWeightsPtr := weights
        }
        return U._dotBaseRadix80(U._prepareBaseRadix80(packedWeightsPtr), w0, w1);
    }

    function finalValue(bytes calldata blob, uint256 offset, uint256[] memory point)
        external
        pure
        returns (uint256)
    {
        return U.evaluateFinalValueBlob64Dim6(blob, offset, point, 0);
    }

    function horner64(bytes calldata blob, uint256 offset, uint256 x)
        external
        pure
        returns (uint256)
    {
        return U._hornerRadix64(U._prepareHornerRadix64(blob, offset), x);
    }
}

contract KoalaBearOptimizedArithmeticTest is Test {
    uint256 private constant M = 0x7f000001;

    KoalaBearOptimizedArithmeticHarness private harness;

    function setUp() external {
        harness = new KoalaBearOptimizedArithmeticHarness();
    }

    function testPackedMulBasisAndMaximum() external view {
        for (uint256 i = 0; i < 5; ++i) {
            for (uint256 j = 0; j < 5; ++j) {
                uint256 a = (M - 1) << (224 - 32 * i);
                uint256 b = (M - 1) << (224 - 32 * j);
                assertEq(harness.mul(a, b), F.mulReference(a, b));
            }
        }

        uint256 maximum = _maximum();
        assertEq(harness.mul(maximum, maximum), F.mulReference(maximum, maximum));
    }

    function testFuzzPackedMulChain(bytes32 seed) external view {
        uint256 actual = _element(seed, 0);
        uint256 expected = actual;
        for (uint256 i = 1; i <= 32; ++i) {
            uint256 factor = _element(seed, i);
            actual = harness.mul(actual, factor);
            expected = F.mulReference(expected, factor);
            assertEq(actual, expected);
            F.validatePacked(actual);
        }
    }

    function testFuzzExtensionDot(bytes32 seed) external view {
        (uint256[16] memory weights, uint256[16] memory values) = _extensionInputs(seed, false);
        assertEq(harness.extensionDot(weights, values), _referenceExtensionDot(weights, values));
    }

    function testExtensionDotMaximum() external view {
        (uint256[16] memory weights, uint256[16] memory values) = _extensionInputs(bytes32(0), true);
        assertEq(harness.extensionDot(weights, values), _referenceExtensionDot(weights, values));
    }

    function testFuzzBaseDot(bytes32 seed) external view {
        (uint256[16] memory weights, uint256[16] memory scalars) = _baseInputs(seed, false);
        (uint256 w0, uint256 w1) = _packScalars(scalars);
        assertEq(harness.baseDot(weights, w0, w1), _referenceBaseDot(weights, scalars));
    }

    function testBaseDotMaximum() external view {
        (uint256[16] memory weights, uint256[16] memory scalars) = _baseInputs(bytes32(0), true);
        (uint256 w0, uint256 w1) = _packScalars(scalars);
        assertEq(harness.baseDot(weights, w0, w1), _referenceBaseDot(weights, scalars));
    }

    function testFuzzFinalValue(bytes32 seed) external view {
        (bytes memory blob, uint256[] memory values, uint256[] memory point) =
            _finalInputs(seed, false);
        assertEq(harness.finalValue(blob, 3, point), _referenceFinalValue(values, point));
    }

    function testFinalValueMaximumAndZero() external view {
        (bytes memory blob, uint256[] memory values, uint256[] memory point) =
            _finalInputs(bytes32(0), true);
        assertEq(harness.finalValue(blob, 3, point), _referenceFinalValue(values, point));

        blob = new bytes(1283);
        assertEq(harness.finalValue(blob, 3, point), 0);
    }

    function testFuzzHornerRadix64(bytes32 seed) external view {
        (bytes memory blob, uint256[64] memory coefficients, uint256 x) = _hornerInputs(seed, false);
        assertEq(harness.horner64(blob, 3, x), _referenceHorner(coefficients, x));
    }

    function testHornerRadix64MaximumAndZero() external view {
        (bytes memory blob, uint256[64] memory coefficients, uint256 x) =
            _hornerInputs(bytes32(0), true);
        assertEq(harness.horner64(blob, 3, x), _referenceHorner(coefficients, x));

        blob = new bytes(1283);
        assertEq(harness.horner64(blob, 3, x), 0);
    }

    function _element(bytes32 seed, uint256 index) private pure returns (uint256 value) {
        for (uint256 coefficient = 0; coefficient < 5; ++coefficient) {
            value |= (uint256(keccak256(abi.encode(seed, index, coefficient))) % M)
                << (224 - 32 * coefficient);
        }
    }

    function _maximum() private pure returns (uint256 value) {
        for (uint256 coefficient = 0; coefficient < 5; ++coefficient) {
            value |= (M - 1) << (224 - 32 * coefficient);
        }
    }

    function _extensionInputs(bytes32 seed, bool maximal)
        private
        pure
        returns (uint256[16] memory weights, uint256[16] memory values)
    {
        for (uint256 i = 0; i < 16; ++i) {
            weights[i] = maximal ? _maximum() : _element(seed, i);
            values[i] = maximal ? _maximum() : _element(seed, 16 + i);
        }
    }

    function _baseInputs(bytes32 seed, bool maximal)
        private
        pure
        returns (uint256[16] memory weights, uint256[16] memory scalars)
    {
        for (uint256 i = 0; i < 16; ++i) {
            weights[i] = maximal ? _maximum() : _element(seed, i);
            scalars[i] = maximal ? M - 1 : uint256(keccak256(abi.encode(seed, i, "scalar"))) % M;
        }
    }

    function _packScalars(uint256[16] memory scalars)
        private
        pure
        returns (uint256 w0, uint256 w1)
    {
        for (uint256 i = 0; i < 8; ++i) {
            w0 |= scalars[i] << (224 - 32 * i);
            w1 |= scalars[8 + i] << (224 - 32 * i);
        }
    }

    function _referenceExtensionDot(uint256[16] memory weights, uint256[16] memory values)
        private
        pure
        returns (uint256 result)
    {
        for (uint256 i = 0; i < 16; ++i) {
            result = F.add(result, F.mulReference(values[i], weights[i]));
        }
    }

    function _referenceBaseDot(uint256[16] memory weights, uint256[16] memory scalars)
        private
        pure
        returns (uint256 result)
    {
        for (uint256 i = 0; i < 16; ++i) {
            result = F.add(result, F.mulBase(weights[i], scalars[i]));
        }
    }

    function _finalInputs(bytes32 seed, bool maximal)
        private
        pure
        returns (bytes memory blob, uint256[] memory values, uint256[] memory point)
    {
        blob = hex"123456";
        values = new uint256[](64);
        point = new uint256[](6);
        for (uint256 i = 0; i < 64; ++i) {
            values[i] = maximal ? _maximum() : _element(seed, i);
            blob = bytes.concat(blob, bytes20(bytes32(values[i])));
        }
        for (uint256 i = 0; i < 6; ++i) {
            point[i] = maximal ? _maximum() : _element(seed, 64 + i);
        }
    }

    function _referenceFinalValue(uint256[] memory values, uint256[] memory point)
        private
        pure
        returns (uint256)
    {
        for (uint256 dimension = 0; dimension < 6; ++dimension) {
            uint256 half = 32 >> dimension;
            for (uint256 i = 0; i < half; ++i) {
                values[i] = F.add(
                    values[i], F.mulReference(F.sub(values[i + half], values[i]), point[dimension])
                );
            }
        }
        return values[0];
    }

    function _hornerInputs(bytes32 seed, bool maximal)
        private
        pure
        returns (bytes memory blob, uint256[64] memory coefficients, uint256 x)
    {
        blob = hex"123456";
        for (uint256 i = 0; i < 64; ++i) {
            coefficients[i] = maximal ? _maximum() : _element(seed, i);
            blob = bytes.concat(blob, bytes20(bytes32(coefficients[i])));
        }
        x = maximal ? M - 1 : uint256(keccak256(abi.encode(seed, "x"))) % M;
    }

    function _referenceHorner(uint256[64] memory coefficients, uint256 x)
        private
        pure
        returns (uint256 acc)
    {
        for (uint256 i = 64; i > 0; --i) {
            acc = F.add(F.mulBase(acc, x), coefficients[i - 1]);
        }
    }
}
