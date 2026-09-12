// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { KoalaBearExt5 as E } from "../src/field/KoalaBearExt5.sol";
import { LeanVmAirLinear as Linear } from "../src/leanvm/LeanVmAirLinear.sol";
import { LeanVmAir } from "../src/leanvm/LeanVmAir.sol";
import { LeanVmAirReference } from "./helpers/LeanVmAirReference.sol";

contract LeanVmAirLinearHarness {
    function sparseTail(
        uint256[16] memory input,
        uint256 first,
        bytes memory constants,
        uint256 offset
    ) external pure returns (uint256[16] memory) {
        _validate(input);
        E.validatePacked(first);
        Linear.sparseTail(input, first, constants, offset);
        _validate(input);
        return input;
    }

    function dot(uint256[16] memory input, bytes memory constants, uint256 offset)
        external
        pure
        returns (uint256)
    {
        _validate(input);
        return Linear.dot16(input, constants, offset);
    }

    function mds(uint256[16] memory input, bool inPlace)
        external
        pure
        returns (uint256[16] memory output)
    {
        _validate(input);
        if (inPlace) output = input;
        uint256 checkpoint;
        assembly ("memory-safe") { checkpoint := mload(0x40) }
        Linear.mds16(input, output);
        uint256 afterCall;
        assembly ("memory-safe") { afterCall := mload(0x40) }
        require(afterCall == checkpoint, "SCRATCH_LIFETIME");
    }

    function matrix(uint256[16] memory input, bytes memory constants, uint256 offset, bool inPlace)
        external
        pure
        returns (uint256[16] memory output)
    {
        _validate(input);
        if (inPlace) output = input;
        uint256 checkpoint;
        assembly ("memory-safe") { checkpoint := mload(0x40) }
        Linear.matrix16(input, constants, offset, output);
        uint256 afterCall;
        assembly ("memory-safe") { afterCall := mload(0x40) }
        require(afterCall == checkpoint, "SCRATCH_LIFETIME");
    }

    function air(uint256[] memory flat, uint256[] memory alphas, uint256[] memory beta)
        external
        pure
        returns (uint256)
    {
        return LeanVmAir.evalPoseidon(flat, new uint256[](0), alphas, beta);
    }

    function referenceAir(uint256[] memory flat, uint256[] memory alphas, uint256[] memory beta)
        external
        pure
        returns (uint256)
    {
        return LeanVmAirReference.evalPoseidon(flat, new uint256[](0), alphas, beta);
    }

    function _validate(uint256[16] memory input) private pure {
        for (uint256 i; i < 16; ++i) {
            E.validatePacked(input[i]);
        }
    }
}

contract LeanVmAirLinearTest is Test {
    uint256 private constant P = 2_130_706_433;
    LeanVmAirLinearHarness private harness;

    function setUp() public {
        harness = new LeanVmAirLinearHarness();
    }

    function testFuzzSparseTailMatchesIndependentCoefficients(uint256 seed) public view {
        uint256[16] memory input = _input(seed);
        uint256 first = _randomWord(seed, 123);
        bytes memory constants = new bytes(12 + 60);
        for (uint256 i; i < 15; ++i) {
            _setScalar(constants, i + 3, uint32(uint256(keccak256(abi.encode(seed, i)))));
        }
        for (uint256 round; round < 3; ++round) {
            uint256[16] memory expected = _referenceSparseTail(input, first, constants, 3);
            input = harness.sparseTail(input, first, constants, 3);
            _equal(input, expected);
            first = input[round + 1];
        }
    }

    function testSparseTailExtremesAndBounds() public {
        uint256[16] memory input;
        bytes memory constants = new bytes(60);
        for (uint256 i; i < 16; ++i) {
            input[i] = _repeated(P - 1);
        }
        for (uint256 i; i < 15; ++i) {
            _setScalar(constants, i, type(uint32).max);
        }
        _equal(
            harness.sparseTail(input, _repeated(P - 1), constants, 0),
            _referenceSparseTail(input, _repeated(P - 1), constants, 0)
        );
        _equal(harness.sparseTail(input, 0, constants, 0), input);
        _equal(harness.sparseTail(input, _repeated(P - 1), new bytes(60), 0), input);
        vm.expectRevert(Linear.MatrixConstantsLength.selector);
        harness.sparseTail(input, 0, new bytes(59), 0);
        vm.expectRevert(Linear.MatrixConstantsLength.selector);
        harness.sparseTail(input, 0, constants, type(uint256).max);
        vm.expectRevert();
        harness.sparseTail(input, P << 224, constants, 0);
        vm.expectRevert();
        harness.sparseTail(input, 1, constants, 0);
    }

    function _referenceSparseTail(
        uint256[16] memory input,
        uint256 first,
        bytes memory constants,
        uint256 offset
    ) private pure returns (uint256[16] memory out) {
        out[0] = input[0];
        uint256[5] memory a = E.unpack(first);
        for (uint256 i = 1; i < 16; ++i) {
            uint256 scalar;
            for (uint256 b; b < 4; ++b) {
                scalar = (scalar << 8) | uint8(constants[4 * (offset + i - 1) + b]);
            }
            uint256[5] memory coefficients = E.unpack(input[i]);
            for (uint256 j; j < 5; ++j) {
                coefficients[j] = addmod(coefficients[j], mulmod(a[j], scalar, P), P);
            }
            out[i] = E.pack(coefficients);
        }
    }

    function testFuzzDotMatchesIndependentCoefficients(uint256 seed) public view {
        uint256[16] memory input = _input(seed);
        bytes memory constants = new bytes(12 + 64);
        uint256[5] memory expected;
        for (uint256 i; i < 16; ++i) {
            uint256 scalar = uint32(uint256(keccak256(abi.encode(seed, i))));
            _setScalar(constants, i + 3, uint32(scalar));
            uint256[5] memory coefficients = E.unpack(input[i]);
            for (uint256 j; j < 5; ++j) {
                expected[j] = addmod(expected[j], mulmod(coefficients[j], scalar, P), P);
            }
        }
        uint256 actual = harness.dot(input, constants, 3);
        E.validatePacked(actual);
        assertEq(actual, E.pack(expected));
    }

    function testDotMaximumScalarsAndBounds() public {
        uint256[16] memory input;
        bytes memory constants = new bytes(64);
        for (uint256 i; i < 16; ++i) {
            input[i] = E.pack([P - 1, P - 1, P - 1, P - 1, P - 1]);
            _setScalar(constants, i, type(uint32).max);
        }
        uint256 coefficient = mulmod(16 * (P - 1), type(uint32).max, P);
        assertEq(
            harness.dot(input, constants, 0),
            E.pack([coefficient, coefficient, coefficient, coefficient, coefficient])
        );
        vm.expectRevert(Linear.MatrixConstantsLength.selector);
        harness.dot(input, new bytes(63), 0);
        vm.expectRevert(Linear.MatrixConstantsLength.selector);
        harness.dot(input, constants, type(uint256).max);
    }

    function testFuzzMdsMatchesIndependentCoefficients(uint256 seed) public view {
        uint256[16] memory input = _input(seed);
        uint256[16] memory expected = _referenceMds(input);
        _equal(harness.mds(input, false), expected);
        _equal(harness.mds(input, true), expected);
    }

    function testFuzzMatrixMatchesIndependentCoefficients(uint256 seed) public view {
        uint256[16] memory input = _input(seed);
        bytes memory constants = new bytes(12 + 1024);
        for (uint256 i; i < 256; ++i) {
            _setScalar(constants, i + 3, uint32(uint256(keccak256(abi.encode(seed, i)))));
        }
        uint256[16] memory expected = _referenceMatrix(input, constants, 3);
        _equal(harness.matrix(input, constants, 3, false), expected);
        _equal(harness.matrix(input, constants, 3, true), expected);
    }

    function testMdsRotationAndEveryExtensionBasis() public view {
        for (uint256 j; j < 16; ++j) {
            for (uint256 k; k < 5; ++k) {
                uint256[16] memory input;
                input[j] = uint256(1) << (224 - 32 * k);
                _equal(harness.mds(input, false), _referenceMds(input));
            }
        }
    }

    function testMaximumInputAndU32Scalars() public view {
        uint256[16] memory input;
        for (uint256 j; j < 16; ++j) {
            input[j] = _repeated(P - 1);
        }
        bytes memory constants = new bytes(1024);
        for (uint256 i; i < 256; ++i) {
            _setScalar(constants, i, type(uint32).max);
        }
        _equal(harness.matrix(input, constants, 0, true), _referenceMatrix(input, constants, 0));
        _equal(harness.mds(input, true), _referenceMds(input));
    }

    function testIdentityAndZeroMatrices() public view {
        uint256[16] memory input = _input(123_456);
        bytes memory constants = new bytes(1024);
        uint256[16] memory zero;
        _equal(harness.matrix(input, constants, 0, false), zero);
        for (uint256 i; i < 16; ++i) {
            _setScalar(constants, i * 17, 1);
        }
        _equal(harness.matrix(input, constants, 0, true), input);
    }

    function testRepeatedMatrixCallsKeepInputsAndResultsAlive() public view {
        uint256[16] memory input = _input(789);
        uint256[16] memory expected = _referenceMds(input);
        uint256[16] memory actual = harness.mds(input, true);
        for (uint256 i; i < 4; ++i) {
            actual = harness.mds(actual, true);
            expected = _referenceMds(expected);
        }
        _equal(actual, expected);
        _equal(input, _input(789));
    }

    function testRejectsShortConstantsAndOverflowingOffset() public {
        uint256[16] memory input;
        vm.expectRevert(Linear.MatrixConstantsLength.selector);
        harness.matrix(input, new bytes(1023), 0, false);
        vm.expectRevert(Linear.MatrixConstantsLength.selector);
        harness.matrix(input, new bytes(1024), 1, false);
        vm.expectRevert(Linear.MatrixConstantsLength.selector);
        harness.matrix(input, new bytes(1024), type(uint256).max, false);
    }

    function testRejectsNoncanonicalInputAtBoundary() public {
        uint256[16] memory input;
        input[7] = P << 224;
        vm.expectRevert();
        harness.mds(input, false);
        input[7] = 1;
        vm.expectRevert();
        harness.matrix(input, new bytes(1024), 0, false);
    }

    function testCompleteAirMaximumValuesMatchReference() public view {
        uint256[] memory flat = _filled(110, _repeated(P - 1));
        uint256[] memory alphas = _filled(96, _repeated(P - 1));
        uint256[] memory beta = _filled(16, _repeated(P - 1));
        assertEq(harness.air(flat, alphas, beta), harness.referenceAir(flat, alphas, beta));
    }

    function testCompleteAirMixedValuesMatchReference() public view {
        uint256[] memory flat = new uint256[](110);
        uint256[] memory alphas = new uint256[](96);
        uint256[] memory beta = new uint256[](16);
        for (uint256 i; i < 110; ++i) {
            flat[i] = _randomWord(1234, i);
        }
        for (uint256 i; i < 96; ++i) {
            alphas[i] = _randomWord(5678, i);
        }
        for (uint256 i; i < 16; ++i) {
            beta[i] = _randomWord(9012, i);
        }
        assertEq(harness.air(flat, alphas, beta), harness.referenceAir(flat, alphas, beta));
    }

    function _referenceMds(uint256[16] memory input)
        private
        pure
        returns (uint256[16] memory output)
    {
        uint256[16] memory firstRow =
            [uint256(1), 1, 51, 1, 11, 17, 2, 1, 101, 63, 15, 2, 67, 22, 13, 3];
        for (uint256 i; i < 16; ++i) {
            for (uint256 k; k < 5; ++k) {
                uint256 sum;
                for (uint256 j; j < 16; ++j) {
                    uint256 c = (input[j] >> (224 - 32 * k)) & 0xffffffff;
                    sum = addmod(sum, mulmod(c, firstRow[(j + 16 - i) % 16], P), P);
                }
                output[i] |= sum << (224 - 32 * k);
            }
        }
    }

    function _referenceMatrix(uint256[16] memory input, bytes memory constants, uint256 offset)
        private
        pure
        returns (uint256[16] memory output)
    {
        for (uint256 i; i < 16; ++i) {
            for (uint256 k; k < 5; ++k) {
                uint256 sum;
                for (uint256 j; j < 16; ++j) {
                    uint256 at = (offset + i * 16 + j) * 4;
                    uint256 scalar = (uint256(uint8(constants[at])) << 24)
                        | (uint256(uint8(constants[at + 1])) << 16)
                        | (uint256(uint8(constants[at + 2])) << 8)
                        | uint256(uint8(constants[at + 3]));
                    uint256 c = (input[j] >> (224 - 32 * k)) & 0xffffffff;
                    sum = addmod(sum, mulmod(c, scalar, P), P);
                }
                output[i] |= sum << (224 - 32 * k);
            }
        }
    }

    function _input(uint256 seed) private pure returns (uint256[16] memory input) {
        for (uint256 j; j < 16; ++j) {
            input[j] = _randomWord(seed, j);
        }
    }

    function _randomWord(uint256 seed, uint256 j) private pure returns (uint256 word) {
        for (uint256 k; k < 5; ++k) {
            word |= (uint256(keccak256(abi.encode(seed, j, k))) % P) << (224 - 32 * k);
        }
    }

    function _repeated(uint256 value) private pure returns (uint256 word) {
        for (uint256 k; k < 5; ++k) {
            word |= value << (224 - 32 * k);
        }
    }

    function _filled(uint256 count, uint256 value) private pure returns (uint256[] memory out) {
        out = new uint256[](count);
        for (uint256 i; i < count; ++i) {
            out[i] = value;
        }
    }

    function _setScalar(bytes memory constants, uint256 index, uint32 scalar) private pure {
        for (uint256 k; k < 4; ++k) {
            constants[index * 4 + k] = bytes1(uint8(scalar >> (24 - 8 * k)));
        }
    }

    function _equal(uint256[16] memory actual, uint256[16] memory expected) private pure {
        for (uint256 i; i < 16; ++i) {
            E.validatePacked(actual[i]);
            assertEq(actual[i], expected[i]);
        }
    }
}
