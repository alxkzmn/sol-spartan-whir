// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";

import { KoalaBear } from "../src/field/KoalaBear.sol";
import { KoalaBearExt8 } from "../src/field/KoalaBearExt8.sol";
import { WhirVerifierCore8 } from "../src/whir/k22_jb100_lir6_ff4_rsv1/WhirVerifierCore8.sol";
import { WhirVerifierUtils8 } from "../src/whir/k22_jb100_lir6_ff4_rsv1/WhirVerifierUtils8.sol";

contract Ext8TowerOptimizationsTest is Test {
    function testTowerBlobRowMatchesReferenceEvaluation() external view {
        bytes memory rowBlob = _makeExt8RowBlob();
        uint256[4] memory point = _makePoint();

        (bytes32 digest, uint256 evalValue) =
            this.towerBlobHashAndEvaluate(rowBlob, point[0], point[1], point[2], point[3]);

        assertEq(digest, _maskedLeafDigest(rowBlob));
        assertEq(evalValue, _referenceRowEval(rowBlob, point));
    }

    function testTowerBlobRowMaxLanesMatchesReferenceDotProduct() external view {
        bytes memory rowBlob = _makeMaxExt8RowBlob();
        uint256 maxValue = _maxExt8();

        (bytes32 digest, uint256 evalValue) =
            this.towerBlobHashAndEvaluateWithRepeatedWeight(rowBlob, maxValue);

        assertEq(digest, _maskedLeafDigest(rowBlob));
        assertEq(evalValue, _referenceRowDot(rowBlob, maxValue));
    }

    function testTowerSelectPolyMatchesReferenceHelper() external pure {
        uint256[] memory fullPoint = _makeFullPoint();
        uint256[4] memory vars = [_base(101), _base(202), _base(303), _base(404)];

        unchecked {
            for (uint256 i = 0; i < vars.length; ++i) {
                assertEq(
                    WhirVerifierCore8._selectPolyEvalAtOffsetTower(vars[i], fullPoint, 0x80, 18),
                    WhirVerifierUtils8.selectPolyEval(vars[i], fullPoint, 4, 18)
                );
                assertEq(
                    WhirVerifierCore8._selectPolyEvalAtOffsetTower(vars[i], fullPoint, 0x100, 14),
                    WhirVerifierUtils8.selectPolyEval(vars[i], fullPoint, 8, 14)
                );
                assertEq(
                    WhirVerifierCore8._selectPolyEvalAtOffsetTower(vars[i], fullPoint, 0x180, 10),
                    WhirVerifierUtils8.selectPolyEval(vars[i], fullPoint, 12, 10)
                );
            }
        }
    }

    function testTowerEqTermMultiplyMatchesReferenceHelper() external pure {
        uint256[8] memory inputs = _makeExt8Inputs();
        unchecked {
            for (uint256 i = 0; i < inputs.length; ++i) {
                for (uint256 j = 0; j < inputs.length; ++j) {
                    uint256 acc = inputs[(i + j + 1) & 7];
                    uint256 p = inputs[i];
                    uint256 q = inputs[j];
                    assertEq(
                        WhirVerifierCore8._mulEqTermTower(acc, p, q),
                        KoalaBearExt8.mul(acc, WhirVerifierCore8._eqTerm(p, q))
                    );
                }
            }
        }
    }

    function towerBlobHashAndEvaluate(
        bytes calldata rowBlob,
        uint256 p0,
        uint256 p1,
        uint256 p2,
        uint256 p3
    ) external pure returns (bytes32 digest, uint256 evalValue) {
        uint256 weightsPtr = WhirVerifierUtils8._computeDim4EqWeights(p0, p1, p2, p3);
        return WhirVerifierUtils8._hashAndEvaluateExtensionRowDim4BlobTowerPackedPoints(
            rowBlob, 0, weightsPtr
        );
    }

    function towerBlobHashAndEvaluateWithRepeatedWeight(bytes calldata rowBlob, uint256 weight)
        external
        pure
        returns (bytes32 digest, uint256 evalValue)
    {
        uint256 weightsPtr;
        assembly ("memory-safe") {
            weightsPtr := mload(0x40)
            mstore(0x40, add(weightsPtr, 0x200))
            for { let i := 0 } lt(i, 16) { i := add(i, 1) } {
                mstore(add(weightsPtr, shl(5, i)), weight)
            }
        }
        return WhirVerifierUtils8._hashAndEvaluateExtensionRowDim4BlobTowerPackedPoints(
            rowBlob, 0, weightsPtr
        );
    }

    function _referenceRowEval(bytes memory rowBlob, uint256[4] memory point)
        internal
        pure
        returns (uint256)
    {
        uint256[] memory evals = new uint256[](16);
        unchecked {
            for (uint256 i = 0; i < 16; ++i) {
                uint256 value;
                assembly ("memory-safe") {
                    value := mload(add(add(rowBlob, 0x20), shl(5, i)))
                }
                evals[i] = value;
            }
        }

        uint256[] memory pointArray = new uint256[](4);
        pointArray[0] = point[0];
        pointArray[1] = point[1];
        pointArray[2] = point[2];
        pointArray[3] = point[3];
        return KoalaBearExt8.evaluate_hypercube(evals, pointArray);
    }

    function _referenceRowDot(bytes memory rowBlob, uint256 weight)
        internal
        pure
        returns (uint256 acc)
    {
        unchecked {
            for (uint256 i = 0; i < 16; ++i) {
                uint256 value;
                assembly ("memory-safe") {
                    value := mload(add(add(rowBlob, 0x20), shl(5, i)))
                }
                acc = KoalaBearExt8.add(acc, KoalaBearExt8.mul(value, weight));
            }
        }
    }

    function _maskedLeafDigest(bytes memory rowBlob) internal pure returns (bytes32) {
        return
            bytes32(uint256(keccak256(bytes.concat(hex"00", rowBlob))) & ~((uint256(1) << 96) - 1));
    }

    function _makeExt8Inputs() internal pure returns (uint256[8] memory inputs) {
        unchecked {
            for (uint256 i = 0; i < inputs.length; ++i) {
                uint256[8] memory coeffs;
                for (uint256 j = 0; j < coeffs.length; ++j) {
                    coeffs[j] = _base(21 + i * 19 + j * 11);
                }
                inputs[i] = KoalaBearExt8.pack(coeffs);
            }
        }
    }

    function _makePoint() internal pure returns (uint256[4] memory point) {
        unchecked {
            for (uint256 i = 0; i < point.length; ++i) {
                uint256[8] memory coeffs;
                for (uint256 j = 0; j < coeffs.length; ++j) {
                    coeffs[j] = _base(901 + i * 29 + j * 13);
                }
                point[i] = KoalaBearExt8.pack(coeffs);
            }
        }
    }

    function _makeFullPoint() internal pure returns (uint256[] memory point) {
        point = new uint256[](22);
        unchecked {
            for (uint256 i = 0; i < point.length; ++i) {
                uint256[8] memory coeffs;
                for (uint256 j = 0; j < coeffs.length; ++j) {
                    coeffs[j] = _base(1701 + i * 31 + j * 19);
                }
                point[i] = KoalaBearExt8.pack(coeffs);
            }
        }
    }

    function _makeExt8RowBlob() internal pure returns (bytes memory blob) {
        blob = new bytes(0x200);
        unchecked {
            for (uint256 i = 0; i < 16; ++i) {
                uint256[8] memory coeffs;
                for (uint256 j = 0; j < coeffs.length; ++j) {
                    coeffs[j] = _base(301 + i * 23 + j * 17);
                }
                uint256 value = KoalaBearExt8.pack(coeffs);
                assembly ("memory-safe") {
                    mstore(add(add(blob, 0x20), shl(5, i)), value)
                }
            }
        }
    }

    function _makeMaxExt8RowBlob() internal pure returns (bytes memory blob) {
        blob = new bytes(0x200);
        uint256 value = _maxExt8();
        unchecked {
            for (uint256 i = 0; i < 16; ++i) {
                assembly ("memory-safe") {
                    mstore(add(add(blob, 0x20), shl(5, i)), value)
                }
            }
        }
    }

    function _maxExt8() internal pure returns (uint256) {
        uint256[8] memory coeffs;
        unchecked {
            for (uint256 i = 0; i < coeffs.length; ++i) {
                coeffs[i] = KoalaBear.MODULUS - 1;
            }
        }
        return KoalaBearExt8.pack(coeffs);
    }

    function _base(uint256 seed) internal pure returns (uint256) {
        return (seed * 1_315_423_911 + 17) % KoalaBear.MODULUS;
    }
}
