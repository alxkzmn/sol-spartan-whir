// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { KoalaBear } from "../src/field/KoalaBear.sol";
import { KoalaBearExt5 } from "../src/field/KoalaBearExt5.sol";
import {
    WhirVerifierCore5
} from "../src/whir/k22_jb100_ext5_lir4_ff4_rsv3_pow28/WhirVerifierCore5.sol";
import {
    WhirVerifierUtils5
} from "../src/whir/k22_jb100_ext5_lir4_ff4_rsv3_pow28/WhirVerifierUtils5.sol";

contract QuinticSelectKroneckerTest is Test {
    uint256 internal constant P = KoalaBear.MODULUS;

    function evaluateFixedEqTerms(
        bytes calldata statementPointBlob,
        uint256 initialOodPoint,
        uint256 round0OodPoint,
        uint256 round1OodPoint,
        uint256 round2OodPoint,
        uint256[] memory fullPoint
    )
        external
        pure
        returns (
            uint256 statementEq,
            uint256 initialEq,
            uint256 round0Eq,
            uint256 round1Eq,
            uint256 round2Eq
        )
    {
        return WhirVerifierCore5._evaluateFixedEqTermsBlobRaw(
            statementPointBlob,
            0,
            initialOodPoint,
            round0OodPoint,
            round1OodPoint,
            round2OodPoint,
            fullPoint
        );
    }

    function testFuzzSelectChainsMatchReference(bytes32 seed, uint256 var0, uint256 var1)
        external
        pure
    {
        _checkChains(_point(seed), var0 % P, var1 % P);
    }

    function testSelectChainsBoundaryVariables() external pure {
        uint256[] memory point = _point(bytes32(uint256(1)));
        _checkChains(point, 0, 1);
        _checkChains(point, P - 1, 2);
    }

    function testSelectChainsMaximalPoint() external pure {
        uint256[] memory point = _constantPoint(_maximum());
        _checkChains(point, 0, P - 1);
    }

    function testFuzzSelectCubicDerivedPointOffset(bytes32 seed, uint256 var_) external pure {
        uint256[] memory point = _point(seed);
        uint256[] memory preparedPointPairs = WhirVerifierCore5._prepareSelectCubicPairs(point);
        uint256 expected = WhirVerifierUtils5.selectPolyEval(var_ % P, point, 4, 10);
        assertEq(
            WhirVerifierCore5._selectCubicPolyEvalFixed(var_ % P, preparedPointPairs, 4, 10),
            expected
        );
    }

    function testFuzzEqFormsChainMatchesEqTermChain(bytes32 leftSeed, bytes32 rightSeed)
        external
        pure
    {
        _checkEqChain(_point(leftSeed), _point(rightSeed));
    }

    function testEqFormsChainMaximalCoefficients() external pure {
        uint256[] memory point = _constantPoint(_maximum());
        _checkEqChain(point, point);
    }

    function testFuzzFixedEqAccumulatorMatchesEqTermProducts(
        bytes32 statementSeed,
        bytes32 fullPointSeed,
        bytes32 oodSeed
    ) external view {
        uint256[] memory statementPoint = _point(statementSeed);
        uint256[] memory fullPoint = _point(fullPointSeed);
        uint256 initialOodPoint = _element(oodSeed, 0);
        uint256 round0OodPoint = _element(oodSeed, 1);
        uint256 round1OodPoint = _element(oodSeed, 2);
        uint256 round2OodPoint = _element(oodSeed, 3);

        (
            uint256 statementEq,
            uint256 initialEq,
            uint256 round0Eq,
            uint256 round1Eq,
            uint256 round2Eq
        ) = this.evaluateFixedEqTerms(
            _encodeStatementPoint(statementPoint),
            initialOodPoint,
            round0OodPoint,
            round1OodPoint,
            round2OodPoint,
            fullPoint
        );

        assertEq(statementEq, _referenceStatementEq(statementPoint, fullPoint));
        assertEq(initialEq, _referenceUnivariateEq(initialOodPoint, fullPoint, 0, 22));
        assertEq(round0Eq, _referenceUnivariateEq(round0OodPoint, fullPoint, 4, 18));
        assertEq(round1Eq, _referenceUnivariateEq(round1OodPoint, fullPoint, 8, 14));
        assertEq(round2Eq, _referenceUnivariateEq(round2OodPoint, fullPoint, 12, 10));
    }

    function _checkChains(uint256[] memory point, uint256 var0, uint256 var1) private pure {
        uint256[] memory preparedPointPairs = WhirVerifierCore5._prepareSelectCubicPairs(point);
        for (uint256 offset = 4; offset <= 12; offset += 4) {
            uint256 dimensions = 22 - offset;
            uint256 expected0 = WhirVerifierUtils5.selectPolyEval(var0, point, offset, dimensions);
            uint256 expected1 = WhirVerifierUtils5.selectPolyEval(var1, point, offset, dimensions);
            assertEq(
                WhirVerifierCore5._selectCubicPolyEvalFixed(
                    var0, preparedPointPairs, offset, dimensions
                ),
                expected0
            );
            (uint256 actual0, uint256 actual1) = WhirVerifierCore5._selectCubicPolyEvalFixedPair(
                var0, var1, preparedPointPairs, offset, dimensions
            );
            assertEq(actual0, expected0);
            assertEq(actual1, expected1);
        }
    }

    function _checkEqChain(uint256[] memory left, uint256[] memory right) private pure {
        uint256 expected = KoalaBearExt5.ONE;
        uint256 low;
        uint256 rev;
        uint256[4] memory preparedRight;

        for (uint256 i; i < left.length; ++i) {
            WhirVerifierCore5._prepareEqTermForms(right[i], preparedRight);
            (uint256 termLow, uint256 termRev) =
                WhirVerifierCore5._eqTermForms(left[i], preparedRight);
            if (i == 0) {
                low = termLow;
                rev = termRev;
            } else {
                (low, rev) = WhirVerifierCore5._mulEqTermForms(low, rev, termLow, termRev);
            }

            expected = KoalaBearExt5.mulReference(
                expected, WhirVerifierCore5._eqTerm(left[i], right[i])
            );
            uint256 actual = _packForms(low, rev);
            KoalaBearExt5.validatePacked(actual);
            assertEq(actual, expected);
        }
    }

    function _packForms(uint256 low, uint256 rev) private pure returns (uint256 out) {
        assembly ("memory-safe") {
            out := or(
                or(
                    or(shl(224, and(low, 0xffffffff)), shl(192, and(shr(64, low), 0xffffffff))),
                    or(shl(160, and(shr(128, low), 0xffffffff)), shl(128, shr(192, low)))
                ),
                shl(96, and(rev, 0xffffffff))
            )
        }
    }

    function _referenceStatementEq(uint256[] memory statementPoint, uint256[] memory fullPoint)
        private
        pure
        returns (uint256 acc)
    {
        acc = KoalaBearExt5.ONE;
        for (uint256 i; i < statementPoint.length; ++i) {
            acc = KoalaBearExt5.mulReference(
                acc, WhirVerifierCore5._eqTerm(statementPoint[i], fullPoint[i])
            );
        }
    }

    function _referenceUnivariateEq(
        uint256 current,
        uint256[] memory fullPoint,
        uint256 pointOffset,
        uint256 dimensions
    ) private pure returns (uint256 acc) {
        acc = KoalaBearExt5.ONE;
        for (uint256 i = dimensions; i > 0; --i) {
            acc = KoalaBearExt5.mulReference(
                acc, WhirVerifierCore5._eqTerm(current, fullPoint[pointOffset + i - 1])
            );
            current = KoalaBearExt5.mulReference(current, current);
        }
    }

    function _encodeStatementPoint(uint256[] memory point)
        private
        pure
        returns (bytes memory encoded)
    {
        // The final store writes 12 zero bytes past the logical payload. Allocate
        // that padding explicitly, then restore the 22 * 20-byte logical length.
        encoded = new bytes(22 * 20 + 12);
        assembly ("memory-safe") {
            mstore(encoded, 440)
            let src := add(point, 32)
            let srcEnd := add(src, 704)
            let dst := add(encoded, 32)
            for { } lt(src, srcEnd) {
                src := add(src, 32)
                dst := add(dst, 20)
            } {
                mstore(dst, mload(src))
            }
        }
    }

    function _maximum() private pure returns (uint256) {
        uint256[5] memory coefficients = [P - 1, P - 1, P - 1, P - 1, P - 1];
        return KoalaBearExt5.pack(coefficients);
    }

    function _constantPoint(uint256 value) private pure returns (uint256[] memory point) {
        point = new uint256[](22);
        for (uint256 i; i < point.length; ++i) {
            point[i] = value;
        }
    }

    function _point(bytes32 seed) private pure returns (uint256[] memory point) {
        point = new uint256[](22);
        for (uint256 i; i < point.length; ++i) {
            point[i] = _element(seed, i);
        }
    }

    function _element(bytes32 seed, uint256 index) private pure returns (uint256) {
        uint256[5] memory coefficients;
        for (uint256 j; j < 5; ++j) {
            coefficients[j] = uint256(keccak256(abi.encode(seed, index, j))) % P;
        }
        return KoalaBearExt5.pack(coefficients);
    }
}
