// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { BabyBear } from "../src/field/BabyBear.sol";
import { BabyBearExt5 } from "../src/field/BabyBearExt5.sol";
import {
    BabyBearWhirVerifierCore5
} from "../src/whir/babybear_k22_jb100_ext5_lir4_ff4_rsv3_pow28/BabyBearWhirVerifierCore5.sol";
import { BabyBearReference as Ref } from "./helpers/BabyBearReference.sol";

contract BabyBearQuinticProductionKernelsTest is Test {
    uint256 internal constant P = BabyBear.MODULUS;

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
        return BabyBearWhirVerifierCore5._evaluateFixedEqTermsBlobRaw(
            statementPointBlob,
            0,
            initialOodPoint,
            round0OodPoint,
            round1OodPoint,
            round2OodPoint,
            fullPoint
        );
    }

    function testFuzzConstraintSelectKernelsMatchReference(
        bytes32 pointSeed,
        bytes32 valueSeed,
        uint256[3] memory rawSelVars
    ) external pure {
        uint256[] memory point = _point(pointSeed);
        uint256[] memory cache = BabyBearWhirVerifierCore5._prepareSelectCubicPairs(point);
        uint256[] memory selVars = new uint256[](rawSelVars.length);
        for (uint256 i; i < rawSelVars.length; ++i) {
            selVars[i] = rawSelVars[i] % P;
        }
        uint256 challenge = _element(valueSeed, 0);
        uint256 eqEval = _element(valueSeed, 1);

        assertEq(
            BabyBearWhirVerifierCore5._evaluateConstraintCubicRaw18WithPrecomputedEq(
                challenge, eqEval, selVars, cache
            ),
            _referenceConstraint(challenge, eqEval, selVars, point, 4, 18)
        );
        assertEq(
            BabyBearWhirVerifierCore5._evaluateConstraintCubicRaw14WithPrecomputedEq(
                challenge, eqEval, selVars, cache
            ),
            _referenceConstraint(challenge, eqEval, selVars, point, 8, 14)
        );
        assertEq(
            BabyBearWhirVerifierCore5._evaluateConstraintCubicRaw10WithPrecomputedEq(
                challenge, eqEval, selVars, cache
            ),
            _referenceConstraint(challenge, eqEval, selVars, point, 12, 10)
        );
    }

    function testFuzzSelectNonterminalRangeUsesDerivedPointer(
        bytes32 seed,
        uint256 var0,
        uint256 var1
    ) external pure {
        uint256[] memory point = _point(seed);
        uint256[] memory cache = BabyBearWhirVerifierCore5._prepareSelectCubicPairs(point);
        _checkSelectRange(point, cache, var0 % P, var1 % P, 4, 10);
    }

    function testFuzzEqFormProductsMatchReference(bytes32 leftSeed, bytes32 rightSeed)
        external
        pure
    {
        uint256[] memory left = _point(leftSeed);
        uint256[] memory right = _point(rightSeed);
        uint256 expected = BabyBearExt5.ONE;
        uint256 low;
        uint256 rev;
        uint256[4] memory preparedRight;

        for (uint256 i; i < left.length; ++i) {
            BabyBearWhirVerifierCore5._prepareEqTermForms(right[i], preparedRight);
            (uint256 termLow, uint256 termRev) =
                BabyBearWhirVerifierCore5._eqTermForms(left[i], preparedRight);
            if (i == 0) {
                low = termLow;
                rev = termRev;
            } else {
                (low, rev) = BabyBearWhirVerifierCore5._mulEqTermForms(low, rev, termLow, termRev);
            }

            expected = Ref.mul(expected, _referenceEqTerm(left[i], right[i]), P, 1);
            uint256 actual = _packForms(low, rev);
            BabyBearExt5.validatePacked(actual);
            assertEq(actual, expected);
        }
    }

    function testFuzzFixedEqAccumulatorMatchesReference(
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

    function _checkSelectRange(
        uint256[] memory point,
        uint256[] memory cache,
        uint256 var0,
        uint256 var1,
        uint256 pointOffset,
        uint256 dimensions
    ) private pure {
        uint256 expected0 = Ref.chain(var0, point, pointOffset, dimensions, P, 1);
        uint256 expected1 = Ref.chain(var1, point, pointOffset, dimensions, P, 1);

        assertEq(
            BabyBearWhirVerifierCore5._selectCubicPolyEvalFixed(
                var0, cache, pointOffset, dimensions
            ),
            expected0
        );
        (uint256 actual0, uint256 actual1) = BabyBearWhirVerifierCore5._selectCubicPolyEvalFixedPair(
            var0, var1, cache, pointOffset, dimensions
        );
        assertEq(actual0, expected0);
        assertEq(actual1, expected1);
    }

    function _referenceConstraint(
        uint256 challenge,
        uint256 eqEval,
        uint256[] memory selVars,
        uint256[] memory point,
        uint256 pointOffset,
        uint256 dimensions
    ) private pure returns (uint256 total) {
        for (uint256 i = selVars.length; i > 0; --i) {
            total = Ref.add(
                Ref.mul(total, challenge, P, 1),
                Ref.chain(selVars[i - 1], point, pointOffset, dimensions, P, 1),
                P
            );
        }
        return Ref.add(Ref.mul(total, challenge, P, 1), eqEval, P);
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
        acc = BabyBearExt5.ONE;
        for (uint256 i; i < statementPoint.length; ++i) {
            acc = Ref.mul(acc, _referenceEqTerm(statementPoint[i], fullPoint[i]), P, 1);
        }
    }

    function _referenceUnivariateEq(
        uint256 current,
        uint256[] memory fullPoint,
        uint256 pointOffset,
        uint256 dimensions
    ) private pure returns (uint256 acc) {
        acc = BabyBearExt5.ONE;
        for (uint256 i = dimensions; i > 0; --i) {
            acc = Ref.mul(acc, _referenceEqTerm(current, fullPoint[pointOffset + i - 1]), P, 1);
            current = Ref.mul(current, current, P, 1);
        }
    }

    function _referenceEqTerm(uint256 a, uint256 b) private pure returns (uint256 out) {
        out = Ref.add(BabyBearExt5.ONE, Ref.scale(a, P - 1, P), P);
        out = Ref.add(out, Ref.scale(b, P - 1, P), P);
        out = Ref.add(out, Ref.scale(Ref.mul(a, b, P, 1), 2, P), P);
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
            } { mstore(dst, mload(src)) }
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
        return BabyBearExt5.pack(coefficients);
    }
}
