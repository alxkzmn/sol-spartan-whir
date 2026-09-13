// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import { Test } from "forge-std/Test.sol";
import { KoalaBearExt5 as EF } from "../src/field/KoalaBearExt5.sol";
import { LeanVmWhir as Whir } from "../src/leanvm/LeanVmWhir.sol";
import { LeanVmPolynomial as Poly } from "../src/leanvm/LeanVmPolynomial.sol";

contract LeanVmSharedWeightsTest is Test {
    uint256 constant ONE = uint256(1) << 224;
    uint256 constant P = 2_130_706_433;

    function field(bytes32 seed, uint256 index) private pure returns (uint256) {
        uint256[5] memory a;
        for (uint256 j; j < 5; ++j) {
            a[j] = uint256(keccak256(abi.encode(seed, index, j))) % P;
        }
        return EF.pack(a);
    }

    function point(bytes32 seed, uint256 n) private pure returns (uint256[] memory out) {
        out = new uint256[](n);
        for (uint256 i; i < n; ++i) {
            out[i] = field(seed, i);
        }
    }

    function copy(uint256[] memory value) private pure returns (uint256[] memory out) {
        out = new uint256[](value.length);
        for (uint256 i; i < value.length; ++i) {
            out[i] = value[i];
        }
    }

    function indicator(uint256[] memory value, uint256 index) private pure returns (uint256 out) {
        out = ONE;
        for (uint256 i; i < value.length; ++i) {
            out = EF.mulReference(
                out, ((index >> (value.length - 1 - i)) & 1) == 0 ? EF.sub(ONE, value[i]) : value[i]
            );
        }
    }

    function makeStatement(
        uint256[] memory claim,
        uint256 first,
        uint256 n,
        bool shifted,
        bool interleaved
    ) private pure returns (Whir.Statement memory s) {
        uint256[] memory selectors = new uint256[](n);
        for (uint256 i; i < n; ++i) {
            selectors[i] = interleaved ? first + (i / 2) + (i % 2) * 8 : first + i;
        }
        return Whir.Statement(8, claim, selectors, new uint256[](n), shifted);
    }

    function oracle(
        Whir.Statement[][3] memory groups,
        uint256 gamma,
        uint256 theta,
        uint256 thetaPower,
        uint256[] memory evaluation
    ) private pure returns (uint256 result) {
        for (uint256 group; group < 3; ++group) {
            uint256 acc;
            uint256 power = ONE;
            for (uint256 i; i < groups[group].length; ++i) {
                Whir.Statement memory s = groups[group][i];
                uint256 h = s.point.length;
                uint256[] memory tail = Poly.slice(evaluation, 8 - h, h);
                uint256 common;
                for (uint256 row; row < (uint256(1) << h); ++row) {
                    uint256 nextRow = s.isNext && row + 1 < (uint256(1) << h) ? row + 1 : row;
                    common = EF.add(
                        common, EF.mulReference(indicator(s.point, row), indicator(tail, nextRow))
                    );
                }
                uint256[] memory prefix = Poly.slice(evaluation, 0, 8 - h);
                for (uint256 j; j < s.selectors.length; ++j) {
                    acc = EF.add(
                        acc,
                        EF.mulReference(
                            power, EF.mulReference(common, indicator(prefix, s.selectors[j]))
                        )
                    );
                    power = EF.mulReference(power, gamma);
                }
            }
            result = EF.add(result, EF.mulReference(thetaPower, acc));
            thetaPower = EF.mulReference(thetaPower, theta);
        }
    }

    function check(bytes32 seed, uint256 gamma, uint256 theta, uint256 thetaPower, uint256 mode)
        private
        pure
    {
        uint256[] memory evaluation = point(seed, 8);
        uint256[] memory a = point(keccak256(abi.encode(seed)), 4);
        uint256[] memory b = point(keccak256(abi.encode(seed, uint256(1))), 3);
        if (mode == 1) {
            for (uint256 i; i < 8; ++i) {
                evaluation[i] = 0;
            }
        }
        if (mode == 2) {
            for (uint256 i; i < 8; ++i) {
                evaluation[i] = ONE;
            }
        }
        if (mode == 3) {
            uint256[5] memory max = [P - 1, P - 1, P - 1, P - 1, P - 1];
            for (uint256 i; i < 8; ++i) {
                evaluation[i] = EF.pack(max);
            }
        }
        Whir.Statement[][3] memory groups;
        groups[0] = new Whir.Statement[](3);
        groups[0][0] = makeStatement(a, 0, 2, true, false);
        groups[0][1] = makeStatement(a, 0, 16, false, true);
        groups[0][2] = makeStatement(b, 7, 8, false, false);
        groups[1] = new Whir.Statement[](3);
        groups[1][0] = makeStatement(b, 0, 5, false, false);
        groups[1][1] = makeStatement(copy(a), 3, 4, false, false);
        groups[1][2] = makeStatement(b, 20, 2, true, false);
        groups[2] = new Whir.Statement[](3);
        groups[2][0] = makeStatement(a, 5, 5, false, false);
        groups[2][1] = makeStatement(b, 10, 8, true, false);
        groups[2][2] = makeStatement(copy(a), 0, 16, true, true);
        uint256 got = Whir.evaluateThreeGroupWeights(groups, gamma, theta, thetaPower, evaluation);
        EF.validatePacked(got);
        assertEq(got, oracle(groups, gamma, theta, thetaPower, evaluation));
    }

    function testFuzzSharedWeightsAgainstBooleanDefinition(bytes32 seed, uint256 mode)
        external
        pure
    {
        check(seed, field(seed, 30), field(seed, 31), field(seed, 32), mode % 4);
    }

    function testZeroAndOneChallenges() external pure {
        for (uint256 i; i < 4; ++i) {
            check(bytes32(i + 1), 0, ONE, ONE, i);
            check(bytes32(i + 2), ONE, 0, ONE, i);
            check(bytes32(i + 3), ONE, ONE, 0, i);
            check(bytes32(i + 4), ONE, ONE, ONE, i);
        }
    }

    function testFuzzSuccessorAndEqualityAgainstBooleanDefinition(bytes32 seed, uint256 raw)
        external
        pure
    {
        uint256 n = raw % 6;
        uint256[] memory a = point(seed, n);
        uint256[] memory full = point(keccak256(abi.encode(seed)), n + 2);
        uint256[] memory b = Poly.slice(full, 2, n);
        (uint256 successor, uint256 equality) = Poly.nextAndEq(a, full, 2);
        uint256 expectedNext;
        uint256 expectedEq;
        for (uint256 row; row < (uint256(1) << n); ++row) {
            uint256 x = indicator(a, row);
            expectedEq = EF.add(expectedEq, EF.mulReference(x, indicator(b, row)));
            uint256 nextRow = row + 1 < (uint256(1) << n) ? row + 1 : row;
            expectedNext = EF.add(expectedNext, EF.mulReference(x, indicator(b, nextRow)));
        }
        assertEq(successor, expectedNext);
        assertEq(equality, expectedEq);
    }
}
