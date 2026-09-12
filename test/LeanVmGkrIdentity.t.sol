// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { KoalaBearExt5 as EF } from "../src/field/KoalaBearExt5.sol";
import { LeanVmGkrSumcheck as Cubic } from "../src/leanvm/LeanVmGkrSumcheck.sol";

contract LeanVmGkrIdentityHarness {
    function sum(uint256[4] memory c) external pure returns (uint256 out) {
        for (uint256 i; i < 4; ++i) {
            EF.validatePacked(c[i]);
        }
        out = Cubic.sumAtZeroAndOne(c[0], c[1], c[2], c[3]);
        EF.validatePacked(out);
    }
}

contract LeanVmGkrIdentityTest is Test {
    uint256 private constant P = 2_130_706_433;
    LeanVmGkrIdentityHarness private harness;

    function setUp() public {
        harness = new LeanVmGkrIdentityHarness();
    }

    function testFuzzIdentityMatchesScalarCoefficients(uint256 seed) public view {
        uint256[4] memory c;
        for (uint256 i; i < 4; ++i) {
            uint256[5] memory coefficients;
            for (uint256 j; j < 5; ++j) {
                coefficients[j] = uint256(keccak256(abi.encode(seed, i, j))) % P;
            }
            c[i] = EF.pack(coefficients);
        }
        assertEq(harness.sum(c), _reference(c));
    }

    function testZeroOneAndMaximumCarryCombinations() public view {
        uint256[3] memory choices = [uint256(0), 1, P - 1];
        for (uint256 selection; selection < 81; ++selection) {
            uint256[4] memory c;
            uint256 remaining = selection;
            for (uint256 i; i < 4; ++i) {
                uint256 value = choices[remaining % 3];
                remaining /= 3;
                c[i] = EF.pack([value, value, value, value, value]);
            }
            assertEq(harness.sum(c), _reference(c));
        }
        uint256[4] memory mixed;
        mixed[0] = EF.pack([P - 1, 0, P - 1, 1, P - 1]);
        mixed[1] = EF.pack([uint256(1), P - 1, 0, P - 1, P - 1]);
        mixed[2] = EF.pack([P - 1, 1, 1, 0, P - 1]);
        mixed[3] = EF.pack([uint256(0), 0, P - 1, P - 1, P - 1]);
        assertEq(harness.sum(mixed), _reference(mixed));
    }

    function testEveryInputAndCoefficientPosition() public view {
        for (uint256 i; i < 4; ++i) {
            for (uint256 j; j < 5; ++j) {
                uint256[4] memory c;
                c[i] = (P - 1) << (224 - 32 * j);
                assertEq(harness.sum(c), _reference(c));
            }
        }
    }

    function testRejectsMalformedPackedInputsAtBoundary() public {
        for (uint256 i; i < 4; ++i) {
            uint256[4] memory c;
            c[i] = 1;
            vm.expectRevert();
            harness.sum(c);
            for (uint256 j; j < 5; ++j) {
                c[i] = P << (224 - 32 * j);
                vm.expectRevert();
                harness.sum(c);
            }
        }
    }

    // Compute the complete integer sum separately in each coefficient and reduce
    // only once. Each sum is at most 5*(P-1), so uint256 arithmetic is exact.
    function _reference(uint256[4] memory c) private pure returns (uint256 out) {
        for (uint256 j; j < 5; ++j) {
            uint256 shift = 224 - 32 * j;
            uint256 coefficient = 2 * ((c[0] >> shift) & 0xffffffff);
            for (uint256 i = 1; i < 4; ++i) {
                coefficient += (c[i] >> shift) & 0xffffffff;
            }
            out |= (coefficient % P) << shift;
        }
    }
}
