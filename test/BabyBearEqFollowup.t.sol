// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import { Test } from "forge-std/Test.sol";
import { BabyBearReference as Ref } from "./helpers/BabyBearReference.sol";
import {
    KoalaBearEqPackedMulHarness,
    BabyBearEqPackedMulHarness
} from "./helpers/BabyBearEqVariants.sol";
import {
    KoalaBearEqShiftedHarness,
    KoalaBearEqShiftedNoFinalHarness,
    BabyBearEqShiftedHarness,
    BabyBearEqShiftedNoFinalHarness
} from "./helpers/BabyBearEqFollowup.sol";

interface IEqHarness {
    function mul(uint256 a, uint256 b) external pure returns (uint256);
    function square(uint256 a) external pure returns (uint256);
    function eq(uint256 a, uint256 b) external pure returns (uint256);
    function squares(uint256 a, uint256 n) external view returns (uint256, uint256);
    function prepare(bytes calldata statement, uint256[4] memory ood, uint256[] memory point)
        external
        view
        returns (uint256, uint256[5] memory);
}

contract BabyBearEqFollowupTest is Test {
    IEqHarness[6] h;

    function setUp() external {
        h[0] = IEqHarness(address(new KoalaBearEqPackedMulHarness()));
        h[1] = IEqHarness(address(new KoalaBearEqShiftedHarness()));
        h[2] = IEqHarness(address(new KoalaBearEqShiftedNoFinalHarness()));
        h[3] = IEqHarness(address(new BabyBearEqPackedMulHarness()));
        h[4] = IEqHarness(address(new BabyBearEqShiftedHarness()));
        h[5] = IEqHarness(address(new BabyBearEqShiftedNoFinalHarness()));
    }

    function _canonical(uint256[5] memory a, uint256 p) private pure returns (uint256) {
        uint256[5] memory b;
        for (uint256 i; i < 5; ++i) {
            b[i] = a[i] % p;
        }
        return Ref.pack(b);
    }

    function _eq(uint256 a, uint256 b, uint256 p, uint256 f) private pure returns (uint256) {
        return Ref.add(
            uint256(1) << 224,
            Ref.add(Ref.scale(Ref.mul(a, b, p, f), 2, p), Ref.scale(Ref.add(a, b, p), p - 1, p), p),
            p
        );
    }

    function testFuzzSquareAndEq(uint256[5] memory a, uint256[5] memory b) external view {
        for (uint256 i; i < 6; ++i) {
            uint256 p = i < 3 ? 0x7f000001 : 0x78000001;
            uint256 f = i < 3 ? 0 : 1;
            uint256 x = _canonical(a, p);
            uint256 y = _canonical(b, p);
            assertEq(h[i].mul(x, y), Ref.mul(x, y, p, f), "multiply oracle");
            assertEq(h[i].square(x), Ref.mul(x, x, p, f), "square oracle");
            assertEq(h[i].eq(x, y), _eq(x, y, p, f), "equality oracle");
        }
    }

    function testBoundarySquaresAndEq() external view {
        for (uint256 i; i < 6; ++i) {
            uint256 p = i < 3 ? 0x7f000001 : 0x78000001;
            uint256 f = i < 3 ? 0 : 1;
            uint256 x = Ref.pack([p - 1, p - 1, p - 1, p - 1, p - 1]);
            assertEq(h[i].square(x), Ref.mul(x, x, p, f));
            assertEq(h[i].eq(x, x), _eq(x, x, p, f));
            assertEq(h[i].eq(0, x), _eq(0, x, p, f));
            for (uint256 j; j < 5; ++j) {
                for (uint256 k; k < 5; ++k) {
                    uint256 a = (p - 1) << (224 - 32 * j);
                    uint256 b = (p - 1) << (224 - 32 * k);
                    assertEq(h[i].mul(a, b), Ref.mul(a, b, p, f), "basis product");
                }
            }
        }
    }

    function _packed(uint256 seed, uint256 i) private pure returns (uint256) {
        uint256[5] memory a;
        for (uint256 j; j < 5; ++j) {
            a[j] = uint256(keccak256(abi.encode(seed, i, j))) % 0x78000001;
        }
        return Ref.pack(a);
    }

    function _inputs(uint256 seed)
        private
        pure
        returns (bytes memory statement, uint256[4] memory ood, uint256[] memory point)
    {
        statement = new bytes(472);
        point = new uint256[](22);
        for (uint256 i; i < 22; ++i) {
            uint256 x = _packed(seed, i);
            assembly ("memory-safe") { mstore(add(add(statement, 32), mul(i, 20)), x) }
            point[i] = _packed(seed, i + 22);
        }
        assembly ("memory-safe") { mstore(statement, 440) }
        for (uint256 j; j < 4; ++j) {
            ood[j] = _packed(seed, j + 44);
        }
    }

    function testFixedPreparation() external view {
        _checkPreparation(20_260_905);
    }

    function testFuzzFixedPreparation(uint256 seed) external view {
        _checkPreparation(seed);
    }

    function _checkPreparation(uint256 seed) private view {
        (bytes memory statement, uint256[4] memory ood, uint256[] memory point) = _inputs(seed);
        for (uint256 f; f < 2; ++f) {
            uint256 p = f == 0 ? 0x7f000001 : 0x78000001;
            uint256[5] memory expected;
            uint256[4] memory current;
            for (uint256 j; j < 5; ++j) {
                expected[j] = uint256(1) << 224;
            }
            for (uint256 j; j < 4; ++j) {
                current[j] = ood[j];
            }
            for (uint256 i = 22; i > 0; --i) {
                uint256 x;
                assembly ("memory-safe") {
                    x := and(
                        mload(add(add(statement, 32), mul(sub(i, 1), 20))),
                        not(sub(shl(96, 1), 1))
                    )
                }
                uint256 q = point[i - 1];
                expected[0] = Ref.mul(expected[0], _eq(x, q, p, f), p, f);
                for (uint256 j; j < 4; ++j) {
                    if (i > 4 * j) {
                        expected[j + 1] = Ref.mul(expected[j + 1], _eq(current[j], q, p, f), p, f);
                        current[j] = Ref.mul(current[j], current[j], p, f);
                    }
                }
            }
            for (uint256 j = f == 0 ? 0 : 3; j < (f == 0 ? 3 : 6); ++j) {
                (, uint256[5] memory actual) = h[j].prepare(statement, ood, point);
                assertEq(abi.encode(actual), abi.encode(expected), "fixed preparation oracle");
            }
        }
    }

    function testBenchmarkPreparation() external {
        (bytes memory statement, uint256[4] memory ood, uint256[] memory point) =
            _inputs(20_260_905);
        string[6] memory names = [
            "KoalaBearEqPackedMul",
            "KoalaBearEqShifted",
            "KoalaBearEqShiftedNoFinal",
            "BabyBearEqPackedMul",
            "BabyBearEqShifted",
            "BabyBearEqShiftedNoFinal"
        ];
        for (uint256 i; i < 6; ++i) {
            (uint256 used, uint256[5] memory result) = h[i].prepare(statement, ood, point);
            assertTrue((result[0] | result[1] | result[2] | result[3] | result[4]) != 0);
            emit log_named_uint(string.concat(names[i], ".prepare"), used);
            (uint256 squaresGas, uint256 value) = h[i].squares(ood[0], 64);
            assertTrue(value != 0);
            emit log_named_uint(string.concat(names[i], ".squares64"), squaresGas);
        }
    }

    function testProfileBestEquality() external view {
        (bytes memory statement, uint256[4] memory ood, uint256[] memory point) =
            _inputs(20_260_905);
        (, uint256[5] memory result) = h[4].prepare(statement, ood, point);
        assertTrue(result[0] != 0);
    }
}
