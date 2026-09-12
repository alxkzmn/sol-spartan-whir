// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import { Test } from "forge-std/Test.sol";
import { BabyBearReference as Ref } from "./helpers/BabyBearReference.sol";
import {
    KoalaBearRowNineHarness,
    KoalaBearRowFiveHarness,
    KoalaBearRowKroneckerHarness,
    KoalaBearRowKroneckerFiveHarness,
    KoalaBearRowKroneckerStreamHarness,
    KoalaBearRowKroneckerStreamPackedWeightsHarness,
    KoalaBearRowKroneckerStreamLoopHarness,
    BabyBearRowNineHarness,
    BabyBearRowFiveHarness,
    BabyBearRowKroneckerHarness,
    BabyBearRowKroneckerFiveHarness,
    BabyBearRowKroneckerStreamHarness,
    BabyBearRowKroneckerStreamPackedWeightsHarness,
    BabyBearRowKroneckerStreamLoopHarness
} from "./helpers/BabyBearRowVariants.sol";

interface IRowHarness {
    function dot(uint256[16] memory values, uint256[16] memory weights)
        external
        view
        returns (uint256, uint256);
    function batch(bytes calldata blob, uint256[4] memory point, uint256 count)
        external
        view
        returns (uint256, uint256, uint256, bytes32);
}

contract BabyBearRowBenchmarkTest is Test {
    IRowHarness[14] h;

    function setUp() external {
        h[0] = IRowHarness(address(new KoalaBearRowNineHarness()));
        h[1] = IRowHarness(address(new KoalaBearRowFiveHarness()));
        h[2] = IRowHarness(address(new KoalaBearRowKroneckerHarness()));
        h[3] = IRowHarness(address(new KoalaBearRowKroneckerFiveHarness()));
        h[4] = IRowHarness(address(new KoalaBearRowKroneckerStreamHarness()));
        h[5] = IRowHarness(address(new KoalaBearRowKroneckerStreamPackedWeightsHarness()));
        h[6] = IRowHarness(address(new KoalaBearRowKroneckerStreamLoopHarness()));
        h[7] = IRowHarness(address(new BabyBearRowNineHarness()));
        h[8] = IRowHarness(address(new BabyBearRowFiveHarness()));
        h[9] = IRowHarness(address(new BabyBearRowKroneckerHarness()));
        h[10] = IRowHarness(address(new BabyBearRowKroneckerFiveHarness()));
        h[11] = IRowHarness(address(new BabyBearRowKroneckerStreamHarness()));
        h[12] = IRowHarness(address(new BabyBearRowKroneckerStreamPackedWeightsHarness()));
        h[13] = IRowHarness(address(new BabyBearRowKroneckerStreamLoopHarness()));
    }

    function _packed(bytes32 seed, uint256 i, uint256 p) private pure returns (uint256) {
        uint256[5] memory a;
        for (uint256 j; j < 5; ++j) {
            a[j] = uint256(keccak256(abi.encode(seed, i, j))) % p;
        }
        return Ref.pack(a);
    }

    function _weights(uint256[4] memory point, uint256 p, uint256 f)
        private
        pure
        returns (uint256[16] memory weights)
    {
        for (uint256 i; i < 16; ++i) {
            uint256 w = uint256(1) << 224;
            for (uint256 j; j < 4; ++j) {
                uint256 factor = ((i >> (3 - j)) & 1) != 0
                    ? point[j]
                    : Ref.add(uint256(1) << 224, Ref.scale(point[j], p - 1, p), p);
                w = Ref.mul(w, factor, p, f);
            }
            weights[i] = w;
        }
    }

    function _blob(bytes32 seed, uint256 count, uint256 p)
        private
        pure
        returns (bytes memory blob)
    {
        // Reserve padding for the final overlapping 32-byte write of a 20-byte element.
        blob = new bytes(count * 320 + 32);
        for (uint256 i; i < count * 16; ++i) {
            uint256 v = _packed(seed, i, p);
            assembly ("memory-safe") { mstore(add(add(blob, 32), mul(i, 20)), v) }
        }
        assembly ("memory-safe") { mstore(blob, mul(count, 320)) }
    }

    function testFuzzDotProducts(bytes32 seed) external view {
        for (uint256 f; f < 2; ++f) {
            uint256 p = f == 0 ? 0x7f000001 : 0x78000001;
            uint256[16] memory values;
            uint256[16] memory weights;
            uint256 expected;
            for (uint256 i; i < 16; ++i) {
                values[i] = _packed(seed, i, p);
                weights[i] = _packed(seed, i + 16, p);
                expected = Ref.add(expected, Ref.mul(values[i], weights[i], p, f), p);
            }
            for (uint256 i = f * 7; i < f * 7 + 7; ++i) {
                (, uint256 actual) = h[i].dot(values, weights);
                assertEq(actual, expected, "row oracle");
            }
        }
    }

    function testDotMaximalCoefficients() external view {
        for (uint256 f; f < 2; ++f) {
            uint256 p = f == 0 ? 0x7f000001 : 0x78000001;
            uint256 value = Ref.pack([p - 1, p - 1, p - 1, p - 1, p - 1]);
            uint256[16] memory values;
            uint256[16] memory weights;
            for (uint256 i; i < 16; ++i) {
                values[i] = value;
                weights[i] = value;
            }
            uint256 expected = Ref.scale(Ref.mul(value, value, p, f), 16, p);
            for (uint256 i = f * 7; i < f * 7 + 7; ++i) {
                (, uint256 actual) = h[i].dot(values, weights);
                assertEq(actual, expected);
            }
        }
    }

    function testFusedHashAndEvaluation() external view {
        for (uint256 f; f < 2; ++f) {
            uint256 p = f == 0 ? 0x7f000001 : 0x78000001;
            uint256[4] memory point;
            for (uint256 i; i < 4; ++i) {
                point[i] = _packed(bytes32(uint256(67)), i, p);
            }
            uint256[16] memory weights = _weights(point, p, f);
            bytes memory blob = _blob(bytes32(uint256(73)), 3, p);
            bytes32 expectedDigest;
            uint256 expectedValue;
            for (uint256 row; row < 3; ++row) {
                uint256 value;
                bytes memory leaf = new bytes(321);
                for (uint256 i; i < 320; ++i) {
                    leaf[i + 1] = blob[row * 320 + i];
                }
                for (uint256 i; i < 16; ++i) {
                    uint256 v;
                    assembly ("memory-safe") {
                        v := and(
                            mload(add(add(blob, 32), add(mul(row, 320), mul(i, 20)))),
                            not(sub(shl(96, 1), 1))
                        )
                    }
                    value = Ref.add(value, Ref.mul(v, weights[i], p, f), p);
                }
                expectedValue ^= value;
                expectedDigest ^= bytes32(bytes20(keccak256(leaf)));
            }
            for (uint256 i = f * 7; i < f * 7 + 7; ++i) {
                (,, uint256 actual, bytes32 digest) = h[i].batch(blob, point, 3);
                assertEq(actual, expectedValue, "fused value");
                assertEq(digest, expectedDigest, "leaf prefix and bytes");
            }
        }
    }

    function testRejectNoncanonicalRows() external {
        uint256[4] memory point;
        for (uint256 f; f < 2; ++f) {
            uint256 p = f == 0 ? 0x7f000001 : 0x78000001;
            for (uint256 element; element < 16; ++element) {
                for (uint256 lane; lane < 5; ++lane) {
                    bytes memory blob = new bytes(352);
                    assembly ("memory-safe") { mstore(blob, 320) }
                    uint256 bad = p << (224 - 32 * lane);
                    assembly ("memory-safe") { mstore(add(add(blob, 32), mul(element, 20)), bad) }
                    for (uint256 i = f * 7; i < f * 7 + 7; ++i) {
                        vm.expectRevert(abi.encodeWithSelector(bytes4(0xd53cfe5c), bad));
                        h[i].batch(blob, point, 1);
                    }
                }
            }
        }
    }

    function testBenchmarkRows() external {
        uint256[4] memory point;
        for (uint256 i; i < 4; ++i) {
            point[i] = _packed(bytes32(uint256(67)), i, 0x78000001);
        }
        uint256[3] memory counts = [uint256(31), 19, 14];
        bytes[3] memory blobs;
        for (uint256 r; r < 3; ++r) {
            blobs[r] = _blob(bytes32(uint256(73 + r)), counts[r], 0x78000001);
        }
        string[14] memory names = [
            "KoalaBearRowNine",
            "KoalaBearRowFive",
            "KoalaBearRowKronecker",
            "KoalaBearRowKroneckerFive",
            "KoalaBearRowKroneckerStream",
            "KoalaBearRowKroneckerStreamPackedWeights",
            "KoalaBearRowKroneckerStreamLoop",
            "BabyBearRowNine",
            "BabyBearRowFive",
            "BabyBearRowKronecker",
            "BabyBearRowKroneckerFive",
            "BabyBearRowKroneckerStream",
            "BabyBearRowKroneckerStreamPackedWeights",
            "BabyBearRowKroneckerStreamLoop"
        ];
        for (uint256 i; i < 14; ++i) {
            for (uint256 r; r < 3; ++r) {
                (uint256 setupGas, uint256 rowGas, uint256 result, bytes32 digest) =
                    h[i].batch(blobs[r], point, counts[r]);
                emit log_named_uint(
                    string.concat(names[i], ".setup", vm.toString(counts[r])), setupGas
                );
                emit log_named_uint(
                    string.concat(names[i], ".rows", vm.toString(counts[r])), rowGas
                );
                assertTrue(result != 0 && digest != 0);
            }
        }
        uint256[16] memory values;
        uint256[16] memory weights;
        for (uint256 i; i < 16; ++i) {
            values[i] = _packed(bytes32(uint256(73)), i, 0x78000001);
            weights[i] = _packed(bytes32(uint256(67)), i, 0x78000001);
        }
        for (uint256 i; i < 14; ++i) {
            (uint256 used, uint256 result) = h[i].dot(values, weights);
            emit log_named_uint(string.concat(names[i], ".dot16"), used);
            assertTrue(result != 0);
        }
    }

    function testProfileBabyBearStream() external view {
        uint256[4] memory point;
        for (uint256 i; i < 4; ++i) {
            point[i] = _packed(bytes32(uint256(67)), i, 0x78000001);
        }
        bytes memory blob = _blob(bytes32(uint256(73)), 31, 0x78000001);
        (,, uint256 value,) = h[11].batch(blob, point, 31);
        assertTrue(value != 0);
    }

    function testProfileKoalaBearNine() external view {
        uint256[4] memory point;
        for (uint256 i; i < 4; ++i) {
            point[i] = _packed(bytes32(uint256(67)), i, 0x78000001);
        }
        bytes memory blob = _blob(bytes32(uint256(73)), 31, 0x78000001);
        (,, uint256 value,) = h[0].batch(blob, point, 31);
        assertTrue(value != 0);
    }

    function testProfileBabyBearNine() external view {
        uint256[4] memory point;
        for (uint256 i; i < 4; ++i) {
            point[i] = _packed(bytes32(uint256(67)), i, 0x78000001);
        }
        bytes memory blob = _blob(bytes32(uint256(73)), 31, 0x78000001);
        (,, uint256 value,) = h[7].batch(blob, point, 31);
        assertTrue(value != 0);
    }

    function testProfileBabyBearFive() external view {
        uint256[4] memory point;
        for (uint256 i; i < 4; ++i) {
            point[i] = _packed(bytes32(uint256(67)), i, 0x78000001);
        }
        bytes memory blob = _blob(bytes32(uint256(73)), 31, 0x78000001);
        (,, uint256 value,) = h[8].batch(blob, point, 31);
        assertTrue(value != 0);
    }

    function testProfileBabyBearKronecker() external view {
        uint256[4] memory point;
        for (uint256 i; i < 4; ++i) {
            point[i] = _packed(bytes32(uint256(67)), i, 0x78000001);
        }
        bytes memory blob = _blob(bytes32(uint256(73)), 31, 0x78000001);
        (,, uint256 value,) = h[9].batch(blob, point, 31);
        assertTrue(value != 0);
    }
}
