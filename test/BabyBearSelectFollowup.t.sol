// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import { Test } from "forge-std/Test.sol";
import { BabyBearReference as Ref } from "./helpers/BabyBearReference.sol";
import {
    BabyBearSelectFormsHarness,
    BabyBearSelectInlineHarness,
    BabyBearSelectSinglesHarness,
    BabyBearSelectAssemblyLoopHarness,
    BabyBearSelectCubicsHarness,
    KoalaBearSelectCubicsHarness,
    BabyBearSelectCubicsPackedHornerHarness
} from "./helpers/BabyBearSelectFollowup.sol";

interface H {
    function batch(uint256[] memory, uint256[][3] memory, uint256[3] memory, uint256[3] memory)
        external
        view
        returns (uint256, uint256[3] memory);
    function chains(uint256[] memory, uint256, uint256, uint256, uint256)
        external
        view
        returns (uint256, uint256, uint256);
    function single(uint256[] memory, uint256, uint256, uint256) external pure returns (uint256);
}

contract BabyBearSelectFollowupTest is Test {
    uint256 constant Q = 0x78000001;
    H[6] h;
    H kh;

    function setUp() external {
        h[5] = H(address(new BabyBearSelectCubicsPackedHornerHarness()));
        kh = H(address(new KoalaBearSelectCubicsHarness()));
        h[4] = H(address(new BabyBearSelectCubicsHarness()));
        h[0] = H(address(new BabyBearSelectFormsHarness()));
        h[1] = H(address(new BabyBearSelectInlineHarness()));
        h[2] = H(address(new BabyBearSelectSinglesHarness()));
        h[3] = H(address(new BabyBearSelectAssemblyLoopHarness()));
    }

    function point(bytes32 seed) private pure returns (uint256[] memory p) {
        p = new uint256[](22);
        for (uint256 i; i < 22; ++i) {
            uint256[5] memory a;
            for (uint256 j; j < 5; ++j) {
                a[j] = uint256(keccak256(abi.encode(seed, i, j))) % Q;
            }
            p[i] = Ref.pack(a);
        }
    }

    function inputs()
        private
        pure
        returns (
            uint256[] memory p,
            uint256[][3] memory s,
            uint256[3] memory c,
            uint256[3] memory eq
        )
    {
        p = point(bytes32(uint256(20_260_905)));
        uint256[3] memory counts = [uint256(38), 31, 19];
        for (uint256 r; r < 3; ++r) {
            s[r] = new uint256[](counts[r]);
            for (uint256 i; i < counts[r]; ++i) {
                s[r][i] = uint256(keccak256(abi.encode(r, i))) % Q;
            }
            c[r] = p[r];
            eq[r] = p[r + 3];
        }
    }

    function testBenchmark() external {
        (uint256[] memory p, uint256[][3] memory s, uint256[3] memory c, uint256[3] memory eq) =
            inputs();
        (, uint256[3] memory expected) = h[0].batch(p, s, c, eq);
        {
            (uint256 gasUsed, uint256[3] memory result) = h[0].batch(p, s, c, eq);
            emit log_named_uint("Forms", gasUsed);
            assertEq(abi.encode(result), abi.encode(expected));
        }
        {
            (uint256 gasUsed, uint256[3] memory result) = h[1].batch(p, s, c, eq);
            emit log_named_uint("Inline", gasUsed);
            assertEq(abi.encode(result), abi.encode(expected));
        }
        {
            (uint256 gasUsed, uint256[3] memory result) = h[2].batch(p, s, c, eq);
            emit log_named_uint("Singles", gasUsed);
            assertEq(abi.encode(result), abi.encode(expected));
        }
        {
            (uint256 gasUsed, uint256[3] memory result) = h[3].batch(p, s, c, eq);
            emit log_named_uint("AssemblyLoop", gasUsed);
            assertEq(abi.encode(result), abi.encode(expected));
        }
        {
            (uint256 gasUsed, uint256[3] memory result) = h[4].batch(p, s, c, eq);
            emit log_named_uint("Cubics", gasUsed);
            assertEq(abi.encode(result), abi.encode(expected));
        }
        {
            (uint256 gasUsed,) = kh.batch(p, s, c, eq);
            emit log_named_uint("KoalaCubics", gasUsed);
        }
        {
            (uint256 gasUsed, uint256[3] memory result) = h[5].batch(p, s, c, eq);
            emit log_named_uint("PackedHorner", gasUsed);
            assertEq(abi.encode(result), abi.encode(expected));
        }
    }

    function testFuzzChains(bytes32 seed, uint256 a, uint256 b) external view {
        uint256[] memory p = point(seed);
        a %= Q;
        b %= Q;
        for (uint256 n = 10; n <= 18; n += 4) {
            uint256 expected = Ref.chain(a, p, 22 - n, n, Q, 1);
            uint256 expectedB = Ref.chain(b, p, 22 - n, n, Q, 1);
            for (uint256 i; i < h.length; ++i) {
                (, uint256 x, uint256 y) = h[i].chains(p, a, b, 22 - n, n);
                assertEq(x, expected);
                assertEq(y, expectedB);
                assertEq(h[i].single(p, a, 22 - n, n), expected);
            }
        }
    }

    function testBoundaryChains() external view {
        uint256[] memory p = new uint256[](22);
        for (uint256 j; j < 22; ++j) {
            p[j] = Ref.pack([Q - 1, Q - 1, Q - 1, Q - 1, Q - 1]);
        }
        for (uint256 n; n <= 18; n += 9) {
            uint256 ex = Ref.chain(0, p, 22 - n, n, Q, 1);
            uint256 ey = Ref.chain(Q - 1, p, 22 - n, n, Q, 1);
            for (uint256 i; i < h.length; ++i) {
                (, uint256 x, uint256 y) = h[i].chains(p, 0, Q - 1, 22 - n, n);
                assertEq(x, ex);
                assertEq(y, ey);
            }
        }
    }

    function testFuzzKoala(bytes32 seed, uint256 a, uint256 b) external view {
        uint256 P = 0x7f000001;
        uint256[] memory p = new uint256[](22);
        for (uint256 i; i < 22; ++i) {
            uint256[5] memory v;
            for (uint256 j; j < 5; ++j) {
                v[j] = uint256(keccak256(abi.encode(seed, i, j))) % P;
            }
            p[i] = Ref.pack(v);
        }
        a %= P;
        b %= P;
        for (uint256 n = 10; n <= 18; n += 4) {
            uint256 ex = Ref.chain(a, p, 22 - n, n, P, 0);
            uint256 ey = Ref.chain(b, p, 22 - n, n, P, 0);
            (, uint256 x, uint256 y) = kh.chains(p, a, b, 22 - n, n);
            assertEq(x, ex);
            assertEq(y, ey);
        }
    }

    function testCubicBasisAndMaxima() external view {
        for (uint256 f; f < 2; ++f) {
            uint256 m = f == 0 ? Q : 0x7f000001;
            H target = f == 0 ? h[4] : kh;
            uint256[] memory p = new uint256[](22);
            for (uint256 a; a < 5; ++a) {
                for (uint256 b; b < 5; ++b) {
                    for (uint256 j; j < 22; ++j) {
                        p[j] = (m - 1) << (224 - 32 * (j % 2 == 0 ? a : b));
                    }
                    (, uint256 x, uint256 y) = target.chains(p, 0, m - 1, 4, 18);
                    assertEq(x, Ref.chain(0, p, 4, 18, m, f == 0 ? 1 : 0));
                    assertEq(y, Ref.chain(m - 1, p, 4, 18, m, f == 0 ? 1 : 0));
                }
            }
            for (uint256 j; j < 22; ++j) {
                p[j] = Ref.pack([m - 1, m - 1, m - 1, m - 1, m - 1]);
            }
            for (uint256 n; n <= 18; n += 2) {
                (, uint256 x, uint256 y) = target.chains(p, 1, m - 1, 22 - n, n);
                assertEq(x, Ref.chain(1, p, 22 - n, n, m, f == 0 ? 1 : 0));
                assertEq(y, Ref.chain(m - 1, p, 22 - n, n, m, f == 0 ? 1 : 0));
            }
        }
    }

    function testProfileCubicBabyBear() external view {
        (uint256[] memory p, uint256[][3] memory s, uint256[3] memory c, uint256[3] memory eq) =
            inputs();
        (, uint256[3] memory r) = h[4].batch(p, s, c, eq);
        assertTrue(r[0] != 0);
    }

    function testProfileBaselineBabyBear() external view {
        (uint256[] memory p, uint256[][3] memory s, uint256[3] memory c, uint256[3] memory eq) =
            inputs();
        (, uint256[3] memory r) = h[0].batch(p, s, c, eq);
        assertTrue(r[0] != 0);
    }
}
