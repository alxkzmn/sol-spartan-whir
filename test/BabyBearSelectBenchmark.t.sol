// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import { Test } from "forge-std/Test.sol";
import { BabyBearReference as Ref } from "./helpers/BabyBearReference.sol";
import {
    KoalaBearSelectReciprocalHarness,
    KoalaBearSelectBaselineHarness,
    KoalaBearSelectPeelHarness,
    KoalaBearSelectBranchlessHarness,
    KoalaBearSelectRawHarness,
    KoalaBearSelectCombinedHarness,
    KoalaBearSelectPrepackedHarness,
    KoalaBearSelectPrepackedCombinedHarness,
    BabyBearSelectBaselineHarness,
    BabyBearSelectPeelHarness,
    BabyBearSelectBranchlessHarness,
    BabyBearSelectRawHarness,
    BabyBearSelectCombinedHarness,
    BabyBearSelectPrepackedHarness,
    BabyBearSelectPrepackedCombinedHarness
} from "./helpers/BabyBearSelectVariants.sol";

import {
    BabyBearSelectFormsHarness,
    KoalaBearSelectFormsHarness,
    BabyBearSelectFormsSharedPairHarness,
    KoalaBearSelectFormsSharedPairHarness,
    BabyBearSelectFormsPackedHornerHarness,
    KoalaBearSelectFormsPackedHornerHarness
} from "./helpers/BabyBearSelectForms.sol";

interface ISelectHarness {
    function term(uint256 a, uint256 b, uint256 s) external pure returns (uint256);
    function chains(uint256[] memory point, uint256 a, uint256 b, uint256 offset, uint256 n)
        external
        view
        returns (uint256, uint256, uint256);
    function single(uint256[] memory point, uint256 a, uint256 offset, uint256 n)
        external
        pure
        returns (uint256);
    function batch(
        uint256[] memory point,
        uint256[][3] memory selectors,
        uint256[3] memory challenges,
        uint256[3] memory eqs
    ) external view returns (uint256, uint256[3] memory);
}

contract BabyBearSelectBenchmarkTest is Test {
    uint256 constant P = 0x7f000001;
    uint256 constant Q = 0x78000001;
    uint256 constant COUNT = 7;
    ISelectHarness[14] h;
    ISelectHarness reciprocal;
    ISelectHarness[6] forms;

    function setUp() external {
        forms[4] = ISelectHarness(address(new KoalaBearSelectFormsSharedPairHarness()));
        forms[5] = ISelectHarness(address(new BabyBearSelectFormsSharedPairHarness()));
        forms[2] = ISelectHarness(address(new KoalaBearSelectFormsPackedHornerHarness()));
        forms[3] = ISelectHarness(address(new BabyBearSelectFormsPackedHornerHarness()));
        forms[0] = ISelectHarness(address(new KoalaBearSelectFormsHarness()));
        forms[1] = ISelectHarness(address(new BabyBearSelectFormsHarness()));
        reciprocal = ISelectHarness(address(new KoalaBearSelectReciprocalHarness()));
        h[0] = ISelectHarness(address(new KoalaBearSelectBaselineHarness()));
        h[1] = ISelectHarness(address(new KoalaBearSelectPeelHarness()));
        h[2] = ISelectHarness(address(new KoalaBearSelectBranchlessHarness()));
        h[3] = ISelectHarness(address(new KoalaBearSelectRawHarness()));
        h[4] = ISelectHarness(address(new KoalaBearSelectCombinedHarness()));
        h[5] = ISelectHarness(address(new KoalaBearSelectPrepackedHarness()));
        h[6] = ISelectHarness(address(new KoalaBearSelectPrepackedCombinedHarness()));
        h[7] = ISelectHarness(address(new BabyBearSelectBaselineHarness()));
        h[8] = ISelectHarness(address(new BabyBearSelectPeelHarness()));
        h[9] = ISelectHarness(address(new BabyBearSelectBranchlessHarness()));
        h[10] = ISelectHarness(address(new BabyBearSelectRawHarness()));
        h[11] = ISelectHarness(address(new BabyBearSelectCombinedHarness()));
        h[12] = ISelectHarness(address(new BabyBearSelectPrepackedHarness()));
        h[13] = ISelectHarness(address(new BabyBearSelectPrepackedCombinedHarness()));
    }

    function _point(bytes32 seed, uint256 p) private pure returns (uint256[] memory point) {
        point = new uint256[](22);
        for (uint256 i; i < 22; ++i) {
            uint256[5] memory a;
            for (uint256 j; j < 5; ++j) {
                a[j] = uint256(keccak256(abi.encode(seed, i, j))) % p;
            }
            point[i] = Ref.pack(a);
        }
    }

    function _canonical(uint256[5] memory a, uint256 p) private pure returns (uint256) {
        uint256[5] memory b;
        for (uint256 j; j < 5; ++j) {
            b[j] = a[j] % p;
        }
        return Ref.pack(b);
    }

    function _checkTerm(uint256 a, uint256 b, uint256 s, uint256 p, uint256 first) private view {
        uint256 expected = Ref.select(a, b, s, p, first == 0 ? 0 : 1);
        if (first == 0) assertEq(reciprocal.term(a, b, s), expected, "reciprocal term");
        for (uint256 i = first; i < first + COUNT; ++i) {
            uint256 actual = h[i].term(a, b, s);
            assertEq(actual, expected, "select oracle");
            assertEq(actual & ((uint256(1) << 96) - 1), 0, "padding");
            uint256[5] memory c = Ref.unpack(actual);
            for (uint256 j; j < 5; ++j) {
                assertLt(c[j], p, "canonical output");
            }
        }
    }

    function testFuzzSelectArithmetic(uint256[5] memory a, uint256[5] memory b, uint256 s)
        external
        view
    {
        _checkTerm(_canonical(a, P), _canonical(b, P), s % (2 * P - 1), P, 0);
        _checkTerm(_canonical(a, Q), _canonical(b, Q), s % (2 * Q - 1), Q, COUNT);
    }

    function testSelectBoundaryProducts() external view {
        for (uint256 f; f < 2; ++f) {
            uint256 p = f == 0 ? P : Q;
            uint256 max = Ref.pack([p - 1, p - 1, p - 1, p - 1, p - 1]);
            _checkTerm(max, max, 0, p, COUNT * f);
            _checkTerm(max, max, 1, p, COUNT * f);
            _checkTerm(max, max, p - 1, p, COUNT * f);
            _checkTerm(max, max, 2 * p - 2, p, COUNT * f);
            for (uint256 i; i < 5; ++i) {
                for (uint256 j; j < 5; ++j) {
                    _checkTerm(
                        (p - 1) << (224 - 32 * i), (p - 1) << (224 - 32 * j), p - 1, p, COUNT * f
                    );
                }
            }
        }
    }

    function testFuzzCompleteChains(bytes32 seed, uint256 a, uint256 b) external view {
        for (uint256 f; f < 2; ++f) {
            uint256 p = f == 0 ? P : Q;
            uint256[] memory point = _point(seed, p);
            for (uint256 n = 10; n <= 18; n += 4) {
                uint256 x = Ref.chain(a % p, point, 22 - n, n, p, f);
                uint256 y = Ref.chain(b % p, point, 22 - n, n, p, f);
                (, uint256 fx, uint256 fy) = forms[f].chains(point, a % p, b % p, 22 - n, n);
                assertEq(fx, x, "forms first");
                assertEq(fy, y, "forms second");
                assertEq(forms[f].single(point, a % p, 22 - n, n), x, "forms single");
                if (f == 0) {
                    (, uint256 rx, uint256 ry) = reciprocal.chains(point, a % p, b % p, 22 - n, n);
                    assertEq(rx, x, "reciprocal first");
                    assertEq(ry, y, "reciprocal second");
                    assertEq(reciprocal.single(point, a % p, 22 - n, n), x, "reciprocal single");
                }
                for (uint256 i = f * COUNT; i < f * COUNT + COUNT; ++i) {
                    (, uint256 ax, uint256 ay) = h[i].chains(point, a % p, b % p, 22 - n, n);
                    assertEq(ax, x, "pair first");
                    assertEq(ay, y, "pair second");
                    assertEq(h[i].single(point, a % p, 22 - n, n), x, "single");
                }
            }
        }
    }

    function testEmptyAndBoundaryChains() external view {
        for (uint256 f; f < 2; ++f) {
            uint256 p = f == 0 ? P : Q;
            uint256[] memory point = new uint256[](22);
            uint256 max = Ref.pack([p - 1, p - 1, p - 1, p - 1, p - 1]);
            for (uint256 j; j < 22; ++j) {
                point[j] = max;
            }
            for (uint256 n; n <= 18; n += 9) {
                (, uint256 fx, uint256 fy) = forms[f].chains(point, 0, p - 1, 22 - n, n);
                assertEq(fx, Ref.chain(0, point, 22 - n, n, p, f));
                assertEq(fy, Ref.chain(p - 1, point, 22 - n, n, p, f));
            }
            for (uint256 i = f * COUNT; i < f * COUNT + COUNT; ++i) {
                (, uint256 x, uint256 y) = h[i].chains(point, 0, p - 1, 22, 0);
                assertEq(x, uint256(1) << 224);
                assertEq(y, uint256(1) << 224);
                (, x, y) = h[i].chains(point, 0, p - 1, 4, 18);
                assertEq(x, Ref.chain(0, point, 4, 18, p, f));
                assertEq(y, Ref.chain(p - 1, point, 4, 18, p, f));
            }
        }
    }

    function _inputs()
        private
        pure
        returns (
            uint256[] memory point,
            uint256[][3] memory selectors,
            uint256[3] memory challenges,
            uint256[3] memory eqs
        )
    {
        point = _point(bytes32(uint256(20_260_905)), Q);
        uint256[3] memory counts = [uint256(38), 31, 19];
        for (uint256 r; r < 3; ++r) {
            selectors[r] = new uint256[](counts[r]);
            for (uint256 i; i < counts[r]; ++i) {
                selectors[r][i] = uint256(keccak256(abi.encode(r, i))) % Q;
            }
            challenges[r] = point[r];
            eqs[r] = point[r + 3];
        }
    }

    function testConfiguredBatchCorrectness() external view {
        (
            uint256[] memory point,
            uint256[][3] memory selectors,
            uint256[3] memory challenges,
            uint256[3] memory eqs
        ) = _inputs();
        for (uint256 f; f < 2; ++f) {
            uint256 p = f == 0 ? P : Q;
            uint256[3] memory expected;
            for (uint256 r; r < 3; ++r) {
                uint256 n = 18 - 4 * r;
                for (uint256 j = selectors[r].length; j > 0; --j) {
                    expected[r] = Ref.add(
                        Ref.mul(expected[r], challenges[r], p, f),
                        Ref.chain(selectors[r][j - 1], point, 22 - n, n, p, f),
                        p
                    );
                }
                expected[r] = Ref.add(Ref.mul(expected[r], challenges[r], p, f), eqs[r], p);
            }
            for (uint256 k; k < 3; ++k) {
                (, uint256[3] memory actual) =
                    forms[f + 2 * k].batch(point, selectors, challenges, eqs);
                assertEq(abi.encode(actual), abi.encode(expected), "forms batch oracle");
            }
            for (uint256 i = f * COUNT; i < f * COUNT + COUNT; ++i) {
                (, uint256[3] memory actual) = h[i].batch(point, selectors, challenges, eqs);
                assertEq(abi.encode(actual), abi.encode(expected), "batch oracle");
            }
            if (f == 0) {
                (, uint256[3] memory actual) = reciprocal.batch(point, selectors, challenges, eqs);
                assertEq(abi.encode(actual), abi.encode(expected), "reciprocal batch");
            }
        }
    }

    function testProfileBabyBearForms() external view {
        (
            uint256[] memory point,
            uint256[][3] memory selectors,
            uint256[3] memory challenges,
            uint256[3] memory eqs
        ) = _inputs();
        (, uint256[3] memory result) = forms[1].batch(point, selectors, challenges, eqs);
        assertTrue(result[0] != 0);
    }

    function testBenchmarkSelectVariants() external {
        (
            uint256[] memory point,
            uint256[][3] memory selectors,
            uint256[3] memory challenges,
            uint256[3] memory eqs
        ) = _inputs();
        for (uint256 f; f < 6; ++f) {
            (uint256 used,) = forms[f].batch(point, selectors, challenges, eqs);
            emit log_named_uint(
                f == 0
                    ? "KoalaBearSelectForms.batch"
                    : f == 1
                        ? "BabyBearSelectForms.batch"
                        : f == 2
                            ? "KoalaBearSelectFormsPackedHorner.batch"
                            : f == 3
                                ? "BabyBearSelectFormsPackedHorner.batch"
                                : f == 4
                                    ? "KoalaBearSelectFormsSharedPair.batch"
                                    : "BabyBearSelectFormsSharedPair.batch",
                used
            );
        }
        (uint256 reciprocalGas,) = reciprocal.batch(point, selectors, challenges, eqs);
        emit log_named_uint("KoalaBearSelectReciprocal.batch", reciprocalGas);
        {
            (uint256 used, uint256[3] memory result) = h[0].batch(point, selectors, challenges, eqs);
            emit log_named_uint("KoalaBearSelectBaseline.batch", used);
            assertTrue((result[0] | result[1] | result[2]) != 0);
            for (uint256 n = 10; n <= 18; n += 4) {
                (used,,) = h[0].chains(point, selectors[0][0], selectors[0][1], 22 - n, n);
                emit log_named_uint(
                    string.concat("KoalaBearSelectBaseline.pair", vm.toString(n)), used
                );
            }
        }
        {
            (uint256 used, uint256[3] memory result) = h[1].batch(point, selectors, challenges, eqs);
            emit log_named_uint("KoalaBearSelectPeel.batch", used);
            assertTrue((result[0] | result[1] | result[2]) != 0);
            for (uint256 n = 10; n <= 18; n += 4) {
                (used,,) = h[1].chains(point, selectors[0][0], selectors[0][1], 22 - n, n);
                emit log_named_uint(string.concat("KoalaBearSelectPeel.pair", vm.toString(n)), used);
            }
        }
        {
            (uint256 used, uint256[3] memory result) = h[2].batch(point, selectors, challenges, eqs);
            emit log_named_uint("KoalaBearSelectBranchless.batch", used);
            assertTrue((result[0] | result[1] | result[2]) != 0);
            for (uint256 n = 10; n <= 18; n += 4) {
                (used,,) = h[2].chains(point, selectors[0][0], selectors[0][1], 22 - n, n);
                emit log_named_uint(
                    string.concat("KoalaBearSelectBranchless.pair", vm.toString(n)), used
                );
            }
        }
        {
            (uint256 used, uint256[3] memory result) = h[3].batch(point, selectors, challenges, eqs);
            emit log_named_uint("KoalaBearSelectRaw.batch", used);
            assertTrue((result[0] | result[1] | result[2]) != 0);
            for (uint256 n = 10; n <= 18; n += 4) {
                (used,,) = h[3].chains(point, selectors[0][0], selectors[0][1], 22 - n, n);
                emit log_named_uint(string.concat("KoalaBearSelectRaw.pair", vm.toString(n)), used);
            }
        }
        {
            (uint256 used, uint256[3] memory result) = h[4].batch(point, selectors, challenges, eqs);
            emit log_named_uint("KoalaBearSelectCombined.batch", used);
            assertTrue((result[0] | result[1] | result[2]) != 0);
            for (uint256 n = 10; n <= 18; n += 4) {
                (used,,) = h[4].chains(point, selectors[0][0], selectors[0][1], 22 - n, n);
                emit log_named_uint(
                    string.concat("KoalaBearSelectCombined.pair", vm.toString(n)), used
                );
            }
        }
        {
            (uint256 used, uint256[3] memory result) = h[5].batch(point, selectors, challenges, eqs);
            emit log_named_uint("KoalaBearSelectPrepacked.batch", used);
            assertTrue((result[0] | result[1] | result[2]) != 0);
            for (uint256 n = 10; n <= 18; n += 4) {
                (used,,) = h[5].chains(point, selectors[0][0], selectors[0][1], 22 - n, n);
                emit log_named_uint(
                    string.concat("KoalaBearSelectPrepacked.pair", vm.toString(n)), used
                );
            }
        }
        {
            (uint256 used, uint256[3] memory result) = h[6].batch(point, selectors, challenges, eqs);
            emit log_named_uint("KoalaBearSelectPrepackedCombined.batch", used);
            assertTrue((result[0] | result[1] | result[2]) != 0);
            for (uint256 n = 10; n <= 18; n += 4) {
                (used,,) = h[6].chains(point, selectors[0][0], selectors[0][1], 22 - n, n);
                emit log_named_uint(
                    string.concat("KoalaBearSelectPrepackedCombined.pair", vm.toString(n)), used
                );
            }
        }
        {
            (uint256 used, uint256[3] memory result) = h[7].batch(point, selectors, challenges, eqs);
            emit log_named_uint("BabyBearSelectBaseline.batch", used);
            assertTrue((result[0] | result[1] | result[2]) != 0);
            for (uint256 n = 10; n <= 18; n += 4) {
                (used,,) = h[7].chains(point, selectors[0][0], selectors[0][1], 22 - n, n);
                emit log_named_uint(
                    string.concat("BabyBearSelectBaseline.pair", vm.toString(n)), used
                );
            }
        }
        {
            (uint256 used, uint256[3] memory result) = h[8].batch(point, selectors, challenges, eqs);
            emit log_named_uint("BabyBearSelectPeel.batch", used);
            assertTrue((result[0] | result[1] | result[2]) != 0);
            for (uint256 n = 10; n <= 18; n += 4) {
                (used,,) = h[8].chains(point, selectors[0][0], selectors[0][1], 22 - n, n);
                emit log_named_uint(string.concat("BabyBearSelectPeel.pair", vm.toString(n)), used);
            }
        }
        {
            (uint256 used, uint256[3] memory result) = h[9].batch(point, selectors, challenges, eqs);
            emit log_named_uint("BabyBearSelectBranchless.batch", used);
            assertTrue((result[0] | result[1] | result[2]) != 0);
            for (uint256 n = 10; n <= 18; n += 4) {
                (used,,) = h[9].chains(point, selectors[0][0], selectors[0][1], 22 - n, n);
                emit log_named_uint(
                    string.concat("BabyBearSelectBranchless.pair", vm.toString(n)), used
                );
            }
        }
        {
            (uint256 used, uint256[3] memory result) =
                h[10].batch(point, selectors, challenges, eqs);
            emit log_named_uint("BabyBearSelectRaw.batch", used);
            assertTrue((result[0] | result[1] | result[2]) != 0);
            for (uint256 n = 10; n <= 18; n += 4) {
                (used,,) = h[10].chains(point, selectors[0][0], selectors[0][1], 22 - n, n);
                emit log_named_uint(string.concat("BabyBearSelectRaw.pair", vm.toString(n)), used);
            }
        }
        {
            (uint256 used, uint256[3] memory result) =
                h[11].batch(point, selectors, challenges, eqs);
            emit log_named_uint("BabyBearSelectCombined.batch", used);
            assertTrue((result[0] | result[1] | result[2]) != 0);
            for (uint256 n = 10; n <= 18; n += 4) {
                (used,,) = h[11].chains(point, selectors[0][0], selectors[0][1], 22 - n, n);
                emit log_named_uint(
                    string.concat("BabyBearSelectCombined.pair", vm.toString(n)), used
                );
            }
        }
        {
            (uint256 used, uint256[3] memory result) =
                h[12].batch(point, selectors, challenges, eqs);
            emit log_named_uint("BabyBearSelectPrepacked.batch", used);
            assertTrue((result[0] | result[1] | result[2]) != 0);
            for (uint256 n = 10; n <= 18; n += 4) {
                (used,,) = h[12].chains(point, selectors[0][0], selectors[0][1], 22 - n, n);
                emit log_named_uint(
                    string.concat("BabyBearSelectPrepacked.pair", vm.toString(n)), used
                );
            }
        }
        {
            (uint256 used, uint256[3] memory result) =
                h[13].batch(point, selectors, challenges, eqs);
            emit log_named_uint("BabyBearSelectPrepackedCombined.batch", used);
            assertTrue((result[0] | result[1] | result[2]) != 0);
            for (uint256 n = 10; n <= 18; n += 4) {
                (used,,) = h[13].chains(point, selectors[0][0], selectors[0][1], 22 - n, n);
                emit log_named_uint(
                    string.concat("BabyBearSelectPrepackedCombined.pair", vm.toString(n)), used
                );
            }
        }
    }

    function testProfileKoalaBearBaseline() external view {
        (
            uint256[] memory point,
            uint256[][3] memory selectors,
            uint256[3] memory challenges,
            uint256[3] memory eqs
        ) = _inputs();
        (, uint256[3] memory result) = h[0].batch(point, selectors, challenges, eqs);
        assertTrue((result[0] | result[1] | result[2]) != 0);
    }

    function testProfileBabyBearBaseline() external view {
        (
            uint256[] memory point,
            uint256[][3] memory selectors,
            uint256[3] memory challenges,
            uint256[3] memory eqs
        ) = _inputs();
        (, uint256[3] memory result) = h[7].batch(point, selectors, challenges, eqs);
        assertTrue((result[0] | result[1] | result[2]) != 0);
    }

    function testProfileBabyBearCombined() external view {
        (
            uint256[] memory point,
            uint256[][3] memory selectors,
            uint256[3] memory challenges,
            uint256[3] memory eqs
        ) = _inputs();
        (, uint256[3] memory result) = h[11].batch(point, selectors, challenges, eqs);
        assertTrue((result[0] | result[1] | result[2]) != 0);
    }

    function testProfileBabyBearPrepackedCombined() external view {
        (
            uint256[] memory point,
            uint256[][3] memory selectors,
            uint256[3] memory challenges,
            uint256[3] memory eqs
        ) = _inputs();
        (, uint256[3] memory result) = h[13].batch(point, selectors, challenges, eqs);
        assertTrue((result[0] | result[1] | result[2]) != 0);
    }
}
