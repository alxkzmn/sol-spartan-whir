// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {stdJson} from "forge-std/StdJson.sol";
import {Test} from "forge-std/Test.sol";
import {FieldHarness} from "./helpers/FieldHarness.sol";

struct BaseFieldVectorFixture {
    uint256 a;
    uint256 b;
    uint256 add;
    uint256 sub;
    uint256 mul;
    uint256 inv;
}

struct ExtensionFieldVectorFixture {
    uint256[] a;
    uint256[] b;
    uint256[] add;
    uint256[] sub;
    uint256[] mul;
    uint256[] inv;
    uint256 packed_a;
    uint256 packed_b;
    uint256 packed_add;
    uint256 packed_sub;
    uint256 packed_mul;
    uint256 packed_inv;
}

struct ExtensionExtrapolateVectorFixture {
    uint256 packed_e0;
    uint256 packed_e1;
    uint256 packed_e2;
    uint256 packed_r;
    uint256 packed_result;
}

struct ExtensionEqPolyVectorFixture {
    uint256[] packed_p;
    uint256[] packed_q;
    uint256 packed_result;
}

struct ExtensionHypercubeVectorFixture {
    uint256[] packed_evals;
    uint256[] packed_point;
    uint256 packed_result;
}

struct FieldVectorFixture {
    BaseFieldVectorFixture[] base;
    ExtensionFieldVectorFixture[] quartic;
    ExtensionFieldVectorFixture[] octic;
    ExtensionExtrapolateVectorFixture[] quartic_extrapolate;
    ExtensionEqPolyVectorFixture[] quartic_eq_poly;
    ExtensionHypercubeVectorFixture[] quartic_hypercube;
    ExtensionExtrapolateVectorFixture[] octic_extrapolate;
    ExtensionEqPolyVectorFixture[] octic_eq_poly;
    ExtensionHypercubeVectorFixture[] octic_hypercube;
}

contract FieldArithmeticTest is Test {
    using stdJson for string;

    string internal constant TESTDATA = "testdata/";

    FieldHarness internal harness;
    FieldVectorFixture internal vectors;

    function setUp() public {
        harness = new FieldHarness();
        string memory raw = vm.readFile(
            string.concat(TESTDATA, "field_vectors.json")
        );
        vectors = abi.decode(raw.parseRaw("$"), (FieldVectorFixture));
    }

    function testKoalaBearBaseFieldVectors() external view {
        for (uint256 i = 0; i < vectors.base.length; ++i) {
            BaseFieldVectorFixture memory vector = vectors.base[i];
            assertEq(harness.baseAdd(vector.a, vector.b), vector.add);
            assertEq(harness.baseSub(vector.a, vector.b), vector.sub);
            assertEq(harness.baseMul(vector.a, vector.b), vector.mul);
            assertEq(harness.baseInv(vector.a), vector.inv);
        }
    }

    function testKoalaBearInvRejectsUnreducedZeroRepresentatives() external {
        vm.expectRevert(bytes("ZERO_INV"));
        harness.baseInv(0);

        vm.expectRevert(bytes("ZERO_INV"));
        harness.baseInv(0x7f000001);

        vm.expectRevert(bytes("ZERO_INV"));
        harness.baseInv(0x7f000001 * 3);
    }

    function testKoalaBearInvAcceptsUnreducedNonzeroRepresentative()
        external
        view
    {
        uint256 modulus = 0x7f000001;
        uint256 canonical = 7;
        uint256 unreduced = canonical + modulus * 2;

        assertEq(harness.baseInv(unreduced), harness.baseInv(canonical));
    }

    function testKoalaBearExt4Vectors() external view {
        for (uint256 i = 0; i < vectors.quartic.length; ++i) {
            ExtensionFieldVectorFixture memory vector = vectors.quartic[i];
            assertEq(harness.ext4Pack(vector.a), vector.packed_a);
            assertEq(harness.ext4Pack(vector.b), vector.packed_b);
            _assertEqArray(harness.ext4Unpack(vector.packed_a), vector.a);
            _assertEqArray(harness.ext4Unpack(vector.packed_b), vector.b);

            assertEq(
                harness.ext4Add(vector.packed_a, vector.packed_b),
                vector.packed_add
            );
            assertEq(
                harness.ext4Sub(vector.packed_a, vector.packed_b),
                vector.packed_sub
            );
            assertEq(
                harness.ext4Mul(vector.packed_a, vector.packed_b),
                vector.packed_mul
            );
            assertEq(harness.ext4Inv(vector.packed_a), vector.packed_inv);
            assertEq(
                harness.ext4MulByW(vector.packed_a),
                harness.ext4Pack(_scaleCoeffs(vector.a, 3))
            );
        }
    }

    function testKoalaBearExt4MulMatchesReference() external view {
        for (uint256 i = 0; i < vectors.quartic.length; ++i) {
            ExtensionFieldVectorFixture memory vector = vectors.quartic[i];
            assertEq(
                harness.ext4Mul(vector.packed_a, vector.packed_b),
                harness.ext4MulReference(vector.packed_a, vector.packed_b)
            );
            assertEq(
                harness.ext4Mul(vector.packed_a, vector.packed_a),
                harness.ext4MulReference(vector.packed_a, vector.packed_a)
            );
            assertEq(
                harness.ext4Square(vector.packed_a),
                harness.ext4Mul(vector.packed_a, vector.packed_a)
            );
        }
    }

    function testKoalaBearExt4RejectsNonCanonicalLowBits() external {
        uint256 packed = (uint256(1) << 224) |
            (uint256(2) << 192) |
            (uint256(3) << 160) |
            (uint256(4) << 128) |
            1;

        vm.expectRevert(bytes("LOW_BITS"));
        harness.ext4Unpack(packed);
    }

    function testKoalaBearExt8Vectors() external view {
        for (uint256 i = 0; i < vectors.octic.length; ++i) {
            ExtensionFieldVectorFixture memory vector = vectors.octic[i];
            assertEq(harness.ext8Pack(vector.a), vector.packed_a);
            assertEq(harness.ext8Pack(vector.b), vector.packed_b);
            _assertEqArray(harness.ext8Unpack(vector.packed_a), vector.a);
            _assertEqArray(harness.ext8Unpack(vector.packed_b), vector.b);

            assertEq(
                harness.ext8Add(vector.packed_a, vector.packed_b),
                vector.packed_add
            );
            assertEq(
                harness.ext8Sub(vector.packed_a, vector.packed_b),
                vector.packed_sub
            );
            assertEq(
                harness.ext8Mul(vector.packed_a, vector.packed_b),
                vector.packed_mul
            );
            assertEq(harness.ext8Inv(vector.packed_a), vector.packed_inv);
            assertEq(
                harness.ext8MulByW(vector.packed_a),
                harness.ext8Pack(_scaleCoeffs(vector.a, 3))
            );
        }
    }

    function testKoalaBearExt4ExtrapolateVectors() external view {
        for (uint256 i = 0; i < vectors.quartic_extrapolate.length; ++i) {
            ExtensionExtrapolateVectorFixture memory vector = vectors
                .quartic_extrapolate[i];
            assertEq(
                harness.ext4Extrapolate012(
                    vector.packed_e0,
                    vector.packed_e1,
                    vector.packed_e2,
                    vector.packed_r
                ),
                vector.packed_result
            );
        }
    }

    function testKoalaBearExt8ExtrapolateVectors() external view {
        for (uint256 i = 0; i < vectors.octic_extrapolate.length; ++i) {
            ExtensionExtrapolateVectorFixture memory vector = vectors
                .octic_extrapolate[i];
            assertEq(
                harness.ext8Extrapolate012(
                    vector.packed_e0,
                    vector.packed_e1,
                    vector.packed_e2,
                    vector.packed_r
                ),
                vector.packed_result
            );
        }
    }

    function testKoalaBearExt4EqPolyVectors() external view {
        for (uint256 i = 0; i < vectors.quartic_eq_poly.length; ++i) {
            ExtensionEqPolyVectorFixture memory vector = vectors
                .quartic_eq_poly[i];
            assertEq(
                harness.ext4EqPolyEval(vector.packed_p, vector.packed_q),
                vector.packed_result
            );
        }
    }

    function testKoalaBearExt8EqPolyVectors() external view {
        for (uint256 i = 0; i < vectors.octic_eq_poly.length; ++i) {
            ExtensionEqPolyVectorFixture memory vector = vectors.octic_eq_poly[
                i
            ];
            assertEq(
                harness.ext8EqPolyEval(vector.packed_p, vector.packed_q),
                vector.packed_result
            );
        }
    }

    function testKoalaBearExt4HypercubeVectors() external view {
        for (uint256 i = 0; i < vectors.quartic_hypercube.length; ++i) {
            ExtensionHypercubeVectorFixture memory vector = vectors
                .quartic_hypercube[i];
            assertEq(
                harness.ext4EvaluateHypercube(
                    vector.packed_evals,
                    vector.packed_point
                ),
                vector.packed_result
            );
        }
    }

    function testKoalaBearExt8HypercubeVectors() external view {
        for (uint256 i = 0; i < vectors.octic_hypercube.length; ++i) {
            ExtensionHypercubeVectorFixture memory vector = vectors
                .octic_hypercube[i];
            assertEq(
                harness.ext8EvaluateHypercube(
                    vector.packed_evals,
                    vector.packed_point
                ),
                vector.packed_result
            );
        }
    }

    function testExt4Extrapolate012AtInterpolationPoints() external view {
        uint256 e0 = harness.ext4Pack(_coeffs4(5, 7, 11, 13));
        uint256 e1 = harness.ext4Pack(_coeffs4(17, 19, 23, 29));
        uint256 e2 = harness.ext4Pack(_coeffs4(31, 37, 41, 43));

        assertEq(harness.ext4Extrapolate012(e0, e1, e2, 0), e0);
        assertEq(harness.ext4Extrapolate012(e0, e1, e2, _extConst4(1)), e1);
        assertEq(harness.ext4Extrapolate012(e0, e1, e2, _extConst4(2)), e2);
    }

    function testExt4Extrapolate012MatchesReference() external view {
        for (uint256 i = 0; i < vectors.quartic.length; ++i) {
            ExtensionFieldVectorFixture memory vector = vectors.quartic[i];

            assertEq(
                harness.ext4Extrapolate012(
                    vector.packed_a,
                    vector.packed_b,
                    vector.packed_mul,
                    vector.packed_add
                ),
                harness.ext4Extrapolate012Reference(
                    vector.packed_a,
                    vector.packed_b,
                    vector.packed_mul,
                    vector.packed_add
                )
            );
            assertEq(
                harness.ext4Extrapolate012(
                    vector.packed_inv,
                    vector.packed_sub,
                    vector.packed_add,
                    vector.packed_b
                ),
                harness.ext4Extrapolate012Reference(
                    vector.packed_inv,
                    vector.packed_sub,
                    vector.packed_add,
                    vector.packed_b
                )
            );
        }
    }

    function testExt8Extrapolate012AtInterpolationPoints() external view {
        uint256 e0 = harness.ext8Pack(_coeffs8(5, 7, 11, 13, 17, 19, 23, 29));
        uint256 e1 = harness.ext8Pack(_coeffs8(31, 37, 41, 43, 47, 53, 59, 61));
        uint256 e2 = harness.ext8Pack(
            _coeffs8(67, 71, 73, 79, 83, 89, 97, 101)
        );

        assertEq(harness.ext8Extrapolate012(e0, e1, e2, 0), e0);
        assertEq(harness.ext8Extrapolate012(e0, e1, e2, _extConst8(1)), e1);
        assertEq(harness.ext8Extrapolate012(e0, e1, e2, _extConst8(2)), e2);
    }

    function testExt4EqPolyEvalForBooleanPoints() external view {
        uint256[] memory lhs = new uint256[](3);
        lhs[0] = _extConst4(0);
        lhs[1] = _extConst4(1);
        lhs[2] = _extConst4(1);

        uint256[] memory rhs = new uint256[](3);
        rhs[0] = _extConst4(0);
        rhs[1] = _extConst4(1);
        rhs[2] = _extConst4(1);

        assertEq(harness.ext4EqPolyEval(lhs, rhs), _extConst4(1));

        rhs[2] = _extConst4(0);
        assertEq(harness.ext4EqPolyEval(lhs, rhs), 0);
    }

    function testExt8EqPolyEvalForBooleanPoints() external view {
        uint256[] memory lhs = new uint256[](2);
        lhs[0] = _extConst8(1);
        lhs[1] = _extConst8(0);

        uint256[] memory rhs = new uint256[](2);
        rhs[0] = _extConst8(1);
        rhs[1] = _extConst8(0);

        assertEq(harness.ext8EqPolyEval(lhs, rhs), _extConst8(1));

        rhs[0] = _extConst8(0);
        assertEq(harness.ext8EqPolyEval(lhs, rhs), 0);
    }

    function testExt4EvaluateHypercubeSmall() external view {
        uint256[] memory evals = new uint256[](4);
        evals[0] = harness.ext4Pack(_coeffs4(1, 2, 3, 4));
        evals[1] = harness.ext4Pack(_coeffs4(5, 6, 7, 8));
        evals[2] = harness.ext4Pack(_coeffs4(9, 10, 11, 12));
        evals[3] = harness.ext4Pack(_coeffs4(13, 14, 15, 16));

        uint256[] memory point = new uint256[](2);
        point[0] = _extConst4(3);
        point[1] = _extConst4(5);

        uint256 oneMinusR0 = harness.ext4Sub(_extConst4(1), point[0]);
        uint256 oneMinusR1 = harness.ext4Sub(_extConst4(1), point[1]);
        uint256 expected = harness.ext4Add(
            harness.ext4Add(
                harness.ext4Mul(
                    evals[0],
                    harness.ext4Mul(oneMinusR0, oneMinusR1)
                ),
                harness.ext4Mul(evals[1], harness.ext4Mul(oneMinusR0, point[1]))
            ),
            harness.ext4Add(
                harness.ext4Mul(
                    evals[2],
                    harness.ext4Mul(point[0], oneMinusR1)
                ),
                harness.ext4Mul(evals[3], harness.ext4Mul(point[0], point[1]))
            )
        );

        assertEq(harness.ext4EvaluateHypercube(evals, point), expected);
    }

    function testExt8EvaluateHypercubeSmall() external view {
        uint256[] memory evals = new uint256[](4);
        evals[0] = harness.ext8Pack(_coeffs8(1, 2, 3, 4, 5, 6, 7, 8));
        evals[1] = harness.ext8Pack(_coeffs8(9, 10, 11, 12, 13, 14, 15, 16));
        evals[2] = harness.ext8Pack(_coeffs8(17, 18, 19, 20, 21, 22, 23, 24));
        evals[3] = harness.ext8Pack(_coeffs8(25, 26, 27, 28, 29, 30, 31, 32));

        uint256[] memory point = new uint256[](2);
        point[0] = _extConst8(7);
        point[1] = _extConst8(9);

        uint256 oneMinusR0 = harness.ext8Sub(_extConst8(1), point[0]);
        uint256 oneMinusR1 = harness.ext8Sub(_extConst8(1), point[1]);
        uint256 expected = harness.ext8Add(
            harness.ext8Add(
                harness.ext8Mul(
                    evals[0],
                    harness.ext8Mul(oneMinusR0, oneMinusR1)
                ),
                harness.ext8Mul(evals[1], harness.ext8Mul(oneMinusR0, point[1]))
            ),
            harness.ext8Add(
                harness.ext8Mul(
                    evals[2],
                    harness.ext8Mul(point[0], oneMinusR1)
                ),
                harness.ext8Mul(evals[3], harness.ext8Mul(point[0], point[1]))
            )
        );

        assertEq(harness.ext8EvaluateHypercube(evals, point), expected);
    }

    function testGasExt4PackUnpack() external view {
        uint256 packed = harness.ext4Pack(
            _coeffs4(605_061_430, 867_831_285, 498_902_190, 1_861_564_007)
        );
        uint256[] memory unpacked = harness.ext4Unpack(packed);
        assertEq(unpacked[0], 605_061_430);
    }

    function testGasExt8PackUnpack() external view {
        uint256 packed = harness.ext8Pack(
            _coeffs8(
                1_183_641_764,
                916_668_484,
                1_662_695_301,
                1_758_839_722,
                1_364_968_108,
                932_085_352,
                580_647_060,
                1_375_234_661
            )
        );
        uint256[] memory unpacked = harness.ext8Unpack(packed);
        assertEq(unpacked[0], 1_183_641_764);
    }

    function testGasEvaluateHypercubeExt4() external view {
        uint256[] memory evals = new uint256[](16);
        for (uint256 i = 0; i < 16; ++i) {
            evals[i] = harness.ext4Pack(_coeffs4(i + 1, i + 2, i + 3, i + 4));
        }

        uint256[] memory point = new uint256[](4);
        point[0] = _extConst4(3);
        point[1] = _extConst4(5);
        point[2] = _extConst4(7);
        point[3] = _extConst4(11);

        assertTrue(harness.ext4EvaluateHypercube(evals, point) != 0);
    }

    function testGasEvaluateHypercubeExt8() external view {
        uint256[] memory evals = new uint256[](16);
        for (uint256 i = 0; i < 16; ++i) {
            evals[i] = harness.ext8Pack(
                _coeffs8(i + 1, i + 2, i + 3, i + 4, i + 5, i + 6, i + 7, i + 8)
            );
        }

        uint256[] memory point = new uint256[](4);
        point[0] = _extConst8(3);
        point[1] = _extConst8(5);
        point[2] = _extConst8(7);
        point[3] = _extConst8(11);

        assertTrue(harness.ext8EvaluateHypercube(evals, point) != 0);
    }

    function _scaleCoeffs(
        uint256[] memory coeffs,
        uint256 scalar
    ) internal view returns (uint256[] memory out) {
        out = new uint256[](coeffs.length);
        for (uint256 i = 0; i < coeffs.length; ++i) {
            out[i] = harness.baseMul(coeffs[i], scalar);
        }
    }

    function _assertEqArray(
        uint256[] memory lhs,
        uint256[] memory rhs
    ) internal pure {
        assertEq(lhs.length, rhs.length);
        for (uint256 i = 0; i < lhs.length; ++i) {
            assertEq(lhs[i], rhs[i]);
        }
    }

    function _coeffs4(
        uint256 a0,
        uint256 a1,
        uint256 a2,
        uint256 a3
    ) internal pure returns (uint256[] memory out) {
        out = new uint256[](4);
        out[0] = a0;
        out[1] = a1;
        out[2] = a2;
        out[3] = a3;
    }

    function _coeffs8(
        uint256 a0,
        uint256 a1,
        uint256 a2,
        uint256 a3,
        uint256 a4,
        uint256 a5,
        uint256 a6,
        uint256 a7
    ) internal pure returns (uint256[] memory out) {
        out = new uint256[](8);
        out[0] = a0;
        out[1] = a1;
        out[2] = a2;
        out[3] = a3;
        out[4] = a4;
        out[5] = a5;
        out[6] = a6;
        out[7] = a7;
    }

    function _extConst4(uint256 scalar) internal pure returns (uint256) {
        return scalar << 224;
    }

    function _extConst8(uint256 scalar) internal pure returns (uint256) {
        return scalar << 224;
    }
}
