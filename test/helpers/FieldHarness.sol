// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {KoalaBear} from "../../src/field/KoalaBear.sol";
import {KoalaBearExt4} from "../../src/field/KoalaBearExt4.sol";
import {KoalaBearExt8} from "../../src/field/KoalaBearExt8.sol";

contract FieldHarness {
    function baseAdd(uint256 a, uint256 b) external pure returns (uint256) {
        return KoalaBear.add(a, b);
    }

    function baseSub(uint256 a, uint256 b) external pure returns (uint256) {
        return KoalaBear.sub(a, b);
    }

    function baseMul(uint256 a, uint256 b) external pure returns (uint256) {
        return KoalaBear.mul(a, b);
    }

    function baseInv(uint256 a) external pure returns (uint256) {
        return KoalaBear.inv(a);
    }

    function ext4Pack(uint256[] memory coeffs) external pure returns (uint256) {
        return KoalaBearExt4.pack(_to4(coeffs));
    }

    function ext4Unpack(
        uint256 packed
    ) external pure returns (uint256[] memory coeffs) {
        return _from4(KoalaBearExt4.unpack(packed));
    }

    function ext4Add(uint256 a, uint256 b) external pure returns (uint256) {
        return KoalaBearExt4.add(a, b);
    }

    function ext4Sub(uint256 a, uint256 b) external pure returns (uint256) {
        return KoalaBearExt4.sub(a, b);
    }

    function ext4Mul(uint256 a, uint256 b) external pure returns (uint256) {
        return KoalaBearExt4.mul(a, b);
    }

    function ext4Square(uint256 a) external pure returns (uint256) {
        return KoalaBearExt4.square(a);
    }

    function ext4MulReference(
        uint256 a,
        uint256 b
    ) external pure returns (uint256) {
        return KoalaBearExt4.mul_reference(a, b);
    }

    function ext4Inv(uint256 a) external pure returns (uint256) {
        return KoalaBearExt4.inv(a);
    }

    function ext4MulByW(uint256 a) external pure returns (uint256) {
        return KoalaBearExt4.mul_by_w(a);
    }

    function ext4Extrapolate012(
        uint256 e0,
        uint256 e1,
        uint256 e2,
        uint256 r
    ) external pure returns (uint256) {
        return KoalaBearExt4.extrapolate_012(e0, e1, e2, r);
    }

    function ext4Extrapolate012Reference(
        uint256 e0,
        uint256 e1,
        uint256 e2,
        uint256 r
    ) external pure returns (uint256) {
        return KoalaBearExt4.extrapolate_012_reference(e0, e1, e2, r);
    }

    function ext4EqPolyEval(
        uint256[] memory p,
        uint256[] memory q
    ) external pure returns (uint256) {
        return KoalaBearExt4.eq_poly_eval(p, q);
    }

    function ext4EvaluateHypercube(
        uint256[] memory evals,
        uint256[] memory point
    ) external pure returns (uint256) {
        return KoalaBearExt4.evaluate_hypercube(evals, point);
    }

    function ext8Pack(uint256[] memory coeffs) external pure returns (uint256) {
        return KoalaBearExt8.pack(_to8(coeffs));
    }

    function ext8Unpack(
        uint256 packed
    ) external pure returns (uint256[] memory coeffs) {
        return _from8(KoalaBearExt8.unpack(packed));
    }

    function ext8Add(uint256 a, uint256 b) external pure returns (uint256) {
        return KoalaBearExt8.add(a, b);
    }

    function ext8Sub(uint256 a, uint256 b) external pure returns (uint256) {
        return KoalaBearExt8.sub(a, b);
    }

    function ext8Mul(uint256 a, uint256 b) external pure returns (uint256) {
        return KoalaBearExt8.mul(a, b);
    }

    function ext8Inv(uint256 a) external pure returns (uint256) {
        return KoalaBearExt8.inv(a);
    }

    function ext8MulByW(uint256 a) external pure returns (uint256) {
        return KoalaBearExt8.mul_by_w(a);
    }

    function ext8Extrapolate012(
        uint256 e0,
        uint256 e1,
        uint256 e2,
        uint256 r
    ) external pure returns (uint256) {
        return KoalaBearExt8.extrapolate_012(e0, e1, e2, r);
    }

    function ext8EqPolyEval(
        uint256[] memory p,
        uint256[] memory q
    ) external pure returns (uint256) {
        return KoalaBearExt8.eq_poly_eval(p, q);
    }

    function ext8EvaluateHypercube(
        uint256[] memory evals,
        uint256[] memory point
    ) external pure returns (uint256) {
        return KoalaBearExt8.evaluate_hypercube(evals, point);
    }

    function _to4(
        uint256[] memory coeffs
    ) internal pure returns (uint256[4] memory out) {
        require(coeffs.length == 4, "LEN4");
        unchecked {
            for (uint256 i = 0; i < 4; ++i) {
                out[i] = coeffs[i];
            }
        }
    }

    function _from4(
        uint256[4] memory coeffs
    ) internal pure returns (uint256[] memory out) {
        out = new uint256[](4);
        unchecked {
            for (uint256 i = 0; i < 4; ++i) {
                out[i] = coeffs[i];
            }
        }
    }

    function _to8(
        uint256[] memory coeffs
    ) internal pure returns (uint256[8] memory out) {
        require(coeffs.length == 8, "LEN8");
        unchecked {
            for (uint256 i = 0; i < 8; ++i) {
                out[i] = coeffs[i];
            }
        }
    }

    function _from8(
        uint256[8] memory coeffs
    ) internal pure returns (uint256[] memory out) {
        out = new uint256[](8);
        unchecked {
            for (uint256 i = 0; i < 8; ++i) {
                out[i] = coeffs[i];
            }
        }
    }
}
