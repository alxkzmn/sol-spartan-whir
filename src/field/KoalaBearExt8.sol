// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { KoalaBear } from "./KoalaBear.sol";

library KoalaBearExt8 {
    uint256 internal constant DEGREE = 8;
    uint256 internal constant COEFF_MASK = 0xffffffff;
    uint256 internal constant ONE = uint256(1) << 224;
    uint256 internal constant TWO = uint256(2) << 224;
    uint256 internal constant INV_TWO = 1_065_353_217;
    uint256 internal constant DTH_ROOT = 1_748_172_362;

    error BaseScalarOutOfRange(uint256 value);

    function pack(uint256[8] memory coeffs) internal pure returns (uint256 packed) {
        unchecked {
            packed = (coeffs[0] << 224) | (coeffs[1] << 192) | (coeffs[2] << 160)
                | (coeffs[3] << 128) | (coeffs[4] << 96) | (coeffs[5] << 64) | (coeffs[6] << 32)
                | coeffs[7];
        }
    }

    function unpack(uint256 packed) internal pure returns (uint256[8] memory coeffs) {
        coeffs[0] = packed >> 224;
        coeffs[1] = (packed >> 192) & COEFF_MASK;
        coeffs[2] = (packed >> 160) & COEFF_MASK;
        coeffs[3] = (packed >> 128) & COEFF_MASK;
        coeffs[4] = (packed >> 96) & COEFF_MASK;
        coeffs[5] = (packed >> 64) & COEFF_MASK;
        coeffs[6] = (packed >> 32) & COEFF_MASK;
        coeffs[7] = packed & COEFF_MASK;
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256[8] memory lhs = unpack(a);
        uint256[8] memory rhs = unpack(b);
        uint256[8] memory out;

        unchecked {
            for (uint256 i = 0; i < DEGREE; ++i) {
                out[i] = KoalaBear.add(lhs[i], rhs[i]);
            }
        }

        return pack(out);
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256[8] memory lhs = unpack(a);
        uint256[8] memory rhs = unpack(b);
        uint256[8] memory out;

        unchecked {
            for (uint256 i = 0; i < DEGREE; ++i) {
                out[i] = KoalaBear.sub(lhs[i], rhs[i]);
            }
        }

        return pack(out);
    }

    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        return pack(_mul_coeffs(unpack(a), unpack(b)));
    }

    function square(uint256 a) internal pure returns (uint256) {
        return mul(a, a);
    }

    function fromBase(uint256 value) internal pure returns (uint256) {
        if (value >= KoalaBear.MODULUS) {
            revert BaseScalarOutOfRange(value);
        }
        return value << 224;
    }

    function mulBase(uint256 a, uint256 scalar) internal pure returns (uint256) {
        if (scalar >= KoalaBear.MODULUS) {
            revert BaseScalarOutOfRange(scalar);
        }
        return _scalar_mul(a, scalar);
    }

    function inv(uint256 a) internal pure returns (uint256) {
        require(a != 0, "ZERO_INV");

        uint256 prodConj = _frobenius(a);
        for (uint256 i = 2; i < DEGREE; ++i) {
            prodConj = _frobenius(mul(prodConj, a));
        }

        uint256[8] memory lhs = unpack(a);
        uint256[8] memory rhs = unpack(prodConj);
        uint256 norm = _norm(lhs, rhs);

        return _scalar_mul(prodConj, KoalaBear.inv(norm));
    }

    function mul_by_w(uint256 a) internal pure returns (uint256) {
        return _scalar_mul(a, KoalaBear.W);
    }

    function extrapolate_012(uint256 e0, uint256 e1, uint256 e2, uint256 r)
        internal
        pure
        returns (uint256)
    {
        uint256 l0 = _scalar_mul(mul(sub(r, ONE), sub(r, TWO)), INV_TWO);
        uint256 l1 = mul(r, sub(TWO, r));
        uint256 l2 = _scalar_mul(mul(r, sub(r, ONE)), INV_TWO);
        return add(add(mul(e0, l0), mul(e1, l1)), mul(e2, l2));
    }

    function eq_poly_eval(uint256[] memory p, uint256[] memory q)
        internal
        pure
        returns (uint256 acc)
    {
        require(p.length == q.length, "LEN");
        acc = ONE;

        unchecked {
            for (uint256 i = 0; i < p.length; ++i) {
                uint256 term = add(ONE, sub(sub(_scalar_mul(mul(p[i], q[i]), 2), p[i]), q[i]));
                acc = mul(acc, term);
            }
        }
    }

    function evaluate_hypercube(uint256[] memory evals, uint256[] memory point)
        internal
        pure
        returns (uint256)
    {
        uint256 size = evals.length;
        require(size != 0 && _is_power_of_two(size), "BAD_EVALS");
        require(size == (uint256(1) << point.length), "DIM");

        unchecked {
            for (uint256 i = 0; i < point.length; ++i) {
                size >>= 1;
                for (uint256 j = 0; j < size; ++j) {
                    evals[j] = _fold_once(evals[j], evals[j + size], point[i]);
                }
            }
        }

        return evals[0];
    }

    function _fold_once(uint256 a0, uint256 a1, uint256 r) internal pure returns (uint256) {
        return add(a0, mul(r, sub(a1, a0)));
    }

    function _scalar_mul(uint256 a, uint256 scalar) internal pure returns (uint256) {
        uint256[8] memory coeffs = unpack(a);

        unchecked {
            for (uint256 i = 0; i < DEGREE; ++i) {
                coeffs[i] = KoalaBear.mul(coeffs[i], scalar);
            }
        }

        return pack(coeffs);
    }

    function _frobenius(uint256 a) internal pure returns (uint256) {
        return _repeated_frobenius(a, 1);
    }

    function _repeated_frobenius(uint256 a, uint256 count) internal pure returns (uint256) {
        uint256 power = count % DEGREE;
        if (power == 0) {
            return a;
        }

        uint256 z = KoalaBear.pow(DTH_ROOT, power);
        uint256 running = 1;
        uint256[8] memory coeffs = unpack(a);

        unchecked {
            for (uint256 i = 0; i < DEGREE; ++i) {
                coeffs[i] = KoalaBear.mul(coeffs[i], running);
                running = KoalaBear.mul(running, z);
            }
        }

        return pack(coeffs);
    }

    function _norm(uint256[8] memory a, uint256[8] memory b) internal pure returns (uint256) {
        uint256 wCoeff;

        unchecked {
            for (uint256 i = 1; i < DEGREE; ++i) {
                wCoeff = KoalaBear.add(wCoeff, KoalaBear.mul(a[i], b[DEGREE - i]));
            }
        }

        return KoalaBear.add(KoalaBear.mul(a[0], b[0]), KoalaBear.mul(KoalaBear.W, wCoeff));
    }

    function _mul_coeffs(uint256[8] memory a, uint256[8] memory b)
        internal
        pure
        returns (uint256[8] memory out)
    {
        unchecked {
            for (uint256 i = 0; i < DEGREE; ++i) {
                for (uint256 j = 0; j < DEGREE; ++j) {
                    uint256 term = KoalaBear.mul(a[i], b[j]);
                    uint256 idx = i + j;
                    if (idx >= DEGREE) {
                        out[idx - DEGREE] =
                            KoalaBear.add(out[idx - DEGREE], KoalaBear.mul(term, KoalaBear.W));
                    } else {
                        out[idx] = KoalaBear.add(out[idx], term);
                    }
                }
            }
        }
    }

    function _is_power_of_two(uint256 x) internal pure returns (bool) {
        return x & (x - 1) == 0;
    }
}
