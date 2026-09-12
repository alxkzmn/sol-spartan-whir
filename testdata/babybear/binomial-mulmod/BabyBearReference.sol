// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @dev Independent schoolbook oracle. Polynomial 0: X^5+X^2-1;
/// polynomial 1: X^5-2; polynomial 2: X^5-X^3-1.
library BabyBearReference {
    function pack(uint256[5] memory a) internal pure returns (uint256 out) {
        for (uint256 i; i < 5; ++i) {
            out |= a[i] << (224 - 32 * i);
        }
    }

    function unpack(uint256 a) internal pure returns (uint256[5] memory out) {
        for (uint256 i; i < 5; ++i) {
            out[i] = (a >> (224 - 32 * i)) & 0xffffffff;
        }
    }

    function add(uint256 a, uint256 b, uint256 p) internal pure returns (uint256) {
        uint256[5] memory x = unpack(a);
        uint256[5] memory y = unpack(b);
        for (uint256 i; i < 5; ++i) {
            x[i] = addmod(x[i], y[i], p);
        }
        return pack(x);
    }

    function scale(uint256 a, uint256 s, uint256 p) internal pure returns (uint256) {
        uint256[5] memory x = unpack(a);
        for (uint256 i; i < 5; ++i) {
            x[i] = mulmod(x[i], s, p);
        }
        return pack(x);
    }

    function mul(uint256 a, uint256 b, uint256 p, uint256 polynomial)
        internal
        pure
        returns (uint256)
    {
        uint256[5] memory x = unpack(a);
        uint256[5] memory y = unpack(b);
        uint256[9] memory c;
        for (uint256 i; i < 5; ++i) {
            for (uint256 j; j < 5; ++j) {
                c[i + j] = addmod(c[i + j], mulmod(x[i], y[j], p), p);
            }
        }
        for (uint256 k = 9; k > 5;) {
            --k;
            if (polynomial == 1) {
                c[k - 5] = addmod(c[k - 5], mulmod(2, c[k], p), p);
            } else {
                c[k - 5] = addmod(c[k - 5], c[k], p);
                if (polynomial == 0) c[k - 3] = addmod(c[k - 3], p - c[k], p);
                else c[k - 2] = addmod(c[k - 2], c[k], p);
            }
            c[k] = 0;
        }
        for (uint256 i; i < 5; ++i) {
            x[i] = c[i];
        }
        return pack(x);
    }

    function select(uint256 a, uint256 b, uint256 s, uint256 p, uint256 polynomial)
        internal
        pure
        returns (uint256)
    {
        return mul(a, add(uint256(1) << 224, scale(b, s, p), p), p, polynomial);
    }

    function chain(
        uint256 variable,
        uint256[] memory point,
        uint256 offset,
        uint256 n,
        uint256 p,
        uint256 polynomial
    ) internal pure returns (uint256 acc) {
        acc = uint256(1) << 224;
        for (uint256 i = n; i > 0; --i) {
            acc = select(acc, point[offset + i - 1], addmod(variable, p - 1, p), p, polynomial);
            variable = mulmod(variable, variable, p);
        }
    }
}
