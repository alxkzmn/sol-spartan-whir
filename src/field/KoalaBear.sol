// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

library KoalaBear {
    uint256 internal constant MODULUS = 0x7f000001;
    uint256 internal constant W = 3;

    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            uint256 c = a + b;
            return c >= MODULUS ? c - MODULUS : c;
        }
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            return a >= b ? a - b : a + MODULUS - b;
        }
    }

    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        return mulmod(a, b, MODULUS);
    }

    function pow(uint256 a, uint256 exponent) internal pure returns (uint256 result) {
        result = 1;
        while (exponent != 0) {
            if (exponent & 1 != 0) {
                result = mul(result, a);
            }
            a = mul(a, a);
            exponent >>= 1;
        }
    }

    function inv(uint256 a) internal pure returns (uint256) {
        require(a != 0, "ZERO_INV");
        return pow(a, MODULUS - 2);
    }
}
