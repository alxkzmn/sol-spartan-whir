// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

library KoalaBear {
    uint256 internal constant MODULUS = 0x7f000001;
    uint256 internal constant W = 3;

    // Assumes a,b are canonical KoalaBear elements in [0, MODULUS).
    // Do not use for lazy-reduced / unreduced accumulators
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            uint256 c = a + b;
            return c >= MODULUS ? c - MODULUS : c;
        }
    }

    // Assumes a,b are canonical KoalaBear elements in [0, MODULUS).
    // Do not use for lazy-reduced / unreduced accumulators
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            return a >= b ? a - b : a + MODULUS - b;
        }
    }

    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        return mulmod(a, b, MODULUS);
    }

    function pow(
        uint256 a,
        uint256 exponent
    ) internal pure returns (uint256 result) {
        assembly {
            result := 1
            let m := 0x7f000001
            for {

            } gt(exponent, 0) {
                exponent := shr(1, exponent)
            } {
                if and(exponent, 1) {
                    result := mulmod(result, a, m)
                }
                a := mulmod(a, a, m)
            }
        }
    }

    function inv(uint256 a) internal pure returns (uint256) {
        require(a % MODULUS != 0, "ZERO_INV");
        return pow(a, MODULUS - 2);
    }
}
