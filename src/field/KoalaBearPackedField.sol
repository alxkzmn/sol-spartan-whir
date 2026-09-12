// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import { KoalaBearExt5 } from "./KoalaBearExt5.sol";

library KoalaBearPackedField {
    uint256 internal constant ONE = uint256(1) << 224;

    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        return KoalaBearExt5.add(a, b);
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        return KoalaBearExt5.sub(a, b);
    }

    function square(uint256 a) internal pure returns (uint256) {
        return mul(a, a);
    }

    function mul(uint256 acc, uint256 pointValue) internal pure returns (uint256 out) {
        assembly ("memory-safe") {
            let M := 0x7f000001
            let mask := 0xffffffff

            let low
            let high
            let c4
            {
                let a0 := shr(224, acc)
                let a1 := and(shr(192, acc), mask)
                let a2 := and(shr(160, acc), mask)
                let a3 := and(shr(128, acc), mask)
                let a4 := and(shr(96, acc), mask)
                let b0 := shr(224, pointValue)
                let b1 := and(shr(192, pointValue), mask)
                let b2 := and(shr(160, pointValue), mask)
                let b3 := and(shr(128, pointValue), mask)
                let b4 := and(shr(96, pointValue), mask)

                let aLow := or(or(a0, shl(64, a1)), or(shl(128, a2), shl(192, a3)))
                let bLow := or(or(b0, shl(64, b1)), or(shl(128, b2), shl(192, b3)))
                // Four middle terms fit in the top lane; the fifth is added separately.
                c4 := add(shr(192, mul(aLow, or(shr(64, bLow), shl(192, b4)))), mul(a4, b0))
                // The low four coefficients in each order have at most four terms.
                // Since 4 * (M - 1)^2 < 2^64, their 64-bit lanes cannot carry.
                low := mul(aLow, bLow)
                high := mul(
                    or(or(a4, shl(64, a3)), or(shl(128, a2), shl(192, a1))),
                    or(or(b4, shl(64, b3)), or(shl(128, b2), shl(192, b1)))
                )
            }
            let laneMask := 0xffffffffffffffff
            let c0 := and(low, laneMask)
            let c1 := and(shr(64, low), laneMask)
            let c2 := and(shr(128, low), laneMask)
            let c3 := shr(192, low)
            let c5 := shr(192, high)
            let c6 := and(shr(128, high), laneMask)
            let c7 := and(shr(64, high), laneMask)
            let c8 := and(high, laneMask)
            let bias := shl(40, M)
            out := or(
                or(
                    or(
                        shl(224, mod(add(add(c0, c5), sub(bias, c8)), M)),
                        shl(192, mod(add(c1, c6), M))
                    ),
                    or(
                        shl(160, mod(add(add(add(c2, sub(bias, c5)), c7), c8), M)),
                        shl(128, mod(add(add(c3, sub(bias, c6)), c8), M))
                    )
                ),
                shl(96, mod(add(c4, sub(bias, c7)), M))
            )
        }
    }

    function eq(uint256 a, uint256 pointValue) internal pure returns (uint256 out) {
        assembly ("memory-safe") {
            let M := 0x7f000001
            let mask := 0xffffffff

            let low
            let high
            let c4
            {
                let a0 := shr(224, a)
                let a1 := and(shr(192, a), mask)
                let a2 := and(shr(160, a), mask)
                let a3 := and(shr(128, a), mask)
                let a4 := and(shr(96, a), mask)
                let b0 := shr(224, pointValue)
                let b1 := and(shr(192, pointValue), mask)
                let b2 := and(shr(160, pointValue), mask)
                let b3 := and(shr(128, pointValue), mask)
                let b4 := and(shr(96, pointValue), mask)

                let aLow := or(or(a0, shl(64, a1)), or(shl(128, a2), shl(192, a3)))
                let bLow := or(or(b0, shl(64, b1)), or(shl(128, b2), shl(192, b3)))
                // Four middle terms fit in the top lane; the fifth is added separately.
                c4 := add(shr(192, mul(aLow, or(shr(64, bLow), shl(192, b4)))), mul(a4, b0))
                // The low four coefficients in each order have at most four terms.
                // Since 4 * (M - 1)^2 < 2^64, their 64-bit lanes cannot carry.
                low := mul(aLow, bLow)
                high := mul(
                    or(or(a4, shl(64, a3)), or(shl(128, a2), shl(192, a1))),
                    or(or(b4, shl(64, b3)), or(shl(128, b2), shl(192, b1)))
                )
            }
            let laneMask := 0xffffffffffffffff
            let c0 := and(low, laneMask)
            let c1 := and(shr(64, low), laneMask)
            let c2 := and(shr(128, low), laneMask)
            let c3 := shr(192, low)
            let c5 := shr(192, high)
            let c6 := and(shr(128, high), laneMask)
            let c7 := and(shr(64, high), laneMask)
            let c8 := and(high, laneMask)
            let bias := shl(40, M)
            let m0 := add(add(c0, c5), sub(bias, c8))
            let a0 := and(shr(224, a), 0xffffffff)
            let b0 := and(shr(224, pointValue), 0xffffffff)
            let m1 := add(c1, c6)
            let a1 := and(shr(192, a), 0xffffffff)
            let b1 := and(shr(192, pointValue), 0xffffffff)
            let m2 := add(add(add(c2, sub(bias, c5)), c7), c8)
            let a2 := and(shr(160, a), 0xffffffff)
            let b2 := and(shr(160, pointValue), 0xffffffff)
            let m3 := add(add(c3, sub(bias, c6)), c8)
            let a3 := and(shr(128, a), 0xffffffff)
            let b3 := and(shr(128, pointValue), 0xffffffff)
            let m4 := add(c4, sub(bias, c7))
            let a4 := and(shr(96, a), 0xffffffff)
            let b4 := and(shr(96, pointValue), 0xffffffff)
            let b := shl(2, M)
            let o0 := mod(add(add(add(1, shl(1, m0)), b), sub(0, add(a0, b0))), M)
            let o1 := mod(add(add(shl(1, m1), b), sub(0, add(a1, b1))), M)
            let o2 := mod(add(add(shl(1, m2), b), sub(0, add(a2, b2))), M)
            let o3 := mod(add(add(shl(1, m3), b), sub(0, add(a3, b3))), M)
            let o4 := mod(add(add(shl(1, m4), b), sub(0, add(a4, b4))), M)

            out := or(
                or(or(shl(224, o0), shl(192, o1)), or(shl(160, o2), shl(128, o3))),
                shl(96, o4)
            )
        }
        return out;
    }
}
