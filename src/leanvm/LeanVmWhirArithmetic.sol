// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import { KoalaBearExt5 as EF } from "../field/KoalaBearExt5.sol";
import { KoalaBearPackedField as Packed } from "../field/KoalaBearPackedField.sol";

/// @dev Prepared evaluation of eq([x,x^2,...], point), with x in the base field.
library LeanVmWhirArithmetic {
    uint256 internal constant ONE = uint256(1) << 224;
    uint256 internal constant MODULUS = 2_130_706_433;

    function prepareBaseEq(uint256[] memory point, uint256 offset, uint256 variables)
        internal pure returns (uint256[] memory cache)
    {
        require(offset + variables <= point.length, "EQ_POINT");
        uint256 pairs = variables / 2;
        cache = new uint256[](5 * pairs + 1);
        for (uint256 i; i < pairs; ++i) {
            uint256 r = point[offset + 2 * i];
            uint256 s = point[offset + 2 * i + 1];
            uint256 rs = Packed.mul(r, s);
            uint256 twiceRs = EF.add(rs, rs);
            uint256 twiceR = EF.add(r, r);
            uint256 twiceS = EF.add(s, s);
            // ((1-r)+(2r-1)x) * ((1-s)+(2s-1)x^2).
            uint256 a = EF.add(EF.sub(EF.sub(ONE, r), s), rs);
            uint256 b = EF.sub(EF.add(twiceR, s), EF.add(ONE, twiceRs));
            uint256 c = EF.sub(EF.add(twiceS, r), EF.add(ONE, twiceRs));
            uint256 d = EF.add(EF.sub(EF.sub(EF.add(twiceRs, twiceRs), twiceR), twiceS), ONE);
            uint256 ptr;
            assembly ("memory-safe") { ptr := add(add(cache, 32), mul(i, 160)) }
            storeForm(ptr, a);
            storeForm(ptr + 32, b);
            storeForm(ptr + 64, c);
            storeForm(ptr + 96, d);
            assembly ("memory-safe") {
                mstore(add(ptr, 128), or(or(and(shr(96, a), 0xffffffff), shl(64, and(shr(96, b), 0xffffffff))), or(shl(128, and(shr(96, c), 0xffffffff)), shl(192, and(shr(96, d), 0xffffffff)))))
            }
        }
        if (variables & 1 != 0) cache[5 * pairs] = point[offset + variables - 1];
    }

    function evaluateBaseEq(uint256[] memory cache, uint256 variables, uint256 x)
        internal pure returns (uint256 out)
    {
        require(x < MODULUS && cache.length == 5 * (variables / 2) + 1, "EQ_CACHE");
        uint256 low = 1;
        uint256 rev;
        uint256 current = x;
        for (uint256 i; i < variables / 2; ++i) {
            uint256 ptr;
            assembly ("memory-safe") { ptr := add(add(cache, 32), mul(i, 160)) }
            (uint256 bLow, uint256 bRev, uint256 next) = evaluatePair(ptr, current);
            if (i == 0) {
                low = bLow;
                rev = bRev;
            } else {
                (low, rev) = mulForms(low, rev, bLow, bRev);
            }
            current = next;
        }
        out = packForms(low, rev);
        if (variables & 1 != 0) {
            uint256 r = cache[cache.length - 1];
            uint256 term = EF.add(EF.sub(ONE, r), EF.mulBase(EF.sub(EF.add(r, r), ONE), current));
            out = variables == 1 ? term : Packed.mul(out, term);
        }
    }

    // Canonical coefficients and x keep every cubic lane below 4*(p-1)^2 < 2^64.
    // The product kernels use the same canonical 64-bit-lane convolution bounds.
    function mulForms(uint256 aLow, uint256 aRev, uint256 bLow, uint256 bRev)
        private
        pure
        returns (uint256 lowOut, uint256 revOut)
    {
        assembly ("memory-safe") {
            let M := 0x7f000001
            let c4 :=
                add(
                    shr(192, mul(aLow, or(shr(64, bLow), shl(192, and(bRev, 0xffffffff))))),
                    mul(and(aRev, 0xffffffff), and(bLow, 0xffffffff))
                )
            let low := mul(aLow, bLow)
            let high := mul(aRev, bRev)
            let c0 := and(low, 0xffffffffffffffff)
            let c1 := and(shr(64, low), 0xffffffffffffffff)
            let c2 := and(shr(128, low), 0xffffffffffffffff)
            let c3 := shr(192, low)
            let c5 := shr(192, high)
            let c6 := and(shr(128, high), 0xffffffffffffffff)
            let c7 := and(shr(64, high), 0xffffffffffffffff)
            let c8 := and(high, 0xffffffffffffffff)
            let bias := shl(40, M)
            let o0 := mod(add(add(c0, c5), sub(bias, c8)), M)
            let o1 := mod(add(c1, c6), M)
            let o2 := mod(add(add(add(c2, sub(bias, c5)), c7), c8), M)
            let o3 := mod(add(add(c3, sub(bias, c6)), c8), M)
            let o4 := mod(add(c4, sub(bias, c7)), M)
            lowOut := or(or(o0, shl(64, o1)), or(shl(128, o2), shl(192, o3)))
            revOut := or(or(o4, shl(64, o3)), or(shl(128, o2), shl(192, o1)))
        }
    }

    function packForms(uint256 low, uint256 rev) private pure returns (uint256 out) {
        assembly ("memory-safe") {
            out := or(
                or(
                    or(shl(224, and(low, 0xffffffff)), shl(192, and(shr(64, low), 0xffffffff))),
                    or(shl(160, and(shr(128, low), 0xffffffff)), shl(128, shr(192, low)))
                ),
                shl(96, and(rev, 0xffffffff))
            )
        }
    }

    function evaluatePair(uint256 ptr, uint256 x)
        private
        pure
        returns (uint256 lowOut, uint256 revOut, uint256 next)
    {
        assembly ("memory-safe") {
            let M := 0x7f000001
            let x2 := mulmod(x, x, M)
            let x3 := mulmod(x2, x, M)
            next := mulmod(x2, x2, M)
            let low :=
                add(
                    add(mload(ptr), mul(mload(add(ptr, 32)), x)),
                    add(mul(mload(add(ptr, 64)), x2), mul(mload(add(ptr, 96)), x3))
                )
            let last :=
                shr(
                    192,
                    mul(mload(add(ptr, 128)), or(or(x3, shl(64, x2)), or(shl(128, x), shl(192, 1))))
                )
            let o0 := mod(and(low, 0xffffffffffffffff), M)
            let o1 := mod(and(shr(64, low), 0xffffffffffffffff), M)
            let o2 := mod(and(shr(128, low), 0xffffffffffffffff), M)
            let o3 := mod(shr(192, low), M)
            let o4 := mod(last, M)
            lowOut := or(or(o0, shl(64, o1)), or(shl(128, o2), shl(192, o3)))
            revOut := or(or(o4, shl(64, o3)), or(shl(128, o2), shl(192, o1)))
        }
    }

    function storeForm(uint256 ptr, uint256 b) private pure {
        assembly ("memory-safe") {
            mstore(
                ptr,
                or(
                    or(shr(224, b), shl(64, and(shr(192, b), 0xffffffff))),
                    or(
                        shl(128, and(shr(160, b), 0xffffffff)),
                        shl(192, and(shr(128, b), 0xffffffff))
                    )
                )
            )
        }
    }

}
