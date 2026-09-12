// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import { KoalaBearExt5 as EF } from "../field/KoalaBearExt5.sol";
import { KoalaBearPackedField as Packed } from "../field/KoalaBearPackedField.sol";

/// @dev Dimension-four EQ weights and row dots over the quintic field.
/// Coordinates and row coefficients must already be canonical. Row bytes are
/// BE-u32 scalars, with five consecutive scalars per extension-field value.
library LeanVmWhirFolding {
    function prepare16(uint256[] memory point, bool baseLeaf) internal pure returns (uint256 ptr) {
        require(point.length == 4, "FOLD_POINT");
        uint256 packedPtr = _computeDim4EqWeights(point[0], point[1], point[2], point[3]);
        return baseLeaf ? _prepareBaseRadix80(packedPtr) : _prepareRowWeights(packedPtr);
    }

    function prepare32(uint256[] memory point, bool baseLeaf) internal pure returns (uint256 ptr) {
        require(point.length == 5, "FOLD_POINT");
        uint256 packedPtr = _computeDim4EqWeights(point[1], point[2], point[3], point[4]);
        return baseLeaf ? _prepareBaseRadix80(packedPtr) : _prepareRowWeights(packedPtr);
    }

    function fold32(bytes calldata row, uint256 offset, uint256 ptr, bool baseLeaf, uint256 firstPoint)
        internal pure returns (uint256)
    {
        uint256 left = fold16(row, offset, ptr, baseLeaf);
        uint256 right = fold16(row, offset + (baseLeaf ? 64 : 320), ptr, baseLeaf);
        return EF.add(left, Packed.mul(firstPoint, EF.sub(right, left)));
    }

    function fold16(bytes calldata row, uint256 offset, uint256 ptr, bool baseLeaf)
        internal pure returns (uint256 out)
    {
        require(offset <= row.length && (baseLeaf ? 64 : 320) <= row.length - offset, "FOLD_ROW");
        if (baseLeaf) {
            uint256 w0;
            uint256 w1;
            assembly ("memory-safe") {
                w0 := calldataload(add(row.offset, offset))
                w1 := calldataload(add(add(row.offset, offset), 32))
            }
            return _dotBaseRadix80(ptr, w0, w1);
        }
        return _evaluateFinalRow16(row, offset, ptr);
    }

    function _computeDim4EqWeights(uint256 p0, uint256 p1, uint256 p2, uint256 p3)
        internal
        pure
        returns (uint256 weightsPtr)
    {
        uint256 a11 = Packed.mul(p0, p1);
        uint256 a10 = EF.sub(p0, a11);
        uint256 a01 = EF.sub(p1, a11);
        uint256 a00 = EF.sub(EF.sub(EF.ONE, p0), a01);
        uint256 b001 = Packed.mul(a00, p2);
        uint256 b000 = EF.sub(a00, b001);
        uint256 b011 = Packed.mul(a01, p2);
        uint256 b010 = EF.sub(a01, b011);
        uint256 b101 = Packed.mul(a10, p2);
        uint256 b100 = EF.sub(a10, b101);
        uint256 b111 = Packed.mul(a11, p2);
        uint256 b110 = EF.sub(a11, b111);

        assembly ("memory-safe") {
            weightsPtr := mload(0x40)
            mstore(0x40, add(weightsPtr, 0x200))
        }

        _storeDim4EqWeightPair(weightsPtr, 0x000, b000, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x040, b001, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x080, b010, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x0c0, b011, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x100, b100, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x140, b101, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x180, b110, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x1c0, b111, p3);
    }

    function _storeDim4EqWeightPair(uint256 weightsPtr, uint256 offset, uint256 prefix, uint256 p3)
        private
        pure
    {
        uint256 w1 = Packed.mul(prefix, p3);
        uint256 w0 = EF.sub(prefix, w1);
        assembly ("memory-safe") {
            mstore(add(weightsPtr, offset), w0)
            mstore(add(add(weightsPtr, offset), 0x20), w1)
        }
    }

    function _prepareRowWeights(uint256 packedPtr) internal pure returns (uint256 ptr) {
        assembly ("memory-safe") {
            ptr := mload(0x40)
            mstore(0x40, add(ptr, 1536))
            for { let i := 0 } lt(i, 16) { i := add(i, 1) } {
                let a := mload(add(packedPtr, shl(5, i)))
                let dst := add(ptr, mul(i, 96))
                let u :=
                    or(
                        and(shr(224, a), 0xffffffff),
                        or(
                            shl(51, and(shr(192, a), 0xffffffff)),
                            or(
                                shl(102, and(shr(160, a), 0xffffffff)),
                                or(
                                    shl(153, and(shr(128, a), 0xffffffff)),
                                    shl(204, and(shr(96, a), 0xffffffff))
                                )
                            )
                        )
                    )
                let low := and(u, 0xffff000000001fffe000000003fffc000000007fff800000000ffff)
                let high :=
                    and(shr(16, u), 0xffff000000001fffe000000003fffc000000007fff800000000ffff)
                mstore(dst, low)
                mstore(add(dst, 32), high)
                mstore(add(dst, 64), add(low, high))
            }
        }
    }

    function _prepareBaseRadix80(uint256 packedPtr) internal pure returns (uint256 ptr) {
        assembly ("memory-safe") {
            ptr := mload(0x40)
            mstore(0x40, add(ptr, 0x400))
            for { let i := 0 } lt(i, 16) { i := add(i, 1) } {
                let w := mload(add(packedPtr, shl(5, i)))
                let dst := add(ptr, shl(6, i))
                mstore(
                    dst,
                    or(
                        or(shr(224, w), shl(80, and(shr(192, w), 0xffffffff))),
                        shl(160, and(shr(160, w), 0xffffffff))
                    )
                )
                mstore(
                    add(dst, 32),
                    or(and(shr(128, w), 0xffffffff), shl(80, and(shr(96, w), 0xffffffff)))
                )
            }
        }
    }

    function _dotBaseRadix80(uint256 weightsPtr, uint256 w0, uint256 w1)
        internal
        pure
        returns (uint256 out)
    {
        assembly ("memory-safe") {
            let a := 0
            let b := 0
            function accumulate(s, w, ca, cb) -> aa, bb {
                aa := add(ca, mul(s, mload(w)))
                bb := add(cb, mul(s, mload(add(w, 32))))
            }
            a, b := accumulate(and(shr(224, w0), 0xffffffff), add(weightsPtr, 0), a, b)
            a, b := accumulate(and(shr(192, w0), 0xffffffff), add(weightsPtr, 64), a, b)
            a, b := accumulate(and(shr(160, w0), 0xffffffff), add(weightsPtr, 128), a, b)
            a, b := accumulate(and(shr(128, w0), 0xffffffff), add(weightsPtr, 192), a, b)
            a, b := accumulate(and(shr(96, w0), 0xffffffff), add(weightsPtr, 256), a, b)
            a, b := accumulate(and(shr(64, w0), 0xffffffff), add(weightsPtr, 320), a, b)
            a, b := accumulate(and(shr(32, w0), 0xffffffff), add(weightsPtr, 384), a, b)
            a, b := accumulate(and(shr(0, w0), 0xffffffff), add(weightsPtr, 448), a, b)
            a, b := accumulate(and(shr(224, w1), 0xffffffff), add(weightsPtr, 512), a, b)
            a, b := accumulate(and(shr(192, w1), 0xffffffff), add(weightsPtr, 576), a, b)
            a, b := accumulate(and(shr(160, w1), 0xffffffff), add(weightsPtr, 640), a, b)
            a, b := accumulate(and(shr(128, w1), 0xffffffff), add(weightsPtr, 704), a, b)
            a, b := accumulate(and(shr(96, w1), 0xffffffff), add(weightsPtr, 768), a, b)
            a, b := accumulate(and(shr(64, w1), 0xffffffff), add(weightsPtr, 832), a, b)
            a, b := accumulate(and(shr(32, w1), 0xffffffff), add(weightsPtr, 896), a, b)
            a, b := accumulate(and(shr(0, w1), 0xffffffff), add(weightsPtr, 960), a, b)
            let M := 0x7f000001
            let mask := sub(shl(80, 1), 1)
            out := or(
                or(
                    or(shl(224, mod(and(a, mask), M)), shl(192, mod(and(shr(80, a), mask), M))),
                    shl(160, mod(shr(160, a), M))
                ),
                or(shl(128, mod(and(b, mask), M)), shl(96, mod(shr(80, b), M)))
            )
        }
    }

    function _evaluateFinalRow16(bytes calldata blob, uint256 offset, uint256 weightsPtr)
        private
        pure
        returns (uint256 out)
    {
        assembly ("memory-safe") {
            let src := add(blob.offset, offset)
            let M := 0x7f000001
            let c0 := 0
            let c1 := 0
            let c2 := 0
            function accumulate(a, w, d0, d1, d2) -> e0, e1, e2 {
                let u :=
                    or(
                        and(shr(224, a), 0xffffffff),
                        or(
                            shl(51, and(shr(192, a), 0xffffffff)),
                            or(
                                shl(102, and(shr(160, a), 0xffffffff)),
                                or(
                                    shl(153, and(shr(128, a), 0xffffffff)),
                                    shl(204, and(shr(96, a), 0xffffffff))
                                )
                            )
                        )
                    )
                let low := and(u, 0xffff000000001fffe000000003fffc000000007fff800000000ffff)
                let high :=
                    and(shr(16, u), 0xffff000000001fffe000000003fffc000000007fff800000000ffff)
                e0 := addmod(
                    d0,
                    mulmod(
                        low,
                        mload(w),
                        0x800000000000000000000000000000000000003fffffffffffffffffffffffff
                    ),
                    0x800000000000000000000000000000000000003fffffffffffffffffffffffff
                )
                e1 := addmod(
                    d1,
                    mulmod(
                        high,
                        mload(add(w, 32)),
                        0x800000000000000000000000000000000000003fffffffffffffffffffffffff
                    ),
                    0x800000000000000000000000000000000000003fffffffffffffffffffffffff
                )
                e2 := addmod(
                    d2,
                    mulmod(
                        add(low, high),
                        mload(add(w, 64)),
                        0x800000000000000000000000000000000000003fffffffffffffffffffffffff
                    ),
                    0x800000000000000000000000000000000000003fffffffffffffffffffffffff
                )
            }
            c0, c1, c2 :=
                accumulate(
                and(calldataload(add(src, 0)), not(sub(shl(96, 1), 1))),
                add(weightsPtr, 0),
                c0,
                c1,
                c2
            )
            c0, c1, c2 :=
                accumulate(
                and(calldataload(add(src, 20)), not(sub(shl(96, 1), 1))),
                add(weightsPtr, 96),
                c0,
                c1,
                c2
            )
            c0, c1, c2 :=
                accumulate(
                and(calldataload(add(src, 40)), not(sub(shl(96, 1), 1))),
                add(weightsPtr, 192),
                c0,
                c1,
                c2
            )
            c0, c1, c2 :=
                accumulate(
                and(calldataload(add(src, 60)), not(sub(shl(96, 1), 1))),
                add(weightsPtr, 288),
                c0,
                c1,
                c2
            )
            c0, c1, c2 :=
                accumulate(
                and(calldataload(add(src, 80)), not(sub(shl(96, 1), 1))),
                add(weightsPtr, 384),
                c0,
                c1,
                c2
            )
            c0, c1, c2 :=
                accumulate(
                and(calldataload(add(src, 100)), not(sub(shl(96, 1), 1))),
                add(weightsPtr, 480),
                c0,
                c1,
                c2
            )
            c0, c1, c2 :=
                accumulate(
                and(calldataload(add(src, 120)), not(sub(shl(96, 1), 1))),
                add(weightsPtr, 576),
                c0,
                c1,
                c2
            )
            c0, c1, c2 :=
                accumulate(
                and(calldataload(add(src, 140)), not(sub(shl(96, 1), 1))),
                add(weightsPtr, 672),
                c0,
                c1,
                c2
            )
            c0, c1, c2 :=
                accumulate(
                and(calldataload(add(src, 160)), not(sub(shl(96, 1), 1))),
                add(weightsPtr, 768),
                c0,
                c1,
                c2
            )
            c0, c1, c2 :=
                accumulate(
                and(calldataload(add(src, 180)), not(sub(shl(96, 1), 1))),
                add(weightsPtr, 864),
                c0,
                c1,
                c2
            )
            c0, c1, c2 :=
                accumulate(
                and(calldataload(add(src, 200)), not(sub(shl(96, 1), 1))),
                add(weightsPtr, 960),
                c0,
                c1,
                c2
            )
            c0, c1, c2 :=
                accumulate(
                and(calldataload(add(src, 220)), not(sub(shl(96, 1), 1))),
                add(weightsPtr, 1056),
                c0,
                c1,
                c2
            )
            c0, c1, c2 :=
                accumulate(
                and(calldataload(add(src, 240)), not(sub(shl(96, 1), 1))),
                add(weightsPtr, 1152),
                c0,
                c1,
                c2
            )
            c0, c1, c2 :=
                accumulate(
                and(calldataload(add(src, 260)), not(sub(shl(96, 1), 1))),
                add(weightsPtr, 1248),
                c0,
                c1,
                c2
            )
            c0, c1, c2 :=
                accumulate(
                and(calldataload(add(src, 280)), not(sub(shl(96, 1), 1))),
                add(weightsPtr, 1344),
                c0,
                c1,
                c2
            )
            c0, c1, c2 :=
                accumulate(
                and(calldataload(add(src, 300)), not(sub(shl(96, 1), 1))),
                add(weightsPtr, 1440),
                c0,
                c1,
                c2
            )
            let bias := shl(80, M)
            c0 := addmod(
                c0,
                0x40000000000008000000000001000000000000200000000000040000000000,
                0x800000000000000000000000000000000000003fffffffffffffffffffffffff
            )
            c1 := addmod(
                c1,
                0x40000000000008000000000001000000000000200000000000040000000000,
                0x800000000000000000000000000000000000003fffffffffffffffffffffffff
            )
            c2 := addmod(
                c2,
                0x40000000000008000000000001000000000000200000000000040000000000,
                0x800000000000000000000000000000000000003fffffffffffffffffffffffff
            )
            let l0 := and(shr(0, c0), 0x7ffffffffffff)
            let h0 := and(shr(0, c1), 0x7ffffffffffff)
            let s0 := and(shr(0, c2), 0x7ffffffffffff)
            let r0 :=
                mod(
                    sub(
                        add(add(add(l0, shl(16, s0)), shl(32, h0)), 0x7efffc0103fffc0000000000),
                        shl(16, add(l0, h0))
                    ),
                    M
                )
            let l1 := and(shr(51, c0), 0x7ffffffffffff)
            let h1 := and(shr(51, c1), 0x7ffffffffffff)
            let s1 := and(shr(51, c2), 0x7ffffffffffff)
            let r1 :=
                mod(
                    sub(
                        add(add(add(l1, shl(16, s1)), shl(32, h1)), 0x7efffc0103fffc0000000000),
                        shl(16, add(l1, h1))
                    ),
                    M
                )
            let l2 := and(shr(102, c0), 0x7ffffffffffff)
            let h2 := and(shr(102, c1), 0x7ffffffffffff)
            let s2 := and(shr(102, c2), 0x7ffffffffffff)
            let r2 :=
                mod(
                    sub(
                        add(add(add(l2, shl(16, s2)), shl(32, h2)), 0x7efffc0103fffc0000000000),
                        shl(16, add(l2, h2))
                    ),
                    M
                )
            let l3 := and(shr(153, c0), 0x7ffffffffffff)
            let h3 := and(shr(153, c1), 0x7ffffffffffff)
            let s3 := and(shr(153, c2), 0x7ffffffffffff)
            let r3 :=
                mod(
                    sub(
                        add(add(add(l3, shl(16, s3)), shl(32, h3)), 0x7efffc0103fffc0000000000),
                        shl(16, add(l3, h3))
                    ),
                    M
                )
            let l4 := and(shr(204, c0), 0x7ffffffffffff)
            let h4 := and(shr(204, c1), 0x7ffffffffffff)
            let s4 := and(shr(204, c2), 0x7ffffffffffff)
            let r4 :=
                mod(
                    sub(
                        add(add(add(l4, shl(16, s4)), shl(32, h4)), 0x7efffc0103fffc0000000000),
                        shl(16, add(l4, h4))
                    ),
                    M
                )
            out := or(
                shl(224, r0),
                or(shl(192, r1), or(shl(160, r2), or(shl(128, r3), shl(96, r4))))
            )
        }
    }

}
