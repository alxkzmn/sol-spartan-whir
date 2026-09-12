// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import {KoalaBearExt5} from "../../src/field/KoalaBearExt5.sol";
import {BabyBearBenchField} from "./BabyBearSelectVariants.sol";
import {BabyBearPackedField, KoalaBearPackedField} from "./BabyBearPackedFields.sol";
import {BabyBearRowMulmodUMask, KoalaBearRowMulmod} from "./Rows.sol";

library BabyFusedRow {
function _computeDim4EqWeights(uint256 p0, uint256 p1, uint256 p2, uint256 p3)
        internal
        pure
        returns (uint256 weightsPtr)
    {
        uint256 a11 = BabyBearBenchField.mul(p0, p1);
        uint256 a10 = BabyBearBenchField.sub(p0, a11);
        uint256 a01 = BabyBearBenchField.sub(p1, a11);
        uint256 a00 =
            BabyBearBenchField.sub(BabyBearBenchField.sub(BabyBearBenchField.ONE, p0), a01);
        uint256 b001 = BabyBearBenchField.mul(a00, p2);
        uint256 b000 = BabyBearBenchField.sub(a00, b001);
        uint256 b011 = BabyBearBenchField.mul(a01, p2);
        uint256 b010 = BabyBearBenchField.sub(a01, b011);
        uint256 b101 = BabyBearBenchField.mul(a10, p2);
        uint256 b100 = BabyBearBenchField.sub(a10, b101);
        uint256 b111 = BabyBearBenchField.mul(a11, p2);
        uint256 b110 = BabyBearBenchField.sub(a11, b111);

        assembly ("memory-safe") {
            weightsPtr := mload(0x40)
            mstore(0x40, add(weightsPtr, 0x200))
        }

        _storeDim4EqWeightPair(weightsPtr, 0x000, b000, 0, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x040, b001, 0, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x080, b010, 0, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x0c0, b011, 0, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x100, b100, 0, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x140, b101, 0, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x180, b110, 0, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x1c0, b111, 0, p3);
    }
function _storeDim4EqWeightPair(
        uint256 weightsPtr,
        uint256 offset,
        uint256 prefix,
        uint256 q3,
        uint256 p3
    ) private pure {
        uint256 w1 = BabyBearBenchField.mul(prefix, p3);
        uint256 w0 = BabyBearBenchField.sub(prefix, w1);
        assembly ("memory-safe") {
            mstore(add(weightsPtr, offset), w0)
            mstore(add(add(weightsPtr, offset), 0x20), w1)
        }
    }
function prepare(uint256 packedPtr) internal pure returns(uint256 ptr){assembly("memory-safe"){ptr:=mload(0x40) mstore(0x40,add(ptr,1536)) for{let i:=0} lt(i,16){i:=add(i,1)}{let a:=mload(add(packedPtr,shl(5,i))) let dst:=add(ptr,mul(i,96)) let u:=or(and(shr(224,a),0xffffffff),or(shl(51,and(shr(192,a),0xffffffff)),or(shl(102,and(shr(160,a),0xffffffff)),or(shl(153,and(shr(128,a),0xffffffff)),shl(204,and(shr(96,a),0xffffffff)))))) let low:=and(u,0xffff000000001fffe000000003fffc000000007fff800000000ffff) let high:=and(shr(16,u),0xffff000000001fffe000000003fffc000000007fff800000000ffff) mstore(dst,low) mstore(add(dst,32),high) mstore(add(dst,64),add(low,high))}}}
function hashAndFold(bytes calldata blob,uint256 offset,uint256 weightsPtr,uint256 claim,uint256 challengePtr) internal pure returns (bytes32 digest, uint256 evalValue) {
        assembly ("memory-safe") {
            let src := add(blob.offset, offset)
            let lowMask := not(sub(shl(96, 1), 1))
            function validateExt5(packed) {
                let highBitMask :=
                    0x8000000080000000800000008000000080000000000000000000000000000000
                let low31Mask := 0x7fffffff7fffffff7fffffff7fffffff7fffffff000000000000000000000000
                let bias := 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000
                if or(
                    and(packed, highBitMask),
                    and(add(and(packed, low31Mask), bias), highBitMask)
                ) {
                    mstore(0x00, 0xd53cfe5c00000000000000000000000000000000000000000000000000000000)
                    mstore(0x04, packed)
                    revert(0x00, 0x24)
                }
            }

            let invalidBits := 0
            let M := 0x78000001
            let c0 := 0
            let c1 := 0
            let c2 := 0
            function accumulate(a,w,d0,d1,d2)->e0,e1,e2{let u:=or(and(shr(224,a),0xffffffff),or(shl(51,and(shr(192,a),0xffffffff)),or(shl(102,and(shr(160,a),0xffffffff)),or(shl(153,and(shr(128,a),0xffffffff)),shl(204,and(shr(96,a),0xffffffff)))))) let low:=and(u,0xffff000000001fffe000000003fffc000000007fff800000000ffff) let high:=and(shr(16,u),0xffff000000001fffe000000003fffc000000007fff800000000ffff) e0:=add(d0,mulmod(low,mload(w),0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe)) e1:=add(d1,mulmod(high,mload(add(w,32)),0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe)) e2:=add(d2,mulmod(add(low,high),mload(add(w,64)),0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe))}
            c0,c1,c2 := accumulate(claim,challengePtr,c0,c1,c2)
            {
                let v := and(calldataload(add(src, 0)), lowMask)
                invalidBits := or(
                    invalidBits,
                    or(
                        v,
                        add(v, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000)
                    )
                )
                c0,c1,c2 := accumulate(v, add(weightsPtr, 0), c0,c1,c2)
            }
            {
                let v := and(calldataload(add(src, 20)), lowMask)
                invalidBits := or(
                    invalidBits,
                    or(
                        v,
                        add(v, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000)
                    )
                )
                c0,c1,c2 := accumulate(v, add(weightsPtr, 96), c0,c1,c2)
            }
            {
                let v := and(calldataload(add(src, 40)), lowMask)
                invalidBits := or(
                    invalidBits,
                    or(
                        v,
                        add(v, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000)
                    )
                )
                c0,c1,c2 := accumulate(v, add(weightsPtr, 192), c0,c1,c2)
            }
            {
                let v := and(calldataload(add(src, 60)), lowMask)
                invalidBits := or(
                    invalidBits,
                    or(
                        v,
                        add(v, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000)
                    )
                )
                c0,c1,c2 := accumulate(v, add(weightsPtr, 288), c0,c1,c2)
            }
            {
                let v := and(calldataload(add(src, 80)), lowMask)
                invalidBits := or(
                    invalidBits,
                    or(
                        v,
                        add(v, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000)
                    )
                )
                c0,c1,c2 := accumulate(v, add(weightsPtr, 384), c0,c1,c2)
            }
            {
                let v := and(calldataload(add(src, 100)), lowMask)
                invalidBits := or(
                    invalidBits,
                    or(
                        v,
                        add(v, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000)
                    )
                )
                c0,c1,c2 := accumulate(v, add(weightsPtr, 480), c0,c1,c2)
            }
            {
                let v := and(calldataload(add(src, 120)), lowMask)
                invalidBits := or(
                    invalidBits,
                    or(
                        v,
                        add(v, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000)
                    )
                )
                c0,c1,c2 := accumulate(v, add(weightsPtr, 576), c0,c1,c2)
            }
            {
                let v := and(calldataload(add(src, 140)), lowMask)
                invalidBits := or(
                    invalidBits,
                    or(
                        v,
                        add(v, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000)
                    )
                )
                c0,c1,c2 := accumulate(v, add(weightsPtr, 672), c0,c1,c2)
            }
            {
                let v := and(calldataload(add(src, 160)), lowMask)
                invalidBits := or(
                    invalidBits,
                    or(
                        v,
                        add(v, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000)
                    )
                )
                c0,c1,c2 := accumulate(v, add(weightsPtr, 768), c0,c1,c2)
            }
            {
                let v := and(calldataload(add(src, 180)), lowMask)
                invalidBits := or(
                    invalidBits,
                    or(
                        v,
                        add(v, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000)
                    )
                )
                c0,c1,c2 := accumulate(v, add(weightsPtr, 864), c0,c1,c2)
            }
            {
                let v := and(calldataload(add(src, 200)), lowMask)
                invalidBits := or(
                    invalidBits,
                    or(
                        v,
                        add(v, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000)
                    )
                )
                c0,c1,c2 := accumulate(v, add(weightsPtr, 960), c0,c1,c2)
            }
            {
                let v := and(calldataload(add(src, 220)), lowMask)
                invalidBits := or(
                    invalidBits,
                    or(
                        v,
                        add(v, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000)
                    )
                )
                c0,c1,c2 := accumulate(v, add(weightsPtr, 1056), c0,c1,c2)
            }
            {
                let v := and(calldataload(add(src, 240)), lowMask)
                invalidBits := or(
                    invalidBits,
                    or(
                        v,
                        add(v, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000)
                    )
                )
                c0,c1,c2 := accumulate(v, add(weightsPtr, 1152), c0,c1,c2)
            }
            {
                let v := and(calldataload(add(src, 260)), lowMask)
                invalidBits := or(
                    invalidBits,
                    or(
                        v,
                        add(v, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000)
                    )
                )
                c0,c1,c2 := accumulate(v, add(weightsPtr, 1248), c0,c1,c2)
            }
            {
                let v := and(calldataload(add(src, 280)), lowMask)
                invalidBits := or(
                    invalidBits,
                    or(
                        v,
                        add(v, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000)
                    )
                )
                c0,c1,c2 := accumulate(v, add(weightsPtr, 1344), c0,c1,c2)
            }
            {
                let v := and(calldataload(add(src, 300)), lowMask)
                invalidBits := or(
                    invalidBits,
                    or(
                        v,
                        add(v, 0x07ffffff07ffffff07ffffff07ffffff07ffffff000000000000000000000000)
                    )
                )
                c0,c1,c2 := accumulate(v, add(weightsPtr, 1440), c0,c1,c2)
            }
            if and(
                invalidBits,
                0x8000000080000000800000008000000080000000000000000000000000000000
            ) {
                for {
                    let i := 0
                } lt(i, 16) { i := add(i, 1) } {
                    validateExt5(and(calldataload(add(src, mul(i, 20))), lowMask))
                }
            }
            let cross:=sub(sub(c2,c0),c1)
let r0:=mod(add(add(and(shr(0,c0),0x7ffffffffffff),shl(16,and(shr(0,cross),0x7ffffffffffff))),shl(32,and(shr(0,c1),0x7ffffffffffff))),M)
let r1:=mod(add(add(and(shr(51,c0),0x7ffffffffffff),shl(16,and(shr(51,cross),0x7ffffffffffff))),shl(32,and(shr(51,c1),0x7ffffffffffff))),M)
let r2:=mod(add(add(and(shr(102,c0),0x7ffffffffffff),shl(16,and(shr(102,cross),0x7ffffffffffff))),shl(32,and(shr(102,c1),0x7ffffffffffff))),M)
let r3:=mod(add(add(and(shr(153,c0),0x7ffffffffffff),shl(16,and(shr(153,cross),0x7ffffffffffff))),shl(32,and(shr(153,c1),0x7ffffffffffff))),M)
let r4:=mod(add(add(and(shr(204,c0),0x7ffffffffffff),shl(16,and(shr(204,cross),0x7ffffffffffff))),shl(32,and(shr(204,c1),0x7ffffffffffff))),M)
evalValue := or(
                or(
                    or(shl(224, r0), shl(192, r1)),
                    or(shl(160, r2), shl(128, r3))
                ),
                shl(96, r4)
            )
            let ptr := mload(0x40)
            mstore8(ptr, 0)
            calldatacopy(add(ptr, 1), src, 320)
            digest := and(keccak256(ptr, 321), lowMask)
        }
    }
function _dotExt5Weights16Unpacked(
        uint256 weightsPtr,
        uint256 v0,
        uint256 v1,
        uint256 v2,
        uint256 v3,
        uint256 v4,
        uint256 v5,
        uint256 v6,
        uint256 v7,
        uint256 v8,
        uint256 v9,
        uint256 v10,
        uint256 v11,
        uint256 v12,
        uint256 v13,
        uint256 v14,
        uint256 v15, uint256 claim, uint256 challengePtr
    ) internal pure returns (uint256 out) {
        assembly ("memory-safe") {
            let M := 0x78000001
            let c0 := 0
            let c1 := 0
            let c2 := 0
            function accumulate(a,w,d0,d1,d2)->e0,e1,e2{let u:=or(and(shr(224,a),0xffffffff),or(shl(51,and(shr(192,a),0xffffffff)),or(shl(102,and(shr(160,a),0xffffffff)),or(shl(153,and(shr(128,a),0xffffffff)),shl(204,and(shr(96,a),0xffffffff)))))) let low:=and(u,0xffff000000001fffe000000003fffc000000007fff800000000ffff) let high:=and(shr(16,u),0xffff000000001fffe000000003fffc000000007fff800000000ffff) e0:=add(d0,mulmod(low,mload(w),0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe)) e1:=add(d1,mulmod(high,mload(add(w,32)),0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe)) e2:=add(d2,mulmod(add(low,high),mload(add(w,64)),0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe))}
            c0,c1,c2 := accumulate(claim,challengePtr,c0,c1,c2)
            c0,c1,c2 := accumulate(v0, add(weightsPtr, 0), c0,c1,c2)
            c0,c1,c2 := accumulate(v1, add(weightsPtr, 96), c0,c1,c2)
            c0,c1,c2 := accumulate(v2, add(weightsPtr, 192), c0,c1,c2)
            c0,c1,c2 := accumulate(v3, add(weightsPtr, 288), c0,c1,c2)
            c0,c1,c2 := accumulate(v4, add(weightsPtr, 384), c0,c1,c2)
            c0,c1,c2 := accumulate(v5, add(weightsPtr, 480), c0,c1,c2)
            c0,c1,c2 := accumulate(v6, add(weightsPtr, 576), c0,c1,c2)
            c0,c1,c2 := accumulate(v7, add(weightsPtr, 672), c0,c1,c2)
            c0,c1,c2 := accumulate(v8, add(weightsPtr, 768), c0,c1,c2)
            c0,c1,c2 := accumulate(v9, add(weightsPtr, 864), c0,c1,c2)
            c0,c1,c2 := accumulate(v10, add(weightsPtr, 960), c0,c1,c2)
            c0,c1,c2 := accumulate(v11, add(weightsPtr, 1056), c0,c1,c2)
            c0,c1,c2 := accumulate(v12, add(weightsPtr, 1152), c0,c1,c2)
            c0,c1,c2 := accumulate(v13, add(weightsPtr, 1248), c0,c1,c2)
            c0,c1,c2 := accumulate(v14, add(weightsPtr, 1344), c0,c1,c2)
            c0,c1,c2 := accumulate(v15, add(weightsPtr, 1440), c0,c1,c2)
            let cross:=sub(sub(c2,c0),c1)
let r0:=mod(add(add(and(shr(0,c0),0x7ffffffffffff),shl(16,and(shr(0,cross),0x7ffffffffffff))),shl(32,and(shr(0,c1),0x7ffffffffffff))),M)
let r1:=mod(add(add(and(shr(51,c0),0x7ffffffffffff),shl(16,and(shr(51,cross),0x7ffffffffffff))),shl(32,and(shr(51,c1),0x7ffffffffffff))),M)
let r2:=mod(add(add(and(shr(102,c0),0x7ffffffffffff),shl(16,and(shr(102,cross),0x7ffffffffffff))),shl(32,and(shr(102,c1),0x7ffffffffffff))),M)
let r3:=mod(add(add(and(shr(153,c0),0x7ffffffffffff),shl(16,and(shr(153,cross),0x7ffffffffffff))),shl(32,and(shr(153,c1),0x7ffffffffffff))),M)
let r4:=mod(add(add(and(shr(204,c0),0x7ffffffffffff),shl(16,and(shr(204,cross),0x7ffffffffffff))),shl(32,and(shr(204,c1),0x7ffffffffffff))),M)
out := or(
                or(
                    or(shl(224, r0), shl(192, r1)),
                    or(shl(160, r2), shl(128, r3))
                ),
                shl(96, r4)
            )
        }
    }
function dotArray(uint256 weightsPtr, uint256[16] memory values,uint256 claim,uint256 challengePtr)
        internal
        pure
        returns (uint256 out)
    {
        assembly ("memory-safe") {
            let M := 0x78000001
            let c0 := 0
            let c1 := 0
            let c2 := 0
            function accumulate(a,w,d0,d1,d2)->e0,e1,e2{let u:=or(and(shr(224,a),0xffffffff),or(shl(51,and(shr(192,a),0xffffffff)),or(shl(102,and(shr(160,a),0xffffffff)),or(shl(153,and(shr(128,a),0xffffffff)),shl(204,and(shr(96,a),0xffffffff)))))) let low:=and(u,0xffff000000001fffe000000003fffc000000007fff800000000ffff) let high:=and(shr(16,u),0xffff000000001fffe000000003fffc000000007fff800000000ffff) e0:=add(d0,mulmod(low,mload(w),0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe)) e1:=add(d1,mulmod(high,mload(add(w,32)),0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe)) e2:=add(d2,mulmod(add(low,high),mload(add(w,64)),0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe))}
            c0,c1,c2 := accumulate(claim,challengePtr,c0,c1,c2)
            c0,c1,c2 :=
                accumulate(mload(add(values, 0)), add(weightsPtr, 0), c0,c1,c2)
            c0,c1,c2 :=
                accumulate(mload(add(values, 32)), add(weightsPtr, 96), c0,c1,c2)
            c0,c1,c2 :=
                accumulate(mload(add(values, 64)), add(weightsPtr, 192), c0,c1,c2)
            c0,c1,c2 :=
                accumulate(mload(add(values, 96)), add(weightsPtr, 288), c0,c1,c2)
            c0,c1,c2 :=
                accumulate(mload(add(values, 128)), add(weightsPtr, 384), c0,c1,c2)
            c0,c1,c2 :=
                accumulate(mload(add(values, 160)), add(weightsPtr, 480), c0,c1,c2)
            c0,c1,c2 :=
                accumulate(mload(add(values, 192)), add(weightsPtr, 576), c0,c1,c2)
            c0,c1,c2 :=
                accumulate(mload(add(values, 224)), add(weightsPtr, 672), c0,c1,c2)
            c0,c1,c2 :=
                accumulate(mload(add(values, 256)), add(weightsPtr, 768), c0,c1,c2)
            c0,c1,c2 :=
                accumulate(mload(add(values, 288)), add(weightsPtr, 864), c0,c1,c2)
            c0,c1,c2 :=
                accumulate(mload(add(values, 320)), add(weightsPtr, 960), c0,c1,c2)
            c0,c1,c2 :=
                accumulate(mload(add(values, 352)), add(weightsPtr, 1056), c0,c1,c2)
            c0,c1,c2 :=
                accumulate(mload(add(values, 384)), add(weightsPtr, 1152), c0,c1,c2)
            c0,c1,c2 :=
                accumulate(mload(add(values, 416)), add(weightsPtr, 1248), c0,c1,c2)
            c0,c1,c2 :=
                accumulate(mload(add(values, 448)), add(weightsPtr, 1344), c0,c1,c2)
            c0,c1,c2 :=
                accumulate(mload(add(values, 480)), add(weightsPtr, 1440), c0,c1,c2)
            let cross:=sub(sub(c2,c0),c1)
let r0:=mod(add(add(and(shr(0,c0),0x7ffffffffffff),shl(16,and(shr(0,cross),0x7ffffffffffff))),shl(32,and(shr(0,c1),0x7ffffffffffff))),M)
let r1:=mod(add(add(and(shr(51,c0),0x7ffffffffffff),shl(16,and(shr(51,cross),0x7ffffffffffff))),shl(32,and(shr(51,c1),0x7ffffffffffff))),M)
let r2:=mod(add(add(and(shr(102,c0),0x7ffffffffffff),shl(16,and(shr(102,cross),0x7ffffffffffff))),shl(32,and(shr(102,c1),0x7ffffffffffff))),M)
let r3:=mod(add(add(and(shr(153,c0),0x7ffffffffffff),shl(16,and(shr(153,cross),0x7ffffffffffff))),shl(32,and(shr(153,c1),0x7ffffffffffff))),M)
let r4:=mod(add(add(and(shr(204,c0),0x7ffffffffffff),shl(16,and(shr(204,cross),0x7ffffffffffff))),shl(32,and(shr(204,c1),0x7ffffffffffff))),M)
out := or(
                or(
                    or(shl(224, r0), shl(192, r1)),
                    or(shl(160, r2), shl(128, r3))
                ),
                shl(96, r4)
            )
        }
    }
function prepareChallenge(uint256 a) internal pure returns(uint256 ptr) {assembly("memory-safe") {ptr:=mload(0x40) mstore(0x40,add(ptr,96)) let u:=or(and(shr(224,a),0xffffffff),or(shl(51,and(shr(192,a),0xffffffff)),or(shl(102,and(shr(160,a),0xffffffff)),or(shl(153,and(shr(128,a),0xffffffff)),shl(204,and(shr(96,a),0xffffffff)))))) let low:=and(u,0xffff000000001fffe000000003fffc000000007fff800000000ffff) let high:=and(shr(16,u),0xffff000000001fffe000000003fffc000000007fff800000000ffff) mstore(ptr,low) mstore(add(ptr,32),high) mstore(add(ptr,64),add(low,high))}}
}

contract BabyUnfusedRowHarness {
function batch(bytes calldata blob,uint256[4] memory point,uint256 count,uint256 claim,uint256 challenge,uint256 ood) external view returns(uint256 setupGas,uint256 rowGas,uint256 result,bytes32 digest) {
require(blob.length==count*320&&count>0,"SHAPE"); uint256 start=gasleft(); uint256 packedPtr=BabyBearRowMulmodUMask._computeDim4EqWeights(point[0],point[1],point[2],point[3]); uint256 ptr=BabyBearRowMulmodUMask.prepare(packedPtr);

setupGas=start-gasleft();start=gasleft();result=claim;
unchecked{for(uint256 i=count;i>0;--i){(bytes32 h,uint256 row)=BabyBearRowMulmodUMask._hashAndEvaluateExtension5RowDim4BlobUnpacked(blob,(i-1)*320,ptr,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0); result=BabyBearPackedField.add(BabyBearPackedField.mul(result,challenge),row); digest^=h;}} result=BabyBearPackedField.add(BabyBearPackedField.mul(result,challenge),ood);
rowGas=start-gasleft();
}
function dot(uint256[16] memory values,uint256[16] memory weights,uint256 claim,uint256 challenge) external view returns(uint256 used,uint256 result) {uint256 start=gasleft();uint256 packedPtr;assembly("memory-safe"){packedPtr:=weights}uint256 ptr=BabyBearRowMulmodUMask.prepare(packedPtr);result=BabyBearPackedField.add(BabyBearRowMulmodUMask.dotArray(ptr,values),BabyBearPackedField.mul(claim,challenge));used=start-gasleft();}
}

contract BabyFusedRowHarness {
function batch(bytes calldata blob,uint256[4] memory point,uint256 count,uint256 claim,uint256 challenge,uint256 ood) external view returns(uint256 setupGas,uint256 rowGas,uint256 result,bytes32 digest) {
require(blob.length==count*320&&count>0,"SHAPE"); uint256 start=gasleft(); uint256 packedPtr=BabyBearRowMulmodUMask._computeDim4EqWeights(point[0],point[1],point[2],point[3]); uint256 ptr=BabyBearRowMulmodUMask.prepare(packedPtr);
uint256 chPtr=BabyFusedRow.prepareChallenge(challenge);
setupGas=start-gasleft();start=gasleft();result=claim;
unchecked{for(uint256 i=count;i>0;--i){(bytes32 h,uint256 next)=BabyFusedRow.hashAndFold(blob,(i-1)*320,ptr,result,chPtr); result=next; digest^=h;}} result=BabyBearPackedField.add(BabyBearPackedField.mul(result,challenge),ood);
rowGas=start-gasleft();
}
function dot(uint256[16] memory values,uint256[16] memory weights,uint256 claim,uint256 challenge) external view returns(uint256 used,uint256 result) {uint256 start=gasleft();uint256 packedPtr;assembly("memory-safe"){packedPtr:=weights}uint256 ptr=BabyBearRowMulmodUMask.prepare(packedPtr);uint256 chPtr=BabyFusedRow.prepareChallenge(challenge);result=BabyFusedRow.dotArray(ptr,values,claim,chPtr);used=start-gasleft();}
}

library KoalaFusedRow {
function _computeDim4EqWeights(uint256 p0, uint256 p1, uint256 p2, uint256 p3)
        internal
        pure
        returns (uint256 weightsPtr)
    {
        uint256 a11 = KoalaBearExt5.mul(p0, p1);
        uint256 a10 = KoalaBearExt5.sub(p0, a11);
        uint256 a01 = KoalaBearExt5.sub(p1, a11);
        uint256 a00 = KoalaBearExt5.sub(KoalaBearExt5.sub(KoalaBearExt5.ONE, p0), a01);
        uint256 b001 = KoalaBearExt5.mul(a00, p2);
        uint256 b000 = KoalaBearExt5.sub(a00, b001);
        uint256 b011 = KoalaBearExt5.mul(a01, p2);
        uint256 b010 = KoalaBearExt5.sub(a01, b011);
        uint256 b101 = KoalaBearExt5.mul(a10, p2);
        uint256 b100 = KoalaBearExt5.sub(a10, b101);
        uint256 b111 = KoalaBearExt5.mul(a11, p2);
        uint256 b110 = KoalaBearExt5.sub(a11, b111);

        assembly ("memory-safe") {
            weightsPtr := mload(0x40)
            mstore(0x40, add(weightsPtr, 0x200))
        }

        _storeDim4EqWeightPair(weightsPtr, 0x000, b000, 0, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x040, b001, 0, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x080, b010, 0, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x0c0, b011, 0, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x100, b100, 0, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x140, b101, 0, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x180, b110, 0, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x1c0, b111, 0, p3);
    }
function _storeDim4EqWeightPair(
        uint256 weightsPtr,
        uint256 offset,
        uint256 prefix,
        uint256 q3,
        uint256 p3
    ) private pure {
        uint256 w1 = KoalaBearExt5.mul(prefix, p3);
        uint256 w0 = KoalaBearExt5.sub(prefix, w1);
        assembly ("memory-safe") {
            mstore(add(weightsPtr, offset), w0)
            mstore(add(add(weightsPtr, offset), 0x20), w1)
        }
    }
function prepare(uint256 packedPtr) internal pure returns(uint256 ptr){assembly("memory-safe"){ptr:=mload(0x40) mstore(0x40,add(ptr,1536)) for{let i:=0} lt(i,16){i:=add(i,1)}{let a:=mload(add(packedPtr,shl(5,i))) let dst:=add(ptr,mul(i,96)) let u:=or(and(shr(224,a),0xffffffff),or(shl(51,and(shr(192,a),0xffffffff)),or(shl(102,and(shr(160,a),0xffffffff)),or(shl(153,and(shr(128,a),0xffffffff)),shl(204,and(shr(96,a),0xffffffff)))))) let low:=and(u,0xffff000000001fffe000000003fffc000000007fff800000000ffff) let high:=and(shr(16,u),0xffff000000001fffe000000003fffc000000007fff800000000ffff) mstore(dst,low) mstore(add(dst,32),high) mstore(add(dst,64),add(low,high))}}}
function hashAndFold(bytes calldata blob,uint256 offset,uint256 weightsPtr,uint256 claim,uint256 challengePtr) internal pure returns (bytes32 digest, uint256 evalValue) {
        uint256 src;
        uint256 v0;
        uint256 v1;
        uint256 v2;
        uint256 v3;
        uint256 v4;
        uint256 v5;
        uint256 v6;
        uint256 v7;
        uint256 v8;
        uint256 v9;
        uint256 v10;
        uint256 v11;
        uint256 v12;
        uint256 v13;
        uint256 v14;
        uint256 v15;
        assembly ("memory-safe") {
            src := add(blob.offset, offset)
            let lowMask := not(sub(shl(96, 1), 1))
            let ptr := mload(0x40)
            v0 := and(calldataload(src), lowMask)
            v1 := and(calldataload(add(src, 20)), lowMask)
            v2 := and(calldataload(add(src, 40)), lowMask)
            v3 := and(calldataload(add(src, 60)), lowMask)
            v4 := and(calldataload(add(src, 80)), lowMask)
            v5 := and(calldataload(add(src, 100)), lowMask)
            v6 := and(calldataload(add(src, 120)), lowMask)
            v7 := and(calldataload(add(src, 140)), lowMask)
            v8 := and(calldataload(add(src, 160)), lowMask)
            v9 := and(calldataload(add(src, 180)), lowMask)
            v10 := and(calldataload(add(src, 200)), lowMask)
            v11 := and(calldataload(add(src, 220)), lowMask)
            v12 := and(calldataload(add(src, 240)), lowMask)
            v13 := and(calldataload(add(src, 260)), lowMask)
            v14 := and(calldataload(add(src, 280)), lowMask)
            v15 := and(calldataload(add(src, 300)), lowMask)

            function validateExt5(packed) {
                let highBitMask :=
                    0x8000000080000000800000008000000080000000000000000000000000000000
                let low31Mask := 0x7fffffff7fffffff7fffffff7fffffff7fffffff000000000000000000000000
                let bias := 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000
                if or(
                    and(packed, highBitMask),
                    and(add(and(packed, low31Mask), bias), highBitMask)
                ) {
                    mstore(0x00, 0xd53cfe5c00000000000000000000000000000000000000000000000000000000)
                    mstore(0x04, packed)
                    revert(0x00, 0x24)
                }
            }

            let invalidBits := 0
            invalidBits := or(
                invalidBits,
                or(v0, add(v0, 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000))
            )
            invalidBits := or(
                invalidBits,
                or(v1, add(v1, 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000))
            )
            invalidBits := or(
                invalidBits,
                or(v2, add(v2, 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000))
            )
            invalidBits := or(
                invalidBits,
                or(v3, add(v3, 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000))
            )
            invalidBits := or(
                invalidBits,
                or(v4, add(v4, 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000))
            )
            invalidBits := or(
                invalidBits,
                or(v5, add(v5, 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000))
            )
            invalidBits := or(
                invalidBits,
                or(v6, add(v6, 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000))
            )
            invalidBits := or(
                invalidBits,
                or(v7, add(v7, 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000))
            )
            invalidBits := or(
                invalidBits,
                or(v8, add(v8, 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000))
            )
            invalidBits := or(
                invalidBits,
                or(v9, add(v9, 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000))
            )
            invalidBits := or(
                invalidBits,
                or(
                    v10,
                    add(v10, 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000)
                )
            )
            invalidBits := or(
                invalidBits,
                or(
                    v11,
                    add(v11, 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000)
                )
            )
            invalidBits := or(
                invalidBits,
                or(
                    v12,
                    add(v12, 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000)
                )
            )
            invalidBits := or(
                invalidBits,
                or(
                    v13,
                    add(v13, 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000)
                )
            )
            invalidBits := or(
                invalidBits,
                or(
                    v14,
                    add(v14, 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000)
                )
            )
            invalidBits := or(
                invalidBits,
                or(
                    v15,
                    add(v15, 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000)
                )
            )
            if and(
                invalidBits,
                0x8000000080000000800000008000000080000000000000000000000000000000
            ) {
                validateExt5(v0)
                validateExt5(v1)
                validateExt5(v2)
                validateExt5(v3)
                validateExt5(v4)
                validateExt5(v5)
                validateExt5(v6)
                validateExt5(v7)
                validateExt5(v8)
                validateExt5(v9)
                validateExt5(v10)
                validateExt5(v11)
                validateExt5(v12)
                validateExt5(v13)
                validateExt5(v14)
                validateExt5(v15)
            }

            mstore8(ptr, 0x00)
            calldatacopy(add(ptr, 0x01), src, 320)
            digest := and(keccak256(ptr, 321), lowMask)
        }


        evalValue = _dotExt5Weights16Unpacked(
            weightsPtr, v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, claim, challengePtr
        );
    }
function _dotExt5Weights16Unpacked(
        uint256 weightsPtr,
        uint256 v0,
        uint256 v1,
        uint256 v2,
        uint256 v3,
        uint256 v4,
        uint256 v5,
        uint256 v6,
        uint256 v7,
        uint256 v8,
        uint256 v9,
        uint256 v10,
        uint256 v11,
        uint256 v12,
        uint256 v13,
        uint256 v14,
        uint256 v15, uint256 claim, uint256 challengePtr
    ) internal pure returns (uint256 out) {
        assembly ("memory-safe") {
            let M := 0x7f000001
            let c0 := 0
            let c1 := 0
            let c2 := 0
            function accumulate(a,w,d0,d1,d2)->e0,e1,e2{let u:=or(and(shr(224,a),0xffffffff),or(shl(51,and(shr(192,a),0xffffffff)),or(shl(102,and(shr(160,a),0xffffffff)),or(shl(153,and(shr(128,a),0xffffffff)),shl(204,and(shr(96,a),0xffffffff)))))) let low:=and(u,0xffff000000001fffe000000003fffc000000007fff800000000ffff) let high:=and(shr(16,u),0xffff000000001fffe000000003fffc000000007fff800000000ffff) e0:=addmod(d0,mulmod(low,mload(w),0x800000000000000000000000000000000000003fffffffffffffffffffffffff),0x800000000000000000000000000000000000003fffffffffffffffffffffffff) e1:=addmod(d1,mulmod(high,mload(add(w,32)),0x800000000000000000000000000000000000003fffffffffffffffffffffffff),0x800000000000000000000000000000000000003fffffffffffffffffffffffff) e2:=addmod(d2,mulmod(add(low,high),mload(add(w,64)),0x800000000000000000000000000000000000003fffffffffffffffffffffffff),0x800000000000000000000000000000000000003fffffffffffffffffffffffff)}
            c0,c1,c2 := accumulate(claim,challengePtr,c0,c1,c2)
            c0,c1,c2 :=
                accumulate(v0, add(weightsPtr, 0), c0,c1,c2)
            c0,c1,c2 :=
                accumulate(v1, add(weightsPtr, 96), c0,c1,c2)
            c0,c1,c2 :=
                accumulate(v2, add(weightsPtr, 192), c0,c1,c2)
            c0,c1,c2 :=
                accumulate(v3, add(weightsPtr, 288), c0,c1,c2)
            c0,c1,c2 :=
                accumulate(v4, add(weightsPtr, 384), c0,c1,c2)
            c0,c1,c2 :=
                accumulate(v5, add(weightsPtr, 480), c0,c1,c2)
            c0,c1,c2 :=
                accumulate(v6, add(weightsPtr, 576), c0,c1,c2)
            c0,c1,c2 :=
                accumulate(v7, add(weightsPtr, 672), c0,c1,c2)
            c0,c1,c2 :=
                accumulate(v8, add(weightsPtr, 768), c0,c1,c2)
            c0,c1,c2 :=
                accumulate(v9, add(weightsPtr, 864), c0,c1,c2)
            c0,c1,c2 :=
                accumulate(v10, add(weightsPtr, 960), c0,c1,c2)
            c0,c1,c2 :=
                accumulate(v11, add(weightsPtr, 1056), c0,c1,c2)
            c0,c1,c2 :=
                accumulate(v12, add(weightsPtr, 1152), c0,c1,c2)
            c0,c1,c2 :=
                accumulate(v13, add(weightsPtr, 1248), c0,c1,c2)
            c0,c1,c2 :=
                accumulate(v14, add(weightsPtr, 1344), c0,c1,c2)
            c0,c1,c2 :=
                accumulate(v15, add(weightsPtr, 1440), c0,c1,c2)
            let bias := shl(80, M)
c0:=addmod(c0,0x40000000000008000000000001000000000000200000000000040000000000,0x800000000000000000000000000000000000003fffffffffffffffffffffffff)
c1:=addmod(c1,0x40000000000008000000000001000000000000200000000000040000000000,0x800000000000000000000000000000000000003fffffffffffffffffffffffff)
c2:=addmod(c2,0x40000000000008000000000001000000000000200000000000040000000000,0x800000000000000000000000000000000000003fffffffffffffffffffffffff)
let l0:=and(shr(0,c0),0x7ffffffffffff) let h0:=and(shr(0,c1),0x7ffffffffffff) let s0:=and(shr(0,c2),0x7ffffffffffff)
let r0:=mod(sub(add(add(add(l0,shl(16,s0)),shl(32,h0)),0x7efffc0103fffc0000000000),shl(16,add(l0,h0))),M)
let l1:=and(shr(51,c0),0x7ffffffffffff) let h1:=and(shr(51,c1),0x7ffffffffffff) let s1:=and(shr(51,c2),0x7ffffffffffff)
let r1:=mod(sub(add(add(add(l1,shl(16,s1)),shl(32,h1)),0x7efffc0103fffc0000000000),shl(16,add(l1,h1))),M)
let l2:=and(shr(102,c0),0x7ffffffffffff) let h2:=and(shr(102,c1),0x7ffffffffffff) let s2:=and(shr(102,c2),0x7ffffffffffff)
let r2:=mod(sub(add(add(add(l2,shl(16,s2)),shl(32,h2)),0x7efffc0103fffc0000000000),shl(16,add(l2,h2))),M)
let l3:=and(shr(153,c0),0x7ffffffffffff) let h3:=and(shr(153,c1),0x7ffffffffffff) let s3:=and(shr(153,c2),0x7ffffffffffff)
let r3:=mod(sub(add(add(add(l3,shl(16,s3)),shl(32,h3)),0x7efffc0103fffc0000000000),shl(16,add(l3,h3))),M)
let l4:=and(shr(204,c0),0x7ffffffffffff) let h4:=and(shr(204,c1),0x7ffffffffffff) let s4:=and(shr(204,c2),0x7ffffffffffff)
let r4:=mod(sub(add(add(add(l4,shl(16,s4)),shl(32,h4)),0x7efffc0103fffc0000000000),shl(16,add(l4,h4))),M)
out:=or(shl(224,r0),or(shl(192,r1),or(shl(160,r2),or(shl(128,r3),shl(96,r4)))))
}
}
function dotArray(uint256 weightsPtr, uint256[16] memory values,uint256 claim,uint256 challengePtr)
        internal
        pure
        returns (uint256 out)
    {
        assembly ("memory-safe") {
            let M := 0x7f000001
            let c0 := 0
            let c1 := 0
            let c2 := 0
            function accumulate(a,w,d0,d1,d2)->e0,e1,e2{let u:=or(and(shr(224,a),0xffffffff),or(shl(51,and(shr(192,a),0xffffffff)),or(shl(102,and(shr(160,a),0xffffffff)),or(shl(153,and(shr(128,a),0xffffffff)),shl(204,and(shr(96,a),0xffffffff)))))) let low:=and(u,0xffff000000001fffe000000003fffc000000007fff800000000ffff) let high:=and(shr(16,u),0xffff000000001fffe000000003fffc000000007fff800000000ffff) e0:=addmod(d0,mulmod(low,mload(w),0x800000000000000000000000000000000000003fffffffffffffffffffffffff),0x800000000000000000000000000000000000003fffffffffffffffffffffffff) e1:=addmod(d1,mulmod(high,mload(add(w,32)),0x800000000000000000000000000000000000003fffffffffffffffffffffffff),0x800000000000000000000000000000000000003fffffffffffffffffffffffff) e2:=addmod(d2,mulmod(add(low,high),mload(add(w,64)),0x800000000000000000000000000000000000003fffffffffffffffffffffffff),0x800000000000000000000000000000000000003fffffffffffffffffffffffff)}
            c0,c1,c2 := accumulate(claim,challengePtr,c0,c1,c2)
            c0,c1,c2 :=
                accumulate(
                mload(add(values, 0)),
                add(weightsPtr, 0),
                c0,c1,c2
            )
            c0,c1,c2 :=
                accumulate(
                mload(add(values, 32)),
                add(weightsPtr, 96),
                c0,c1,c2
            )
            c0,c1,c2 :=
                accumulate(
                mload(add(values, 64)),
                add(weightsPtr, 192),
                c0,c1,c2
            )
            c0,c1,c2 :=
                accumulate(
                mload(add(values, 96)),
                add(weightsPtr, 288),
                c0,c1,c2
            )
            c0,c1,c2 :=
                accumulate(
                mload(add(values, 128)),
                add(weightsPtr, 384),
                c0,c1,c2
            )
            c0,c1,c2 :=
                accumulate(
                mload(add(values, 160)),
                add(weightsPtr, 480),
                c0,c1,c2
            )
            c0,c1,c2 :=
                accumulate(
                mload(add(values, 192)),
                add(weightsPtr, 576),
                c0,c1,c2
            )
            c0,c1,c2 :=
                accumulate(
                mload(add(values, 224)),
                add(weightsPtr, 672),
                c0,c1,c2
            )
            c0,c1,c2 :=
                accumulate(
                mload(add(values, 256)),
                add(weightsPtr, 768),
                c0,c1,c2
            )
            c0,c1,c2 :=
                accumulate(
                mload(add(values, 288)),
                add(weightsPtr, 864),
                c0,c1,c2
            )
            c0,c1,c2 :=
                accumulate(
                mload(add(values, 320)),
                add(weightsPtr, 960),
                c0,c1,c2
            )
            c0,c1,c2 :=
                accumulate(
                mload(add(values, 352)),
                add(weightsPtr, 1056),
                c0,c1,c2
            )
            c0,c1,c2 :=
                accumulate(
                mload(add(values, 384)),
                add(weightsPtr, 1152),
                c0,c1,c2
            )
            c0,c1,c2 :=
                accumulate(
                mload(add(values, 416)),
                add(weightsPtr, 1248),
                c0,c1,c2
            )
            c0,c1,c2 :=
                accumulate(
                mload(add(values, 448)),
                add(weightsPtr, 1344),
                c0,c1,c2
            )
            c0,c1,c2 :=
                accumulate(
                mload(add(values, 480)),
                add(weightsPtr, 1440),
                c0,c1,c2
            )
            let bias := shl(80, M)
c0:=addmod(c0,0x40000000000008000000000001000000000000200000000000040000000000,0x800000000000000000000000000000000000003fffffffffffffffffffffffff)
c1:=addmod(c1,0x40000000000008000000000001000000000000200000000000040000000000,0x800000000000000000000000000000000000003fffffffffffffffffffffffff)
c2:=addmod(c2,0x40000000000008000000000001000000000000200000000000040000000000,0x800000000000000000000000000000000000003fffffffffffffffffffffffff)
let l0:=and(shr(0,c0),0x7ffffffffffff) let h0:=and(shr(0,c1),0x7ffffffffffff) let s0:=and(shr(0,c2),0x7ffffffffffff)
let r0:=mod(sub(add(add(add(l0,shl(16,s0)),shl(32,h0)),0x7efffc0103fffc0000000000),shl(16,add(l0,h0))),M)
let l1:=and(shr(51,c0),0x7ffffffffffff) let h1:=and(shr(51,c1),0x7ffffffffffff) let s1:=and(shr(51,c2),0x7ffffffffffff)
let r1:=mod(sub(add(add(add(l1,shl(16,s1)),shl(32,h1)),0x7efffc0103fffc0000000000),shl(16,add(l1,h1))),M)
let l2:=and(shr(102,c0),0x7ffffffffffff) let h2:=and(shr(102,c1),0x7ffffffffffff) let s2:=and(shr(102,c2),0x7ffffffffffff)
let r2:=mod(sub(add(add(add(l2,shl(16,s2)),shl(32,h2)),0x7efffc0103fffc0000000000),shl(16,add(l2,h2))),M)
let l3:=and(shr(153,c0),0x7ffffffffffff) let h3:=and(shr(153,c1),0x7ffffffffffff) let s3:=and(shr(153,c2),0x7ffffffffffff)
let r3:=mod(sub(add(add(add(l3,shl(16,s3)),shl(32,h3)),0x7efffc0103fffc0000000000),shl(16,add(l3,h3))),M)
let l4:=and(shr(204,c0),0x7ffffffffffff) let h4:=and(shr(204,c1),0x7ffffffffffff) let s4:=and(shr(204,c2),0x7ffffffffffff)
let r4:=mod(sub(add(add(add(l4,shl(16,s4)),shl(32,h4)),0x7efffc0103fffc0000000000),shl(16,add(l4,h4))),M)
out:=or(shl(224,r0),or(shl(192,r1),or(shl(160,r2),or(shl(128,r3),shl(96,r4)))))
}
}
function prepareChallenge(uint256 a) internal pure returns(uint256 ptr) {assembly("memory-safe") {ptr:=mload(0x40) mstore(0x40,add(ptr,96)) let u:=or(and(shr(224,a),0xffffffff),or(shl(51,and(shr(192,a),0xffffffff)),or(shl(102,and(shr(160,a),0xffffffff)),or(shl(153,and(shr(128,a),0xffffffff)),shl(204,and(shr(96,a),0xffffffff)))))) let low:=and(u,0xffff000000001fffe000000003fffc000000007fff800000000ffff) let high:=and(shr(16,u),0xffff000000001fffe000000003fffc000000007fff800000000ffff) mstore(ptr,low) mstore(add(ptr,32),high) mstore(add(ptr,64),add(low,high))}}
}

contract KoalaUnfusedRowHarness {
function batch(bytes calldata blob,uint256[4] memory point,uint256 count,uint256 claim,uint256 challenge,uint256 ood) external view returns(uint256 setupGas,uint256 rowGas,uint256 result,bytes32 digest) {
require(blob.length==count*320&&count>0,"SHAPE"); uint256 start=gasleft(); uint256 packedPtr=KoalaBearRowMulmod._computeDim4EqWeights(point[0],point[1],point[2],point[3]); uint256 ptr=KoalaBearRowMulmod.prepare(packedPtr);

setupGas=start-gasleft();start=gasleft();result=claim;
unchecked{for(uint256 i=count;i>0;--i){(bytes32 h,uint256 row)=KoalaBearRowMulmod._hashAndEvaluateExtension5RowDim4BlobUnpacked(blob,(i-1)*320,ptr,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0); result=KoalaBearPackedField.add(KoalaBearPackedField.mul(result,challenge),row); digest^=h;}} result=KoalaBearPackedField.add(KoalaBearPackedField.mul(result,challenge),ood);
rowGas=start-gasleft();
}
function dot(uint256[16] memory values,uint256[16] memory weights,uint256 claim,uint256 challenge) external view returns(uint256 used,uint256 result) {uint256 start=gasleft();uint256 packedPtr;assembly("memory-safe"){packedPtr:=weights}uint256 ptr=KoalaBearRowMulmod.prepare(packedPtr);result=KoalaBearPackedField.add(KoalaBearRowMulmod.dotArray(ptr,values),KoalaBearPackedField.mul(claim,challenge));used=start-gasleft();}
}

contract KoalaFusedRowHarness {
function batch(bytes calldata blob,uint256[4] memory point,uint256 count,uint256 claim,uint256 challenge,uint256 ood) external view returns(uint256 setupGas,uint256 rowGas,uint256 result,bytes32 digest) {
require(blob.length==count*320&&count>0,"SHAPE"); uint256 start=gasleft(); uint256 packedPtr=KoalaBearRowMulmod._computeDim4EqWeights(point[0],point[1],point[2],point[3]); uint256 ptr=KoalaBearRowMulmod.prepare(packedPtr);
uint256 chPtr=KoalaFusedRow.prepareChallenge(challenge);
setupGas=start-gasleft();start=gasleft();result=claim;
unchecked{for(uint256 i=count;i>0;--i){(bytes32 h,uint256 next)=KoalaFusedRow.hashAndFold(blob,(i-1)*320,ptr,result,chPtr); result=next; digest^=h;}} result=KoalaBearPackedField.add(KoalaBearPackedField.mul(result,challenge),ood);
rowGas=start-gasleft();
}
function dot(uint256[16] memory values,uint256[16] memory weights,uint256 claim,uint256 challenge) external view returns(uint256 used,uint256 result) {uint256 start=gasleft();uint256 packedPtr;assembly("memory-safe"){packedPtr:=weights}uint256 ptr=KoalaBearRowMulmod.prepare(packedPtr);uint256 chPtr=KoalaFusedRow.prepareChallenge(challenge);result=KoalaFusedRow.dotArray(ptr,values,claim,chPtr);used=start-gasleft();}
}
