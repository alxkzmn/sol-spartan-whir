// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { LeanVmPoseidonAirConstants as C } from "./LeanVmPoseidonAirConstants.sol";

/// Poseidon1 over KoalaBear: width 16, cubic S-box, 8 full and 20 partial rounds.
library LeanVmPoseidon1 {
    uint256 internal constant MODULUS = 2_130_706_433;
    error NonCanonicalField();
    error InvalidLeafLength();

    function permute(uint256[16] memory state) internal pure {
        uint256 free;
        assembly ("memory-safe") { free := mload(0x40) }
        bytes memory constants = C.values();
        _permute(state, constants);
        // Only the caller-owned state survives; constants and scratch are temporary.
        assembly ("memory-safe") { mstore(0x40, free) }
    }

    function _permute(uint256[16] memory state, bytes memory constants) private pure {
        assembly ("memory-safe") {
            function constant(data, index) -> value {
                value := shr(224, mload(add(add(data, 32), shl(2, index))))
            }
            function fullRounds(roundState, roundConstants, start) {
                let p := 2130706433
                // No allocation occurs inside this assembly block. Scratch does not escape.
                let scratch := mload(0x40)
                for { let round := 0 } lt(round, 4) { round := add(round, 1) } {
                    let offset := add(start, shl(4, round))
                    for { let i := 0 } lt(i, 16) { i := add(i, 1) } {
                        let slot := add(roundState, shl(5, i))
                        // ADDMOD also normalizes arbitrary uint256 inputs in the first round.
                        let x := addmod(mload(slot), constant(roundConstants, add(offset, i)), p)
                        // x < p: the unreduced cube is below 2^93.
                        mstore(slot, mod(mul(mul(x, x), x), p))
                    }
                    mstore(add(scratch, 0), mod(add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(mload(add(roundState, 0)), mload(add(roundState, 32))), mul(mload(add(roundState, 64)), 51)), mload(add(roundState, 96))), mul(mload(add(roundState, 128)), 11)), mul(mload(add(roundState, 160)), 17)), mul(mload(add(roundState, 192)), 2)), mload(add(roundState, 224))), mul(mload(add(roundState, 256)), 101)), mul(mload(add(roundState, 288)), 63)), mul(mload(add(roundState, 320)), 15)), mul(mload(add(roundState, 352)), 2)), mul(mload(add(roundState, 384)), 67)), mul(mload(add(roundState, 416)), 22)), mul(mload(add(roundState, 448)), 13)), mul(mload(add(roundState, 480)), 3)), p))
                    mstore(add(scratch, 32), mod(add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(mul(mload(add(roundState, 0)), 3), mload(add(roundState, 32))), mload(add(roundState, 64))), mul(mload(add(roundState, 96)), 51)), mload(add(roundState, 128))), mul(mload(add(roundState, 160)), 11)), mul(mload(add(roundState, 192)), 17)), mul(mload(add(roundState, 224)), 2)), mload(add(roundState, 256))), mul(mload(add(roundState, 288)), 101)), mul(mload(add(roundState, 320)), 63)), mul(mload(add(roundState, 352)), 15)), mul(mload(add(roundState, 384)), 2)), mul(mload(add(roundState, 416)), 67)), mul(mload(add(roundState, 448)), 22)), mul(mload(add(roundState, 480)), 13)), p))
                    mstore(add(scratch, 64), mod(add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(mul(mload(add(roundState, 0)), 13), mul(mload(add(roundState, 32)), 3)), mload(add(roundState, 64))), mload(add(roundState, 96))), mul(mload(add(roundState, 128)), 51)), mload(add(roundState, 160))), mul(mload(add(roundState, 192)), 11)), mul(mload(add(roundState, 224)), 17)), mul(mload(add(roundState, 256)), 2)), mload(add(roundState, 288))), mul(mload(add(roundState, 320)), 101)), mul(mload(add(roundState, 352)), 63)), mul(mload(add(roundState, 384)), 15)), mul(mload(add(roundState, 416)), 2)), mul(mload(add(roundState, 448)), 67)), mul(mload(add(roundState, 480)), 22)), p))
                    mstore(add(scratch, 96), mod(add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(mul(mload(add(roundState, 0)), 22), mul(mload(add(roundState, 32)), 13)), mul(mload(add(roundState, 64)), 3)), mload(add(roundState, 96))), mload(add(roundState, 128))), mul(mload(add(roundState, 160)), 51)), mload(add(roundState, 192))), mul(mload(add(roundState, 224)), 11)), mul(mload(add(roundState, 256)), 17)), mul(mload(add(roundState, 288)), 2)), mload(add(roundState, 320))), mul(mload(add(roundState, 352)), 101)), mul(mload(add(roundState, 384)), 63)), mul(mload(add(roundState, 416)), 15)), mul(mload(add(roundState, 448)), 2)), mul(mload(add(roundState, 480)), 67)), p))
                    mstore(add(scratch, 128), mod(add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(mul(mload(add(roundState, 0)), 67), mul(mload(add(roundState, 32)), 22)), mul(mload(add(roundState, 64)), 13)), mul(mload(add(roundState, 96)), 3)), mload(add(roundState, 128))), mload(add(roundState, 160))), mul(mload(add(roundState, 192)), 51)), mload(add(roundState, 224))), mul(mload(add(roundState, 256)), 11)), mul(mload(add(roundState, 288)), 17)), mul(mload(add(roundState, 320)), 2)), mload(add(roundState, 352))), mul(mload(add(roundState, 384)), 101)), mul(mload(add(roundState, 416)), 63)), mul(mload(add(roundState, 448)), 15)), mul(mload(add(roundState, 480)), 2)), p))
                    mstore(add(scratch, 160), mod(add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(mul(mload(add(roundState, 0)), 2), mul(mload(add(roundState, 32)), 67)), mul(mload(add(roundState, 64)), 22)), mul(mload(add(roundState, 96)), 13)), mul(mload(add(roundState, 128)), 3)), mload(add(roundState, 160))), mload(add(roundState, 192))), mul(mload(add(roundState, 224)), 51)), mload(add(roundState, 256))), mul(mload(add(roundState, 288)), 11)), mul(mload(add(roundState, 320)), 17)), mul(mload(add(roundState, 352)), 2)), mload(add(roundState, 384))), mul(mload(add(roundState, 416)), 101)), mul(mload(add(roundState, 448)), 63)), mul(mload(add(roundState, 480)), 15)), p))
                    mstore(add(scratch, 192), mod(add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(mul(mload(add(roundState, 0)), 15), mul(mload(add(roundState, 32)), 2)), mul(mload(add(roundState, 64)), 67)), mul(mload(add(roundState, 96)), 22)), mul(mload(add(roundState, 128)), 13)), mul(mload(add(roundState, 160)), 3)), mload(add(roundState, 192))), mload(add(roundState, 224))), mul(mload(add(roundState, 256)), 51)), mload(add(roundState, 288))), mul(mload(add(roundState, 320)), 11)), mul(mload(add(roundState, 352)), 17)), mul(mload(add(roundState, 384)), 2)), mload(add(roundState, 416))), mul(mload(add(roundState, 448)), 101)), mul(mload(add(roundState, 480)), 63)), p))
                    mstore(add(scratch, 224), mod(add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(mul(mload(add(roundState, 0)), 63), mul(mload(add(roundState, 32)), 15)), mul(mload(add(roundState, 64)), 2)), mul(mload(add(roundState, 96)), 67)), mul(mload(add(roundState, 128)), 22)), mul(mload(add(roundState, 160)), 13)), mul(mload(add(roundState, 192)), 3)), mload(add(roundState, 224))), mload(add(roundState, 256))), mul(mload(add(roundState, 288)), 51)), mload(add(roundState, 320))), mul(mload(add(roundState, 352)), 11)), mul(mload(add(roundState, 384)), 17)), mul(mload(add(roundState, 416)), 2)), mload(add(roundState, 448))), mul(mload(add(roundState, 480)), 101)), p))
                    mstore(add(scratch, 256), mod(add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(mul(mload(add(roundState, 0)), 101), mul(mload(add(roundState, 32)), 63)), mul(mload(add(roundState, 64)), 15)), mul(mload(add(roundState, 96)), 2)), mul(mload(add(roundState, 128)), 67)), mul(mload(add(roundState, 160)), 22)), mul(mload(add(roundState, 192)), 13)), mul(mload(add(roundState, 224)), 3)), mload(add(roundState, 256))), mload(add(roundState, 288))), mul(mload(add(roundState, 320)), 51)), mload(add(roundState, 352))), mul(mload(add(roundState, 384)), 11)), mul(mload(add(roundState, 416)), 17)), mul(mload(add(roundState, 448)), 2)), mload(add(roundState, 480))), p))
                    mstore(add(scratch, 288), mod(add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(mload(add(roundState, 0)), mul(mload(add(roundState, 32)), 101)), mul(mload(add(roundState, 64)), 63)), mul(mload(add(roundState, 96)), 15)), mul(mload(add(roundState, 128)), 2)), mul(mload(add(roundState, 160)), 67)), mul(mload(add(roundState, 192)), 22)), mul(mload(add(roundState, 224)), 13)), mul(mload(add(roundState, 256)), 3)), mload(add(roundState, 288))), mload(add(roundState, 320))), mul(mload(add(roundState, 352)), 51)), mload(add(roundState, 384))), mul(mload(add(roundState, 416)), 11)), mul(mload(add(roundState, 448)), 17)), mul(mload(add(roundState, 480)), 2)), p))
                    mstore(add(scratch, 320), mod(add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(mul(mload(add(roundState, 0)), 2), mload(add(roundState, 32))), mul(mload(add(roundState, 64)), 101)), mul(mload(add(roundState, 96)), 63)), mul(mload(add(roundState, 128)), 15)), mul(mload(add(roundState, 160)), 2)), mul(mload(add(roundState, 192)), 67)), mul(mload(add(roundState, 224)), 22)), mul(mload(add(roundState, 256)), 13)), mul(mload(add(roundState, 288)), 3)), mload(add(roundState, 320))), mload(add(roundState, 352))), mul(mload(add(roundState, 384)), 51)), mload(add(roundState, 416))), mul(mload(add(roundState, 448)), 11)), mul(mload(add(roundState, 480)), 17)), p))
                    mstore(add(scratch, 352), mod(add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(mul(mload(add(roundState, 0)), 17), mul(mload(add(roundState, 32)), 2)), mload(add(roundState, 64))), mul(mload(add(roundState, 96)), 101)), mul(mload(add(roundState, 128)), 63)), mul(mload(add(roundState, 160)), 15)), mul(mload(add(roundState, 192)), 2)), mul(mload(add(roundState, 224)), 67)), mul(mload(add(roundState, 256)), 22)), mul(mload(add(roundState, 288)), 13)), mul(mload(add(roundState, 320)), 3)), mload(add(roundState, 352))), mload(add(roundState, 384))), mul(mload(add(roundState, 416)), 51)), mload(add(roundState, 448))), mul(mload(add(roundState, 480)), 11)), p))
                    mstore(add(scratch, 384), mod(add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(mul(mload(add(roundState, 0)), 11), mul(mload(add(roundState, 32)), 17)), mul(mload(add(roundState, 64)), 2)), mload(add(roundState, 96))), mul(mload(add(roundState, 128)), 101)), mul(mload(add(roundState, 160)), 63)), mul(mload(add(roundState, 192)), 15)), mul(mload(add(roundState, 224)), 2)), mul(mload(add(roundState, 256)), 67)), mul(mload(add(roundState, 288)), 22)), mul(mload(add(roundState, 320)), 13)), mul(mload(add(roundState, 352)), 3)), mload(add(roundState, 384))), mload(add(roundState, 416))), mul(mload(add(roundState, 448)), 51)), mload(add(roundState, 480))), p))
                    mstore(add(scratch, 416), mod(add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(mload(add(roundState, 0)), mul(mload(add(roundState, 32)), 11)), mul(mload(add(roundState, 64)), 17)), mul(mload(add(roundState, 96)), 2)), mload(add(roundState, 128))), mul(mload(add(roundState, 160)), 101)), mul(mload(add(roundState, 192)), 63)), mul(mload(add(roundState, 224)), 15)), mul(mload(add(roundState, 256)), 2)), mul(mload(add(roundState, 288)), 67)), mul(mload(add(roundState, 320)), 22)), mul(mload(add(roundState, 352)), 13)), mul(mload(add(roundState, 384)), 3)), mload(add(roundState, 416))), mload(add(roundState, 448))), mul(mload(add(roundState, 480)), 51)), p))
                    mstore(add(scratch, 448), mod(add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(mul(mload(add(roundState, 0)), 51), mload(add(roundState, 32))), mul(mload(add(roundState, 64)), 11)), mul(mload(add(roundState, 96)), 17)), mul(mload(add(roundState, 128)), 2)), mload(add(roundState, 160))), mul(mload(add(roundState, 192)), 101)), mul(mload(add(roundState, 224)), 63)), mul(mload(add(roundState, 256)), 15)), mul(mload(add(roundState, 288)), 2)), mul(mload(add(roundState, 320)), 67)), mul(mload(add(roundState, 352)), 22)), mul(mload(add(roundState, 384)), 13)), mul(mload(add(roundState, 416)), 3)), mload(add(roundState, 448))), mload(add(roundState, 480))), p))
                    mstore(add(scratch, 480), mod(add(add(add(add(add(add(add(add(add(add(add(add(add(add(add(mload(add(roundState, 0)), mul(mload(add(roundState, 32)), 51)), mload(add(roundState, 64))), mul(mload(add(roundState, 96)), 11)), mul(mload(add(roundState, 128)), 17)), mul(mload(add(roundState, 160)), 2)), mload(add(roundState, 192))), mul(mload(add(roundState, 224)), 101)), mul(mload(add(roundState, 256)), 63)), mul(mload(add(roundState, 288)), 15)), mul(mload(add(roundState, 320)), 2)), mul(mload(add(roundState, 352)), 67)), mul(mload(add(roundState, 384)), 22)), mul(mload(add(roundState, 416)), 13)), mul(mload(add(roundState, 448)), 3)), mload(add(roundState, 480))), p))
                    for { let i := 0 } lt(i, 512) { i := add(i, 32) } {
                        mstore(add(roundState, i), mload(add(scratch, i)))
                    }
                }
            }
            let p := 2130706433
            fullRounds(state, constants, 0)
            for { let i := 0 } lt(i, 16) { i := add(i, 1) } {
                let slot := add(state, shl(5, i))
                mstore(slot, add(mload(slot), constant(constants, add(128, i))))
            }
            // M_I = diag(1, B), where B is the exported 15 by 15 transition matrix.
            // Inputs are below 2p, so each unreduced tail output is below 30p^2.
            let scratch := mload(0x40)
            for { let i := 1 } lt(i, 16) { i := add(i, 1) } {
                let acc := 0
                let row := add(144, shl(4, i))
                for { let j := 1 } lt(j, 16) { j := add(j, 1) } {
                    acc := add(acc, mul(mload(add(state, shl(5, j))), constant(constants, add(row, j))))
                }
                mstore(add(scratch, shl(5, i)), acc)
            }
            for { let i := 1 } lt(i, 16) { i := add(i, 1) } {
                mstore(add(state, shl(5, i)), mload(add(scratch, shl(5, i))))
            }
            for { let round := 0 } lt(round, 20) { round := add(round, 1) } {
                // The first x is below 2p; subsequent x values are canonical.
                let x := mload(state)
                x := mod(mul(mul(x, x), x), p)
                if lt(round, 19) { x := add(x, constant(constants, add(400, round))) }
                // Every sparse first-row coefficient at index zero is one.
                let next0 := x
                let firstRow := add(419, shl(4, round))
                let v := add(739, shl(4, round))
                // The tail accumulates at most 20 terms below 2p^2, staying below
                // 70p^2 < 2^69. The first-row dot product stays below 1051p^3 < 2^104.
                {
                    let slot := add(state, 32)
                    let old := mload(slot)
                    next0 := add(next0, mul(old, constant(constants, add(firstRow, 1))))
                    mstore(slot, add(old, mul(x, constant(constants, add(v, 0)))))
                }
                {
                    let slot := add(state, 64)
                    let old := mload(slot)
                    next0 := add(next0, mul(old, constant(constants, add(firstRow, 2))))
                    mstore(slot, add(old, mul(x, constant(constants, add(v, 1)))))
                }
                {
                    let slot := add(state, 96)
                    let old := mload(slot)
                    next0 := add(next0, mul(old, constant(constants, add(firstRow, 3))))
                    mstore(slot, add(old, mul(x, constant(constants, add(v, 2)))))
                }
                {
                    let slot := add(state, 128)
                    let old := mload(slot)
                    next0 := add(next0, mul(old, constant(constants, add(firstRow, 4))))
                    mstore(slot, add(old, mul(x, constant(constants, add(v, 3)))))
                }
                {
                    let slot := add(state, 160)
                    let old := mload(slot)
                    next0 := add(next0, mul(old, constant(constants, add(firstRow, 5))))
                    mstore(slot, add(old, mul(x, constant(constants, add(v, 4)))))
                }
                {
                    let slot := add(state, 192)
                    let old := mload(slot)
                    next0 := add(next0, mul(old, constant(constants, add(firstRow, 6))))
                    mstore(slot, add(old, mul(x, constant(constants, add(v, 5)))))
                }
                {
                    let slot := add(state, 224)
                    let old := mload(slot)
                    next0 := add(next0, mul(old, constant(constants, add(firstRow, 7))))
                    mstore(slot, add(old, mul(x, constant(constants, add(v, 6)))))
                }
                {
                    let slot := add(state, 256)
                    let old := mload(slot)
                    next0 := add(next0, mul(old, constant(constants, add(firstRow, 8))))
                    mstore(slot, add(old, mul(x, constant(constants, add(v, 7)))))
                }
                {
                    let slot := add(state, 288)
                    let old := mload(slot)
                    next0 := add(next0, mul(old, constant(constants, add(firstRow, 9))))
                    mstore(slot, add(old, mul(x, constant(constants, add(v, 8)))))
                }
                {
                    let slot := add(state, 320)
                    let old := mload(slot)
                    next0 := add(next0, mul(old, constant(constants, add(firstRow, 10))))
                    mstore(slot, add(old, mul(x, constant(constants, add(v, 9)))))
                }
                {
                    let slot := add(state, 352)
                    let old := mload(slot)
                    next0 := add(next0, mul(old, constant(constants, add(firstRow, 11))))
                    mstore(slot, add(old, mul(x, constant(constants, add(v, 10)))))
                }
                {
                    let slot := add(state, 384)
                    let old := mload(slot)
                    next0 := add(next0, mul(old, constant(constants, add(firstRow, 12))))
                    mstore(slot, add(old, mul(x, constant(constants, add(v, 11)))))
                }
                {
                    let slot := add(state, 416)
                    let old := mload(slot)
                    next0 := add(next0, mul(old, constant(constants, add(firstRow, 13))))
                    mstore(slot, add(old, mul(x, constant(constants, add(v, 12)))))
                }
                {
                    let slot := add(state, 448)
                    let old := mload(slot)
                    next0 := add(next0, mul(old, constant(constants, add(firstRow, 14))))
                    mstore(slot, add(old, mul(x, constant(constants, add(v, 13)))))
                }
                {
                    let slot := add(state, 480)
                    let old := mload(slot)
                    next0 := add(next0, mul(old, constant(constants, add(firstRow, 15))))
                    mstore(slot, add(old, mul(x, constant(constants, add(v, 14)))))
                }
                mstore(state, mod(next0, p))
            }
            // ADDMOD in the first terminal round normalizes the accumulated tail.
            fullRounds(state, constants, 64)
        }
    }

    function compress(uint256[8] memory left, uint256[8] memory right)
        internal
        pure
        returns (uint256[8] memory result)
    {
        uint256[16] memory state;
        for (uint256 i = 0; i < 8; ++i) {
            state[i] = left[i];
            state[i + 8] = right[i];
        }
        permute(state);
        for (uint256 i = 0; i < 8; ++i) {
            result[i] = state[i];
        }
    }

    function hashWords(uint256[] memory values) internal pure returns (uint256[8] memory result) {
        if (values.length == 0 || values.length % 8 != 0) revert InvalidLeafLength();
        uint256[16] memory state;
        state[0] = values.length;
        bytes memory constants = C.values();
        for (uint256 offset = 0; offset < values.length; offset += 8) {
            for (uint256 i = 0; i < 8; ++i) {
                uint256 value = values[offset + i];
                if (value >= MODULUS) revert NonCanonicalField();
                state[i + 8] = value;
            }
            _permute(state, constants);
        }
        for (uint256 i = 0; i < 8; ++i) {
            result[i] = state[i + 8];
        }
    }

    function hashLeaf(uint256[] memory values) internal pure returns (uint256[8] memory result) {
        if (values.length == 0 || values.length % 8 != 0) revert InvalidLeafLength();
        uint256[16] memory state;
        state[0] = values.length;
        bytes memory constants = C.values();
        for (uint256 offset = values.length; offset != 0; offset -= 8) {
            for (uint256 i = 0; i < 8; ++i) {
                uint256 value = values[offset - 8 + i];
                if (value >= MODULUS) revert NonCanonicalField();
                state[i + 8] = value;
            }
            _permute(state, constants);
        }
        for (uint256 i = 0; i < 8; ++i) {
            result[i] = state[i + 8];
        }
    }
}
