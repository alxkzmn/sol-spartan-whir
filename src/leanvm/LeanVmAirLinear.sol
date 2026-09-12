// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @dev Matrix products of canonical packed quintic values and base-field scalars.
/// Callers must validate input coefficients and the zero low 96 padding bits.
/// Sixteen products of a 31-bit coefficient and a u32 scalar sum below 2^67,
/// so 80-bit lanes neither carry nor overflow a 256-bit word. Outputs are canonical.
library LeanVmAirLinear {
    error MatrixConstantsLength();

    function mds16(uint256[16] memory input, uint256[16] memory output) internal pure {
        bytes memory unused;
        _transform(input, output, unused, 0, true);
    }

    function matrix16(
        uint256[16] memory input,
        bytes memory constants,
        uint256 offset,
        uint256[16] memory output
    ) internal pure {
        if (offset > constants.length / 4 || 256 > constants.length / 4 - offset) {
            revert MatrixConstantsLength();
        }
        _transform(input, output, constants, offset, false);
    }

    /// @dev One matrix row, with the same 80-bit bounds as matrix16.
    function dot16(uint256[16] memory input, bytes memory constants, uint256 offset)
        internal
        pure
        returns (uint256 out)
    {
        if (offset > constants.length / 4 || 16 > constants.length / 4 - offset) {
            revert MatrixConstantsLength();
        }
        assembly ("memory-safe") {
            let rows := add(add(constants, 32), shl(2, offset))
            let a := 0
            let b := 0
            for { let j := 0 } lt(j, 16) { j := add(j, 1) } {
                let value := mload(add(input, shl(5, j)))
                let scalar := shr(224, mload(add(rows, shl(2, j))))
                let low :=
                    or(
                        or(shr(224, value), shl(80, and(shr(192, value), 0xffffffff))),
                        shl(160, and(shr(160, value), 0xffffffff))
                    )
                let high :=
                    or(and(shr(128, value), 0xffffffff), shl(80, and(shr(96, value), 0xffffffff)))
                a := add(a, mul(scalar, low))
                b := add(b, mul(scalar, high))
            }
            let mask := sub(shl(80, 1), 1)
            let p := 0x7f000001
            out := or(
                or(
                    or(shl(224, mod(and(a, mask), p)), shl(192, mod(and(shr(80, a), mask), p))),
                    shl(160, mod(shr(160, a), p))
                ),
                or(shl(128, mod(and(b, mask), p)), shl(96, mod(shr(80, b), p)))
            )
        }
    }

    /// @dev Applies the 15 non-leading rows of a sparse matrix in place.
    /// Each coefficient is at most (p-1)*(2^32-1)+(p-1) < 2^63.
    /// The unchanged first input may differ from the supplied old leading value.
    function sparseTail(
        uint256[16] memory input,
        uint256 first,
        bytes memory constants,
        uint256 offset
    ) internal pure {
        if (offset > constants.length / 4 || 15 > constants.length / 4 - offset) {
            revert MatrixConstantsLength();
        }
        assembly ("memory-safe") {
            let a0 := shr(224, first)
            let a1 := and(shr(192, first), 0xffffffff)
            let a2 := and(shr(160, first), 0xffffffff)
            let a3 := and(shr(128, first), 0xffffffff)
            let a4 := and(shr(96, first), 0xffffffff)
            let rows := add(add(constants, 32), shl(2, offset))
            let p := 0x7f000001
            for { let i := 1 } lt(i, 16) { i := add(i, 1) } {
                let destination := add(input, shl(5, i))
                let value := mload(destination)
                let scalar := shr(224, mload(add(rows, shl(2, sub(i, 1)))))
                mstore(
                    destination,
                    or(
                        or(
                            or(
                                shl(224, mod(add(mul(a0, scalar), shr(224, value)), p)),
                                shl(
                                    192,
                                    mod(add(mul(a1, scalar), and(shr(192, value), 0xffffffff)), p)
                                )
                            ),
                            shl(160, mod(add(mul(a2, scalar), and(shr(160, value), 0xffffffff)), p))
                        ),
                        or(
                            shl(
                                128,
                                mod(add(mul(a3, scalar), and(shr(128, value), 0xffffffff)), p)
                            ),
                            shl(96, mod(add(mul(a4, scalar), and(shr(96, value), 0xffffffff)), p))
                        )
                    )
                )
            }
        }
    }

    /// @dev MDS rows sum to 371, so each nonnegative coefficient sum is
    /// bounded by 371*(p-1) < 2^40 and all five lanes fit below bit 200.
    /// General u32 matrices retain two integers with 80-bit lanes.
    function _transform(
        uint256[16] memory input,
        uint256[16] memory output,
        bytes memory constants,
        uint256 offset,
        bool mds
    ) private pure {
        assembly ("memory-safe") {
            // All inputs are prepared before any output is written. Input and
            // output may alias; neither can point into this temporary allocation.
            let scratch := mload(0x40)
            mstore(0x40, add(scratch, 1024))
            let width := 80
            if mds { width := 40 }
            for { let j := 0 } lt(j, 16) { j := add(j, 1) } {
                let value := mload(add(input, shl(5, j)))
                let dst := add(scratch, shl(6, j))
                let low :=
                    or(
                        or(shr(224, value), shl(width, and(shr(192, value), 0xffffffff))),
                        shl(mul(2, width), and(shr(160, value), 0xffffffff))
                    )
                let high :=
                    or(
                        and(shr(128, value), 0xffffffff),
                        shl(width, and(shr(96, value), 0xffffffff))
                    )
                if mds { low := or(low, shl(120, high)) }
                mstore(dst, low)
                mstore(add(dst, 32), high)
            }
            let rows := add(add(constants, 32), shl(2, offset))
            let mask := sub(shl(width, 1), 1)
            let p := 0x7f000001
            for { let i := 0 } lt(i, 16) { i := add(i, 1) } {
                let a := 0
                let b := 0
                for { let j := 0 } lt(j, 16) { j := add(j, 1) } {
                    let scalar := 0
                    switch mds
                    case 1 {
                        // Byte k is firstRow[k]; the row rotation matches the AIR.
                        scalar := and(
                            shr(
                                shl(3, and(sub(add(j, 16), i), 15)),
                                0x030d1643020f3f650102110b01330101
                            ),
                            0xff
                        )
                    }
                    default {
                        scalar := shr(224, mload(add(rows, shl(2, add(shl(4, i), j)))))
                    }
                    let src := add(scratch, shl(6, j))
                    a := add(a, mul(scalar, mload(src)))
                    if iszero(mds) { b := add(b, mul(scalar, mload(add(src, 32)))) }
                }
                if mds { b := shr(120, a) }
                mstore(
                    add(output, shl(5, i)),
                    or(
                        or(
                            or(
                                shl(224, mod(and(a, mask), p)),
                                shl(192, mod(and(shr(width, a), mask), p))
                            ),
                            shl(160, mod(and(shr(mul(2, width), a), mask), p))
                        ),
                        or(shl(128, mod(and(b, mask), p)), shl(96, mod(shr(width, b), p)))
                    )
                )
            }
            // No pointer into scratch escapes this function.
            mstore(0x40, scratch)
        }
    }
}
