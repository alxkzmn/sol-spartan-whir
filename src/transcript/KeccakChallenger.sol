// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

library KeccakChallenger {
    uint256 internal constant KOALABEAR_MODULUS = 0x7f000001;
    uint256 internal constant KOALABEAR_SAMPLE_MASK = 0x7fffffff;
    uint256 internal constant DIGEST_BYTES = 32;
    uint256 internal constant INITIAL_CAPACITY = 64;

    struct State {
        bytes inputBuffer;
        uint256 inputLen;
        bytes32 outputBlock;
        uint256 outputIndex;
    }

    function observeBytes(State memory self, bytes memory data) internal pure {
        self.outputIndex = 0;
        _appendBytes(self, data);
    }

    function observeBytesCalldata(
        State memory self,
        bytes calldata data,
        uint256 offset,
        uint256 len
    ) internal pure {
        self.outputIndex = 0;
        _appendBytesCalldata(self, data, offset, len);
    }

    function observeBase(State memory self, uint256 value) internal pure {
        require(value < KOALABEAR_MODULUS, "BASE_RANGE");
        _appendBaseLE(self, uint32(value));
    }

    function observeHashU8Digest(State memory self, bytes32 digest) internal pure {
        _appendDigest32(self, digest);
    }

    function observeHashU64Digest(State memory self, bytes32 digest) internal pure {
        _appendDigestU64LE(self, digest);
    }

    function observeValidatedPackedExt4(State memory self, uint256 packed) internal pure {
        uint256 oldLen = self.inputLen;
        uint256 newLen = oldLen + 16;
        _ensureCapacity(self, newLen);
        bytes memory buffer = self.inputBuffer;
        assembly ("memory-safe") {
            function bswap32(x) -> y {
                y := or(
                    or(shl(24, and(x, 0xff)), shl(8, and(x, 0xff00))),
                    or(shr(8, and(x, 0xff0000)), shr(24, and(x, 0xff000000)))
                )
            }

            function revertPacked(x) {
                mstore(0x00, shl(224, 0xd53cfe5c))
                mstore(0x04, x)
                revert(0x00, 0x24)
            }

            function validateAndEncode(x, modulus, mask) -> encoded {
                if and(x, sub(shl(128, 1), 1)) {
                    revertPacked(x)
                }

                let x0 := shr(224, x)
                if iszero(lt(x0, modulus)) {
                    revertPacked(x)
                }

                let x1 := and(shr(192, x), mask)
                if iszero(lt(x1, modulus)) {
                    revertPacked(x)
                }

                let x2 := and(shr(160, x), mask)
                if iszero(lt(x2, modulus)) {
                    revertPacked(x)
                }

                let x3 := and(shr(128, x), mask)
                if iszero(lt(x3, modulus)) {
                    revertPacked(x)
                }

                encoded := or(
                    or(shl(224, bswap32(x0)), shl(192, bswap32(x1))),
                    or(shl(160, bswap32(x2)), shl(128, bswap32(x3)))
                )
            }

            let modulus := 0x7f000001
            let mask := 0xffffffff
            let dst := add(add(buffer, 0x20), oldLen)

            mstore(dst, validateAndEncode(packed, modulus, mask))
        }

        self.inputLen = newLen;
        self.outputIndex = 0;
    }

    function observeValidatedPackedExt4Pair(State memory self, uint256 first, uint256 second)
        internal
        pure
    {
        uint256 oldLen = self.inputLen;
        uint256 newLen = oldLen + 32;
        _ensureCapacity(self, newLen + 16);
        bytes memory buffer = self.inputBuffer;
        assembly ("memory-safe") {
            function bswap32(x) -> y {
                y := or(
                    or(shl(24, and(x, 0xff)), shl(8, and(x, 0xff00))),
                    or(shr(8, and(x, 0xff0000)), shr(24, and(x, 0xff000000)))
                )
            }

            function revertPacked(x) {
                mstore(0x00, shl(224, 0xd53cfe5c))
                mstore(0x04, x)
                revert(0x00, 0x24)
            }

            function validateAndEncode(x, modulus, mask) -> encoded {
                if and(x, sub(shl(128, 1), 1)) {
                    revertPacked(x)
                }

                let x0 := shr(224, x)
                if iszero(lt(x0, modulus)) {
                    revertPacked(x)
                }

                let x1 := and(shr(192, x), mask)
                if iszero(lt(x1, modulus)) {
                    revertPacked(x)
                }

                let x2 := and(shr(160, x), mask)
                if iszero(lt(x2, modulus)) {
                    revertPacked(x)
                }

                let x3 := and(shr(128, x), mask)
                if iszero(lt(x3, modulus)) {
                    revertPacked(x)
                }

                encoded := or(
                    or(shl(224, bswap32(x0)), shl(192, bswap32(x1))),
                    or(shl(160, bswap32(x2)), shl(128, bswap32(x3)))
                )
            }

            let modulus := 0x7f000001
            let mask := 0xffffffff
            let dst := add(add(buffer, 0x20), oldLen)

            mstore(dst, validateAndEncode(first, modulus, mask))
            mstore(add(dst, 0x10), validateAndEncode(second, modulus, mask))
        }

        self.inputLen = newLen;
        self.outputIndex = 0;
    }

    function observeValidatedPackedExt5Slice(State memory self, uint256[] calldata values)
        internal
        pure
    {
        uint256 oldLen = self.inputLen;
        uint256 appendLen = values.length * 20;
        uint256 newLen = oldLen + appendLen;
        _ensureCapacity(self, newLen + 12);
        bytes memory buffer = self.inputBuffer;
        assembly ("memory-safe") {
            function bswap32(x) -> y {
                y := or(
                    or(shl(24, and(x, 0xff)), shl(8, and(x, 0xff00))),
                    or(shr(8, and(x, 0xff0000)), shr(24, and(x, 0xff000000)))
                )
            }

            function revertPacked(x) {
                mstore(0x00, shl(224, 0xd53cfe5c))
                mstore(0x04, x)
                revert(0x00, 0x24)
            }

            function validateAndEncode(x, mask) -> encoded {
                let highBitMask :=
                    0x8000000080000000800000008000000080000000000000000000000000000000
                let low31Mask := 0x7fffffff7fffffff7fffffff7fffffff7fffffff000000000000000000000000
                let bias := 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000
                if or(
                    or(and(x, sub(shl(96, 1), 1)), and(x, highBitMask)),
                    and(add(and(x, low31Mask), bias), highBitMask)
                ) { revertPacked(x) }

                let x0 := shr(224, x)
                let x1 := and(shr(192, x), mask)
                let x2 := and(shr(160, x), mask)
                let x3 := and(shr(128, x), mask)
                let x4 := and(shr(96, x), mask)

                encoded := or(
                    or(
                        or(shl(224, bswap32(x0)), shl(192, bswap32(x1))),
                        or(shl(160, bswap32(x2)), shl(128, bswap32(x3)))
                    ),
                    shl(96, bswap32(x4))
                )
            }

            let mask := 0xffffffff
            let src := values.offset
            let end := add(src, shl(5, values.length))
            let dst := add(add(buffer, 0x20), oldLen)

            for { } lt(src, end) {
                src := add(src, 0x20)
                dst := add(dst, 20)
            } {
                mstore(dst, validateAndEncode(calldataload(src), mask))
            }
        }

        self.inputLen = newLen;
        self.outputIndex = 0;
    }

    function observeValidatedPackedExt5(State memory self, uint256 packed) internal pure {
        uint256 oldLen = self.inputLen;
        uint256 newLen = oldLen + 20;
        _ensureCapacity(self, newLen + 12);
        bytes memory buffer = self.inputBuffer;
        assembly ("memory-safe") {
            function bswap32(x) -> y {
                y := or(
                    or(shl(24, and(x, 0xff)), shl(8, and(x, 0xff00))),
                    or(shr(8, and(x, 0xff0000)), shr(24, and(x, 0xff000000)))
                )
            }

            function revertPacked(x) {
                mstore(0x00, shl(224, 0xd53cfe5c))
                mstore(0x04, x)
                revert(0x00, 0x24)
            }

            function validateAndEncode(x, mask) -> encoded {
                let highBitMask :=
                    0x8000000080000000800000008000000080000000000000000000000000000000
                let low31Mask := 0x7fffffff7fffffff7fffffff7fffffff7fffffff000000000000000000000000
                let bias := 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000
                if or(
                    or(and(x, sub(shl(96, 1), 1)), and(x, highBitMask)),
                    and(add(and(x, low31Mask), bias), highBitMask)
                ) { revertPacked(x) }

                let x0 := shr(224, x)
                let x1 := and(shr(192, x), mask)
                let x2 := and(shr(160, x), mask)
                let x3 := and(shr(128, x), mask)
                let x4 := and(shr(96, x), mask)

                encoded := or(
                    or(
                        or(shl(224, bswap32(x0)), shl(192, bswap32(x1))),
                        or(shl(160, bswap32(x2)), shl(128, bswap32(x3)))
                    ),
                    shl(96, bswap32(x4))
                )
            }

            let mask := 0xffffffff
            let dst := add(add(buffer, 0x20), oldLen)
            mstore(dst, validateAndEncode(packed, mask))
        }

        self.inputLen = newLen;
        self.outputIndex = 0;
    }

    function observeValidatedPackedExt5Pair(State memory self, uint256 first, uint256 second)
        internal
        pure
    {
        uint256 oldLen = self.inputLen;
        uint256 newLen = oldLen + 40;
        _ensureCapacity(self, newLen + 24);
        bytes memory buffer = self.inputBuffer;
        assembly ("memory-safe") {
            function bswap32(x) -> y {
                y := or(
                    or(shl(24, and(x, 0xff)), shl(8, and(x, 0xff00))),
                    or(shr(8, and(x, 0xff0000)), shr(24, and(x, 0xff000000)))
                )
            }

            function revertPacked(x) {
                mstore(0x00, shl(224, 0xd53cfe5c))
                mstore(0x04, x)
                revert(0x00, 0x24)
            }

            function validateAndEncode(x, mask) -> encoded {
                let highBitMask :=
                    0x8000000080000000800000008000000080000000000000000000000000000000
                let low31Mask := 0x7fffffff7fffffff7fffffff7fffffff7fffffff000000000000000000000000
                let bias := 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000
                if or(
                    or(and(x, sub(shl(96, 1), 1)), and(x, highBitMask)),
                    and(add(and(x, low31Mask), bias), highBitMask)
                ) { revertPacked(x) }

                let x0 := shr(224, x)
                let x1 := and(shr(192, x), mask)
                let x2 := and(shr(160, x), mask)
                let x3 := and(shr(128, x), mask)
                let x4 := and(shr(96, x), mask)

                encoded := or(
                    or(
                        or(shl(224, bswap32(x0)), shl(192, bswap32(x1))),
                        or(shl(160, bswap32(x2)), shl(128, bswap32(x3)))
                    ),
                    shl(96, bswap32(x4))
                )
            }

            let mask := 0xffffffff
            let dst := add(add(buffer, 0x20), oldLen)
            mstore(dst, validateAndEncode(first, mask))
            mstore(add(dst, 20), validateAndEncode(second, mask))
        }

        self.inputLen = newLen;
        self.outputIndex = 0;
    }

    function observeValidatedPackedExt5Blob(
        State memory self,
        bytes calldata data,
        uint256 offset,
        uint256 count
    ) internal pure {
        uint256 oldLen = self.inputLen;
        uint256 appendLen = count * 20;
        uint256 newLen = oldLen + appendLen;
        _ensureCapacity(self, newLen + 12);
        bytes memory buffer = self.inputBuffer;
        assembly ("memory-safe") {
            function bswap32(x) -> y {
                y := or(
                    or(shl(24, and(x, 0xff)), shl(8, and(x, 0xff00))),
                    or(shr(8, and(x, 0xff0000)), shr(24, and(x, 0xff000000)))
                )
            }

            function revertPacked(x) {
                mstore(0x00, shl(224, 0xd53cfe5c))
                mstore(0x04, x)
                revert(0x00, 0x24)
            }

            function validateAndEncode(x, mask) -> encoded {
                let highBitMask :=
                    0x8000000080000000800000008000000080000000000000000000000000000000
                let low31Mask := 0x7fffffff7fffffff7fffffff7fffffff7fffffff000000000000000000000000
                let bias := 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000
                if or(
                    or(and(x, sub(shl(96, 1), 1)), and(x, highBitMask)),
                    and(add(and(x, low31Mask), bias), highBitMask)
                ) { revertPacked(x) }

                let x0 := shr(224, x)
                let x1 := and(shr(192, x), mask)
                let x2 := and(shr(160, x), mask)
                let x3 := and(shr(128, x), mask)
                let x4 := and(shr(96, x), mask)

                encoded := or(
                    or(
                        or(shl(224, bswap32(x0)), shl(192, bswap32(x1))),
                        or(shl(160, bswap32(x2)), shl(128, bswap32(x3)))
                    ),
                    shl(96, bswap32(x4))
                )
            }

            let mask := 0xffffffff
            let lowMask := not(sub(shl(96, 1), 1))
            let src := add(data.offset, offset)
            let end := add(src, mul(count, 20))
            let dst := add(add(buffer, 0x20), oldLen)

            for { } lt(src, end) {
                src := add(src, 20)
                dst := add(dst, 20)
            } {
                mstore(dst, validateAndEncode(and(calldataload(src), lowMask), mask))
            }
        }

        self.inputLen = newLen;
        self.outputIndex = 0;
    }

    function observeValidatedPackedExt4Slice(State memory self, uint256[] calldata values)
        internal
        pure
    {
        uint256 oldLen = self.inputLen;
        uint256 appendLen = values.length * 16;
        uint256 newLen = oldLen + appendLen;
        _ensureCapacity(self, newLen + 16);
        bytes memory buffer = self.inputBuffer;
        assembly ("memory-safe") {
            function bswap32(x) -> y {
                y := or(
                    or(shl(24, and(x, 0xff)), shl(8, and(x, 0xff00))),
                    or(shr(8, and(x, 0xff0000)), shr(24, and(x, 0xff000000)))
                )
            }

            function revertPacked(x) {
                mstore(0x00, shl(224, 0xd53cfe5c))
                mstore(0x04, x)
                revert(0x00, 0x24)
            }

            function validateAndEncode(x, modulus, mask) -> encoded {
                if and(x, sub(shl(128, 1), 1)) {
                    revertPacked(x)
                }

                let x0 := shr(224, x)
                if iszero(lt(x0, modulus)) {
                    revertPacked(x)
                }

                let x1 := and(shr(192, x), mask)
                if iszero(lt(x1, modulus)) {
                    revertPacked(x)
                }

                let x2 := and(shr(160, x), mask)
                if iszero(lt(x2, modulus)) {
                    revertPacked(x)
                }

                let x3 := and(shr(128, x), mask)
                if iszero(lt(x3, modulus)) {
                    revertPacked(x)
                }

                encoded := or(
                    or(shl(224, bswap32(x0)), shl(192, bswap32(x1))),
                    or(shl(160, bswap32(x2)), shl(128, bswap32(x3)))
                )
            }

            let modulus := 0x7f000001
            let mask := 0xffffffff
            let src := values.offset
            let end := add(src, shl(5, values.length))
            let dst := add(add(buffer, 0x20), oldLen)

            for { } lt(src, end) {
                src := add(src, 0x20)
                dst := add(dst, 0x10)
            } {
                mstore(dst, validateAndEncode(calldataload(src), modulus, mask))
            }
        }

        self.inputLen = newLen;
        self.outputIndex = 0;
    }

    function observeValidatedPackedExt8(State memory self, uint256 packed) internal pure {
        uint256 oldLen = self.inputLen;
        uint256 newLen = oldLen + 32;
        _ensureCapacity(self, newLen);
        bytes memory buffer = self.inputBuffer;
        assembly ("memory-safe") {
            function bswap32(x) -> y {
                y := or(
                    or(shl(24, and(x, 0xff)), shl(8, and(x, 0xff00))),
                    or(shr(8, and(x, 0xff0000)), shr(24, and(x, 0xff000000)))
                )
            }

            function revertPacked(x) {
                mstore(0x00, shl(224, 0xd53cfe5c))
                mstore(0x04, x)
                revert(0x00, 0x24)
            }

            function validateAndEncode(x, modulus, mask) -> encoded {
                let x0 := shr(224, x)
                if iszero(lt(x0, modulus)) {
                    revertPacked(x)
                }
                let x1 := and(shr(192, x), mask)
                if iszero(lt(x1, modulus)) {
                    revertPacked(x)
                }
                let x2 := and(shr(160, x), mask)
                if iszero(lt(x2, modulus)) {
                    revertPacked(x)
                }
                let x3 := and(shr(128, x), mask)
                if iszero(lt(x3, modulus)) {
                    revertPacked(x)
                }
                let x4 := and(shr(96, x), mask)
                if iszero(lt(x4, modulus)) {
                    revertPacked(x)
                }
                let x5 := and(shr(64, x), mask)
                if iszero(lt(x5, modulus)) {
                    revertPacked(x)
                }
                let x6 := and(shr(32, x), mask)
                if iszero(lt(x6, modulus)) {
                    revertPacked(x)
                }
                let x7 := and(x, mask)
                if iszero(lt(x7, modulus)) {
                    revertPacked(x)
                }

                encoded := or(
                    or(
                        or(shl(224, bswap32(x0)), shl(192, bswap32(x1))),
                        or(shl(160, bswap32(x2)), shl(128, bswap32(x3)))
                    ),
                    or(
                        or(shl(96, bswap32(x4)), shl(64, bswap32(x5))),
                        or(shl(32, bswap32(x6)), bswap32(x7))
                    )
                )
            }

            mstore(
                add(add(buffer, 0x20), oldLen),
                validateAndEncode(packed, 0x7f000001, 0xffffffff)
            )
        }

        self.inputLen = newLen;
        self.outputIndex = 0;
    }

    function observeValidatedPackedExt8Pair(State memory self, uint256 first, uint256 second)
        internal
        pure
    {
        uint256 oldLen = self.inputLen;
        uint256 newLen = oldLen + 64;
        _ensureCapacity(self, newLen + 32);
        bytes memory buffer = self.inputBuffer;
        assembly ("memory-safe") {
            function bswap32(x) -> y {
                y := or(
                    or(shl(24, and(x, 0xff)), shl(8, and(x, 0xff00))),
                    or(shr(8, and(x, 0xff0000)), shr(24, and(x, 0xff000000)))
                )
            }

            function revertPacked(x) {
                mstore(0x00, shl(224, 0xd53cfe5c))
                mstore(0x04, x)
                revert(0x00, 0x24)
            }

            function validateAndEncode(x, modulus, mask) -> encoded {
                let x0 := shr(224, x)
                if iszero(lt(x0, modulus)) {
                    revertPacked(x)
                }
                let x1 := and(shr(192, x), mask)
                if iszero(lt(x1, modulus)) {
                    revertPacked(x)
                }
                let x2 := and(shr(160, x), mask)
                if iszero(lt(x2, modulus)) {
                    revertPacked(x)
                }
                let x3 := and(shr(128, x), mask)
                if iszero(lt(x3, modulus)) {
                    revertPacked(x)
                }
                let x4 := and(shr(96, x), mask)
                if iszero(lt(x4, modulus)) {
                    revertPacked(x)
                }
                let x5 := and(shr(64, x), mask)
                if iszero(lt(x5, modulus)) {
                    revertPacked(x)
                }
                let x6 := and(shr(32, x), mask)
                if iszero(lt(x6, modulus)) {
                    revertPacked(x)
                }
                let x7 := and(x, mask)
                if iszero(lt(x7, modulus)) {
                    revertPacked(x)
                }

                encoded := or(
                    or(
                        or(shl(224, bswap32(x0)), shl(192, bswap32(x1))),
                        or(shl(160, bswap32(x2)), shl(128, bswap32(x3)))
                    ),
                    or(
                        or(shl(96, bswap32(x4)), shl(64, bswap32(x5))),
                        or(shl(32, bswap32(x6)), bswap32(x7))
                    )
                )
            }

            let dst := add(add(buffer, 0x20), oldLen)
            mstore(dst, validateAndEncode(first, 0x7f000001, 0xffffffff))
            mstore(add(dst, 0x20), validateAndEncode(second, 0x7f000001, 0xffffffff))
        }

        self.inputLen = newLen;
        self.outputIndex = 0;
    }

    function observeValidatedPackedExt8Slice(State memory self, uint256[] calldata values)
        internal
        pure
    {
        uint256 oldLen = self.inputLen;
        uint256 appendLen = values.length * 32;
        uint256 newLen = oldLen + appendLen;
        _ensureCapacity(self, newLen + 32);
        bytes memory buffer = self.inputBuffer;
        assembly ("memory-safe") {
            function bswap32(x) -> y {
                y := or(
                    or(shl(24, and(x, 0xff)), shl(8, and(x, 0xff00))),
                    or(shr(8, and(x, 0xff0000)), shr(24, and(x, 0xff000000)))
                )
            }

            function revertPacked(x) {
                mstore(0x00, shl(224, 0xd53cfe5c))
                mstore(0x04, x)
                revert(0x00, 0x24)
            }

            function validateAndEncode(x, modulus, mask) -> encoded {
                let x0 := shr(224, x)
                if iszero(lt(x0, modulus)) {
                    revertPacked(x)
                }
                let x1 := and(shr(192, x), mask)
                if iszero(lt(x1, modulus)) {
                    revertPacked(x)
                }
                let x2 := and(shr(160, x), mask)
                if iszero(lt(x2, modulus)) {
                    revertPacked(x)
                }
                let x3 := and(shr(128, x), mask)
                if iszero(lt(x3, modulus)) {
                    revertPacked(x)
                }
                let x4 := and(shr(96, x), mask)
                if iszero(lt(x4, modulus)) {
                    revertPacked(x)
                }
                let x5 := and(shr(64, x), mask)
                if iszero(lt(x5, modulus)) {
                    revertPacked(x)
                }
                let x6 := and(shr(32, x), mask)
                if iszero(lt(x6, modulus)) {
                    revertPacked(x)
                }
                let x7 := and(x, mask)
                if iszero(lt(x7, modulus)) {
                    revertPacked(x)
                }

                encoded := or(
                    or(
                        or(shl(224, bswap32(x0)), shl(192, bswap32(x1))),
                        or(shl(160, bswap32(x2)), shl(128, bswap32(x3)))
                    ),
                    or(
                        or(shl(96, bswap32(x4)), shl(64, bswap32(x5))),
                        or(shl(32, bswap32(x6)), bswap32(x7))
                    )
                )
            }

            let src := values.offset
            let end := add(src, shl(5, values.length))
            let dst := add(add(buffer, 0x20), oldLen)

            for { } lt(src, end) {
                src := add(src, 0x20)
                dst := add(dst, 0x20)
            } {
                mstore(dst, validateAndEncode(calldataload(src), 0x7f000001, 0xffffffff))
            }
        }

        self.inputLen = newLen;
        self.outputIndex = 0;
    }

    function observeReadValidatedPackedExt4Le(
        State memory self,
        bytes calldata data,
        uint256 offset
    ) internal pure returns (uint256 packed) {
        uint256 oldLen = self.inputLen;
        uint256 newLen = oldLen + 16;
        _ensureCapacity(self, newLen);
        bytes memory buffer = self.inputBuffer;
        assembly ("memory-safe") {
            function bswap32(x) -> y {
                y := or(
                    or(shl(24, and(x, 0xff)), shl(8, and(x, 0xff00))),
                    or(shr(8, and(x, 0xff0000)), shr(24, and(x, 0xff000000)))
                )
            }

            function revertPacked(x) {
                mstore(0x00, shl(224, 0xd53cfe5c))
                mstore(0x04, x)
                revert(0x00, 0x24)
            }

            let raw := calldataload(add(data.offset, offset))
            let modulus := 0x7f000001
            let x0 := bswap32(shr(224, raw))
            if iszero(lt(x0, modulus)) {
                revertPacked(raw)
            }
            let x1 := bswap32(and(shr(192, raw), 0xffffffff))
            if iszero(lt(x1, modulus)) {
                revertPacked(raw)
            }
            let x2 := bswap32(and(shr(160, raw), 0xffffffff))
            if iszero(lt(x2, modulus)) {
                revertPacked(raw)
            }
            let x3 := bswap32(and(shr(128, raw), 0xffffffff))
            if iszero(lt(x3, modulus)) {
                revertPacked(raw)
            }

            packed := or(or(shl(224, x0), shl(192, x1)), or(shl(160, x2), shl(128, x3)))

            mstore(add(add(buffer, 0x20), oldLen), raw)
        }

        self.inputLen = newLen;
        self.outputIndex = 0;
    }

    function observeReadValidatedPackedExt4LePair(
        State memory self,
        bytes calldata data,
        uint256 offset
    ) internal pure returns (uint256 first, uint256 second) {
        uint256 oldLen = self.inputLen;
        uint256 newLen = oldLen + 32;
        _ensureCapacity(self, newLen + 16);
        bytes memory buffer = self.inputBuffer;
        assembly ("memory-safe") {
            function bswap32(x) -> y {
                y := or(
                    or(shl(24, and(x, 0xff)), shl(8, and(x, 0xff00))),
                    or(shr(8, and(x, 0xff0000)), shr(24, and(x, 0xff000000)))
                )
            }

            function revertPacked(x) {
                mstore(0x00, shl(224, 0xd53cfe5c))
                mstore(0x04, x)
                revert(0x00, 0x24)
            }

            function decodeAndValidate(raw) -> packed {
                let modulus := 0x7f000001
                let x0 := bswap32(shr(224, raw))
                if iszero(lt(x0, modulus)) {
                    revertPacked(raw)
                }
                let x1 := bswap32(and(shr(192, raw), 0xffffffff))
                if iszero(lt(x1, modulus)) {
                    revertPacked(raw)
                }
                let x2 := bswap32(and(shr(160, raw), 0xffffffff))
                if iszero(lt(x2, modulus)) {
                    revertPacked(raw)
                }
                let x3 := bswap32(and(shr(128, raw), 0xffffffff))
                if iszero(lt(x3, modulus)) {
                    revertPacked(raw)
                }

                packed := or(or(shl(224, x0), shl(192, x1)), or(shl(160, x2), shl(128, x3)))
            }

            let src := add(data.offset, offset)
            let raw0 := calldataload(src)
            let raw1 := calldataload(add(src, 0x10))

            first := decodeAndValidate(raw0)
            second := decodeAndValidate(raw1)

            let dst := add(add(buffer, 0x20), oldLen)
            mstore(dst, raw0)
            mstore(add(dst, 0x10), raw1)
        }

        self.inputLen = newLen;
        self.outputIndex = 0;
    }

    function observeReadValidatedPackedExt8Le(
        State memory self,
        bytes calldata data,
        uint256 offset
    ) internal pure returns (uint256 packed) {
        uint256 oldLen = self.inputLen;
        uint256 newLen = oldLen + 32;
        _ensureCapacity(self, newLen);
        bytes memory buffer = self.inputBuffer;
        assembly ("memory-safe") {
            function bswap32(x) -> y {
                y := or(
                    or(shl(24, and(x, 0xff)), shl(8, and(x, 0xff00))),
                    or(shr(8, and(x, 0xff0000)), shr(24, and(x, 0xff000000)))
                )
            }

            function revertPacked(x) {
                mstore(0x00, shl(224, 0xd53cfe5c))
                mstore(0x04, x)
                revert(0x00, 0x24)
            }

            let raw := calldataload(add(data.offset, offset))
            let modulus := 0x7f000001
            let x0 := bswap32(shr(224, raw))
            if iszero(lt(x0, modulus)) {
                revertPacked(raw)
            }
            let x1 := bswap32(and(shr(192, raw), 0xffffffff))
            if iszero(lt(x1, modulus)) {
                revertPacked(raw)
            }
            let x2 := bswap32(and(shr(160, raw), 0xffffffff))
            if iszero(lt(x2, modulus)) {
                revertPacked(raw)
            }
            let x3 := bswap32(and(shr(128, raw), 0xffffffff))
            if iszero(lt(x3, modulus)) {
                revertPacked(raw)
            }
            let x4 := bswap32(and(shr(96, raw), 0xffffffff))
            if iszero(lt(x4, modulus)) {
                revertPacked(raw)
            }
            let x5 := bswap32(and(shr(64, raw), 0xffffffff))
            if iszero(lt(x5, modulus)) {
                revertPacked(raw)
            }
            let x6 := bswap32(and(shr(32, raw), 0xffffffff))
            if iszero(lt(x6, modulus)) {
                revertPacked(raw)
            }
            let x7 := bswap32(and(raw, 0xffffffff))
            if iszero(lt(x7, modulus)) {
                revertPacked(raw)
            }

            packed := or(
                or(or(shl(224, x0), shl(192, x1)), or(shl(160, x2), shl(128, x3))),
                or(or(shl(96, x4), shl(64, x5)), or(shl(32, x6), x7))
            )

            mstore(add(add(buffer, 0x20), oldLen), raw)
        }

        self.inputLen = newLen;
        self.outputIndex = 0;
    }

    function observeReadValidatedPackedExt8LePair(
        State memory self,
        bytes calldata data,
        uint256 offset
    ) internal pure returns (uint256 first, uint256 second) {
        uint256 oldLen = self.inputLen;
        uint256 newLen = oldLen + 64;
        _ensureCapacity(self, newLen + 32);
        bytes memory buffer = self.inputBuffer;
        assembly ("memory-safe") {
            function bswap32(x) -> y {
                y := or(
                    or(shl(24, and(x, 0xff)), shl(8, and(x, 0xff00))),
                    or(shr(8, and(x, 0xff0000)), shr(24, and(x, 0xff000000)))
                )
            }

            function revertPacked(x) {
                mstore(0x00, shl(224, 0xd53cfe5c))
                mstore(0x04, x)
                revert(0x00, 0x24)
            }

            function decodeAndValidate(raw) -> packed {
                let modulus := 0x7f000001
                let x0 := bswap32(shr(224, raw))
                if iszero(lt(x0, modulus)) {
                    revertPacked(raw)
                }
                let x1 := bswap32(and(shr(192, raw), 0xffffffff))
                if iszero(lt(x1, modulus)) {
                    revertPacked(raw)
                }
                let x2 := bswap32(and(shr(160, raw), 0xffffffff))
                if iszero(lt(x2, modulus)) {
                    revertPacked(raw)
                }
                let x3 := bswap32(and(shr(128, raw), 0xffffffff))
                if iszero(lt(x3, modulus)) {
                    revertPacked(raw)
                }
                let x4 := bswap32(and(shr(96, raw), 0xffffffff))
                if iszero(lt(x4, modulus)) {
                    revertPacked(raw)
                }
                let x5 := bswap32(and(shr(64, raw), 0xffffffff))
                if iszero(lt(x5, modulus)) {
                    revertPacked(raw)
                }
                let x6 := bswap32(and(shr(32, raw), 0xffffffff))
                if iszero(lt(x6, modulus)) {
                    revertPacked(raw)
                }
                let x7 := bswap32(and(raw, 0xffffffff))
                if iszero(lt(x7, modulus)) {
                    revertPacked(raw)
                }

                packed := or(
                    or(or(shl(224, x0), shl(192, x1)), or(shl(160, x2), shl(128, x3))),
                    or(or(shl(96, x4), shl(64, x5)), or(shl(32, x6), x7))
                )
            }

            let src := add(data.offset, offset)
            let raw0 := calldataload(src)
            let raw1 := calldataload(add(src, 0x20))

            first := decodeAndValidate(raw0)
            second := decodeAndValidate(raw1)

            let dst := add(add(buffer, 0x20), oldLen)
            mstore(dst, raw0)
            mstore(add(dst, 0x20), raw1)
        }

        self.inputLen = newLen;
        self.outputIndex = 0;
    }

    function observeReadValidatedPackedExt5Le(
        State memory self,
        bytes calldata data,
        uint256 offset
    ) internal pure returns (uint256 packed) {
        uint256 oldLen = self.inputLen;
        uint256 newLen = oldLen + 20;
        _ensureCapacity(self, newLen + 12);
        bytes memory buffer = self.inputBuffer;
        assembly ("memory-safe") {
            function bswap32(x) -> y {
                y := or(
                    or(shl(24, and(x, 0xff)), shl(8, and(x, 0xff00))),
                    or(shr(8, and(x, 0xff0000)), shr(24, and(x, 0xff000000)))
                )
            }

            function revertPacked(x) {
                mstore(0x00, shl(224, 0xd53cfe5c))
                mstore(0x04, x)
                revert(0x00, 0x24)
            }

            let raw := calldataload(add(data.offset, offset))
            let modulus := 0x7f000001
            let x0 := bswap32(shr(224, raw))
            let x1 := bswap32(and(shr(192, raw), 0xffffffff))
            let x2 := bswap32(and(shr(160, raw), 0xffffffff))
            let x3 := bswap32(and(shr(128, raw), 0xffffffff))
            let x4 := bswap32(and(shr(96, raw), 0xffffffff))
            if or(
                or(or(iszero(lt(x0, modulus)), iszero(lt(x1, modulus))), iszero(lt(x2, modulus))),
                or(iszero(lt(x3, modulus)), iszero(lt(x4, modulus)))
            ) { revertPacked(raw) }

            packed := or(
                or(or(shl(224, x0), shl(192, x1)), or(shl(160, x2), shl(128, x3))),
                shl(96, x4)
            )

            mstore(add(add(buffer, 0x20), oldLen), and(raw, not(sub(shl(96, 1), 1))))
        }

        self.inputLen = newLen;
        self.outputIndex = 0;
    }

    function observeReadValidatedPackedExt5LePair(
        State memory self,
        bytes calldata data,
        uint256 offset
    ) internal pure returns (uint256 first, uint256 second) {
        first = observeReadValidatedPackedExt5Le(self, data, offset);
        second = observeReadValidatedPackedExt5Le(self, data, offset + 20);
    }

    function sampleBase(State memory self) internal pure returns (uint256) {
        while (true) {
            uint256 value = uint256(_sampleUint32(self)) & KOALABEAR_SAMPLE_MASK;
            if (value < KOALABEAR_MODULUS) {
                return value;
            }
        }

        revert("UNREACHABLE");
    }

    function sampleBits(State memory self, uint256 bits) internal pure returns (uint256) {
        require(bits < 256, "BITS_WIDTH");
        if (bits == 0) {
            return 0;
        }

        require((uint256(1) << bits) <= KOALABEAR_MODULUS, "BITS_RANGE");
        return sampleBitsUnchecked(self, bits);
    }

    function sampleBitsUnchecked(State memory self, uint256 bits) internal pure returns (uint256) {
        if (bits == 0) {
            return 0;
        }
        unchecked {
            return uint256(_sampleUint32(self)) & ((uint256(1) << bits) - 1);
        }
    }

    function sampleExt4Coeffs(State memory self) internal pure returns (uint256[4] memory coeffs) {
        unchecked {
            for (uint256 i = 0; i < 4; ++i) {
                coeffs[i] = sampleBase(self);
            }
        }
    }

    function sampleExt8Coeffs(State memory self) internal pure returns (uint256[8] memory coeffs) {
        unchecked {
            for (uint256 i = 0; i < 8; ++i) {
                coeffs[i] = sampleBase(self);
            }
        }
    }

    function sampleExt5Coeffs(State memory self) internal pure returns (uint256[5] memory coeffs) {
        unchecked {
            for (uint256 i = 0; i < 5; ++i) {
                coeffs[i] = sampleBase(self);
            }
        }
    }

    function checkWitness(State memory self, uint256 bits, uint256 witness)
        internal
        pure
        returns (bool)
    {
        if (bits == 0) {
            return true;
        }

        observeBase(self, witness);
        return sampleBitsUnchecked(self, bits) == 0;
    }

    function debugInputHash(State memory self) internal pure returns (bytes32 digest) {
        bytes memory buffer = self.inputBuffer;
        assembly ("memory-safe") {
            digest := keccak256(add(buffer, 0x20), mload(add(self, 0x20)))
        }
    }

    function _flush(State memory self) private pure {
        bytes memory buffer = self.inputBuffer;
        bytes32 digest;
        assembly ("memory-safe") {
            digest := keccak256(add(buffer, 0x20), mload(add(self, 0x20)))
        }
        if (buffer.length < DIGEST_BYTES) {
            buffer = new bytes(INITIAL_CAPACITY);
            self.inputBuffer = buffer;
        }
        assembly ("memory-safe") {
            mstore(add(buffer, 0x20), digest)
        }
        self.inputLen = DIGEST_BYTES;
        self.outputBlock = digest;
        self.outputIndex = DIGEST_BYTES;
    }

    function _sampleUint32(State memory self) private pure returns (uint32 value) {
        if (self.outputIndex == 0) {
            _flush(self);
        }

        unchecked {
            uint256 oldIndex = self.outputIndex;
            self.outputIndex = oldIndex - 4;
            return uint32(uint256(self.outputBlock >> (((DIGEST_BYTES - oldIndex) & 0xff) << 3)));
        }
    }

    function _appendBytes(State memory self, bytes memory data) private pure {
        uint256 oldLen = self.inputLen;
        uint256 appendLen = data.length;
        uint256 newLen = oldLen + appendLen;
        _ensureCapacity(self, newLen);

        bytes memory buffer = self.inputBuffer;
        assembly ("memory-safe") {
            mcopy(add(add(buffer, 0x20), oldLen), add(data, 0x20), appendLen)
        }

        self.inputLen = newLen;
    }

    function _appendBytesCalldata(
        State memory self,
        bytes calldata data,
        uint256 offset,
        uint256 appendLen
    ) private pure {
        uint256 oldLen = self.inputLen;
        uint256 newLen = oldLen + appendLen;
        _ensureCapacity(self, newLen);

        bytes memory buffer = self.inputBuffer;
        assembly ("memory-safe") {
            calldatacopy(add(add(buffer, 0x20), oldLen), add(data.offset, offset), appendLen)
        }

        self.inputLen = newLen;
    }

    function _appendBaseLE(State memory self, uint32 value) private pure {
        uint256 oldLen = self.inputLen;
        uint256 newLen = oldLen + 4;
        _ensureCapacity(self, newLen);

        bytes memory buffer = self.inputBuffer;
        uint256 bigEndian = _bswap32(value);
        assembly ("memory-safe") {
            mstore(add(add(buffer, 0x20), oldLen), shl(224, bigEndian))
        }

        self.inputLen = newLen;
        self.outputIndex = 0;
    }

    function _appendDigest32(State memory self, bytes32 digest) private pure {
        uint256 oldLen = self.inputLen;
        uint256 newLen = oldLen + DIGEST_BYTES;
        _ensureCapacity(self, newLen);

        bytes memory buffer = self.inputBuffer;
        assembly ("memory-safe") {
            mstore(add(add(buffer, 0x20), oldLen), digest)
        }

        self.inputLen = newLen;
        self.outputIndex = 0;
    }

    function _appendDigestU64LE(State memory self, bytes32 digest) private pure {
        uint256 oldLen = self.inputLen;
        uint256 newLen = oldLen + DIGEST_BYTES;
        _ensureCapacity(self, newLen);

        uint256 value = uint256(digest);
        uint256 reordered = (_bswap64(uint64(value >> 192)) << 192)
            | (_bswap64(uint64(value >> 128)) << 128) | (_bswap64(uint64(value >> 64)) << 64)
            | _bswap64(uint64(value));

        bytes memory buffer = self.inputBuffer;
        assembly ("memory-safe") {
            mstore(add(add(buffer, 0x20), oldLen), reordered)
        }

        self.inputLen = newLen;
        self.outputIndex = 0;
    }

    function _ensureCapacity(State memory self, uint256 minCapacity) private pure {
        uint256 capacity = self.inputBuffer.length;
        if (capacity >= minCapacity) {
            return;
        }

        uint256 newCapacity = capacity == 0 ? INITIAL_CAPACITY : capacity;
        while (newCapacity < minCapacity) {
            newCapacity <<= 1;
        }

        bytes memory newBuffer;
        bytes memory oldBuffer = self.inputBuffer;
        uint256 usedLen = self.inputLen;

        assembly ("memory-safe") {
            newBuffer := mload(0x40)
            mstore(newBuffer, newCapacity)
            mstore(0x40, add(newBuffer, and(add(add(newCapacity, 0x20), 0x1f), not(0x1f))))
            if usedLen {
                mcopy(add(newBuffer, 0x20), add(oldBuffer, 0x20), usedLen)
            }
        }

        self.inputBuffer = newBuffer;
    }

    function _bswap32(uint32 x) private pure returns (uint256) {
        return ((uint256(x) & 0x000000ff) << 24) | ((uint256(x) & 0x0000ff00) << 8)
            | ((uint256(x) & 0x00ff0000) >> 8) | ((uint256(x) & 0xff000000) >> 24);
    }

    function _bswap64(uint64 x) private pure returns (uint256 r) {
        assembly ("memory-safe") {
            // Swap adjacent bytes
            r := or(shr(8, and(x, 0xFF00FF00FF00FF00)), shl(8, and(x, 0x00FF00FF00FF00FF)))
            // Swap adjacent 16-bit pairs
            r := or(shr(16, and(r, 0xFFFF0000FFFF0000)), shl(16, and(r, 0x0000FFFF0000FFFF)))
            // Swap 32-bit halves
            r := or(shr(32, r), shl(32, and(r, 0xFFFFFFFF)))
        }
    }
}
