// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

library KeccakChallenger {
    uint256 internal constant KOALABEAR_MODULUS = 0x7f000001;
    uint256 internal constant KOALABEAR_MONTY_R = 0x01fffffe;
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

    function observeBase(State memory self, uint256 value) internal pure {
        require(value < KOALABEAR_MODULUS, "BASE_RANGE");

        // Rust serializes KoalaBear transcript observations in unique Montgomery form,
        // so convert the canonical field element before writing its little-endian bytes.
        _appendBaseLE(
            self,
            uint32(mulmod(value, KOALABEAR_MONTY_R, KOALABEAR_MODULUS))
        );
    }

    function observeHashU8Digest(
        State memory self,
        bytes32 digest
    ) internal pure {
        _appendDigest32(self, digest);
    }

    function observeHashU64Digest(
        State memory self,
        bytes32 digest
    ) internal pure {
        _appendDigestU64LE(self, digest);
    }

    function observePackedExt4(
        State memory self,
        uint256 packed
    ) internal pure {
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

            let modulus := 0x7f000001
            let montyR := 0x01fffffe
            let mask := 0xffffffff
            let dst := add(add(buffer, 0x20), oldLen)

            mstore(
                dst,
                or(
                    or(
                        shl(
                            224,
                            bswap32(mulmod(shr(224, packed), montyR, modulus))
                        ),
                        shl(
                            192,
                            bswap32(
                                mulmod(
                                    and(shr(192, packed), mask),
                                    montyR,
                                    modulus
                                )
                            )
                        )
                    ),
                    or(
                        shl(
                            160,
                            bswap32(
                                mulmod(
                                    and(shr(160, packed), mask),
                                    montyR,
                                    modulus
                                )
                            )
                        ),
                        shl(
                            128,
                            bswap32(
                                mulmod(
                                    and(shr(128, packed), mask),
                                    montyR,
                                    modulus
                                )
                            )
                        )
                    )
                )
            )
        }

        self.inputLen = newLen;
        self.outputIndex = 0;
    }

    function sampleBase(State memory self) internal pure returns (uint256) {
        while (true) {
            uint256 value = uint256(_sampleUint32(self)) &
                KOALABEAR_SAMPLE_MASK;
            if (value < KOALABEAR_MODULUS) {
                return value;
            }
        }

        revert("UNREACHABLE");
    }

    function sampleBits(
        State memory self,
        uint256 bits
    ) internal pure returns (uint256) {
        require(bits < 256, "BITS_WIDTH");
        if (bits == 0) {
            return 0;
        }

        require((uint256(1) << bits) <= KOALABEAR_MODULUS, "BITS_RANGE");
        return uint256(_sampleUint32(self)) & ((uint256(1) << bits) - 1);
    }

    function sampleExt4Coeffs(
        State memory self
    ) internal pure returns (uint256[4] memory coeffs) {
        unchecked {
            for (uint256 i = 0; i < 4; ++i) {
                coeffs[i] = sampleBase(self);
            }
        }
    }

    function sampleExt8Coeffs(
        State memory self
    ) internal pure returns (uint256[8] memory coeffs) {
        unchecked {
            for (uint256 i = 0; i < 8; ++i) {
                coeffs[i] = sampleBase(self);
            }
        }
    }

    function checkWitness(
        State memory self,
        uint256 bits,
        uint256 witness
    ) internal pure returns (bool) {
        if (bits == 0) {
            return true;
        }

        observeBase(self, witness);
        return sampleBits(self, bits) == 0;
    }

    function debugInputHash(
        State memory self
    ) internal pure returns (bytes32 digest) {
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
        _ensureCapacity(self, DIGEST_BYTES);
        buffer = self.inputBuffer;
        assembly ("memory-safe") {
            mstore(add(buffer, 0x20), digest)
        }
        self.inputLen = DIGEST_BYTES;
        self.outputBlock = digest;
        self.outputIndex = DIGEST_BYTES;
    }

    function _sampleByte(State memory self) private pure returns (uint8) {
        if (self.outputIndex == 0) {
            _flush(self);
        }

        unchecked {
            self.outputIndex -= 1;
            return
                uint8(
                    uint256(self.outputBlock >> ((31 - self.outputIndex) << 3))
                );
        }
    }

    function _sampleUint32(
        State memory self
    ) private pure returns (uint32 value) {
        if (self.outputIndex >= 4) {
            unchecked {
                uint256 oldIndex = self.outputIndex;
                self.outputIndex = oldIndex - 4;
                return
                    uint32(
                        uint256(
                            self.outputBlock >>
                                (((DIGEST_BYTES - oldIndex) & 0xff) << 3)
                        )
                    );
            }
        }

        unchecked {
            value = uint32(_sampleByte(self));
            value |= uint32(_sampleByte(self)) << 8;
            value |= uint32(_sampleByte(self)) << 16;
            value |= uint32(_sampleByte(self)) << 24;
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

    function _appendDigestU64LE(
        State memory self,
        bytes32 digest
    ) private pure {
        uint256 oldLen = self.inputLen;
        uint256 newLen = oldLen + DIGEST_BYTES;
        _ensureCapacity(self, newLen);

        uint256 value = uint256(digest);
        uint256 reordered = (_bswap64(uint64(value >> 192)) << 192) |
            (_bswap64(uint64(value >> 128)) << 128) |
            (_bswap64(uint64(value >> 64)) << 64) |
            _bswap64(uint64(value));

        bytes memory buffer = self.inputBuffer;
        assembly ("memory-safe") {
            mstore(add(add(buffer, 0x20), oldLen), reordered)
        }

        self.inputLen = newLen;
        self.outputIndex = 0;
    }

    function _ensureCapacity(
        State memory self,
        uint256 minCapacity
    ) private pure {
        uint256 capacity = self.inputBuffer.length;
        if (capacity >= minCapacity) {
            return;
        }

        uint256 newCapacity = capacity == 0 ? INITIAL_CAPACITY : capacity;
        while (newCapacity < minCapacity) {
            newCapacity <<= 1;
        }

        bytes memory newBuffer = new bytes(newCapacity);
        bytes memory oldBuffer = self.inputBuffer;
        uint256 usedLen = self.inputLen;

        if (usedLen != 0) {
            assembly ("memory-safe") {
                mcopy(add(newBuffer, 0x20), add(oldBuffer, 0x20), usedLen)
            }
        }

        self.inputBuffer = newBuffer;
    }

    function _bswap32(uint32 x) private pure returns (uint256) {
        return
            ((uint256(x) & 0x000000ff) << 24) |
            ((uint256(x) & 0x0000ff00) << 8) |
            ((uint256(x) & 0x00ff0000) >> 8) |
            ((uint256(x) & 0xff000000) >> 24);
    }

    function _bswap64(uint64 x) private pure returns (uint256) {
        uint256 y = uint256(x);
        return
            ((y & 0x00000000000000ff) << 56) |
            ((y & 0x000000000000ff00) << 40) |
            ((y & 0x0000000000ff0000) << 24) |
            ((y & 0x00000000ff000000) << 8) |
            ((y & 0x000000ff00000000) >> 8) |
            ((y & 0x0000ff0000000000) >> 24) |
            ((y & 0x00ff000000000000) >> 40) |
            ((y & 0xff00000000000000) >> 56);
    }
}
