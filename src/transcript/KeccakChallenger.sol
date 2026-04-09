// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

library KeccakChallenger {
    uint256 internal constant KOALABEAR_MODULUS = 0x7f000001;
    uint256 internal constant KOALABEAR_MONTY_R = 0x01fffffe;
    uint256 internal constant KOALABEAR_SAMPLE_MASK = 0x7fffffff;
    uint256 internal constant DIGEST_BYTES = 32;

    struct State {
        bytes inputBuffer;
        bytes outputBuffer;
        uint256 outputIndex;
    }

    function observeBytes(State memory self, bytes memory data) internal pure {
        self.outputBuffer = new bytes(0);
        self.outputIndex = 0;
        self.inputBuffer = bytes.concat(self.inputBuffer, data);
    }

    function observeBase(State memory self, uint256 value) internal pure {
        require(value < KOALABEAR_MODULUS, "BASE_RANGE");

        // Rust serializes KoalaBear transcript observations in unique Montgomery form,
        // so convert the canonical field element before writing its little-endian bytes.
        uint256 unique = mulmod(value, KOALABEAR_MONTY_R, KOALABEAR_MODULUS);

        bytes memory data = new bytes(4);
        unchecked {
            data[0] = bytes1(uint8(unique));
            data[1] = bytes1(uint8(unique >> 8));
            data[2] = bytes1(uint8(unique >> 16));
            data[3] = bytes1(uint8(unique >> 24));
        }

        observeBytes(self, data);
    }

    function observeHashU8Digest(
        State memory self,
        bytes32 digest
    ) internal pure {
        observeBytes(self, abi.encodePacked(digest));
    }

    function observeHashU64Digest(
        State memory self,
        bytes32 digest
    ) internal pure {
        bytes memory digestBytes = abi.encodePacked(digest);
        bytes memory data = new bytes(DIGEST_BYTES);

        unchecked {
            for (uint256 word = 0; word < 4; ++word) {
                uint256 src = word * 8;
                uint256 dst = src;
                data[dst] = digestBytes[src + 7];
                data[dst + 1] = digestBytes[src + 6];
                data[dst + 2] = digestBytes[src + 5];
                data[dst + 3] = digestBytes[src + 4];
                data[dst + 4] = digestBytes[src + 3];
                data[dst + 5] = digestBytes[src + 2];
                data[dst + 6] = digestBytes[src + 1];
                data[dst + 7] = digestBytes[src];
            }
        }

        observeBytes(self, data);
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

    function _flush(State memory self) private pure {
        bytes memory output = abi.encodePacked(keccak256(self.inputBuffer));
        self.inputBuffer = output;
        self.outputBuffer = output;
        self.outputIndex = DIGEST_BYTES;
    }

    function _sampleByte(State memory self) private pure returns (uint8) {
        if (self.outputIndex == 0) {
            _flush(self);
        }

        unchecked {
            self.outputIndex -= 1;
            return uint8(self.outputBuffer[self.outputIndex]);
        }
    }

    function _sampleUint32(
        State memory self
    ) private pure returns (uint32 value) {
        unchecked {
            value = uint32(_sampleByte(self));
            value |= uint32(_sampleByte(self)) << 8;
            value |= uint32(_sampleByte(self)) << 16;
            value |= uint32(_sampleByte(self)) << 24;
        }
    }
}
