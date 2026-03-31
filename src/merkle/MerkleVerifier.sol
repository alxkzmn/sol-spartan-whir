// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Credits: the calldata hashing layout and queue-style reduction are adapted from
// https://github.com/privacy-scaling-explorations/sol-whir/src/merkle/MerkleVerifier.sol.
library MerkleVerifier {
    uint256 internal constant KOALABEAR_MODULUS = 0x7f000001;
    uint256 internal constant COEFF_MASK = 0xffffffff;
    uint256 internal constant DIGEST_MASK_20 = type(uint256).max << 96;

    error EmptyIndices();
    error LengthMismatch(uint256 indices, uint256 openings);
    error FlattenedRowLengthMismatch(uint256 values, uint256 expected);
    error IndicesNotStrictlyIncreasing(uint256 prev, uint256 next);
    error InsufficientDecommitments(uint256 expectedAtLeast, uint256 got);
    error TrailingDecommitments(uint256 consumed, uint256 total);
    error InvalidFinalLayer(uint256 layerSize, uint256 index);
    error FieldElementOutOfRange(uint256 value);

    function hashLeafBase(
        uint256[] calldata values,
        uint256 effectiveDigestBytes
    ) internal pure returns (bytes32 digest) {
        unchecked {
            for (uint256 i = 0; i < values.length; ++i) {
                uint256 value = values[i];
                if (value >= KOALABEAR_MODULUS) {
                    revert FieldElementOutOfRange(value);
                }
            }
        }

        assembly ("memory-safe") {
            let len := values.length
            let size := add(1, shl(2, len))
            let ptr := mload(0x40)
            let free := and(add(add(ptr, size), 31), not(31))
            mstore(0x40, free)

            mstore8(ptr, 0x00)

            let src := values.offset
            let dst := add(ptr, 1)
            let end := add(src, shl(5, len))
            for {

            } lt(src, end) {
                src := add(src, 0x20)
                dst := add(dst, 4)
            } {
                mstore(dst, shl(224, calldataload(src)))
            }

            digest := keccak256(ptr, size)
        }

        return _maskDigestTail(digest, effectiveDigestBytes);
    }

    function compressNode(
        bytes32 left,
        bytes32 right,
        uint256 effectiveDigestBytes
    ) internal pure returns (bytes32 digest) {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore8(ptr, 0x01)
            mstore(add(ptr, 0x01), left)
            mstore(add(ptr, 0x21), right)
            digest := keccak256(ptr, 65)
        }
        return _maskDigestTail(digest, effectiveDigestBytes);
    }

    function compressNode20(
        bytes32 left,
        bytes32 right
    ) internal pure returns (bytes32 digest) {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore8(ptr, 0x01)
            mstore(add(ptr, 0x01), left)
            mstore(add(ptr, 0x21), right)
            digest := keccak256(ptr, 65)
        }
        return bytes32(uint256(digest) & DIGEST_MASK_20);
    }

    function hashLeafBaseSlice(
        uint256[] calldata values,
        uint256 start,
        uint256 rowLen,
        uint256 effectiveDigestBytes
    ) internal pure returns (bytes32 digest) {
        unchecked {
            for (uint256 i = 0; i < rowLen; ++i) {
                uint256 value = values[start + i];
                if (value >= KOALABEAR_MODULUS) {
                    revert FieldElementOutOfRange(value);
                }
            }
        }

        assembly ("memory-safe") {
            let size := add(1, shl(2, rowLen))
            let ptr := mload(0x40)
            let free := and(add(add(ptr, size), 31), not(31))
            mstore(0x40, free)

            mstore8(ptr, 0x00)

            let src := add(values.offset, shl(5, start))
            let dst := add(ptr, 1)
            let end := add(src, shl(5, rowLen))
            for {

            } lt(src, end) {
                src := add(src, 0x20)
                dst := add(dst, 4)
            } {
                mstore(dst, shl(224, calldataload(src)))
            }

            digest := keccak256(ptr, size)
        }

        return _maskDigestTail(digest, effectiveDigestBytes);
    }

    function hashLeafBaseSlice20(
        uint256[] calldata values,
        uint256 start,
        uint256 rowLen
    ) internal pure returns (bytes32 digest) {
        unchecked {
            for (uint256 i = 0; i < rowLen; ++i) {
                uint256 value = values[start + i];
                if (value >= KOALABEAR_MODULUS) {
                    revert FieldElementOutOfRange(value);
                }
            }
        }

        assembly ("memory-safe") {
            let size := add(1, shl(2, rowLen))
            let ptr := mload(0x40)
            let free := and(add(add(ptr, size), 31), not(31))
            mstore(0x40, free)

            mstore8(ptr, 0x00)

            let src := add(values.offset, shl(5, start))
            let dst := add(ptr, 1)
            let end := add(src, shl(5, rowLen))
            for {

            } lt(src, end) {
                src := add(src, 0x20)
                dst := add(dst, 4)
            } {
                mstore(dst, shl(224, calldataload(src)))
            }

            digest := keccak256(ptr, size)
        }

        return bytes32(uint256(digest) & DIGEST_MASK_20);
    }

    function hashLeafExtensionSlice(
        uint256[] calldata values,
        uint256 start,
        uint256 rowLen,
        uint256 effectiveDigestBytes
    ) internal pure returns (bytes32 digest) {
        unchecked {
            for (uint256 i = 0; i < rowLen; ++i) {
                uint256 packed = values[start + i];
                uint256 c0 = packed >> 224;
                uint256 c1 = (packed >> 192) & COEFF_MASK;
                uint256 c2 = (packed >> 160) & COEFF_MASK;
                uint256 c3 = (packed >> 128) & COEFF_MASK;

                if (
                    c0 >= KOALABEAR_MODULUS ||
                    c1 >= KOALABEAR_MODULUS ||
                    c2 >= KOALABEAR_MODULUS ||
                    c3 >= KOALABEAR_MODULUS
                ) {
                    revert FieldElementOutOfRange(packed);
                }
            }
        }

        assembly ("memory-safe") {
            let size := add(1, shl(4, rowLen))
            let ptr := mload(0x40)
            // Each mstore writes 32 bytes while the destination advances by 16,
            // so reserve one extra half-word for the final overlapping tail.
            let free := and(add(add(ptr, add(size, 0x10)), 31), not(31))
            mstore(0x40, free)

            mstore8(ptr, 0x00)

            let src := add(values.offset, shl(5, start))
            let dst := add(ptr, 1)
            let end := add(src, shl(5, rowLen))
            for {

            } lt(src, end) {
                src := add(src, 0x20)
                dst := add(dst, 0x10)
            } {
                // The packed quartic encoding already stores c0..c3 as four big-endian
                // u32 words in the high 16 bytes, which is exactly the leaf preimage layout.
                mstore(dst, calldataload(src))
            }

            digest := keccak256(ptr, size)
        }

        return _maskDigestTail(digest, effectiveDigestBytes);
    }

    function hashLeafExtensionSlice20(
        uint256[] calldata values,
        uint256 start,
        uint256 rowLen
    ) internal pure returns (bytes32 digest) {
        unchecked {
            for (uint256 i = 0; i < rowLen; ++i) {
                uint256 packed = values[start + i];
                uint256 c0 = packed >> 224;
                uint256 c1 = (packed >> 192) & COEFF_MASK;
                uint256 c2 = (packed >> 160) & COEFF_MASK;
                uint256 c3 = (packed >> 128) & COEFF_MASK;

                if (
                    c0 >= KOALABEAR_MODULUS ||
                    c1 >= KOALABEAR_MODULUS ||
                    c2 >= KOALABEAR_MODULUS ||
                    c3 >= KOALABEAR_MODULUS
                ) {
                    revert FieldElementOutOfRange(packed);
                }
            }
        }

        assembly ("memory-safe") {
            let size := add(1, shl(4, rowLen))
            let ptr := mload(0x40)
            let free := and(add(add(ptr, add(size, 0x10)), 31), not(31))
            mstore(0x40, free)

            mstore8(ptr, 0x00)

            let src := add(values.offset, shl(5, start))
            let dst := add(ptr, 1)
            let end := add(src, shl(5, rowLen))
            for {

            } lt(src, end) {
                src := add(src, 0x20)
                dst := add(dst, 0x10)
            } {
                mstore(dst, calldataload(src))
            }

            digest := keccak256(ptr, size)
        }

        return bytes32(uint256(digest) & DIGEST_MASK_20);
    }

    function computeRootFromLeafHashes(
        uint256[] calldata indices,
        bytes32[] memory leafHashes,
        uint256 depth,
        bytes32[] calldata decommitments,
        uint256 effectiveDigestBytes
    ) internal pure returns (bytes32) {
        return
            _computeRootFromLeafHashes(
                _copyIndices(indices),
                leafHashes,
                depth,
                decommitments,
                effectiveDigestBytes
            );
    }

    function computeRootFromFlatBaseRows(
        uint256[] memory indices,
        uint256[] calldata flatValues,
        uint256 rowLen,
        uint256 depth,
        bytes32[] calldata decommitments,
        uint256 effectiveDigestBytes
    ) internal pure returns (bytes32) {
        uint256 expected = indices.length * rowLen;
        if (flatValues.length != expected) {
            revert FlattenedRowLengthMismatch(flatValues.length, expected);
        }

        bytes32[] memory leafHashes = new bytes32[](indices.length);
        unchecked {
            for (uint256 i = 0; i < indices.length; ++i) {
                leafHashes[i] = hashLeafBaseSlice(
                    flatValues,
                    i * rowLen,
                    rowLen,
                    effectiveDigestBytes
                );
            }
        }

        return
            _computeRootFromLeafHashes(
                indices,
                leafHashes,
                depth,
                decommitments,
                effectiveDigestBytes
            );
    }

    function computeRootFromFlatBaseRows20(
        uint256[] memory indices,
        uint256[] calldata flatValues,
        uint256 rowLen,
        uint256 depth,
        bytes32[] calldata decommitments
    ) internal pure returns (bytes32) {
        uint256 expected = indices.length * rowLen;
        if (flatValues.length != expected) {
            revert FlattenedRowLengthMismatch(flatValues.length, expected);
        }

        bytes32[] memory leafHashes = new bytes32[](indices.length);
        unchecked {
            for (uint256 i = 0; i < indices.length; ++i) {
                leafHashes[i] = hashLeafBaseSlice20(
                    flatValues,
                    i * rowLen,
                    rowLen
                );
            }
        }

        return
            _computeRootFromLeafHashes20(
                indices,
                leafHashes,
                depth,
                decommitments
            );
    }

    function computeRootFromFlatExtensionRows(
        uint256[] memory indices,
        uint256[] calldata flatValues,
        uint256 rowLen,
        uint256 depth,
        bytes32[] calldata decommitments,
        uint256 effectiveDigestBytes
    ) internal pure returns (bytes32) {
        uint256 expected = indices.length * rowLen;
        if (flatValues.length != expected) {
            revert FlattenedRowLengthMismatch(flatValues.length, expected);
        }

        bytes32[] memory leafHashes = new bytes32[](indices.length);
        unchecked {
            for (uint256 i = 0; i < indices.length; ++i) {
                leafHashes[i] = hashLeafExtensionSlice(
                    flatValues,
                    i * rowLen,
                    rowLen,
                    effectiveDigestBytes
                );
            }
        }

        return
            _computeRootFromLeafHashes(
                indices,
                leafHashes,
                depth,
                decommitments,
                effectiveDigestBytes
            );
    }

    function computeRootFromFlatExtensionRows20(
        uint256[] memory indices,
        uint256[] calldata flatValues,
        uint256 rowLen,
        uint256 depth,
        bytes32[] calldata decommitments
    ) internal pure returns (bytes32) {
        uint256 expected = indices.length * rowLen;
        if (flatValues.length != expected) {
            revert FlattenedRowLengthMismatch(flatValues.length, expected);
        }

        bytes32[] memory leafHashes = new bytes32[](indices.length);
        unchecked {
            for (uint256 i = 0; i < indices.length; ++i) {
                leafHashes[i] = hashLeafExtensionSlice20(
                    flatValues,
                    i * rowLen,
                    rowLen
                );
            }
        }

        return
            _computeRootFromLeafHashes20(
                indices,
                leafHashes,
                depth,
                decommitments
            );
    }

    function _computeRootFromLeafHashes(
        uint256[] memory indices,
        bytes32[] memory leafHashes,
        uint256 depth,
        bytes32[] calldata decommitments,
        uint256 effectiveDigestBytes
    ) private pure returns (bytes32) {
        _ensureSortedUnique(indices);
        if (indices.length != leafHashes.length) {
            revert LengthMismatch(indices.length, leafHashes.length);
        }

        uint256 frontierLen = indices.length;
        uint256[] memory frontierIndices = new uint256[](frontierLen);
        bytes32[] memory frontierHashes = new bytes32[](frontierLen);

        unchecked {
            for (uint256 i = 0; i < frontierLen; ++i) {
                frontierIndices[i] = indices[i];
                frontierHashes[i] = leafHashes[i];
            }
        }
        uint256[] memory nextIndices = new uint256[](frontierLen);
        bytes32[] memory nextHashes = new bytes32[](frontierLen);

        uint256 decommitmentCursor = 0;

        for (uint256 level = 0; level < depth; ++level) {
            uint256 nextLen = 0;
            uint256 cursor = 0;

            while (cursor < frontierLen) {
                uint256 node = frontierIndices[cursor];
                bytes32 hash = frontierHashes[cursor];
                bytes32 parentHash;

                if (
                    (node & 1) == 0 &&
                    cursor + 1 < frontierLen &&
                    frontierIndices[cursor + 1] == node + 1
                ) {
                    parentHash = compressNode(
                        hash,
                        frontierHashes[cursor + 1],
                        effectiveDigestBytes
                    );
                    cursor += 2;
                } else {
                    if (decommitmentCursor >= decommitments.length) {
                        revert InsufficientDecommitments(
                            decommitmentCursor + 1,
                            decommitments.length
                        );
                    }

                    bytes32 siblingHash = decommitments[decommitmentCursor];
                    decommitmentCursor += 1;
                    cursor += 1;

                    if ((node & 1) == 0) {
                        parentHash = compressNode(
                            hash,
                            siblingHash,
                            effectiveDigestBytes
                        );
                    } else {
                        parentHash = compressNode(
                            siblingHash,
                            hash,
                            effectiveDigestBytes
                        );
                    }
                }

                uint256 parentIndex = node >> 1;
                if (nextLen > 0 && nextIndices[nextLen - 1] == parentIndex) {
                    nextHashes[nextLen - 1] = parentHash;
                } else {
                    nextIndices[nextLen] = parentIndex;
                    nextHashes[nextLen] = parentHash;
                    nextLen += 1;
                }
            }

            uint256[] memory tempIndices = frontierIndices;
            frontierIndices = nextIndices;
            nextIndices = tempIndices;

            bytes32[] memory tempHashes = frontierHashes;
            frontierHashes = nextHashes;
            nextHashes = tempHashes;

            frontierLen = nextLen;
        }

        if (decommitmentCursor != decommitments.length) {
            revert TrailingDecommitments(
                decommitmentCursor,
                decommitments.length
            );
        }

        if (frontierLen != 1 || frontierIndices[0] != 0) {
            revert InvalidFinalLayer(
                frontierLen,
                frontierLen == 0 ? type(uint256).max : frontierIndices[0]
            );
        }

        return frontierHashes[0];
    }

    function _computeRootFromLeafHashes20(
        uint256[] memory indices,
        bytes32[] memory leafHashes,
        uint256 depth,
        bytes32[] calldata decommitments
    ) private pure returns (bytes32) {
        _ensureSortedUnique(indices);
        if (indices.length != leafHashes.length) {
            revert LengthMismatch(indices.length, leafHashes.length);
        }

        uint256 frontierLen = indices.length;
        uint256[] memory frontierIndices = new uint256[](frontierLen);
        bytes32[] memory frontierHashes = new bytes32[](frontierLen);

        unchecked {
            for (uint256 i = 0; i < frontierLen; ++i) {
                frontierIndices[i] = indices[i];
                frontierHashes[i] = leafHashes[i];
            }
        }
        uint256[] memory nextIndices = new uint256[](frontierLen);
        bytes32[] memory nextHashes = new bytes32[](frontierLen);

        uint256 decommitmentCursor = 0;

        for (uint256 level = 0; level < depth; ++level) {
            uint256 nextLen = 0;
            uint256 cursor = 0;

            while (cursor < frontierLen) {
                uint256 node = frontierIndices[cursor];
                bytes32 hash = frontierHashes[cursor];
                bytes32 parentHash;

                if (
                    (node & 1) == 0 &&
                    cursor + 1 < frontierLen &&
                    frontierIndices[cursor + 1] == node + 1
                ) {
                    parentHash = compressNode20(
                        hash,
                        frontierHashes[cursor + 1]
                    );
                    cursor += 2;
                } else {
                    if (decommitmentCursor >= decommitments.length) {
                        revert InsufficientDecommitments(
                            decommitmentCursor + 1,
                            decommitments.length
                        );
                    }

                    bytes32 siblingHash = decommitments[decommitmentCursor];
                    decommitmentCursor += 1;
                    cursor += 1;

                    if ((node & 1) == 0) {
                        parentHash = compressNode20(hash, siblingHash);
                    } else {
                        parentHash = compressNode20(siblingHash, hash);
                    }
                }

                uint256 parentIndex = node >> 1;
                if (nextLen > 0 && nextIndices[nextLen - 1] == parentIndex) {
                    nextHashes[nextLen - 1] = parentHash;
                } else {
                    nextIndices[nextLen] = parentIndex;
                    nextHashes[nextLen] = parentHash;
                    nextLen += 1;
                }
            }

            uint256[] memory tempIndices = frontierIndices;
            frontierIndices = nextIndices;
            nextIndices = tempIndices;

            bytes32[] memory tempHashes = frontierHashes;
            frontierHashes = nextHashes;
            nextHashes = tempHashes;

            frontierLen = nextLen;
        }

        if (decommitmentCursor != decommitments.length) {
            revert TrailingDecommitments(
                decommitmentCursor,
                decommitments.length
            );
        }

        if (frontierLen != 1 || frontierIndices[0] != 0) {
            revert InvalidFinalLayer(
                frontierLen,
                frontierLen == 0 ? type(uint256).max : frontierIndices[0]
            );
        }

        return frontierHashes[0];
    }

    function computeRootFromBaseRows(
        uint256[] calldata indices,
        uint256[][] calldata openedRows,
        uint256 depth,
        bytes32[] calldata decommitments,
        uint256 effectiveDigestBytes
    ) internal pure returns (bytes32) {
        if (indices.length != openedRows.length) {
            revert LengthMismatch(indices.length, openedRows.length);
        }

        bytes32[] memory leafHashes = new bytes32[](openedRows.length);
        unchecked {
            for (uint256 i = 0; i < openedRows.length; ++i) {
                leafHashes[i] = hashLeafBase(
                    openedRows[i],
                    effectiveDigestBytes
                );
            }
        }

        return
            computeRootFromLeafHashes(
                indices,
                leafHashes,
                depth,
                decommitments,
                effectiveDigestBytes
            );
    }

    function verifyBaseRows(
        bytes32 expectedRoot,
        uint256[] calldata indices,
        uint256[][] calldata openedRows,
        uint256 depth,
        bytes32[] calldata decommitments,
        uint256 effectiveDigestBytes
    ) internal pure returns (bool) {
        return
            computeRootFromBaseRows(
                indices,
                openedRows,
                depth,
                decommitments,
                effectiveDigestBytes
            ) == expectedRoot;
    }

    function _copyIndices(
        uint256[] calldata indices
    ) private pure returns (uint256[] memory copied) {
        copied = new uint256[](indices.length);
        unchecked {
            for (uint256 i = 0; i < indices.length; ++i) {
                copied[i] = indices[i];
            }
        }
    }

    function _ensureSortedUnique(uint256[] memory indices) private pure {
        if (indices.length == 0) {
            revert EmptyIndices();
        }

        unchecked {
            for (uint256 i = 1; i < indices.length; ++i) {
                if (indices[i - 1] >= indices[i]) {
                    revert IndicesNotStrictlyIncreasing(
                        indices[i - 1],
                        indices[i]
                    );
                }
            }
        }
    }

    function _maskDigestTail(
        bytes32 digest,
        uint256 effectiveDigestBytes
    ) private pure returns (bytes32) {
        uint256 keep = _clampEffectiveDigestBytes(effectiveDigestBytes);
        if (keep == 32) {
            return digest;
        }

        unchecked {
            uint256 clearBytes = 32 - keep;
            uint256 mask = type(uint256).max << (clearBytes * 8);
            return bytes32(uint256(digest) & mask);
        }
    }

    function _clampEffectiveDigestBytes(
        uint256 effectiveDigestBytes
    ) private pure returns (uint256) {
        if (effectiveDigestBytes == 0) {
            return 1;
        }
        if (effectiveDigestBytes > 32) {
            return 32;
        }
        return effectiveDigestBytes;
    }
}
