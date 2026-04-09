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
    error InvalidEffectiveDigestBytes(uint256 value);

    function hashLeafBase(
        uint256[] calldata values,
        uint256 effectiveDigestBytes
    ) internal pure returns (bytes32 digest) {
        assembly ("memory-safe") {
            let len := values.length
            let size := add(1, shl(2, len))
            let ptr := mload(0x40)

            mstore8(ptr, 0x00)

            let modulus := KOALABEAR_MODULUS
            let src := values.offset
            let dst := add(ptr, 1)
            let end := add(src, shl(5, len))
            for {

            } lt(src, end) {
                src := add(src, 0x20)
                dst := add(dst, 4)
            } {
                let v := calldataload(src)
                if iszero(lt(v, modulus)) {
                    mstore(
                        0x00,
                        0xf512b67800000000000000000000000000000000000000000000000000000000
                    )
                    mstore(0x04, v)
                    revert(0x00, 0x24)
                }
                mstore(dst, shl(224, v))
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
        assembly ("memory-safe") {
            let size := add(1, shl(2, rowLen))
            let ptr := mload(0x40)

            mstore8(ptr, 0x00)

            let modulus := KOALABEAR_MODULUS
            let src := add(values.offset, shl(5, start))
            let dst := add(ptr, 1)
            let end := add(src, shl(5, rowLen))
            for {

            } lt(src, end) {
                src := add(src, 0x20)
                dst := add(dst, 4)
            } {
                let v := calldataload(src)
                if iszero(lt(v, modulus)) {
                    mstore(
                        0x00,
                        0xf512b67800000000000000000000000000000000000000000000000000000000
                    )
                    mstore(0x04, v)
                    revert(0x00, 0x24)
                }
                mstore(dst, shl(224, v))
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
        assembly ("memory-safe") {
            let size := add(1, shl(2, rowLen))
            let ptr := mload(0x40)

            mstore8(ptr, 0x00)

            let modulus := KOALABEAR_MODULUS
            let src := add(values.offset, shl(5, start))
            let dst := add(ptr, 1)
            let end := add(src, shl(5, rowLen))
            for {

            } lt(src, end) {
                src := add(src, 0x20)
                dst := add(dst, 4)
            } {
                let v := calldataload(src)
                if iszero(lt(v, modulus)) {
                    mstore(
                        0x00,
                        0xf512b67800000000000000000000000000000000000000000000000000000000
                    )
                    mstore(0x04, v)
                    revert(0x00, 0x24)
                }
                mstore(dst, shl(224, v))
            }

            digest := and(keccak256(ptr, size), not(sub(shl(96, 1), 1)))
        }
    }

    function hashLeafExtensionSlice(
        uint256[] calldata values,
        uint256 start,
        uint256 rowLen,
        uint256 effectiveDigestBytes
    ) internal pure returns (bytes32 digest) {
        assembly ("memory-safe") {
            let size := add(1, shl(4, rowLen))
            let ptr := mload(0x40)

            mstore8(ptr, 0x00)

            let modulus := KOALABEAR_MODULUS
            let coeffMask := COEFF_MASK
            let src := add(values.offset, shl(5, start))
            let dst := add(ptr, 1)
            let end := add(src, shl(5, rowLen))
            for {

            } lt(src, end) {
                src := add(src, 0x20)
                dst := add(dst, 0x10)
            } {
                let packed := calldataload(src)
                let c0 := shr(224, packed)
                let c1 := and(shr(192, packed), coeffMask)
                let c2 := and(shr(160, packed), coeffMask)
                let c3 := and(shr(128, packed), coeffMask)
                if or(
                    or(iszero(lt(c0, modulus)), iszero(lt(c1, modulus))),
                    or(iszero(lt(c2, modulus)), iszero(lt(c3, modulus)))
                ) {
                    mstore(
                        0x00,
                        0xf512b67800000000000000000000000000000000000000000000000000000000
                    )
                    mstore(0x04, packed)
                    revert(0x00, 0x24)
                }
                mstore(dst, packed)
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
        assembly ("memory-safe") {
            let size := add(1, shl(4, rowLen))
            let ptr := mload(0x40)

            mstore8(ptr, 0x00)

            let modulus := KOALABEAR_MODULUS
            let coeffMask := COEFF_MASK
            let src := add(values.offset, shl(5, start))
            let dst := add(ptr, 1)
            let end := add(src, shl(5, rowLen))
            for {

            } lt(src, end) {
                src := add(src, 0x20)
                dst := add(dst, 0x10)
            } {
                let packed := calldataload(src)
                let c0 := shr(224, packed)
                let c1 := and(shr(192, packed), coeffMask)
                let c2 := and(shr(160, packed), coeffMask)
                let c3 := and(shr(128, packed), coeffMask)
                if or(
                    or(iszero(lt(c0, modulus)), iszero(lt(c1, modulus))),
                    or(iszero(lt(c2, modulus)), iszero(lt(c3, modulus)))
                ) {
                    mstore(
                        0x00,
                        0xf512b67800000000000000000000000000000000000000000000000000000000
                    )
                    mstore(0x04, packed)
                    revert(0x00, 0x24)
                }
                mstore(dst, packed)
            }

            digest := and(keccak256(ptr, size), not(sub(shl(96, 1), 1)))
        }
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
    ) private pure returns (bytes32 root) {
        _ensureSortedUnique(indices);
        if (indices.length != leafHashes.length) {
            revert LengthMismatch(indices.length, leafHashes.length);
        }
        uint256 expectedDecommitments = indices.length * depth;
        if (decommitments.length < expectedDecommitments) {
            revert InsufficientDecommitments(
                expectedDecommitments,
                decommitments.length
            );
        }
        if (decommitments.length > expectedDecommitments) {
            revert TrailingDecommitments(
                expectedDecommitments,
                decommitments.length
            );
        }

        unchecked {
            for (uint256 i = 0; i < indices.length; ++i) {
                uint256 node = indices[i];
                bytes32 hash = leafHashes[i];
                uint256 pathOffset = i * depth;

                for (uint256 level = 0; level < depth; ++level) {
                    bytes32 siblingHash = decommitments[pathOffset + level];
                    hash = (node & 1) == 0
                        ? compressNode(hash, siblingHash, effectiveDigestBytes)
                        : compressNode(siblingHash, hash, effectiveDigestBytes);
                    node >>= 1;
                }

                if (i == 0) {
                    root = hash;
                } else if (hash != root) {
                    revert InvalidFinalLayer(indices.length, i);
                }
            }
        }
    }

    function _computeRootFromLeafHashes20(
        uint256[] memory indices,
        bytes32[] memory leafHashes,
        uint256 depth,
        bytes32[] calldata decommitments
    ) private pure returns (bytes32 root) {
        // Assembly-optimized linear authentication path verification.
        // For each query, walks from leaf to root using per-query sibling paths
        // from calldata, then checks all queries agree on the same root.
        assembly ("memory-safe") {
            let n := mload(indices)

            // Validate decommitments.length == n * depth
            let expected := mul(n, depth)
            let decommLen := decommitments.length
            if lt(decommLen, expected) {
                mstore(
                    0x00,
                    0x90196ee300000000000000000000000000000000000000000000000000000000
                )
                mstore(0x04, expected)
                mstore(0x24, decommLen)
                revert(0x00, 0x44)
            }
            if gt(decommLen, expected) {
                mstore(
                    0x00,
                    0xb48ec3d200000000000000000000000000000000000000000000000000000000
                )
                mstore(0x04, expected)
                mstore(0x24, decommLen)
                revert(0x00, 0x44)
            }

            // Mask: top 160 bits set, bottom 96 bits clear (DIGEST_MASK_20)
            let digestMask := not(sub(shl(96, 1), 1))

            // Allocate 65-byte keccak scratch area
            let scratch := mload(0x40)
            mstore(0x40, add(scratch, 65))
            // Pre-store the 0x01 internal-node domain separator
            mstore8(scratch, 0x01)

            let idxPtr := add(indices, 0x20)
            let hashPtr := add(leafHashes, 0x20)
            let decommBase := decommitments.offset
            // stride = depth * 32 bytes per sibling
            let pathStride := shl(5, depth)

            for {
                let i := 0
            } lt(i, n) {
                i := add(i, 1)
            } {
                let node := mload(add(idxPtr, shl(5, i)))
                let hash := mload(add(hashPtr, shl(5, i)))
                let sibPtr := add(decommBase, mul(i, pathStride))

                for {
                    let level := 0
                } lt(level, depth) {
                    level := add(level, 1)
                } {
                    let sibling := calldataload(sibPtr)
                    sibPtr := add(sibPtr, 0x20)

                    // If node is even (left child): compress(hash, sibling)
                    // If node is odd (right child): compress(sibling, hash)
                    switch and(node, 1)
                    case 0 {
                        mstore(add(scratch, 1), hash)
                        mstore(add(scratch, 0x21), sibling)
                    }
                    default {
                        mstore(add(scratch, 1), sibling)
                        mstore(add(scratch, 0x21), hash)
                    }
                    hash := and(keccak256(scratch, 65), digestMask)
                    node := shr(1, node)
                }

                // First query sets the root; subsequent queries must match.
                switch i
                case 0 {
                    root := hash
                }
                default {
                    if iszero(eq(hash, root)) {
                        mstore(
                            0x00,
                            0x1d72965600000000000000000000000000000000000000000000000000000000
                        )
                        mstore(0x04, n)
                        mstore(0x24, i)
                        revert(0x00, 0x44)
                    }
                }
            }
        }
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
        uint256 keep = _validateEffectiveDigestBytes(effectiveDigestBytes);
        if (keep == 32) {
            return digest;
        }

        unchecked {
            uint256 clearBytes = 32 - keep;
            uint256 mask = type(uint256).max << (clearBytes * 8);
            return bytes32(uint256(digest) & mask);
        }
    }

    function _validateEffectiveDigestBytes(
        uint256 effectiveDigestBytes
    ) private pure returns (uint256) {
        if (effectiveDigestBytes == 0 || effectiveDigestBytes > 32) {
            revert InvalidEffectiveDigestBytes(effectiveDigestBytes);
        }
        return effectiveDigestBytes;
    }
}
