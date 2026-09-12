// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @dev Each opening contains BE-u32 leaf scalars followed by full 32-byte sibling
/// encodings. Keccak digests retain their first 30 bytes and zero the last two.
library LeanVmMerkle {
    uint256 internal constant MODULUS = 2_130_706_433;
    uint256 internal constant DIGEST_MASK = type(uint256).max << 16;

    /// @dev The batch contains full rows at sorted unique query indices, followed
    /// by 30-byte sibling digests in bottom-up, left-to-right frontier order.
    /// Query indices come from Fiat-Shamir; duplicate queries reuse one row.
    /// Returned row offsets follow the original query order. No transcript bytes
    /// are consumed or observed by this transport decoder.
    function openBatch(
        bytes calldata proof,
        uint256 offset,
        uint256 leafScalars,
        uint256 height,
        uint256[] memory indices,
        bytes32 expectedRoot
    ) internal pure returns (uint256[] memory leafOffsets, uint256 nextOffset) {
        require(height < 31, "MERKLE_INDEX");
        require(indices.length != 0, "MERKLE_EMPTY");
        require((uint256(expectedRoot) & 0xffff) == 0, "ROOT_DIGEST");
        leafOffsets = new uint256[](indices.length);
        uint256 scratchStart;
        assembly ("memory-safe") { scratchStart := mload(0x40) }
        (uint256[] memory sorted, uint256 unique) = _sortedUnique(height, indices);
        uint256 rowBytes = leafScalars * 4;
        for (uint256 i; i < indices.length; ++i) {
            uint256 low;
            uint256 high = unique;
            while (low < high) {
                uint256 middle = (low + high) >> 1;
                if (sorted[middle] < indices[i]) low = middle + 1;
                else high = middle;
            }
            leafOffsets[i] = offset + low * rowBytes;
        }
        bytes32[] memory hashes = new bytes32[](unique);
        nextOffset = _openCanonicalBatch(
            proof, offset, leafScalars, height, sorted, hashes, unique, expectedRoot
        );
        // Only row offsets escape. They were allocated before the temporary
        // sorting, hashing, and frontier buffers.
        assembly ("memory-safe") { mstore(0x40, scratchStart) }
    }

    /// @dev The two C1 roots open the same sorted, deduplicated query set. This
    /// keeps its row-number map and frontier buffers across both authentications.
    function openTwoBatches(
        bytes calldata proof,
        uint256 offset,
        uint256 leafScalars,
        uint256 height,
        uint256[] memory indices,
        bytes32 primaryRoot,
        bytes32 secondaryRoot
    )
        internal
        pure
        returns (uint256[] memory rowNumbers, uint256 secondaryOffset, uint256 nextOffset)
    {
        require(height < 31, "MERKLE_INDEX");
        require(indices.length != 0, "MERKLE_EMPTY");
        require((uint256(primaryRoot) & 0xffff) == 0, "ROOT_DIGEST");
        rowNumbers = new uint256[](indices.length);
        uint256 scratchStart;
        assembly ("memory-safe") { scratchStart := mload(0x40) }
        (uint256[] memory sorted, uint256 unique) = _sortedUnique(height, indices);
        for (uint256 i; i < indices.length; ++i) {
            uint256 low;
            uint256 high = unique;
            while (low < high) {
                uint256 middle = (low + high) >> 1;
                if (sorted[middle] < indices[i]) low = middle + 1;
                else high = middle;
            }
            rowNumbers[i] = low;
        }

        // The single-root path may use `sorted` as its in-place node frontier.
        // Keep it intact here so the second root can reuse the same geometry.
        uint256[] memory nodes = new uint256[](unique);
        bytes32[] memory hashes = new bytes32[](unique);
        assembly ("memory-safe") {
            mcopy(add(nodes, 32), add(sorted, 32), shl(5, unique))
        }
        secondaryOffset = _openCanonicalBatch(
            proof, offset, leafScalars, height, nodes, hashes, unique, primaryRoot
        );

        require((uint256(secondaryRoot) & 0xffff) == 0, "ROOT_DIGEST");
        assembly ("memory-safe") {
            mcopy(add(nodes, 32), add(sorted, 32), shl(5, unique))
        }
        nextOffset = _openCanonicalBatch(
            proof, secondaryOffset, leafScalars, height, nodes, hashes, unique, secondaryRoot
        );
        assembly ("memory-safe") { mstore(0x40, scratchStart) }
    }

    function _sortedUnique(uint256 height, uint256[] memory indices)
        private
        pure
        returns (uint256[] memory sorted, uint256 unique)
    {
        sorted = new uint256[](indices.length);
        uint256 limit = uint256(1) << height;
        for (uint256 i; i < indices.length; ++i) {
            uint256 value = indices[i];
            require(value < limit, "MERKLE_INDEX");
            uint256 j = i;
            while (j != 0 && sorted[j - 1] > value) {
                sorted[j] = sorted[j - 1];
                --j;
            }
            sorted[j] = value;
        }
        for (uint256 i; i < sorted.length; ++i) {
            if (unique == 0 || sorted[i] != sorted[unique - 1]) {
                sorted[unique++] = sorted[i];
            }
        }
    }

    function _openCanonicalBatch(
        bytes calldata proof,
        uint256 offset,
        uint256 leafScalars,
        uint256 height,
        uint256[] memory nodes,
        bytes32[] memory hashes,
        uint256 unique,
        bytes32 expectedRoot
    ) private pure returns (uint256 nextOffset) {
        uint256 rowBytes = leafScalars * 4;
        nextOffset = offset + unique * rowBytes;
        require(nextOffset <= proof.length, "MERKLE_END");
        uint256 scratchStart;
        assembly ("memory-safe") { scratchStart := mload(0x40) }
        uint256 leafBytes = rowBytes + 1;
        bytes memory scratch = new bytes(leafBytes > 65 ? leafBytes : 65);
        for (uint256 i; i < unique; ++i) {
            uint256 rowOffset = offset + i * rowBytes;
            uint256 j;
            for (; j + 8 <= leafScalars; j += 8) {
                uint256 invalidFields;
                assembly ("memory-safe") {
                    let word := calldataload(add(add(proof.offset, rowOffset), shl(2, j)))
                    let high := 0x8000000080000000800000008000000080000000800000008000000080000000
                    // Masking each lane to 31 bits prevents carries into an
                    // adjacent lane. The bias tests every coefficient against p.
                    invalidFields := or(
                        and(word, high),
                        and(add(
                            and(word, 0x7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff),
                            0x00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff
                        ), high)
                    )
                }
                require(invalidFields == 0, "LEAF_SCALAR");
            }
            for (; j < leafScalars; ++j) {
                uint256 value;
                assembly ("memory-safe") {
                    value := shr(224, calldataload(add(add(proof.offset, rowOffset), shl(2, j))))
                }
                require(value < MODULUS, "LEAF_SCALAR");
            }
            bytes32 hash;
            assembly ("memory-safe") {
                mstore8(add(scratch, 32), 0)
                calldatacopy(add(scratch, 33), add(proof.offset, rowOffset), rowBytes)
                hash := and(keccak256(add(scratch, 32), leafBytes), not(0xffff))
            }
            hashes[i] = hash;
        }
        // In-place reduction writes only entries already consumed. A paired
        // sibling is read before its parent overwrites an earlier frontier slot.
        uint256 live = unique;
        assembly ("memory-safe") {
            let nodeWords := add(nodes, 32)
            let digests := add(hashes, 32)
            let buffer := add(scratch, 32)
            mstore8(buffer, 1)
            for { let level := 0 } lt(level, height) { level := add(level, 1) } {
                let read := 0
                let written := 0
                for { } lt(read, live) { } {
                    let position := shl(5, read)
                    let node := mload(add(nodeWords, position))
                    let current := mload(add(digests, position))
                    let sibling
                    let paired := 0
                    if and(iszero(and(node, 1)), lt(add(read, 1), live)) {
                        paired := eq(mload(add(nodeWords, add(position, 32))), add(node, 1))
                    }
                    switch paired
                    case 1 {
                        sibling := mload(add(digests, add(position, 32)))
                        read := add(read, 2)
                    }
                    default {
                        sibling := and(calldataload(add(proof.offset, nextOffset)), not(0xffff))
                        nextOffset := add(nextOffset, 30)
                        read := add(read, 1)
                    }
                    switch and(node, 1)
                    case 0 {
                        mstore(add(buffer, 1), current)
                        mstore(add(buffer, 33), sibling)
                    }
                    default {
                        mstore(add(buffer, 1), sibling)
                        mstore(add(buffer, 33), current)
                    }
                    let parent := and(keccak256(buffer, 65), not(0xffff))
                    mstore(add(nodeWords, shl(5, written)), shr(1, node))
                    mstore(add(digests, shl(5, written)), parent)
                    written := add(written, 1)
                }
                live := written
            }
        }
        // The frontier geometry determines the sibling count. Reads beyond
        // this calldata slice cannot be accepted, including at the final node.
        require(nextOffset <= proof.length, "MERKLE_END");
        require(live == 1 && nodes[0] == 0 && hashes[0] == expectedRoot, "MERKLE_ROOT");
        assembly ("memory-safe") { mstore(0x40, scratchStart) }
    }

    function open(
        bytes calldata proof,
        uint256 offset,
        uint256 leafScalars,
        uint256 height,
        uint256 index,
        bytes32 expectedRoot
    ) internal pure returns (uint256[] memory leaf, uint256 nextOffset) {
        require(height < 31 && index < (1 << height), "MERKLE_INDEX");
        require((uint256(expectedRoot) & 0xffff) == 0, "ROOT_DIGEST");
        nextOffset = offset + leafScalars * 4 + height * 32;
        require(nextOffset <= proof.length, "MERKLE_END");
        leaf = new uint256[](leafScalars);
        bytes memory encoded = new bytes(1 + leafScalars * 4);
        for (uint256 i; i < leafScalars; ++i) {
            uint256 value = uint32(bytes4(proof[offset + 4 * i:offset + 4 * i + 4]));
            require(value < MODULUS, "LEAF_SCALAR");
            leaf[i] = value;
        }
        assembly ("memory-safe") {
            calldatacopy(add(encoded, 33), add(proof.offset, offset), mul(leafScalars, 4))
        }
        bytes32 current = bytes32(uint256(keccak256(encoded)) & DIGEST_MASK);
        offset += leafScalars * 4;
        for (uint256 i; i < height; ++i) {
            bytes32 sibling = bytes32(proof[offset:offset + 32]);
            require((uint256(sibling) & 0xffff) == 0, "SIBLING_DIGEST");
            current = bytes32(
                uint256(
                    keccak256(
                        (index & 1) == 0
                            ? abi.encodePacked(bytes1(0x01), current, sibling)
                            : abi.encodePacked(bytes1(0x01), sibling, current)
                    )
                ) & DIGEST_MASK
            );
            offset += 32;
            index >>= 1;
        }
        require(current == expectedRoot, "MERKLE_ROOT");
    }
}
