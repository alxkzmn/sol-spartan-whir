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

    function hashLeafBase(uint256[] calldata values, uint256 effectiveDigestBytes)
        internal
        pure
        returns (bytes32 digest)
    {
        assembly ("memory-safe") {
            let len := values.length
            let size := add(1, shl(2, len))
            let ptr := mload(0x40)

            mstore8(ptr, 0x00)

            let modulus := KOALABEAR_MODULUS
            let src := values.offset
            let dst := add(ptr, 1)
            let end := add(src, shl(5, len))
            for { } lt(src, end) {
                src := add(src, 0x20)
                dst := add(dst, 4)
            } {
                let v := calldataload(src)
                if iszero(lt(v, modulus)) {
                    mstore(0x00, 0xf512b67800000000000000000000000000000000000000000000000000000000)
                    mstore(0x04, v)
                    revert(0x00, 0x24)
                }
                mstore(dst, shl(224, v))
            }

            digest := keccak256(ptr, size)
        }

        return _maskDigestTail(digest, effectiveDigestBytes);
    }

    function compressNode(bytes32 left, bytes32 right, uint256 effectiveDigestBytes)
        internal
        pure
        returns (bytes32 digest)
    {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore8(ptr, 0x01)
            mstore(add(ptr, 0x01), left)
            mstore(add(ptr, 0x21), right)
            digest := keccak256(ptr, 65)
        }
        return _maskDigestTail(digest, effectiveDigestBytes);
    }

    function compressNode20(bytes32 left, bytes32 right) internal pure returns (bytes32 digest) {
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
            for { } lt(src, end) {
                src := add(src, 0x20)
                dst := add(dst, 4)
            } {
                let v := calldataload(src)
                if iszero(lt(v, modulus)) {
                    mstore(0x00, 0xf512b67800000000000000000000000000000000000000000000000000000000)
                    mstore(0x04, v)
                    revert(0x00, 0x24)
                }
                mstore(dst, shl(224, v))
            }

            digest := keccak256(ptr, size)
        }

        return _maskDigestTail(digest, effectiveDigestBytes);
    }

    function hashLeafBaseSlice20(uint256[] calldata values, uint256 start, uint256 rowLen)
        internal
        pure
        returns (bytes32 digest)
    {
        assembly ("memory-safe") {
            let size := add(1, shl(2, rowLen))
            let ptr := mload(0x40)

            mstore8(ptr, 0x00)

            let modulus := KOALABEAR_MODULUS
            let src := add(values.offset, shl(5, start))
            let dst := add(ptr, 1)
            let end := add(src, shl(5, rowLen))
            for { } lt(src, end) {
                src := add(src, 0x20)
                dst := add(dst, 4)
            } {
                let v := calldataload(src)
                if iszero(lt(v, modulus)) {
                    mstore(0x00, 0xf512b67800000000000000000000000000000000000000000000000000000000)
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
            for { } lt(src, end) {
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
                    mstore(0x00, 0xf512b67800000000000000000000000000000000000000000000000000000000)
                    mstore(0x04, packed)
                    revert(0x00, 0x24)
                }
                mstore(dst, packed)
            }

            digest := keccak256(ptr, size)
        }

        return _maskDigestTail(digest, effectiveDigestBytes);
    }

    function hashLeafExtensionSlice20(uint256[] calldata values, uint256 start, uint256 rowLen)
        internal
        pure
        returns (bytes32 digest)
    {
        assembly ("memory-safe") {
            let size := add(1, shl(4, rowLen))
            let ptr := mload(0x40)

            mstore8(ptr, 0x00)

            let modulus := KOALABEAR_MODULUS
            let coeffMask := COEFF_MASK
            let src := add(values.offset, shl(5, start))
            let dst := add(ptr, 1)
            let end := add(src, shl(5, rowLen))
            for { } lt(src, end) {
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
                    mstore(0x00, 0xf512b67800000000000000000000000000000000000000000000000000000000)
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
        return _computeRootFromLeafHashes(
            _copyIndices(indices), leafHashes, depth, decommitments, effectiveDigestBytes
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
                leafHashes[i] =
                    hashLeafBaseSlice(flatValues, i * rowLen, rowLen, effectiveDigestBytes);
            }
        }

        return _computeRootFromLeafHashes(
            indices, leafHashes, depth, decommitments, effectiveDigestBytes
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
        return _computeRootFromFlatRows20(indices, flatValues, rowLen, depth, decommitments, false);
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
                leafHashes[i] =
                    hashLeafExtensionSlice(flatValues, i * rowLen, rowLen, effectiveDigestBytes);
            }
        }

        return _computeRootFromLeafHashes(
            indices, leafHashes, depth, decommitments, effectiveDigestBytes
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
        return _computeRootFromFlatRows20(indices, flatValues, rowLen, depth, decommitments, true);
    }

    function computeRootFromFlatBaseRows20Blob(
        uint256[] memory indices,
        bytes calldata blob,
        uint256 valuesOffset,
        uint256 rowLen,
        uint256 depth,
        uint256 decommOffset,
        uint256 decommLen
    ) internal pure returns (bytes32) {
        if (rowLen == 16) {
            return _computeRootFromFlatBaseRows20Blob16(
                indices, blob, valuesOffset, depth, decommOffset, decommLen
            );
        }
        return _computeRootFromFlatRows20Blob(
            indices, blob, valuesOffset, rowLen, depth, decommOffset, decommLen, false
        );
    }

    function computeRootFromFlatExtensionRows20Blob(
        uint256[] memory indices,
        bytes calldata blob,
        uint256 valuesOffset,
        uint256 rowLen,
        uint256 depth,
        uint256 decommOffset,
        uint256 decommLen
    ) internal pure returns (bytes32) {
        if (rowLen == 16) {
            return _computeRootFromFlatExtensionRows20Blob16(
                indices, blob, valuesOffset, depth, decommOffset, decommLen
            );
        }
        return _computeRootFromFlatRows20Blob(
            indices, blob, valuesOffset, rowLen, depth, decommOffset, decommLen, true
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
        uint256 keep = _validateEffectiveDigestBytes(effectiveDigestBytes);
        uint256 digestMask;
        unchecked {
            digestMask = keep == 32 ? type(uint256).max : (type(uint256).max << ((32 - keep) * 8));
        }

        // Assembly-optimized frontier-swap Merkle reduction with configurable
        // digest truncation mask.
        assembly ("memory-safe") {
            let n := mload(indices)
            let entrySize := 0x40
            let bufBytes := mul(entrySize, n)
            let base := mload(0x40)
            let bufA := base
            let bufB := add(base, bufBytes)
            let scratch := add(bufB, bufBytes)
            mstore(0x40, add(scratch, 65))

            // Pre-store the 0x01 internal-node domain separator.
            mstore8(scratch, 0x01)

            // Copy inputs into bufA (interleaved entries: [index | hash]).
            {
                let idxBase := add(indices, 0x20)
                let hashBase := add(leafHashes, 0x20)
                let dst := bufA
                for {
                    let i := 0
                } lt(i, n) {
                    i := add(i, 1)
                } {
                    let off := shl(5, i)
                    mstore(dst, mload(add(idxBase, off)))
                    mstore(add(dst, 0x20), mload(add(hashBase, off)))
                    dst := add(dst, entrySize)
                }
            }

            let frontierLen := n
            let frontier := bufA
            let nextBuf := bufB
            let decommCursor := 0
            let decommLen := decommitments.length

            for {
                let level := 0
            } lt(level, depth) {
                level := add(level, 1)
            } {
                let nextLen := 0
                let ep := frontier
                let frontierEnd := add(frontier, mul(frontierLen, entrySize))
                let nextPtr := nextBuf
                for { } lt(ep, frontierEnd) { } {
                    let node := mload(ep)
                    let hash := mload(add(ep, 0x20))
                    let parentHash

                    // Try to merge in-frontier sibling pair.
                    let merged := 0
                    if iszero(and(node, 1)) {
                        let nep := add(ep, entrySize)
                        if lt(nep, frontierEnd) {
                            if eq(mload(nep), add(node, 1)) {
                                mstore(add(scratch, 1), hash)
                                mstore(add(scratch, 0x21), mload(add(nep, 0x20)))
                                parentHash := and(keccak256(scratch, 65), digestMask)
                                ep := add(nep, entrySize)
                                merged := 1
                            }
                        }
                    }

                    if iszero(merged) {
                        if iszero(lt(decommCursor, decommLen)) {
                            // revert InsufficientDecommitments(decommCursor+1, decommLen)
                            mstore(
                                0x00,
                                0x90196ee300000000000000000000000000000000000000000000000000000000
                            )
                            mstore(0x04, add(decommCursor, 1))
                            mstore(0x24, decommLen)
                            revert(0x00, 0x44)
                        }
                        let sibling := calldataload(add(decommitments.offset, shl(5, decommCursor)))
                        decommCursor := add(decommCursor, 1)
                        ep := add(ep, entrySize)

                        switch and(node, 1)
                        case 0 {
                            mstore(add(scratch, 1), hash)
                            mstore(add(scratch, 0x21), sibling)
                        }
                        default {
                            mstore(add(scratch, 1), sibling)
                            mstore(add(scratch, 0x21), hash)
                        }
                        parentHash := and(keccak256(scratch, 65), digestMask)
                    }

                    let parentIndex := shr(1, node)
                    let isDup := 0
                    if gt(nextLen, 0) {
                        let lastPtr := sub(nextPtr, entrySize)
                        if eq(mload(lastPtr), parentIndex) {
                            isDup := 1
                            mstore(add(lastPtr, 0x20), parentHash)
                        }
                    }
                    if iszero(isDup) {
                        mstore(nextPtr, parentIndex)
                        mstore(add(nextPtr, 0x20), parentHash)
                        nextPtr := add(nextPtr, entrySize)
                        nextLen := add(nextLen, 1)
                    }
                }

                let tmp := frontier
                frontier := nextBuf
                nextBuf := tmp
                frontierLen := nextLen
            }

            if iszero(eq(decommCursor, decommLen)) {
                // revert TrailingDecommitments(decommCursor, decommLen)
                mstore(0x00, 0xb48ec3d200000000000000000000000000000000000000000000000000000000)
                mstore(0x04, decommCursor)
                mstore(0x24, decommLen)
                revert(0x00, 0x44)
            }

            if or(iszero(eq(frontierLen, 1)), iszero(iszero(mload(frontier)))) {
                // revert InvalidFinalLayer(frontierLen, firstIndex)
                let idx := sub(0, 1)
                if gt(frontierLen, 0) {
                    idx := mload(frontier)
                }
                mstore(0x00, 0x1d72965600000000000000000000000000000000000000000000000000000000)
                mstore(0x04, frontierLen)
                mstore(0x24, idx)
                revert(0x00, 0x44)
            }

            root := mload(add(frontier, 0x20))
        }
    }

    function _computeRootFromFlatRows20(
        uint256[] memory indices,
        uint256[] calldata flatValues,
        uint256 rowLen,
        uint256 depth,
        bytes32[] calldata decommitments,
        bool isExtension
    ) private pure returns (bytes32 root) {
        if (indices.length == 0) {
            revert EmptyIndices();
        }

        bytes memory frontier;
        assembly ("memory-safe") {
            let frontierLen := shl(6, mload(indices))
            frontier := mload(0x40)
            mstore(frontier, frontierLen)
            mstore(0x40, add(add(frontier, 0x20), frontierLen))
        }

        unchecked {
            uint256 prevIdx;
            for (uint256 i = 0; i < indices.length; ++i) {
                uint256 idx = indices[i];
                if (i != 0 && prevIdx >= idx) {
                    revert IndicesNotStrictlyIncreasing(prevIdx, idx);
                }
                prevIdx = idx;

                bytes32 hash = isExtension
                    ? hashLeafExtensionSlice20(flatValues, i * rowLen, rowLen)
                    : hashLeafBaseSlice20(flatValues, i * rowLen, rowLen);

                assembly ("memory-safe") {
                    let dst := add(add(frontier, 0x20), shl(6, i))
                    mstore(dst, idx)
                    mstore(add(dst, 0x20), hash)
                }
            }
        }

        return _computeRootFromFrontier20(frontier, indices.length, depth, decommitments);
    }

    function _computeRootFromFlatBaseRows20Blob16(
        uint256[] memory indices,
        bytes calldata blob,
        uint256 valuesOffset,
        uint256 depth,
        uint256 decommOffset,
        uint256 decommLen
    ) private pure returns (bytes32 root) {
        if (indices.length == 0) {
            revert EmptyIndices();
        }

        bytes memory frontier;
        assembly ("memory-safe") {
            let frontierLen := shl(6, mload(indices))
            frontier := mload(0x40)
            mstore(frontier, frontierLen)
            mstore(0x40, add(add(frontier, 0x20), frontierLen))
        }

        unchecked {
            uint256 prevIdx;
            for (uint256 i = 0; i < indices.length; ++i) {
                uint256 idx = indices[i];
                if (i != 0 && prevIdx >= idx) {
                    revert IndicesNotStrictlyIncreasing(prevIdx, idx);
                }
                prevIdx = idx;

                uint256 rowOffset = valuesOffset + i * 64;
                bytes32 hash = hashLeafBaseSlice20Blob(blob, rowOffset, 16);

                assembly ("memory-safe") {
                    let dst := add(add(frontier, 0x20), shl(6, i))
                    mstore(dst, idx)
                    mstore(add(dst, 0x20), hash)
                }
            }
        }

        return _computeRootFromFrontier20Blob(
            frontier, indices.length, depth, blob, decommOffset, decommLen
        );
    }

    function _computeRootFromFlatExtensionRows20Blob16(
        uint256[] memory indices,
        bytes calldata blob,
        uint256 valuesOffset,
        uint256 depth,
        uint256 decommOffset,
        uint256 decommLen
    ) private pure returns (bytes32 root) {
        if (indices.length == 0) {
            revert EmptyIndices();
        }

        bytes memory frontier;
        assembly ("memory-safe") {
            let frontierLen := shl(6, mload(indices))
            frontier := mload(0x40)
            mstore(frontier, frontierLen)
            mstore(0x40, add(add(frontier, 0x20), frontierLen))
        }

        unchecked {
            uint256 prevIdx;
            for (uint256 i = 0; i < indices.length; ++i) {
                uint256 idx = indices[i];
                if (i != 0 && prevIdx >= idx) {
                    revert IndicesNotStrictlyIncreasing(prevIdx, idx);
                }
                prevIdx = idx;

                uint256 rowOffset = valuesOffset + i * 256;
                bytes32 hash = hashLeafExtensionSlice20Blob(blob, rowOffset, 16);

                assembly ("memory-safe") {
                    let dst := add(add(frontier, 0x20), shl(6, i))
                    mstore(dst, idx)
                    mstore(add(dst, 0x20), hash)
                }
            }
        }

        return _computeRootFromFrontier20Blob(
            frontier, indices.length, depth, blob, decommOffset, decommLen
        );
    }

    function _computeRootFromFlatRows20Blob(
        uint256[] memory indices,
        bytes calldata blob,
        uint256 valuesOffset,
        uint256 rowLen,
        uint256 depth,
        uint256 decommOffset,
        uint256 decommLen,
        bool isExtension
    ) private pure returns (bytes32 root) {
        if (indices.length == 0) {
            revert EmptyIndices();
        }

        bytes memory frontier;
        assembly ("memory-safe") {
            let frontierLen := shl(6, mload(indices))
            frontier := mload(0x40)
            mstore(frontier, frontierLen)
            mstore(0x40, add(add(frontier, 0x20), frontierLen))
        }

        uint256 stride = isExtension ? 16 : 4;
        unchecked {
            uint256 prevIdx;
            uint256 rowBytes = rowLen * stride;
            for (uint256 i = 0; i < indices.length; ++i) {
                uint256 idx = indices[i];
                if (i != 0 && prevIdx >= idx) {
                    revert IndicesNotStrictlyIncreasing(prevIdx, idx);
                }
                prevIdx = idx;

                uint256 rowOffset = valuesOffset + i * rowBytes;
                bytes32 hash = isExtension
                    ? hashLeafExtensionSlice20Blob(blob, rowOffset, rowLen)
                    : hashLeafBaseSlice20Blob(blob, rowOffset, rowLen);

                assembly ("memory-safe") {
                    let dst := add(add(frontier, 0x20), shl(6, i))
                    mstore(dst, idx)
                    mstore(add(dst, 0x20), hash)
                }
            }
        }

        return _computeRootFromFrontier20Blob(
            frontier, indices.length, depth, blob, decommOffset, decommLen
        );
    }

    function _computeRootFromFrontier20(
        bytes memory frontierBytes,
        uint256 frontierLen,
        uint256 depth,
        bytes32[] calldata decommitments
    ) private pure returns (bytes32 root) {
        assembly ("memory-safe") {
            let digestMask := not(sub(shl(96, 1), 1))
            let entrySize := 0x40
            let bufBytes := mul(entrySize, frontierLen)
            let frontier := add(frontierBytes, 0x20)
            let nextBuf := mload(0x40)
            let scratch := add(nextBuf, bufBytes)
            mstore(0x40, add(scratch, 65))
            mstore8(scratch, 0x01)

            let decommLen := decommitments.length
            let decommBase := decommitments.offset
            let decommPtr := decommBase
            let decommEnd := add(decommBase, shl(5, decommLen))

            for {
                let level := 0
            } lt(level, depth) {
                level := add(level, 1)
            } {
                let nextLen := 0
                let ep := frontier
                let frontierEnd := add(frontier, mul(frontierLen, entrySize))
                let nextPtr := nextBuf
                let lastParentIndex := 0
                let hasLastParent := 0
                for { } lt(ep, frontierEnd) { } {
                    let node := mload(ep)
                    let hash := mload(add(ep, 0x20))
                    let nodeIsRight := and(node, 1)
                    let nextReadPtr := add(ep, entrySize)
                    let parentHash

                    // Try to merge with sibling (both leaves present).
                    let merged := 0
                    if iszero(nodeIsRight) {
                        if lt(nextReadPtr, frontierEnd) {
                            if eq(mload(nextReadPtr), add(node, 1)) {
                                mstore(add(scratch, 1), hash)
                                mstore(add(scratch, 0x21), mload(add(nextReadPtr, 0x20)))
                                parentHash := and(keccak256(scratch, 65), digestMask)
                                nextReadPtr := add(nextReadPtr, entrySize)
                                merged := 1
                            }
                        }
                    }

                    if iszero(merged) {
                        // Need a decommitment sibling.
                        if iszero(lt(decommPtr, decommEnd)) {
                            // revert InsufficientDecommitments(consumed+1, decommLen)
                            mstore(
                                0x00,
                                0x90196ee300000000000000000000000000000000000000000000000000000000
                            )
                            mstore(0x04, add(shr(5, sub(decommPtr, decommBase)), 1))
                            mstore(0x24, decommLen)
                            revert(0x00, 0x44)
                        }
                        let sibling := calldataload(decommPtr)
                        decommPtr := add(decommPtr, 0x20)

                        switch nodeIsRight
                        case 0 {
                            mstore(add(scratch, 1), hash)
                            mstore(add(scratch, 0x21), sibling)
                        }
                        default {
                            mstore(add(scratch, 1), sibling)
                            mstore(add(scratch, 0x21), hash)
                        }
                        parentHash := and(keccak256(scratch, 65), digestMask)
                    }

                    ep := nextReadPtr
                    let parentIndex := shr(1, node)
                    let sameParent := and(hasLastParent, eq(lastParentIndex, parentIndex))

                    // Dedup: if the previous entry had the same parent index,
                    // overwrite its hash in place instead of appending a new entry.
                    if sameParent {
                        mstore(sub(nextPtr, 0x20), parentHash)
                    }
                    if iszero(sameParent) {
                        mstore(nextPtr, parentIndex)
                        mstore(add(nextPtr, 0x20), parentHash)
                        nextPtr := add(nextPtr, entrySize)
                        nextLen := add(nextLen, 1)
                        lastParentIndex := parentIndex
                        hasLastParent := 1
                    }
                }

                // Swap frontier <-> next.
                let tmp := frontier
                frontier := nextBuf
                nextBuf := tmp
                frontierLen := nextLen
            }

            // Verify all decommitments consumed.
            if iszero(eq(decommPtr, decommEnd)) {
                // revert TrailingDecommitments(consumed, decommLen)
                mstore(0x00, 0xb48ec3d200000000000000000000000000000000000000000000000000000000)
                mstore(0x04, shr(5, sub(decommPtr, decommBase)))
                mstore(0x24, decommLen)
                revert(0x00, 0x44)
            }

            // Verify single root at index 0.
            if or(iszero(eq(frontierLen, 1)), iszero(iszero(mload(frontier)))) {
                // revert InvalidFinalLayer(frontierLen, firstIndex)
                let idx := sub(0, 1) // type(uint256).max
                if gt(frontierLen, 0) {
                    idx := mload(frontier)
                }
                mstore(0x00, 0x1d72965600000000000000000000000000000000000000000000000000000000)
                mstore(0x04, frontierLen)
                mstore(0x24, idx)
                revert(0x00, 0x44)
            }

            root := mload(add(frontier, 0x20))
        }
    }

    function _computeRootFromFrontier20Blob(
        bytes memory frontierBytes,
        uint256 frontierLen,
        uint256 depth,
        bytes calldata blob,
        uint256 decommOffset,
        uint256 decommLen
    ) private pure returns (bytes32 root) {
        assembly ("memory-safe") {
            let digestMask := not(sub(shl(96, 1), 1))
            let entrySize := 0x40
            let bufBytes := mul(entrySize, frontierLen)
            let frontier := add(frontierBytes, 0x20)
            let nextBuf := mload(0x40)
            let scratch := add(nextBuf, bufBytes)
            mstore(0x40, add(scratch, 65))
            mstore8(scratch, 0x01)

            let decommBase := add(blob.offset, decommOffset)
            let decommPtr := decommBase
            let decommEnd := add(decommBase, mul(decommLen, 20))

            for {
                let level := 0
            } lt(level, depth) {
                level := add(level, 1)
            } {
                let nextLen := 0
                let ep := frontier
                let frontierEnd := add(frontier, mul(frontierLen, entrySize))
                let nextPtr := nextBuf
                let lastParentIndex := 0
                let hasLastParent := 0
                for { } lt(ep, frontierEnd) { } {
                    let node := mload(ep)
                    let hash := mload(add(ep, 0x20))
                    let nodeIsRight := and(node, 1)
                    let nextReadPtr := add(ep, entrySize)
                    let parentHash

                    let merged := 0
                    if iszero(nodeIsRight) {
                        if lt(nextReadPtr, frontierEnd) {
                            if eq(mload(nextReadPtr), add(node, 1)) {
                                mstore(add(scratch, 1), hash)
                                mstore(add(scratch, 0x21), mload(add(nextReadPtr, 0x20)))
                                parentHash := and(keccak256(scratch, 65), digestMask)
                                nextReadPtr := add(nextReadPtr, entrySize)
                                merged := 1
                            }
                        }
                    }

                    if iszero(merged) {
                        if iszero(lt(decommPtr, decommEnd)) {
                            mstore(
                                0x00,
                                0x90196ee300000000000000000000000000000000000000000000000000000000
                            )
                            mstore(0x04, add(div(sub(decommPtr, decommBase), 20), 1))
                            mstore(0x24, decommLen)
                            revert(0x00, 0x44)
                        }
                        let sibling := and(calldataload(decommPtr), digestMask)
                        decommPtr := add(decommPtr, 20)

                        switch nodeIsRight
                        case 0 {
                            mstore(add(scratch, 1), hash)
                            mstore(add(scratch, 0x21), sibling)
                        }
                        default {
                            mstore(add(scratch, 1), sibling)
                            mstore(add(scratch, 0x21), hash)
                        }
                        parentHash := and(keccak256(scratch, 65), digestMask)
                    }

                    ep := nextReadPtr
                    let parentIndex := shr(1, node)
                    let sameParent := and(hasLastParent, eq(lastParentIndex, parentIndex))
                    if sameParent {
                        mstore(sub(nextPtr, 0x20), parentHash)
                    }
                    if iszero(sameParent) {
                        mstore(nextPtr, parentIndex)
                        mstore(add(nextPtr, 0x20), parentHash)
                        nextPtr := add(nextPtr, entrySize)
                        nextLen := add(nextLen, 1)
                        lastParentIndex := parentIndex
                        hasLastParent := 1
                    }
                }

                let tmp := frontier
                frontier := nextBuf
                nextBuf := tmp
                frontierLen := nextLen
            }

            if iszero(eq(decommPtr, decommEnd)) {
                mstore(0x00, 0xb48ec3d200000000000000000000000000000000000000000000000000000000)
                mstore(0x04, div(sub(decommPtr, decommBase), 20))
                mstore(0x24, decommLen)
                revert(0x00, 0x44)
            }

            if or(iszero(eq(frontierLen, 1)), iszero(iszero(mload(frontier)))) {
                let idx := sub(0, 1)
                if gt(frontierLen, 0) {
                    idx := mload(frontier)
                }
                mstore(0x00, 0x1d72965600000000000000000000000000000000000000000000000000000000)
                mstore(0x04, frontierLen)
                mstore(0x24, idx)
                revert(0x00, 0x44)
            }

            root := mload(add(frontier, 0x20))
        }
    }

    function computeRootFromFrontier20Blob(
        bytes memory frontierBytes,
        uint256 frontierLen,
        uint256 depth,
        bytes calldata blob,
        uint256 decommOffset,
        uint256 decommLen
    ) internal pure returns (bytes32 root) {
        return _computeRootFromFrontier20Blob(
            frontierBytes, frontierLen, depth, blob, decommOffset, decommLen
        );
    }

    function hashLeafBaseSlice20Blob(bytes calldata blob, uint256 offset, uint256 rowLen)
        internal
        pure
        returns (bytes32 digest)
    {
        assembly ("memory-safe") {
            let size := add(1, shl(2, rowLen))
            let ptr := mload(0x40)

            mstore8(ptr, 0x00)

            let modulus := KOALABEAR_MODULUS
            let src := add(blob.offset, offset)
            let check := src
            let end := add(src, shl(2, rowLen))
            for { } lt(check, end) {
                check := add(check, 4)
            } {
                let v := shr(224, calldataload(check))
                if iszero(lt(v, modulus)) {
                    mstore(0x00, 0xf512b67800000000000000000000000000000000000000000000000000000000)
                    mstore(0x04, v)
                    revert(0x00, 0x24)
                }
            }

            calldatacopy(add(ptr, 1), src, shl(2, rowLen))
            digest := and(keccak256(ptr, size), not(sub(shl(96, 1), 1)))
        }
    }

    function hashLeafExtensionSlice20Blob(bytes calldata blob, uint256 offset, uint256 rowLen)
        internal
        pure
        returns (bytes32 digest)
    {
        assembly ("memory-safe") {
            let size := add(1, shl(4, rowLen))
            let ptr := mload(0x40)

            mstore8(ptr, 0x00)

            let modulus := KOALABEAR_MODULUS
            let coeffMask := COEFF_MASK
            let src := add(blob.offset, offset)
            let check := src
            let end := add(src, shl(4, rowLen))
            for { } lt(check, end) {
                check := add(check, 0x10)
            } {
                let packed := and(calldataload(check), not(sub(shl(128, 1), 1)))
                let c0 := shr(224, packed)
                let c1 := and(shr(192, packed), coeffMask)
                let c2 := and(shr(160, packed), coeffMask)
                let c3 := and(shr(128, packed), coeffMask)
                if or(
                    or(iszero(lt(c0, modulus)), iszero(lt(c1, modulus))),
                    or(iszero(lt(c2, modulus)), iszero(lt(c3, modulus)))
                ) {
                    mstore(0x00, 0xf512b67800000000000000000000000000000000000000000000000000000000)
                    mstore(0x04, packed)
                    revert(0x00, 0x24)
                }
            }

            calldatacopy(add(ptr, 1), src, shl(4, rowLen))
            digest := and(keccak256(ptr, size), not(sub(shl(96, 1), 1)))
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
                leafHashes[i] = hashLeafBase(openedRows[i], effectiveDigestBytes);
            }
        }

        return computeRootFromLeafHashes(
            indices, leafHashes, depth, decommitments, effectiveDigestBytes
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
        return computeRootFromBaseRows(
            indices, openedRows, depth, decommitments, effectiveDigestBytes
        ) == expectedRoot;
    }

    function _copyIndices(uint256[] calldata indices)
        private
        pure
        returns (uint256[] memory copied)
    {
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
                    revert IndicesNotStrictlyIncreasing(indices[i - 1], indices[i]);
                }
            }
        }
    }

    function _maskDigestTail(bytes32 digest, uint256 effectiveDigestBytes)
        private
        pure
        returns (bytes32)
    {
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

    function _validateEffectiveDigestBytes(uint256 effectiveDigestBytes)
        private
        pure
        returns (uint256)
    {
        if (effectiveDigestBytes == 0 || effectiveDigestBytes > 32) {
            revert InvalidEffectiveDigestBytes(effectiveDigestBytes);
        }
        return effectiveDigestBytes;
    }
}
