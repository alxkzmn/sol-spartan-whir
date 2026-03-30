// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

library MerkleVerifier {
    uint256 internal constant KOALABEAR_MODULUS = 0x7f000001;

    error EmptyIndices();
    error LengthMismatch(uint256 indices, uint256 openings);
    error IndicesNotStrictlyIncreasing(uint256 prev, uint256 next);
    error InsufficientDecommitments(uint256 expectedAtLeast, uint256 got);
    error TrailingDecommitments(uint256 consumed, uint256 total);
    error InvalidFinalLayer(uint256 layerSize, uint256 index);
    error FieldElementOutOfRange(uint256 value);

    function hashLeafBase(
        uint256[] memory values,
        uint256 effectiveDigestBytes
    ) internal pure returns (bytes32) {
        bytes memory preimage = new bytes(1 + values.length * 4);
        preimage[0] = bytes1(uint8(0));

        unchecked {
            for (uint256 i = 0; i < values.length; ++i) {
                uint256 value = values[i];
                if (value >= KOALABEAR_MODULUS) {
                    revert FieldElementOutOfRange(value);
                }

                uint256 offset = 1 + (i * 4);
                preimage[offset] = bytes1(uint8(value >> 24));
                preimage[offset + 1] = bytes1(uint8(value >> 16));
                preimage[offset + 2] = bytes1(uint8(value >> 8));
                preimage[offset + 3] = bytes1(uint8(value));
            }
        }

        return _maskDigestTail(keccak256(preimage), effectiveDigestBytes);
    }

    function compressNode(
        bytes32 left,
        bytes32 right,
        uint256 effectiveDigestBytes
    ) internal pure returns (bytes32) {
        return
            _maskDigestTail(
                keccak256(abi.encodePacked(bytes1(uint8(0x01)), left, right)),
                effectiveDigestBytes
            );
    }

    function computeRootFromLeafHashes(
        uint256[] memory indices,
        bytes32[] memory leafHashes,
        uint256 depth,
        bytes32[] memory decommitments,
        uint256 effectiveDigestBytes
    ) internal pure returns (bytes32) {
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

        uint256 decommitmentCursor = 0;

        for (uint256 level = 0; level < depth; ++level) {
            uint256 nextCapacity = frontierLen;
            uint256[] memory nextIndices = new uint256[](nextCapacity);
            bytes32[] memory nextHashes = new bytes32[](nextCapacity);
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
                        parentHash = compressNode(hash, siblingHash, effectiveDigestBytes);
                    } else {
                        parentHash = compressNode(siblingHash, hash, effectiveDigestBytes);
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

            frontierIndices = nextIndices;
            frontierHashes = nextHashes;
            frontierLen = nextLen;
        }

        if (decommitmentCursor != decommitments.length) {
            revert TrailingDecommitments(decommitmentCursor, decommitments.length);
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
        uint256[] memory indices,
        uint256[][] memory openedRows,
        uint256 depth,
        bytes32[] memory decommitments,
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
        uint256[] memory indices,
        uint256[][] memory openedRows,
        uint256 depth,
        bytes32[] memory decommitments,
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
