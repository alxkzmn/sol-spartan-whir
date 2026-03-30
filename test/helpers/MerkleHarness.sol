// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {MerkleVerifier} from "../../src/merkle/MerkleVerifier.sol";

contract MerkleHarness {
    function hashLeafBase(
        uint256[] memory values,
        uint256 effectiveDigestBytes
    ) external pure returns (bytes32) {
        return MerkleVerifier.hashLeafBase(values, effectiveDigestBytes);
    }

    function compressNode(
        bytes32 left,
        bytes32 right,
        uint256 effectiveDigestBytes
    ) external pure returns (bytes32) {
        return MerkleVerifier.compressNode(left, right, effectiveDigestBytes);
    }

    function computeRootFromLeafHashes(
        uint256[] memory indices,
        bytes32[] memory leafHashes,
        uint256 depth,
        bytes32[] memory decommitments,
        uint256 effectiveDigestBytes
    ) external pure returns (bytes32) {
        return
            MerkleVerifier.computeRootFromLeafHashes(
                indices,
                leafHashes,
                depth,
                decommitments,
                effectiveDigestBytes
            );
    }

    function computeRootFromBaseRows(
        uint256[] memory indices,
        uint256[][] memory openedRows,
        uint256 depth,
        bytes32[] memory decommitments,
        uint256 effectiveDigestBytes
    ) external pure returns (bytes32) {
        return
            MerkleVerifier.computeRootFromBaseRows(
                indices,
                openedRows,
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
    ) external pure returns (bool) {
        return
            MerkleVerifier.verifyBaseRows(
                expectedRoot,
                indices,
                openedRows,
                depth,
                decommitments,
                effectiveDigestBytes
            );
    }
}
