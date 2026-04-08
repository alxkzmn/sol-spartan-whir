// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {MerkleVerifier} from "../src/merkle/MerkleVerifier.sol";
import {MerkleHarness} from "./helpers/MerkleHarness.sol";

contract MerkleVerifierTest is Test {
    string internal constant TESTDATA = "testdata/";

    struct MerkleLeafHashFixture {
        uint256[] values;
        bytes32 digest;
    }

    struct MerkleNodeCompressionFixture {
        bytes32 left;
        bytes32 right;
        bytes32 parent;
    }

    struct MerkleMultiproofFixture {
        uint256 depth;
        uint256[] indices;
        uint256[][] openedRows;
        bytes32[] decommitments;
        bytes32 expectedRoot;
    }

    struct MerkleVectorFixture {
        uint256 effectiveDigestBytes;
        MerkleLeafHashFixture[] leafHashes;
        MerkleNodeCompressionFixture[] nodeCompressions;
        MerkleMultiproofFixture multiproof;
    }

    MerkleHarness internal harness;

    function setUp() external {
        harness = new MerkleHarness();
    }

    function testLeafHashesMatchRustVectors() external view {
        MerkleVectorFixture memory fixture = _loadMerkleFixture();

        unchecked {
            for (uint256 i = 0; i < fixture.leafHashes.length; ++i) {
                assertEq(
                    harness.hashLeafBase(
                        fixture.leafHashes[i].values,
                        fixture.effectiveDigestBytes
                    ),
                    fixture.leafHashes[i].digest
                );
            }
        }
    }

    function testNodeCompressionsMatchRustVectors() external view {
        MerkleVectorFixture memory fixture = _loadMerkleFixture();

        unchecked {
            for (uint256 i = 0; i < fixture.nodeCompressions.length; ++i) {
                MerkleNodeCompressionFixture memory vector = fixture
                    .nodeCompressions[i];
                assertEq(
                    harness.compressNode(
                        vector.left,
                        vector.right,
                        fixture.effectiveDigestBytes
                    ),
                    vector.parent
                );
            }
        }
    }

    function testMultiproofComputesExpectedRoot() external view {
        MerkleVectorFixture memory fixture = _loadMerkleFixture();
        MerkleMultiproofFixture memory multiproof = fixture.multiproof;

        bytes32 root = harness.computeRootFromBaseRows(
            multiproof.indices,
            multiproof.openedRows,
            multiproof.depth,
            multiproof.decommitments,
            fixture.effectiveDigestBytes
        );
        assertEq(root, multiproof.expectedRoot);
        assertTrue(
            harness.verifyBaseRows(
                multiproof.expectedRoot,
                multiproof.indices,
                multiproof.openedRows,
                multiproof.depth,
                multiproof.decommitments,
                fixture.effectiveDigestBytes
            )
        );
    }

    function testGasMerkleLeafHash() external view {
        MerkleVectorFixture memory fixture = _loadMerkleFixture();
        MerkleLeafHashFixture memory leaf = fixture.leafHashes[0];

        assertEq(
            harness.hashLeafBase(leaf.values, fixture.effectiveDigestBytes),
            leaf.digest
        );
    }

    function testGasMerkleNodeCompression() external view {
        MerkleVectorFixture memory fixture = _loadMerkleFixture();
        MerkleNodeCompressionFixture memory node = fixture.nodeCompressions[0];

        assertEq(
            harness.compressNode(
                node.left,
                node.right,
                fixture.effectiveDigestBytes
            ),
            node.parent
        );
    }

    function testGasMerkleMultiproofVerify() external view {
        MerkleVectorFixture memory fixture = _loadMerkleFixture();
        MerkleMultiproofFixture memory multiproof = fixture.multiproof;

        assertTrue(
            harness.verifyBaseRows(
                multiproof.expectedRoot,
                multiproof.indices,
                multiproof.openedRows,
                multiproof.depth,
                multiproof.decommitments,
                fixture.effectiveDigestBytes
            )
        );
    }

    function testRejectsUnsortedIndices() external {
        MerkleVectorFixture memory fixture = _loadMerkleFixture();
        MerkleMultiproofFixture memory multiproof = fixture.multiproof;
        uint256[] memory indices = new uint256[](multiproof.indices.length);

        unchecked {
            for (uint256 i = 0; i < indices.length; ++i) {
                indices[i] = multiproof.indices[i];
            }
        }

        (indices[0], indices[1]) = (indices[1], indices[0]);

        vm.expectRevert(
            abi.encodeWithSelector(
                MerkleVerifier.IndicesNotStrictlyIncreasing.selector,
                indices[0],
                indices[1]
            )
        );
        harness.computeRootFromBaseRows(
            indices,
            multiproof.openedRows,
            multiproof.depth,
            multiproof.decommitments,
            fixture.effectiveDigestBytes
        );
    }

    function testRejectsTrailingDecommitments() external {
        MerkleVectorFixture memory fixture = _loadMerkleFixture();
        MerkleMultiproofFixture memory multiproof = fixture.multiproof;
        bytes32[] memory decommitments = new bytes32[](
            multiproof.decommitments.length + 1
        );

        unchecked {
            for (uint256 i = 0; i < multiproof.decommitments.length; ++i) {
                decommitments[i] = multiproof.decommitments[i];
            }
        }
        decommitments[decommitments.length - 1] = multiproof.expectedRoot;

        vm.expectRevert(
            abi.encodeWithSelector(
                MerkleVerifier.TrailingDecommitments.selector,
                multiproof.decommitments.length,
                decommitments.length
            )
        );
        harness.computeRootFromBaseRows(
            multiproof.indices,
            multiproof.openedRows,
            multiproof.depth,
            decommitments,
            fixture.effectiveDigestBytes
        );
    }

    function testRejectsLengthMismatch() external {
        MerkleVectorFixture memory fixture = _loadMerkleFixture();
        MerkleMultiproofFixture memory multiproof = fixture.multiproof;
        uint256[] memory shortened = new uint256[](
            multiproof.indices.length - 1
        );

        unchecked {
            for (uint256 i = 0; i < shortened.length; ++i) {
                shortened[i] = multiproof.indices[i];
            }
        }

        vm.expectRevert(
            abi.encodeWithSelector(
                MerkleVerifier.LengthMismatch.selector,
                shortened.length,
                multiproof.openedRows.length
            )
        );
        harness.computeRootFromBaseRows(
            shortened,
            multiproof.openedRows,
            multiproof.depth,
            multiproof.decommitments,
            fixture.effectiveDigestBytes
        );
    }

    function testRejectsZeroEffectiveDigestBytes() external {
        MerkleVectorFixture memory fixture = _loadMerkleFixture();
        MerkleLeafHashFixture memory leaf = fixture.leafHashes[0];

        vm.expectRevert(
            abi.encodeWithSelector(
                MerkleVerifier.InvalidEffectiveDigestBytes.selector,
                0
            )
        );
        harness.hashLeafBase(leaf.values, 0);
    }

    function testRejectsDigestBytesAboveKeccakWidth() external {
        MerkleVectorFixture memory fixture = _loadMerkleFixture();
        MerkleNodeCompressionFixture memory node = fixture.nodeCompressions[0];

        vm.expectRevert(
            abi.encodeWithSelector(
                MerkleVerifier.InvalidEffectiveDigestBytes.selector,
                33
            )
        );
        harness.compressNode(node.left, node.right, 33);
    }

    function _loadMerkleFixture()
        internal
        view
        returns (MerkleVectorFixture memory)
    {
        bytes memory raw = vm.readFileBinary(
            string.concat(TESTDATA, "merkle_vectors.abi")
        );
        return abi.decode(raw, (MerkleVectorFixture));
    }
}
