// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {MerkleVerifier} from "../src/merkle/MerkleVerifier.sol";
import {MerkleHarness} from "./helpers/MerkleHarness.sol";

contract MerkleVerifierTest is Test {
    string internal constant TESTDATA = "testdata/";
    uint256 internal constant EXTENSION_BENCHMARK_ROW_LEN = 16;
    uint256 internal constant EXTENSION_BENCHMARK_DIGEST_BYTES = 20;

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

    function testExtensionLeafHashMatchesReference() external view {
        uint256[] memory values = _extensionLeafBenchmarkRow();

        assertEq(
            harness.hashLeafExtensionSlice(
                values,
                0,
                values.length,
                EXTENSION_BENCHMARK_DIGEST_BYTES
            ),
            _hashLeafExtensionReference(
                values,
                0,
                values.length,
                EXTENSION_BENCHMARK_DIGEST_BYTES
            )
        );
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

    function testGasMerkleExtensionLeafHash() external view {
        uint256[] memory values = _extensionLeafBenchmarkRow();

        bytes32 digest = harness.hashLeafExtensionSlice(
            values,
            0,
            values.length,
            EXTENSION_BENCHMARK_DIGEST_BYTES
        );
        assertTrue(digest != bytes32(0));
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

    function _extensionLeafBenchmarkRow()
        internal
        pure
        returns (uint256[] memory values)
    {
        values = new uint256[](EXTENSION_BENCHMARK_ROW_LEN);

        unchecked {
            for (uint256 i = 0; i < values.length; ++i) {
                uint256 base = 4 * i + 1;
                values[i] =
                    (base << 224) |
                    ((base + 1) << 192) |
                    ((base + 2) << 160) |
                    ((base + 3) << 128);
            }
        }
    }

    function _hashLeafExtensionReference(
        uint256[] memory values,
        uint256 start,
        uint256 rowLen,
        uint256 effectiveDigestBytes
    ) internal pure returns (bytes32 digest) {
        bytes memory preimage = new bytes(1 + rowLen * 16);
        preimage[0] = 0x00;

        unchecked {
            uint256 dst = 1;
            for (uint256 i = 0; i < rowLen; ++i) {
                uint256 packed = values[start + i];
                uint256 c0 = packed >> 224;
                uint256 c1 = (packed >> 192) & 0xffffffff;
                uint256 c2 = (packed >> 160) & 0xffffffff;
                uint256 c3 = (packed >> 128) & 0xffffffff;

                preimage[dst] = bytes1(uint8(c0 >> 24));
                preimage[dst + 1] = bytes1(uint8(c0 >> 16));
                preimage[dst + 2] = bytes1(uint8(c0 >> 8));
                preimage[dst + 3] = bytes1(uint8(c0));

                preimage[dst + 4] = bytes1(uint8(c1 >> 24));
                preimage[dst + 5] = bytes1(uint8(c1 >> 16));
                preimage[dst + 6] = bytes1(uint8(c1 >> 8));
                preimage[dst + 7] = bytes1(uint8(c1));

                preimage[dst + 8] = bytes1(uint8(c2 >> 24));
                preimage[dst + 9] = bytes1(uint8(c2 >> 16));
                preimage[dst + 10] = bytes1(uint8(c2 >> 8));
                preimage[dst + 11] = bytes1(uint8(c2));

                preimage[dst + 12] = bytes1(uint8(c3 >> 24));
                preimage[dst + 13] = bytes1(uint8(c3 >> 16));
                preimage[dst + 14] = bytes1(uint8(c3 >> 8));
                preimage[dst + 15] = bytes1(uint8(c3));

                dst += 16;
            }
        }

        digest = keccak256(preimage);
        if (effectiveDigestBytes >= 32) {
            return digest;
        }

        uint256 mask = type(uint256).max << ((32 - effectiveDigestBytes) * 8);
        return bytes32(uint256(digest) & mask);
    }
}
