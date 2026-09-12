// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {LeanVmMerkle} from "../src/leanvm/LeanVmMerkle.sol";

contract LeanVmMerkleBatchTest is Test {
    uint256 private constant P = 2_130_706_433;
    uint256 private constant MASK = type(uint256).max << 16;

    function openBatch(
        bytes calldata proof,
        uint256 leafScalars,
        uint256 height,
        uint256[] memory indices,
        bytes32 root
    ) external pure returns (uint256[] memory values) {
        (uint256[] memory offsets, uint256 next) = LeanVmMerkle.openBatch(proof, 0, leafScalars, height, indices, root);
        require(next == proof.length, "UNUSED_OPENING");
        // Allocate after verification to detect an invalid scratch rewind that
        // would overwrite the returned offsets.
        values = new uint256[](indices.length * leafScalars);
        for (uint256 i; i < indices.length; ++i) {
            for (uint256 j; j < leafScalars; ++j) {
                uint256 offset = offsets[i] + j * 4;
                values[i * leafScalars + j] = uint32(bytes4(proof[offset:offset + 4]));
            }
        }
    }

    function openTwoBatches(
        bytes calldata proof,
        uint256 leafScalars,
        uint256 height,
        uint256[] memory indices,
        bytes32 primaryRoot,
        bytes32 secondaryRoot
    ) external pure returns (uint256[] memory primaryValues, uint256[] memory secondaryValues) {
        (uint256[] memory rowNumbers, uint256 secondaryOffset, uint256 next) =
            LeanVmMerkle.openTwoBatches(
                proof, 0, leafScalars, height, indices, primaryRoot, secondaryRoot
            );
        require(next == proof.length, "UNUSED_OPENING");
        primaryValues = new uint256[](indices.length * leafScalars);
        secondaryValues = new uint256[](indices.length * leafScalars);
        uint256 rowBytes = leafScalars * 4;
        for (uint256 i; i < indices.length; ++i) {
            uint256 rowOffset = rowNumbers[i] * rowBytes;
            for (uint256 j; j < leafScalars; ++j) {
                primaryValues[i * leafScalars + j] =
                    uint32(bytes4(proof[rowOffset + j * 4:rowOffset + j * 4 + 4]));
                uint256 offset = secondaryOffset + rowOffset + j * 4;
                secondaryValues[i * leafScalars + j] = uint32(bytes4(proof[offset:offset + 4]));
            }
        }
    }

    function nativeRoot() private pure returns (bytes32) {
        uint256[8] memory limbs = [
            uint256(675_110_709),
            72_503_284,
            948_112_723,
            22_471_718,
            704_598_758,
            1_007_750_487,
            156_448_890,
            237_370_740
        ];
        uint256 packed;
        for (uint256 i; i < 8; ++i) {
            packed = (packed << 30) | limbs[i];
        }
        return bytes32(packed << 16);
    }

    function nativePair() private pure returns (bytes memory proof) {
        for (uint256 i; i < 16; ++i) {
            proof = bytes.concat(proof, bytes4(uint32(i)));
        }
    }

    function testNativePairUnsortedAndDuplicateQueries() external view {
        uint256[] memory indices = new uint256[](3);
        indices[0] = 1;
        indices[1] = 0;
        indices[2] = 1;
        uint256[] memory values = this.openBatch(nativePair(), 8, 1, indices, nativeRoot());
        for (uint256 i; i < indices.length; ++i) {
            for (uint256 j; j < 8; ++j) {
                assertEq(values[i * 8 + j], indices[i] * 8 + j);
            }
        }
    }

    function testTwoNativePairsReuseUnsortedDuplicateQueries() external view {
        uint256[] memory indices = new uint256[](3);
        indices[0] = 1;
        indices[1] = 0;
        indices[2] = 1;
        (uint256[] memory primaryValues, uint256[] memory secondaryValues) = this.openTwoBatches(
            bytes.concat(nativePair(), nativePair()), 8, 1, indices, nativeRoot(), nativeRoot()
        );
        for (uint256 i; i < indices.length; ++i) {
            for (uint256 j; j < 8; ++j) {
                uint256 expected = indices[i] * 8 + j;
                assertEq(primaryValues[i * 8 + j], expected);
                assertEq(secondaryValues[i * 8 + j], expected);
            }
        }
    }

    function testNativeSingleLeafWithTruncatedSibling() external view {
        uint256[8] memory limbs = [
            uint256(1_042_418_221),
            340_136_717,
            1_014_038_459,
            516_515_936,
            90_680_752,
            1_010_989_489,
            936_432_453,
            950_099_671
        ];
        uint256 packed;
        bytes memory proof;
        for (uint256 i; i < 8; ++i) {
            packed = (packed << 30) | limbs[i];
            proof = bytes.concat(proof, bytes4(uint32(i)));
        }
        proof = bytes.concat(proof, bytes30(bytes32(packed << 16)));
        uint256[] memory indices = new uint256[](1);
        uint256[] memory values = this.openBatch(proof, 8, 1, indices, nativeRoot());
        for (uint256 i; i < 8; ++i) {
            assertEq(values[i], i);
        }
    }

    function treeProof(uint16 mask) private pure returns (bytes memory proof, uint256[] memory indices, bytes32 root) {
        if (mask == 0) mask = 1;
        bytes32[] memory tree = new bytes32[](32);
        uint256 count;
        for (uint256 i; i < 16; ++i) {
            bytes memory row = abi.encodePacked(bytes4(uint32(i)), bytes4(uint32(i + 17)), bytes4(uint32(P - 1 - i)));
            tree[16 + i] = bytes32(uint256(keccak256(bytes.concat(hex"00", row))) & MASK);
            if (((uint256(mask) >> i) & 1) != 0) {
                proof = bytes.concat(proof, row);
                ++count;
            }
        }
        for (uint256 i = 15; i != 0; --i) {
            tree[i] = bytes32(uint256(keccak256(abi.encodePacked(bytes1(0x01), tree[2 * i], tree[2 * i + 1]))) & MASK);
        }
        root = tree[1];
        indices = new uint256[](count + 1);
        uint256[] memory frontier = new uint256[](count);
        uint256 filled;
        for (uint256 i; i < 16; ++i) {
            if (((uint256(mask) >> i) & 1) != 0) {
                frontier[filled] = 16 + i;
                indices[count - 1 - filled] = i;
                ++filled;
            }
        }
        indices[count] = indices[0];
        for (uint256 level; level < 4; ++level) {
            uint256 read;
            uint256 written;
            while (read < count) {
                uint256 node = frontier[read];
                if ((node & 1) == 0 && read + 1 < count && frontier[read + 1] == node + 1) {
                    read += 2;
                } else {
                    proof = bytes.concat(proof, bytes30(tree[node ^ 1]));
                    ++read;
                }
                frontier[written++] = node >> 1;
            }
            count = written;
        }
    }

    function testFuzzFullTreeReference(uint16 mask) external view {
        (bytes memory proof, uint256[] memory indices, bytes32 root) = treeProof(mask);
        uint256[] memory values = this.openBatch(proof, 3, 4, indices, root);
        for (uint256 i; i < indices.length; ++i) {
            assertEq(values[i * 3], indices[i]);
            assertEq(values[i * 3 + 1], indices[i] + 17);
            assertEq(values[i * 3 + 2], P - 1 - indices[i]);
        }
    }

    function testHeightZeroDuplicates() external view {
        bytes memory proof = abi.encodePacked(bytes4(uint32(7)));
        bytes32 root = bytes32(uint256(keccak256(bytes.concat(hex"00", proof))) & MASK);
        uint256[] memory indices = new uint256[](3);
        uint256[] memory values = this.openBatch(proof, 1, 0, indices, root);
        assertEq(values.length, 3);
        for (uint256 i; i < 3; ++i) {
            assertEq(values[i], 7);
        }
    }

    function testRejectChangedLeaf() external {
        (bytes memory proof, uint256[] memory indices, bytes32 root) = treeProof(0x0041);
        proof[3] ^= 0x01;
        vm.expectRevert("MERKLE_ROOT");
        this.openBatch(proof, 3, 4, indices, root);
    }

    function testRejectNoncanonicalLeaf() external {
        (bytes memory proof, uint256[] memory indices, bytes32 root) = treeProof(1);
        bytes4 encoded = bytes4(uint32(P));
        for (uint256 i; i < 4; ++i) {
            proof[i] = encoded[i];
        }
        vm.expectRevert("LEAF_SCALAR");
        this.openBatch(proof, 3, 4, indices, root);
    }

    function testRejectEveryPackedLeafLane() external {
        uint256[] memory indices = new uint256[](1);
        for (uint256 i; i < 19; ++i) {
            for (uint256 kind; kind < 3; ++kind) {
                bytes memory proof = new bytes(19 * 4);
                uint256 invalid = kind == 0 ? P : (kind == 1 ? uint256(1) << 31 : type(uint32).max);
                bytes4 encoded = bytes4(uint32(invalid));
                for (uint256 j; j < 4; ++j) proof[i * 4 + j] = encoded[j];
                bytes32 root = bytes32(uint256(keccak256(bytes.concat(hex"00", proof))) & MASK);
                vm.expectRevert("LEAF_SCALAR");
                this.openBatch(proof, 19, 0, indices, root);
            }
        }
    }

    function testPackedLeafMaximumCoefficientsAndTail() external view {
        uint256[] memory indices = new uint256[](1);
        bytes memory proof;
        for (uint256 i; i < 19; ++i) proof = bytes.concat(proof, bytes4(uint32(P - 1)));
        bytes32 root = bytes32(uint256(keccak256(bytes.concat(hex"00", proof))) & MASK);
        uint256[] memory values = this.openBatch(proof, 19, 0, indices, root);
        for (uint256 i; i < values.length; ++i) assertEq(values[i], P - 1);
    }

    function testRejectChangedSibling() external {
        (bytes memory proof, uint256[] memory indices, bytes32 root) = treeProof(1);
        proof[12] ^= 0x01;
        vm.expectRevert("MERKLE_ROOT");
        this.openBatch(proof, 3, 4, indices, root);
    }

    function testRejectShortSibling() external {
        (bytes memory proof, uint256[] memory indices, bytes32 root) = treeProof(1);
        assembly ("memory-safe") { mstore(proof, sub(mload(proof), 1)) }
        vm.expectRevert("MERKLE_END");
        this.openBatch(proof, 3, 4, indices, root);
    }

    function testRejectExtraBytes() external {
        (bytes memory proof, uint256[] memory indices, bytes32 root) = treeProof(1);
        vm.expectRevert("UNUSED_OPENING");
        this.openBatch(bytes.concat(proof, hex"00"), 3, 4, indices, root);
    }

    function testRejectIndexOutsideTree() external {
        (bytes memory proof, uint256[] memory indices, bytes32 root) = treeProof(1);
        indices[0] = 16;
        vm.expectRevert("MERKLE_INDEX");
        this.openBatch(proof, 3, 4, indices, root);
    }

    function testRejectNoncanonicalRoot() external {
        (bytes memory proof, uint256[] memory indices, bytes32 root) = treeProof(1);
        vm.expectRevert("ROOT_DIGEST");
        this.openBatch(proof, 3, 4, indices, bytes32(uint256(root) | 1));
    }

    function testRejectHeightOutsideRange() external {
        uint256[] memory indices = new uint256[](1);
        vm.expectRevert("MERKLE_INDEX");
        this.openBatch(hex"", 1, 31, indices, bytes32(0));
    }

    function testRejectNoQueries() external {
        vm.expectRevert("MERKLE_EMPTY");
        this.openBatch(hex"", 1, 1, new uint256[](0), bytes32(0));
    }
}
