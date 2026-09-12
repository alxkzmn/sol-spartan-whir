// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import { Test } from "forge-std/Test.sol";
import { LeanVmMerkle } from "../src/leanvm/LeanVmMerkle.sol";
import { LeanVmTranscript } from "../src/leanvm/LeanVmTranscript.sol";

contract LeanVmMerkleTest is Test {
    function digest(uint256[8] memory limbs) internal pure returns (bytes32) {
        uint256[] memory words = new uint256[](8);
        for (uint256 i; i < 8; ++i) {
            words[i] = limbs[i];
        }
        return LeanVmTranscript.digest(words);
    }

    function vector(uint256 index) internal pure returns (bytes memory proof, bytes32 root) {
        root = digest(
            [
                uint256(675_110_709),
                72_503_284,
                948_112_723,
                22_471_718,
                704_598_758,
                1_007_750_487,
                156_448_890,
                237_370_740
            ]
        );
        uint256[8] memory sibling = index == 0
            ? [
                uint256(1_042_418_221),
                340_136_717,
                1_014_038_459,
                516_515_936,
                90_680_752,
                1_010_989_489,
                936_432_453,
                950_099_671
            ]
            : [
                uint256(767_845_451),
                316_274_549,
                822_290_521,
                694_784_522,
                1_003_385_732,
                888_782_743,
                570_097_107,
                833_051_967
            ];
        for (uint256 i; i < 8; ++i) {
            proof = bytes.concat(proof, bytes4(uint32(index * 8 + i)));
        }
        proof = bytes.concat(proof, digest(sibling));
    }

    function open(bytes calldata proof, uint256 index, bytes32 root)
        external
        pure
        returns (uint256[] memory)
    {
        (uint256[] memory leaf, uint256 offset) = LeanVmMerkle.open(proof, 0, 8, 1, index, root);
        require(offset == proof.length, "UNUSED_OPENING");
        return leaf;
    }

    function testNativeTwoLeafVectors() external view {
        for (uint256 index; index < 2; ++index) {
            (bytes memory proof, bytes32 root) = vector(index);
            uint256[] memory leaf = this.open(proof, index, root);
            for (uint256 i; i < 8; ++i) {
                assertEq(leaf[i], index * 8 + i);
            }
        }
    }

    function testRejectChangedLeaf() external {
        (bytes memory proof, bytes32 root) = vector(0);
        proof[3] = 0x01;
        vm.expectRevert("MERKLE_ROOT");
        this.open(proof, 0, root);
    }

    function testRejectWrongIndex() external {
        (bytes memory proof, bytes32 root) = vector(0);
        vm.expectRevert("MERKLE_ROOT");
        this.open(proof, 1, root);
    }

    function testRejectNoncanonicalDigest() external {
        (bytes memory proof, bytes32 root) = vector(0);
        proof[63] = 0x01;
        vm.expectRevert("SIBLING_DIGEST");
        this.open(proof, 0, root);
    }
}
