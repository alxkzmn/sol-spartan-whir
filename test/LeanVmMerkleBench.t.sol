// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import { Test, console2 } from "forge-std/Test.sol";
import { LeanVmMerkle } from "../src/leanvm/LeanVmMerkle.sol";

/// @dev Scratch micro-benchmark: cost of LeanVmMerkle.openBatch per query and per level.
contract LeanVmMerkleBenchHarness {
    function openBatch(bytes calldata proof, uint256 leafScalars, uint256 height, uint256[] memory indices, bytes32 root)
        external view returns (uint256 gas)
    {
        gas = gasleft();
        (, uint256 next) = LeanVmMerkle.openBatch(proof, 0, leafScalars, height, indices, root);
        gas -= gasleft();
        require(next == proof.length, "UNUSED");
    }
}

contract LeanVmMerkleBenchTest is Test {
    uint256 private constant P = 2_130_706_433;
    uint256 private constant MASK = type(uint256).max << 16;
    LeanVmMerkleBenchHarness h;

    function setUp() public { h = new LeanVmMerkleBenchHarness(); }

    function leafRow(uint256 index, uint256 scalars) private pure returns (bytes memory row) {
        row = new bytes(scalars * 4);
        for (uint256 j; j < scalars; ++j) {
            uint256 v = uint256(keccak256(abi.encode(index, j))) % P;
            row[4 * j] = bytes1(uint8(v >> 24));
            row[4 * j + 1] = bytes1(uint8(v >> 16));
            row[4 * j + 2] = bytes1(uint8(v >> 8));
            row[4 * j + 3] = bytes1(uint8(v));
        }
    }

    function build(uint256 height, uint256 scalars, uint256 queries, uint256 seed)
        private pure returns (bytes memory proof, uint256[] memory indices, bytes32 root)
    {
        uint256 n = 1 << height;
        bytes32[] memory tree = new bytes32[](2 * n);
        for (uint256 i; i < n; ++i) {
            tree[n + i] = bytes32(uint256(keccak256(bytes.concat(hex"00", leafRow(i, scalars)))) & MASK);
        }
        for (uint256 i = n - 1; i != 0; --i) {
            tree[i] = bytes32(uint256(keccak256(abi.encodePacked(bytes1(0x01), tree[2 * i], tree[2 * i + 1]))) & MASK);
        }
        root = tree[1];
        indices = new uint256[](queries);
        for (uint256 q; q < queries; ++q) indices[q] = uint256(keccak256(abi.encode(seed, q))) % n;
        // sorted unique
        uint256[] memory sorted = new uint256[](queries);
        uint256 unique;
        for (uint256 q; q < queries; ++q) {
            uint256 v = indices[q];
            uint256 k = unique;
            while (k != 0 && sorted[k - 1] > v) { sorted[k] = sorted[k - 1]; --k; }
            sorted[k] = v; ++unique;
        }
        uint256 u;
        for (uint256 i; i < unique; ++i) if (u == 0 || sorted[i] != sorted[u - 1]) sorted[u++] = sorted[i];
        for (uint256 i; i < u; ++i) proof = bytes.concat(proof, leafRow(sorted[i], scalars));
        uint256[] memory frontier = new uint256[](u);
        for (uint256 i; i < u; ++i) frontier[i] = n + sorted[i];
        uint256 count = u;
        for (uint256 level; level < height; ++level) {
            uint256 read; uint256 written;
            while (read < count) {
                uint256 node = frontier[read];
                if ((node & 1) == 0 && read + 1 < count && frontier[read + 1] == node + 1) read += 2;
                else { proof = bytes.concat(proof, bytes30(tree[node ^ 1])); ++read; }
                frontier[written++] = node >> 1;
            }
            count = written;
        }
    }

    function run(uint256 height, uint256 scalars, uint256 queries) private view {
        (bytes memory proof, uint256[] memory indices, bytes32 root) = build(height, scalars, queries, height * 100 + scalars);
        uint256 gas = h.openBatch(proof, scalars, height, indices, root);
        console2.log("height/scalars/queries", height, scalars, queries);
        console2.log("  openBatch gas, proof bytes", gas, proof.length);
    }

    // One case per test so the tree-building scratch memory is released between cases.
    function testMerkleBench_h12_s32_q1() public view { run(12, 32, 1); }
    function testMerkleBench_h8_s32_q1() public view { run(8, 32, 1); }
    function testMerkleBench_h12_s32_q26() public view { run(12, 32, 26); }
    function testMerkleBench_h8_s32_q26() public view { run(8, 32, 26); }
    function testMerkleBench_h9_s80_q16() public view { run(9, 80, 16); }
    function testMerkleBench_h5_s80_q16() public view { run(5, 80, 16); }
    function testMerkleBench_h9_s80_q1() public view { run(9, 80, 1); }
    function testMerkleBench_h5_s80_q1() public view { run(5, 80, 1); }
}
