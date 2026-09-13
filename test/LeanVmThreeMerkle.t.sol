// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import { Test, console2 } from "forge-std/Test.sol";
import { LeanVmMerkle as Merkle } from "../src/leanvm/LeanVmMerkle.sol";

contract ThreeMerkleHarness {
    function baseline(
        bytes calldata proof,
        uint256 width,
        uint256 height,
        uint256[] memory indices,
        bytes32[3] memory roots
    ) external view returns (uint256 gas, uint256[] memory rows, uint256 next) {
        uint256 start = gasleft();
        uint256 second;
        (rows, second, next) =
            Merkle.openTwoBatches(proof, 0, width, height, indices, roots[0], roots[1]);
        uint256 third = next;
        uint256[] memory offsets;
        (offsets, next) = Merkle.openBatch(proof, next, width, height, indices, roots[2]);
        gas = start - gasleft();
        require(third == 2 * second && next == 3 * second && next == proof.length, "LENGTH");
        for (uint256 i; i < indices.length; ++i) {
            require(offsets[i] == third + rows[i] * width * 4, "ROWS");
        }
    }

    function candidateAt(
        bytes calldata proof,
        uint256 offset,
        uint256 width,
        uint256 height,
        uint256[] memory indices,
        bytes32[3] memory roots
    ) external pure returns (uint256[] memory rows, uint256 span, uint256 next) {
        (rows, span, next) = Merkle.openThreeBatches(proof, offset, width, height, indices, roots);
        // Allocate after the call to exercise scratch-memory lifetime.
        bytes memory sentinel = new bytes(2048);
        for (uint256 i; i < sentinel.length; ++i) {
            sentinel[i] = bytes1(uint8(i));
        }
        require(sentinel[255] == 0xff, "SENTINEL");
    }

    function candidate(
        bytes calldata proof,
        uint256 width,
        uint256 height,
        uint256[] memory indices,
        bytes32[3] memory roots
    ) external view returns (uint256 gas, uint256[] memory rows, uint256 next) {
        uint256 start = gasleft();
        uint256 span;
        (rows, span, next) = Merkle.openThreeBatches(proof, 0, width, height, indices, roots);
        gas = start - gasleft();
        require(next == 3 * span && next == proof.length, "LENGTH");
    }
}

contract ThreeMerkleTest is Test {
    ThreeMerkleHarness h;

    function setUp() public {
        h = new ThreeMerkleHarness();
    }

    struct Fixture {
        bytes proof;
        uint256 width;
        uint256 height;
        uint256[] indices;
        bytes32[3] roots;
        uint256[] rows;
        uint256 span;
    }

    function load(uint256 i) internal view returns (Fixture memory f) {
        string memory s =
            vm.readFile(string.concat("testdata/three_merkle/", vm.toString(i), ".json"));
        f.proof = vm.parseJsonBytes(s, ".proof");
        f.width = vm.parseJsonUint(s, ".width");
        f.height = vm.parseJsonUint(s, ".height");
        f.indices = vm.parseJsonUintArray(s, ".indices");
        f.rows = vm.parseJsonUintArray(s, ".row_numbers");
        f.span = vm.parseJsonUint(s, ".batch_bytes");
        bytes32[] memory roots = vm.parseJsonBytes32Array(s, ".roots");
        f.roots = [roots[0], roots[1], roots[2]];
    }

    function testCanonicalLanesAndRootEncoding() public {
        for (uint256 caseId; caseId < 2; ++caseId) {
            Fixture memory f = load(caseId == 0 ? 0 : 7);
            for (uint256 tree; tree < 3; ++tree) {
                for (uint256 lane; lane < f.width; ++lane) {
                    uint256 at = tree * f.span + lane * 4;
                    bytes4 before = bytes4(0);
                    for (uint256 k; k < 4; ++k) {
                        before |= bytes4(f.proof[at + k]) >> (k * 8);
                    }
                    for (uint256 value; value < 2; ++value) {
                        bytes4 bad =
                            value == 0 ? bytes4(uint32(2_130_706_433)) : bytes4(uint32(0x80000000));
                        for (uint256 k; k < 4; ++k) {
                            f.proof[at + k] = bad[k];
                        }
                        vm.expectRevert(bytes("LEAF_SCALAR"));
                        h.candidate(f.proof, f.width, f.height, f.indices, f.roots);
                    }
                    for (uint256 k; k < 4; ++k) {
                        f.proof[at + k] = before[k];
                    }
                }
                bytes32 root = f.roots[tree];
                f.roots[tree] = root | bytes32(uint256(1));
                vm.expectRevert(bytes("ROOT_DIGEST"));
                h.candidate(f.proof, f.width, f.height, f.indices, f.roots);
                f.roots[tree] = root;
            }
        }
    }

    function testOffsetBoundsAndMemoryLifetime() public {
        Fixture memory f = load(0);
        bytes memory proof = bytes.concat(hex"ff123456789abcdef0", f.proof, hex"aabbccdd");
        (uint256[] memory rows, uint256 span, uint256 next) =
            h.candidateAt(proof, 9, f.width, f.height, f.indices, f.roots);
        assertEq(rows, f.rows);
        assertEq(span, f.span);
        assertEq(next, 9 + f.proof.length);
        vm.expectRevert(bytes("MERKLE_END"));
        h.candidateAt(f.proof, 1, f.width, f.height, f.indices, f.roots);
        uint256[] memory empty = new uint256[](0);
        vm.expectRevert(bytes("MERKLE_EMPTY"));
        h.candidate(f.proof, f.width, f.height, empty, f.roots);
        vm.expectRevert(bytes("MERKLE_INDEX"));
        h.candidate(f.proof, f.width, 31, f.indices, f.roots);
    }

    function testFuzzFullTrees(uint256 seed, uint8 heightInput, uint8 widthInput) public view {
        uint256 height = uint256(heightInput) % 7;
        uint256 width = uint256(widthInput) % 10;
        uint256 leaves = uint256(1) << height;
        bool[] memory selected = new bool[](leaves);
        uint256[] memory indices = new uint256[](12);
        for (uint256 i; i < indices.length; ++i) {
            indices[i] = uint256(keccak256(abi.encode(seed, i))) % leaves;
            selected[indices[i]] = true;
        }
        uint256[] memory expectedRows = new uint256[](indices.length);
        uint256 row;
        for (uint256 i; i < leaves; ++i) {
            if (selected[i]) {
                for (uint256 j; j < indices.length; ++j) {
                    if (indices[j] == i) expectedRows[j] = row;
                }
                ++row;
            }
        }
        bytes memory proof;
        bytes32[3] memory roots;
        for (uint256 tree; tree < 3; ++tree) {
            (bytes memory batch, bytes32 root) = fullTree(seed, tree, height, width, selected);
            proof = bytes.concat(proof, batch);
            roots[tree] = root;
        }
        (, uint256[] memory oldRows, uint256 oldNext) =
            h.baseline(proof, width, height, indices, roots);
        (, uint256[] memory newRows, uint256 newNext) =
            h.candidate(proof, width, height, indices, roots);
        assertEq(oldRows, expectedRows);
        assertEq(newRows, expectedRows);
        assertEq(oldNext, newNext);
    }

    function fullTree(
        uint256 seed,
        uint256 tree,
        uint256 height,
        uint256 width,
        bool[] memory selected
    ) internal pure returns (bytes memory proof, bytes32 root) {
        uint256 leaves = uint256(1) << height;
        bytes32[] memory hashes = new bytes32[](2 * leaves);
        bool[] memory active = new bool[](2 * leaves);
        uint256 mask = ~uint256(0xffff);
        for (uint256 i; i < leaves; ++i) {
            bytes memory row;
            for (uint256 j; j < width; ++j) {
                uint256 value = uint256(keccak256(abi.encode(seed, tree, i, j))) % 2_130_706_433;
                if (j == 0 && i == 0) value = 2_130_706_432;
                row = bytes.concat(row, bytes4(uint32(value)));
            }
            hashes[leaves + i] = bytes32(uint256(keccak256(bytes.concat(hex"00", row))) & mask);
            active[leaves + i] = selected[i];
            if (selected[i]) proof = bytes.concat(proof, row);
        }
        for (uint256 i = leaves - 1; i != 0; --i) {
            hashes[i] = bytes32(
                uint256(keccak256(abi.encodePacked(bytes1(0x01), hashes[2 * i], hashes[2 * i + 1])))
                    & mask
            );
        }
        // Traverse a complete independently constructed tree level by level.
        for (uint256 start = leaves; start > 1; start >>= 1) {
            for (uint256 i = start; i < 2 * start; ++i) {
                if (active[i]) {
                    if (!active[i ^ 1]) proof = bytes.concat(proof, bytes30(hashes[i ^ 1]));
                    active[i >> 1] = true;
                }
            }
        }
        root = hashes[1];
    }

    function testParityAndGas() public view {
        for (uint256 i; i < 13; ++i) {
            Fixture memory f = load(i);
            (uint256 b, uint256[] memory br, uint256 bn) =
                h.baseline(f.proof, f.width, f.height, f.indices, f.roots);
            (uint256 c, uint256[] memory cr, uint256 cn) =
                h.candidate(f.proof, f.width, f.height, f.indices, f.roots);
            assertEq(br, f.rows);
            assertEq(cr, f.rows);
            assertEq(bn, cn);
            if (i < 3) console2.log("baseline/candidate", b, c);
        }
    }

    function testRejectRowsSiblingsRootsAndTruncation() public {
        Fixture memory f = load(0);
        for (uint256 tree; tree < 3; ++tree) {
            bytes32 root = f.roots[tree];
            f.roots[tree] = root ^ bytes32(uint256(1) << 255);
            vm.expectRevert();
            h.candidate(f.proof, f.width, f.height, f.indices, f.roots);
            f.roots[tree] = root;
            for (uint256 j; j < 2; ++j) {
                uint256 at = tree * f.span + (j == 0 ? 3 : f.span - 1);
                bytes1 before = f.proof[at];
                f.proof[at] = before ^ bytes1(0x01);
                vm.expectRevert();
                h.candidate(f.proof, f.width, f.height, f.indices, f.roots);
                f.proof[at] = before;
            }
        }
        bytes memory truncated = new bytes(f.proof.length - 1);
        for (uint256 i; i < truncated.length; ++i) {
            truncated[i] = f.proof[i];
        }
        vm.expectRevert();
        h.candidate(truncated, f.width, f.height, f.indices, f.roots);
        f.indices[0] = uint256(1) << f.height;
        vm.expectRevert();
        h.candidate(f.proof, f.width, f.height, f.indices, f.roots);
    }
}
