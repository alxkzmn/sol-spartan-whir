// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import { Test, console2 } from "forge-std/Test.sol";
import { LeanVmPoseidon1 } from "../src/leanvm/LeanVmPoseidon1.sol";
import {
    LeanVmPoseidon1DenseReference as Dense
} from "./helpers/LeanVmPoseidon1DenseReference.sol";

contract LeanVmPoseidon1Test is Test {
    function testFuzzSparseMatchesDense(uint256[16] memory input) external pure {
        _comparePermutation(input);
    }

    function testSparseBasisAndBoundaries() external pure {
        for (uint256 i; i < 16; ++i) {
            uint256[16] memory state;
            state[i] = 1;
            _comparePermutation(state);
        }
        uint256[16] memory boundary;
        for (uint256 i; i < 16; ++i) {
            boundary[i] = i % 4 == 0 ? type(uint256).max : 2_130_706_432 + i % 4;
        }
        _comparePermutation(boundary);
    }

    function _comparePermutation(uint256[16] memory input) private pure {
        uint256[16] memory expected;
        for (uint256 i; i < 16; ++i) {
            expected[i] = input[i];
        }
        LeanVmPoseidon1.permute(input);
        Dense.permute(expected);
        for (uint256 i; i < 16; ++i) {
            assertEq(input[i], expected[i]);
        }
    }

    function testSparseHashOrderingAndInputPreserved() external pure {
        for (uint256 blocks = 1; blocks <= 3; ++blocks) {
            uint256[] memory words = new uint256[](blocks * 8);
            for (uint256 i; i < words.length; ++i) {
                words[i] = 2_130_706_432 - i;
            }
            uint256[8] memory forward = LeanVmPoseidon1.hashWords(words);
            uint256[8] memory forwardExpected = Dense.hashWords(words);
            uint256[8] memory reverse = LeanVmPoseidon1.hashLeaf(words);
            uint256[8] memory reverseExpected = Dense.hashLeaf(words);
            for (uint256 i; i < 8; ++i) {
                assertEq(forward[i], forwardExpected[i]);
                assertEq(reverse[i], reverseExpected[i]);
            }
            for (uint256 i; i < words.length; ++i) {
                assertEq(words[i], 2_130_706_432 - i);
            }
        }
    }

    function testSparseTemporaryMemoryDoesNotEscape() external pure {
        uint256[16] memory state;
        uint256[] memory sentinel = new uint256[](40);
        for (uint256 i; i < sentinel.length; ++i) {
            sentinel[i] = 7919 + i;
        }
        uint256 before;
        uint256 afterPermutation;
        assembly ("memory-safe") { before := mload(0x40) }
        LeanVmPoseidon1.permute(state);
        assembly ("memory-safe") { afterPermutation := mload(0x40) }
        assertEq(before, afterPermutation);
        uint256[] memory overwrite = new uint256[](160);
        for (uint256 i; i < overwrite.length; ++i) {
            overwrite[i] = type(uint256).max;
        }
        for (uint256 i; i < sentinel.length; ++i) {
            assertEq(sentinel[i], 7919 + i);
        }
        assertEq(state[0], 2_096_630_793);
        assertEq(overwrite[159], type(uint256).max);
    }

    function hashWordsExternal(uint256[] memory values) external pure returns (uint256[8] memory) {
        return LeanVmPoseidon1.hashWords(values);
    }

    function hashLeafExternal(uint256[] memory values) external pure returns (uint256[8] memory) {
        return LeanVmPoseidon1.hashLeaf(values);
    }

    function testSparseRejectsInvalidHashInputs() external {
        uint256[] memory words = new uint256[](8);
        words[7] = 2_130_706_433;
        vm.expectRevert(LeanVmPoseidon1.NonCanonicalField.selector);
        this.hashWordsExternal(words);
        vm.expectRevert(LeanVmPoseidon1.NonCanonicalField.selector);
        this.hashLeafExternal(words);
        vm.expectRevert(LeanVmPoseidon1.InvalidLeafLength.selector);
        this.hashWordsExternal(new uint256[](0));
        vm.expectRevert(LeanVmPoseidon1.InvalidLeafLength.selector);
        this.hashLeafExternal(new uint256[](9));
    }

    function testSparseDenseNodeMetadataComparison() external view {
        (uint256[] memory words, uint256[] memory expected) = _nodeMetadata();
        uint256 beforeGas = gasleft();
        uint256[8] memory candidate = LeanVmPoseidon1.hashWords(words);
        uint256 candidateGas = beforeGas - gasleft();
        beforeGas = gasleft();
        uint256[8] memory dense = Dense.hashWords(words);
        uint256 denseGas = beforeGas - gasleft();
        for (uint256 i; i < 8; ++i) {
            assertEq(candidate[i], expected[i]);
            assertEq(dense[i], expected[i]);
        }
        console2.log("sparse node metadata execution gas", candidateGas);
        console2.log("dense node metadata execution gas", denseGas);
    }

    function testNodeMetadataDigest() external view {
        (uint256[] memory words, uint256[] memory expected) = _nodeMetadata();
        uint256 beforeGas = gasleft();
        uint256[8] memory result = LeanVmPoseidon1.hashWords(words);
        uint256 used = beforeGas - gasleft();
        for (uint256 i = 0; i < 8; ++i) {
            assertEq(result[i], expected[i]);
        }
        console2.log("poseidon1 node metadata execution gas", used);
    }

    function _nodeMetadata()
        private
        view
        returns (uint256[] memory words, uint256[] memory expected)
    {
        string memory fixture = vm.readFile("testdata/leanvm_poseidon1/node-metadata.json");
        words = vm.parseJsonUintArray(fixture, ".words");
        expected = vm.parseJsonUintArray(fixture, ".digest");
        assertEq(words.length, 256);
        assertEq(expected.length, 8);
    }

    function testPermutation0() external pure {
        uint256[16] memory state = [uint256(0), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        uint256[16] memory expected = [
            uint256(2_096_630_793),
            502_841_916,
            2_048_234_017,
            615_698_125,
            1_716_747_525,
            1_717_817_948,
            194_562_273,
            959_725_011,
            1_720_971_930,
            2_093_224_065,
            1_607_677_051,
            1_849_387_246,
            2_054_104_179,
            1_529_778_884,
            1_740_781_079,
            92_100_382
        ];
        LeanVmPoseidon1.permute(state);
        for (uint256 i = 0; i < 16; ++i) {
            assertEq(state[i], expected[i]);
        }
    }

    function testPermutation1() external pure {
        uint256[16] memory state = [uint256(0), 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        uint256[16] memory expected = [
            uint256(610_090_613),
            935_319_874,
            1_893_335_292,
            796_792_199,
            356_405_232,
            552_237_741,
            55_134_556,
            1_215_104_204,
            1_823_723_405,
            1_133_298_033,
            1_780_633_798,
            1_453_946_561,
            710_069_176,
            1_128_629_550,
            1_917_333_254,
            1_175_481_618
        ];
        LeanVmPoseidon1.permute(state);
        for (uint256 i = 0; i < 16; ++i) {
            assertEq(state[i], expected[i]);
        }
    }

    function testPermutation2() external pure {
        uint256[16] memory state = [
            uint256(2_130_706_432),
            2_130_706_432,
            2_130_706_432,
            2_130_706_432,
            2_130_706_432,
            2_130_706_432,
            2_130_706_432,
            2_130_706_432,
            2_130_706_432,
            2_130_706_432,
            2_130_706_432,
            2_130_706_432,
            2_130_706_432,
            2_130_706_432,
            2_130_706_432,
            2_130_706_432
        ];
        uint256[16] memory expected = [
            uint256(80_767_616),
            383_372_031,
            1_503_356_788,
            2_125_894_918,
            1_946_887_912,
            879_437_609,
            1_712_137_281,
            672_292_544,
            1_911_844_364,
            828_626_166,
            1_140_802_964,
            650_895_436,
            1_866_586_638,
            613_293_787,
            1_870_649_746,
            481_320_165
        ];
        LeanVmPoseidon1.permute(state);
        for (uint256 i = 0; i < 16; ++i) {
            assertEq(state[i], expected[i]);
        }
    }

    function testLeaf512() external view {
        uint256[] memory leaf = new uint256[](512);
        for (uint256 i = 0; i < 512; ++i) {
            leaf[i] = i;
        }
        uint256 beforeGas = gasleft();
        uint256[8] memory result = LeanVmPoseidon1.hashLeaf(leaf);
        uint256 used = beforeGas - gasleft();
        uint256[8] memory expected = [
            uint256(181_386_867),
            2_004_972_015,
            1_785_769_907,
            285_151_450,
            364_346_237,
            1_451_605_140,
            192_200_614,
            117_171_388
        ];
        for (uint256 i = 0; i < 8; ++i) {
            assertEq(result[i], expected[i]);
        }
        console2.log("poseidon1 leaf512 execution gas", used);
    }

    function testPermutationGas() external view {
        uint256[16] memory state;
        uint256 beforeGas = gasleft();
        LeanVmPoseidon1.permute(state);
        uint256 used = beforeGas - gasleft();
        assertEq(state[0], 2_096_630_793);
        console2.log("poseidon1 permutation execution gas", used);
    }
}
