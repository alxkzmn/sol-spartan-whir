// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Script, console2 } from "forge-std/Script.sol";

import { Ext8PrecompileHarness } from "../test/helpers/Ext8PrecompileHarness.sol";

contract Ext8PrecompileArithmeticDiffScript is Script {
    string internal constant TESTDATA = "testdata/";
    uint256 internal constant CHUNK = 250;

    function run() external returns (address harnessAddress) {
        (
            uint256[] memory packedA,
            uint256[] memory packedB,
            uint256[] memory expectedMul,
            uint256[] memory expectedSquareA
        ) = abi.decode(
            vm.readFileBinary(string.concat(TESTDATA, "ext8_precompile_vectors.abi")),
            (uint256[], uint256[], uint256[], uint256[])
        );

        require(packedA.length == packedB.length, "LEN_B");
        require(packedA.length == expectedMul.length, "LEN_MUL");
        require(packedA.length == expectedSquareA.length, "LEN_SQ");

        vm.startBroadcast();
        Ext8PrecompileHarness harness = new Ext8PrecompileHarness();
        harnessAddress = address(harness);

        uint256 total = packedA.length;
        for (uint256 start = 0; start < total; start += CHUNK) {
            uint256 end = start + CHUNK;
            if (end > total) {
                end = total;
            }
            harness.checkArithmeticVectorsTx(
                _slice(packedA, start, end),
                _slice(packedB, start, end),
                _slice(expectedMul, start, end),
                _slice(expectedSquareA, start, end)
            );
        }
        vm.stopBroadcast();

        console2.log("ext8PrecompileDiffHarness", harnessAddress);
        console2.log("vectorCount", total);
        console2.log("chunkSize", CHUNK);
    }

    function _slice(uint256[] memory input, uint256 start, uint256 end)
        internal
        pure
        returns (uint256[] memory out)
    {
        out = new uint256[](end - start);
        unchecked {
            for (uint256 i = start; i < end; ++i) {
                out[i - start] = input[i];
            }
        }
    }
}
