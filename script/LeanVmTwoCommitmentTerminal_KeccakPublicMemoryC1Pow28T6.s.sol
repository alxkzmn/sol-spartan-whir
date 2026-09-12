// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Script, console2 } from "forge-std/Script.sol";
import {
    LeanVmTwoCommitmentTerminalVerifier
} from "../src/leanvm/LeanVmTwoCommitmentTerminalVerifier.sol";
import {
    LeanVmTwoCommitmentTerminal_KeccakPublicMemoryC1Pow28T6
} from "../src/leanvm/generated/LeanVmTwoCommitmentTerminal_KeccakPublicMemoryC1Pow28T6.sol";

contract LeanVmTwoCommitmentTerminal_KeccakPublicMemoryC1Pow28T6TxBenchmark is Script {
    function run() external {
        bytes memory encoded =
            vm.readFileBinary("testdata/leanvm_terminal/KeccakPublicMemoryC1Pow28T6/proof.abi");
        LeanVmTwoCommitmentTerminalVerifier.Proof memory proof =
            abi.decode(encoded, (LeanVmTwoCommitmentTerminalVerifier.Proof));
        bytes memory data =
            vm.readFileBinary("testdata/leanvm_terminal/KeccakPublicMemoryC1Pow28T6/calldata.bin");
        require(
            keccak256(data)
                == keccak256(
                    abi.encodeCall(LeanVmTwoCommitmentTerminalVerifier.verifyC1V1, (proof))
                ),
            "CALLDATA_ENCODING"
        );
        vm.startBroadcast();
        LeanVmTwoCommitmentTerminal_KeccakPublicMemoryC1Pow28T6 verifier =
            new LeanVmTwoCommitmentTerminal_KeccakPublicMemoryC1Pow28T6();
        (bool ok, bytes memory result) = address(verifier).call(data);
        require(ok && abi.decode(result, (bool)), "VERIFY_FAILED");
        vm.stopBroadcast();
        console2.log("complete two-commitment terminal verifier", address(verifier));
        console2.log("complete verification calldata bytes", data.length);
    }
}
