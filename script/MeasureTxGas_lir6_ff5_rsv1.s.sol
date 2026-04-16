// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Script, console } from "forge-std/Script.sol";
import { WhirStructs } from "../src/whir/WhirStructs.sol";
import { WhirVerifier4 } from "../src/whir/WhirVerifier4_lir6_ff5_rsv1.sol";

/// @dev Wrapper that makes verify() state-changing so forge script broadcasts it
contract VerifyWrapper {
    bool public result;

    function verifyAndStore(
        WhirVerifier4 verifier,
        bytes32 expectedCommitment,
        WhirStructs.WhirStatement calldata statement,
        WhirStructs.WhirProof calldata proof
    ) external {
        result = verifier.verify(expectedCommitment, statement, proof);
    }
}

contract MeasureTxGas is Script {
    string internal constant TESTDATA = "testdata/";

    function run() external {
        // Load fixture data
        WhirStructs.WhirProof memory proof = abi.decode(
            vm.readFileBinary(
                string.concat(TESTDATA, "quartic_whir_lir6_ff5_rsv1_success_proof.abi")
            ),
            (WhirStructs.WhirProof)
        );
        WhirStructs.WhirStatement memory statement = abi.decode(
            vm.readFileBinary(
                string.concat(TESTDATA, "quartic_whir_lir6_ff5_rsv1_success_statement.abi")
            ),
            (WhirStructs.WhirStatement)
        );

        vm.startBroadcast();
        WhirVerifier4 verifier = new WhirVerifier4();
        VerifyWrapper wrapper = new VerifyWrapper();

        // This is state-changing, so it will be broadcast as a real tx
        wrapper.verifyAndStore(verifier, proof.initialCommitment, statement, proof);
        vm.stopBroadcast();

        console.log("Verify result:", wrapper.result());
    }
}
