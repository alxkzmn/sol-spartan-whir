// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";

import { WhirStructs } from "../src/whir/WhirStructs.sol";
import {
    WhirBlobVerifierNative5_cfsr_pow27_ff4_rest3_lir4_rsv4
} from "../src/whir/quintic_shortlist_cfsr_pow27_ff4_rest3_lir4_rsv4/WhirBlobVerifierNative5_cfsr_pow27_ff4_rest3_lir4_rsv4.sol";

contract QuinticShortlistCfsrPow27Ff4Rest3Lir4Rsv4Test is Test {
    WhirBlobVerifierNative5_cfsr_pow27_ff4_rest3_lir4_rsv4 private verifier;

    function setUp() external {
        verifier = new WhirBlobVerifierNative5_cfsr_pow27_ff4_rest3_lir4_rsv4();
    }

    function testGasShortlistCfsrPow27Ff4Rest3Lir4Rsv4() external view {
        WhirStructs.WhirProof memory proof = abi.decode(
            vm.readFileBinary(
                "testdata/quintic_shortlist/quintic_whir_cfsr_pow27_ff4_rest3_lir4_rsv4_success_proof.abi"
            ),
            (WhirStructs.WhirProof)
        );
        bytes memory blob = vm.readFileBinary(
            "testdata/quintic_shortlist/quintic_whir_cfsr_pow27_ff4_rest3_lir4_rsv4_success.blob"
        );
        assertTrue(verifier.verify(proof.initialCommitment, blob));
    }
}
