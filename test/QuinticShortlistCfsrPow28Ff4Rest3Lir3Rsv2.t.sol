// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";

import { WhirStructs } from "../src/whir/WhirStructs.sol";
import {
    WhirBlobVerifierNative5_cfsr_pow28_ff4_rest3_lir3_rsv2
} from "../src/whir/quintic_shortlist_cfsr_pow28_ff4_rest3_lir3_rsv2/WhirBlobVerifierNative5_cfsr_pow28_ff4_rest3_lir3_rsv2.sol";

contract QuinticShortlistCfsrPow28Ff4Rest3Lir3Rsv2Test is Test {
    WhirBlobVerifierNative5_cfsr_pow28_ff4_rest3_lir3_rsv2 private verifier;

    function setUp() external {
        verifier = new WhirBlobVerifierNative5_cfsr_pow28_ff4_rest3_lir3_rsv2();
    }

    function testGasShortlistCfsrPow28Ff4Rest3Lir3Rsv2() external view {
        WhirStructs.WhirProof memory proof = abi.decode(
            vm.readFileBinary(
                "testdata/quintic_shortlist/quintic_whir_cfsr_pow28_ff4_rest3_lir3_rsv2_success_proof.abi"
            ),
            (WhirStructs.WhirProof)
        );
        bytes memory blob = vm.readFileBinary(
            "testdata/quintic_shortlist/quintic_whir_cfsr_pow28_ff4_rest3_lir3_rsv2_success.blob"
        );
        assertTrue(verifier.verify(proof.initialCommitment, blob));
    }
}
