// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";

import { WhirStructs } from "../src/whir/WhirStructs.sol";
import {
    WhirBlobVerifierNative5_constant_pow27_ff4_lir4_rsv4
} from "../src/whir/quintic_shortlist_constant_pow27_ff4_lir4_rsv4/WhirBlobVerifierNative5_constant_pow27_ff4_lir4_rsv4.sol";

contract QuinticShortlistConstantPow27Ff4Lir4Rsv4Test is Test {
    WhirBlobVerifierNative5_constant_pow27_ff4_lir4_rsv4 private verifier;

    function setUp() external {
        verifier = new WhirBlobVerifierNative5_constant_pow27_ff4_lir4_rsv4();
    }

    function testGasShortlistConstantPow27Ff4Lir4Rsv4() external view {
        WhirStructs.WhirProof memory proof = abi.decode(
            vm.readFileBinary(
                "testdata/quintic_shortlist/quintic_whir_constant_pow27_ff4_lir4_rsv4_success_proof.abi"
            ),
            (WhirStructs.WhirProof)
        );
        bytes memory blob = vm.readFileBinary(
            "testdata/quintic_shortlist/quintic_whir_constant_pow27_ff4_lir4_rsv4_success.blob"
        );
        assertTrue(verifier.verify(proof.initialCommitment, blob));
    }
}
