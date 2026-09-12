// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";

import { WhirStructs } from "../src/whir/WhirStructs.sol";
import {
    BabyBearWhirBlobVerifierNative5_k22_jb100_ext5_lir4_ff4_rsv3_pow28 as BabyBearNativeVerifier
} from "../src/whir/babybear_k22_jb100_ext5_lir4_ff4_rsv3_pow28/BabyBearWhirBlobVerifierNative5_k22_jb100_ext5_lir4_ff4_rsv3_pow28.sol";
import {
    WhirBlobVerifierNative5_k22_jb100_ext5_lir4_ff4_rsv3_pow28 as KoalaBearNativeVerifier
} from "../src/whir/k22_jb100_ext5_lir4_ff4_rsv3_pow28/WhirBlobVerifierNative5_k22_jb100_ext5_lir4_ff4_rsv3_pow28.sol";

// The blob header does not encode the field. The verifier contract fixes the field semantics.
contract BabyBearNativeRejectsKoalaBearBlobTest is Test {
    string internal constant TESTDATA = "testdata/";

    BabyBearNativeVerifier internal verifier;

    function setUp() external {
        verifier = new BabyBearNativeVerifier();
    }

    function testBabyBearNativeRejectsKoalaBearBlob() external {
        WhirStructs.WhirProof memory proof = abi.decode(
            vm.readFileBinary(
                string.concat(
                    TESTDATA, "quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_success_proof.abi"
                )
            ),
            (WhirStructs.WhirProof)
        );
        bytes memory blob = vm.readFileBinary(
            string.concat(TESTDATA, "quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_success.blob")
        );

        vm.expectRevert();
        verifier.verify(proof.initialCommitment, blob);
    }
}

contract KoalaBearNativeRejectsBabyBearBlobTest is Test {
    string internal constant TESTDATA = "testdata/";

    KoalaBearNativeVerifier internal verifier;

    function setUp() external {
        verifier = new KoalaBearNativeVerifier();
    }

    function testKoalaBearNativeRejectsBabyBearBlob() external {
        WhirStructs.WhirProof memory proof = abi.decode(
            vm.readFileBinary(
                string.concat(
                    TESTDATA,
                    "babybear_quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_success_proof.abi"
                )
            ),
            (WhirStructs.WhirProof)
        );
        bytes memory blob = vm.readFileBinary(
            string.concat(
                TESTDATA, "babybear_quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_success.blob"
            )
        );

        vm.expectRevert();
        verifier.verify(proof.initialCommitment, blob);
    }
}
