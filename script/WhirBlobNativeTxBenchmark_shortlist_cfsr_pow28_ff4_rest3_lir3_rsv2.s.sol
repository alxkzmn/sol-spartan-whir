// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { QuinticShortlistTxBenchmarkBase } from "./QuinticShortlistTxBenchmarkBase.s.sol";
import {
    WhirBlobVerifierNative5_cfsr_pow28_ff4_rest3_lir3_rsv2 as Verifier
} from "../src/whir/quintic_shortlist_cfsr_pow28_ff4_rest3_lir3_rsv2/WhirBlobVerifierNative5_cfsr_pow28_ff4_rest3_lir3_rsv2.sol";

contract WhirBlobNativeTxBenchmarkShortlistCfsrPow28Lir3Script is QuinticShortlistTxBenchmarkBase {
    function run() external returns (address verifierAddress) {
        (bytes32 commitment, bytes memory blob) = _load("cfsr_pow28_ff4_rest3_lir3_rsv2");
        vm.startBroadcast();
        verifierAddress = address(new Verifier());
        _verify(verifierAddress, commitment, blob);
        vm.stopBroadcast();
    }
}
