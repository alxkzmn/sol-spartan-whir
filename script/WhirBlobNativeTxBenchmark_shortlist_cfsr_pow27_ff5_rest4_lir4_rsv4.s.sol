// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { QuinticShortlistTxBenchmarkBase } from "./QuinticShortlistTxBenchmarkBase.s.sol";
import {
    WhirBlobVerifierNative5_cfsr_pow27_ff5_rest4_lir4_rsv4 as Verifier
} from "../src/whir/quintic_shortlist_cfsr_pow27_ff5_rest4_lir4_rsv4/WhirBlobVerifierNative5_cfsr_pow27_ff5_rest4_lir4_rsv4.sol";

contract WhirBlobNativeTxBenchmarkShortlistCfsrPow27Ff5Script is QuinticShortlistTxBenchmarkBase {
    function run() external returns (address verifierAddress) {
        (bytes32 commitment, bytes memory blob) = _load("cfsr_pow27_ff5_rest4_lir4_rsv4");
        vm.startBroadcast();
        verifierAddress = address(new Verifier());
        _verify(verifierAddress, commitment, blob);
        vm.stopBroadcast();
    }
}
