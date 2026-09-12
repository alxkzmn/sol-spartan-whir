// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { QuinticShortlistTxBenchmarkBase } from "./QuinticShortlistTxBenchmarkBase.s.sol";
import {
    WhirBlobVerifierNative5_constant_pow27_ff4_lir4_rsv4 as Verifier
} from "../src/whir/quintic_shortlist_constant_pow27_ff4_lir4_rsv4/WhirBlobVerifierNative5_constant_pow27_ff4_lir4_rsv4.sol";

contract WhirBlobNativeTxBenchmarkShortlistConstantPow27Script is QuinticShortlistTxBenchmarkBase {
    function run() external returns (address verifierAddress) {
        (bytes32 commitment, bytes memory blob) = _load("constant_pow27_ff4_lir4_rsv4");
        vm.startBroadcast();
        verifierAddress = address(new Verifier());
        _verify(verifierAddress, commitment, blob);
        vm.stopBroadcast();
    }
}
