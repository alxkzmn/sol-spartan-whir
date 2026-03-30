// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {WhirStructs} from "./WhirStructs.sol";
import {WhirVerifierCore4} from "./WhirVerifierCore4.sol";

contract WhirVerifierDebug4 {
    function verify(
        bytes32 expectedCommitment,
        WhirStructs.ExpandedWhirConfig calldata config,
        WhirStructs.WhirStatement calldata statement,
        WhirStructs.WhirProof calldata proof
    ) external pure returns (bool) {
        return
            WhirVerifierCore4.verify(
                expectedCommitment,
                config,
                statement,
                proof
            );
    }
}
