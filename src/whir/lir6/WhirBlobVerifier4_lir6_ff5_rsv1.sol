// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { WhirStructs } from "../WhirStructs.sol";
import { WhirBlobCodec4 } from "./WhirBlobCodec4_lir6_ff5_rsv1.sol";
import { WhirVerifier4 } from "./WhirVerifier4_lir6_ff5_rsv1.sol";

contract WhirBlobVerifier4 {
    WhirVerifier4 public immutable verifier;

    constructor(WhirVerifier4 verifier_) {
        verifier = verifier_;
    }

    function verify(bytes32 expectedCommitment, bytes calldata blob) external view returns (bool) {
        (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof) =
            WhirBlobCodec4.decode(blob);
        return verifier.verify(expectedCommitment, statement, proof);
    }
}
