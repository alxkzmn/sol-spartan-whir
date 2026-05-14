// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { WhirStructs } from "../WhirStructs.sol";
import { WhirBlobCodec5 } from "./WhirBlobCodec5_k22_jb100_ext5_lir4_ff4_rsv4.sol";
import {
    WhirVerifier5_k22_jb100_ext5_lir4_ff4_rsv4 as WhirVerifier5
} from "./WhirVerifier5_k22_jb100_ext5_lir4_ff4_rsv4.sol";

contract WhirBlobVerifier5_k22_jb100_ext5_lir4_ff4_rsv4 {
    WhirVerifier5 public immutable verifier;

    constructor(WhirVerifier5 verifier_) {
        verifier = verifier_;
    }

    function verify(bytes32 expectedCommitment, bytes calldata blob) external view returns (bool) {
        (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof) =
            WhirBlobCodec5.decode(blob);
        return verifier.verify(expectedCommitment, statement, proof);
    }
}
