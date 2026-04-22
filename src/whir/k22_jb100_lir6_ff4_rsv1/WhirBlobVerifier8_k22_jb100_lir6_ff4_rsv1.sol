// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { WhirStructs } from "../WhirStructs.sol";
import { WhirBlobCodec8 } from "./WhirBlobCodec8_k22_jb100_lir6_ff4_rsv1.sol";
import {
    WhirVerifier8_k22_jb100_lir6_ff4_rsv1 as WhirVerifier8
} from "./WhirVerifier8_k22_jb100_lir6_ff4_rsv1.sol";

contract WhirBlobVerifier8_k22_jb100_lir6_ff4_rsv1 {
    WhirVerifier8 public immutable verifier;

    constructor(WhirVerifier8 verifier_) {
        verifier = verifier_;
    }

    function verify(bytes32 expectedCommitment, bytes calldata blob) external view returns (bool) {
        (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof) =
            WhirBlobCodec8.decode(blob);
        return verifier.verify(expectedCommitment, statement, proof);
    }
}
