// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { WhirStructs } from "../WhirStructs.sol";
import { WhirBlobCodecLir11 } from "./WhirBlobCodec4_lir11_ff5_rsv3.sol";
import { WhirVerifierLir11 } from "./WhirVerifier4_lir11_ff5_rsv3.sol";

contract WhirBlobVerifierLir11 {
    WhirVerifierLir11 public immutable verifier;

    constructor(WhirVerifierLir11 verifier_) {
        verifier = verifier_;
    }

    function verify(bytes32 expectedCommitment, bytes calldata blob) external view returns (bool) {
        (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof) =
            WhirBlobCodecLir11.decode(blob);
        return verifier.verify(expectedCommitment, statement, proof);
    }
}
