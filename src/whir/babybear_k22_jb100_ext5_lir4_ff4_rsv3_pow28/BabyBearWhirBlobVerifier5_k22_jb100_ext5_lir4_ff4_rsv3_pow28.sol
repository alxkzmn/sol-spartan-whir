// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { WhirStructs } from "../WhirStructs.sol";
import {
    BabyBearWhirBlobCodec5
} from "./BabyBearWhirBlobCodec5_k22_jb100_ext5_lir4_ff4_rsv3_pow28.sol";
import {
    BabyBearWhirVerifier5_k22_jb100_ext5_lir4_ff4_rsv3_pow28 as BabyBearWhirVerifier5
} from "./BabyBearWhirVerifier5_k22_jb100_ext5_lir4_ff4_rsv3_pow28.sol";

contract BabyBearWhirBlobVerifier5_k22_jb100_ext5_lir4_ff4_rsv3_pow28 {
    BabyBearWhirVerifier5 public immutable verifier;

    constructor(BabyBearWhirVerifier5 verifier_) {
        verifier = verifier_;
    }

    function verify(bytes32 expectedCommitment, bytes calldata blob) external view returns (bool) {
        (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof) =
            BabyBearWhirBlobCodec5.decode(blob);
        return verifier.verify(expectedCommitment, statement, proof);
    }
}
