// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {WhirStructs} from "../whir/WhirStructs.sol";

library SpartanStructs {
    struct SpartanInstance {
        uint256[] publicInputs;
        bytes32 witnessCommitment;
    }

    struct SpartanProof {
        uint256[] outerSumcheckPolys;
        uint256[3] outerClaims;
        uint256[] innerSumcheckPolys;
        uint256 witnessEval;
        WhirStructs.WhirProof pcsProof;
    }
}
