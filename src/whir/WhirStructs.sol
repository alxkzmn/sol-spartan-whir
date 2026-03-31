// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

library WhirStructs {
    struct QueryBatchOpening {
        uint8 kind;
        uint256 numQueries;
        uint256 rowLen;
        uint256[] values;
        bytes32[] decommitments;
    }

    struct SumcheckData {
        uint256[] polynomialEvals;
        uint256[] powWitnesses;
    }

    struct WhirRoundProof {
        bytes32 commitment;
        uint256[] oodAnswers;
        uint256 powWitness;
        QueryBatchOpening queryBatch;
        SumcheckData sumcheck;
    }

    struct WhirProof {
        bytes32 initialCommitment;
        uint256[] initialOodAnswers;
        SumcheckData initialSumcheck;
        WhirRoundProof[] rounds;
        uint256[] finalPoly;
        uint256 finalPowWitness;
        bool finalQueryBatchPresent;
        QueryBatchOpening finalQueryBatch;
        bool finalSumcheckPresent;
        SumcheckData finalSumcheck;
    }

    struct WhirStatement {
        uint256[][] points;
        uint256[] evaluations;
    }
}
