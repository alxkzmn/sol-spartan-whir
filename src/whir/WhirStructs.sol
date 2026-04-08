// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

library WhirStructs {
    struct RoundConfig {
        uint256 powBits;
        uint256 foldingPowBits;
        uint256 numQueries;
        uint256 oodSamples;
        uint256 numVariables;
        uint256 foldingFactor;
        uint256 domainSize;
        uint256 foldedDomainGen;
    }

    struct ExpandedWhirConfig {
        uint256 numVariables;
        uint256 securityLevel;
        uint256 maxPowBits;
        uint256 commitmentOodSamples;
        uint256 startingLogInvRate;
        uint256 startingFoldingPowBits;
        uint256 rsDomainInitialReductionFactor;
        uint256 finalSumcheckRounds;
        uint8 soundnessAssumption;
        uint32 merkleSecurityBits;
        uint8 effectiveDigestBytes;
        uint256[] whirFsPattern;
        RoundConfig[] roundParameters;
        RoundConfig finalRoundConfig;
    }

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
