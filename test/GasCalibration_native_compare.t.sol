// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test, console } from "forge-std/Test.sol";

import { KoalaBearExt4 } from "../src/field/KoalaBearExt4.sol";
import { KoalaBearExt8 } from "../src/field/KoalaBearExt8.sol";
import { KeccakChallenger } from "../src/transcript/KeccakChallenger.sol";
import { QuarticWhirFixedConfig } from "../src/generated/QuarticWhirFixedConfig_lir6_ff5_rsv1.sol";
import {
    OcticWhirFixedConfig_k22_jb100_lir6_ff4_rsv1 as OcticWhirFixedConfig
} from "../src/generated/OcticWhirFixedConfig_k22_jb100_lir6_ff4_rsv1.sol";
import { WhirStructs } from "../src/whir/WhirStructs.sol";
import { WhirBlobCodec4 } from "../src/whir/lir6/WhirBlobCodec4_lir6_ff5_rsv1.sol";
import {
    WhirBlobVerifierNative4
} from "../src/whir/lir6/WhirBlobVerifierNative4_lir6_ff5_rsv1.sol";
import { WhirVerifierCore4 } from "../src/whir/WhirVerifierCore4.sol";
import { WhirVerifierUtils4 } from "../src/whir/WhirVerifierUtils4.sol";
import {
    WhirBlobCodec8
} from "../src/whir/k22_jb100_lir6_ff4_rsv1/WhirBlobCodec8_k22_jb100_lir6_ff4_rsv1.sol";
import {
    WhirBlobVerifierNative8_k22_jb100_lir6_ff4_rsv1 as WhirBlobVerifierNative8
} from "../src/whir/k22_jb100_lir6_ff4_rsv1/WhirBlobVerifierNative8_k22_jb100_lir6_ff4_rsv1.sol";
import { WhirVerifierCore8 } from "../src/whir/k22_jb100_lir6_ff4_rsv1/WhirVerifierCore8.sol";
import { WhirVerifierUtils8 } from "../src/whir/k22_jb100_lir6_ff4_rsv1/WhirVerifierUtils8.sol";

contract NativePhaseCalibrationHarness {
    using KeccakChallenger for KeccakChallenger.State;

    struct QuarticPhaseGas {
        uint256 setup;
        uint256 initialSumcheck;
        uint256 round0Parse;
        uint256 round0Stir;
        uint256 round0Sumcheck;
        uint256 round1Parse;
        uint256 round1Stir;
        uint256 round1Sumcheck;
        uint256 observeFinalPoly;
        uint256 finalStir;
        uint256 finalSumcheck;
        uint256 constraintRounds;
        uint256 constraintInitial;
        uint256 finalValueCheck;
    }

    struct OcticPhaseGas {
        uint256 setup;
        uint256 initialSumcheck;
        uint256 round0Parse;
        uint256 round0Stir;
        uint256 round0Sumcheck;
        uint256 round1Parse;
        uint256 round1Stir;
        uint256 round1Sumcheck;
        uint256 round2Parse;
        uint256 round2Stir;
        uint256 round2Sumcheck;
        uint256 observeFinalPoly;
        uint256 finalStir;
        uint256 finalSumcheck;
        uint256 constraintEqTerms;
        uint256 constraintRounds;
        uint256 constraintInitial;
        uint256 finalValueCheck;
    }

    function measureQuarticNativePhases(bytes32 expectedCommitment, bytes calldata blob)
        external
        view
        returns (QuarticPhaseGas memory pg)
    {
        uint256 g;
        uint256 offset;
        KeccakChallenger.State memory challenger;
        uint256 claimedEval;
        uint256[] memory allRandomness = new uint256[](QuarticWhirFixedConfig.NUM_VARIABLES);
        uint256 randomnessCursor;
        uint256 round0ConstraintChallenge;
        uint256[] memory round0EqFlatPoints;
        uint256[] memory round0SelVars;
        uint256 round1ConstraintChallenge;
        uint256[] memory round1EqFlatPoints;
        uint256[] memory round1SelVars;
        uint256 round1RandomnessOffset;
        uint256 finalStirRandomnessOffset;
        uint256 statementPointOffset;
        WhirVerifierCore4.FixedParsedCommitment memory parsedCommitment;

        g = gasleft();
        (uint256 round0DecommLen, uint256 round1DecommLen, uint256 finalDecommLen) =
            WhirBlobCodec4.validateHeader(blob);

        offset = WhirBlobCodec4.HEADER_BYTES;
        QuarticWhirFixedConfig.observePattern(challenger);

        statementPointOffset = offset;
        unchecked {
            for (uint256 i = 0; i < QuarticWhirFixedConfig.NUM_VARIABLES; ++i) {
                uint256 pointValue;
                (pointValue, offset) = WhirBlobCodec4.readExt4(blob, offset);
                WhirVerifierUtils4.validatePackedExt4(pointValue);
            }
        }

        uint256 statementEval;
        (statementEval, offset) = WhirBlobCodec4.readExt4(blob, offset);
        WhirVerifierUtils4.validatePackedExt4(statementEval);

        uint256 initialOod0;
        uint256 initialOod1;
        uint256 nextOffset;
        (parsedCommitment, initialOod0, initialOod1, nextOffset) =
            WhirVerifierCore4._parseFixedCommitment16x2Blob(challenger, blob, offset);
        offset = nextOffset;

        require(parsedCommitment.root == expectedCommitment, "COMMITMENT");

        uint256 initialConstraintChallenge = WhirVerifierUtils4.sampleExt4(challenger);
        claimedEval = WhirVerifierCore4._hornerStep(
            WhirVerifierCore4._hornerStep(
                WhirVerifierCore4._hornerStep(0, initialConstraintChallenge, initialOod1),
                initialConstraintChallenge,
                initialOod0
            ),
            initialConstraintChallenge,
            statementEval
        );
        pg.setup = g - gasleft();

        uint256 round0RandomnessOffset = randomnessCursor;

        g = gasleft();
        (claimedEval, randomnessCursor, offset) = WhirVerifierCore4._verifySumcheckBlob(
            blob,
            offset,
            challenger,
            claimedEval,
            QuarticWhirFixedConfig.INITIAL_SUMCHECK_ROUNDS,
            QuarticWhirFixedConfig.STARTING_FOLDING_POW_BITS,
            allRandomness,
            randomnessCursor
        );
        pg.initialSumcheck = g - gasleft();

        WhirVerifierCore4.FixedParsedCommitment memory prevCommitment = parsedCommitment;

        g = gasleft();
        WhirVerifierCore4.FixedParsedCommitment memory round0Commitment;
        uint256 round0Ood0;
        uint256 round0Ood1;
        (round0Commitment, round0Ood0, round0Ood1, nextOffset) =
            WhirVerifierCore4._parseFixedCommitment12x2Blob(challenger, blob, offset);
        offset = nextOffset;
        pg.round0Parse = g - gasleft();

        uint256 round0PowWitnessOffset = offset;
        unchecked {
            offset += 4;
        }

        g = gasleft();
        {
            uint256 round0Contribution;
            (round0ConstraintChallenge, round0Contribution, round0SelVars, offset) =
                WhirVerifierCore4._verifyStirAndCombineConstraintBlob(
                    challenger,
                    prevCommitment.root,
                    26,
                    9,
                    18,
                    1_816_824_389,
                    blob,
                    offset,
                    round0DecommLen,
                    round0PowWitnessOffset,
                    allRandomness,
                    round0RandomnessOffset,
                    0,
                    round0Ood0,
                    round0Ood1
                );
            claimedEval = KoalaBearExt4.add(claimedEval, round0Contribution);
        }
        pg.round0Stir = g - gasleft();
        round0EqFlatPoints = round0Commitment.oodFlatPoints;

        round1RandomnessOffset = randomnessCursor;
        g = gasleft();
        (claimedEval, randomnessCursor, offset) = WhirVerifierCore4._verifySumcheckBlob(
            blob,
            offset,
            challenger,
            claimedEval,
            QuarticWhirFixedConfig.FINAL_FOLDING_FACTOR,
            0,
            allRandomness,
            randomnessCursor
        );
        pg.round0Sumcheck = g - gasleft();
        prevCommitment = round0Commitment;

        g = gasleft();
        WhirVerifierCore4.FixedParsedCommitment memory round1Commitment;
        uint256 round1Ood0;
        uint256 round1Ood1;
        (round1Commitment, round1Ood0, round1Ood1, nextOffset) =
            WhirVerifierCore4._parseFixedCommitment8x2Blob(challenger, blob, offset);
        offset = nextOffset;
        pg.round1Parse = g - gasleft();

        uint256 round1PowWitnessOffset = offset;
        unchecked {
            offset += 4;
        }

        g = gasleft();
        {
            uint256 round1Contribution;
            (round1ConstraintChallenge, round1Contribution, round1SelVars, offset) =
                WhirVerifierCore4._verifyStirAndCombineConstraintBlob(
                    challenger,
                    prevCommitment.root,
                    26,
                    6,
                    17,
                    373_019_801,
                    blob,
                    offset,
                    round1DecommLen,
                    round1PowWitnessOffset,
                    allRandomness,
                    round1RandomnessOffset,
                    1,
                    round1Ood0,
                    round1Ood1
                );
            claimedEval = KoalaBearExt4.add(claimedEval, round1Contribution);
        }
        pg.round1Stir = g - gasleft();
        round1EqFlatPoints = round1Commitment.oodFlatPoints;

        finalStirRandomnessOffset = randomnessCursor;
        g = gasleft();
        (claimedEval, randomnessCursor, offset) = WhirVerifierCore4._verifySumcheckBlob(
            blob,
            offset,
            challenger,
            claimedEval,
            QuarticWhirFixedConfig.FINAL_FOLDING_FACTOR,
            4,
            allRandomness,
            randomnessCursor
        );
        pg.round1Sumcheck = g - gasleft();
        prevCommitment = round1Commitment;

        uint256 finalPolyOffset = offset;
        g = gasleft();
        unchecked {
            for (uint256 i = 0; i < QuarticWhirFixedConfig.FINAL_POLY_LENGTH; i += 2) {
                uint256 coeff0;
                uint256 coeff1;
                (coeff0, offset) = WhirBlobCodec4.readExt4(blob, offset);
                (coeff1, offset) = WhirBlobCodec4.readExt4(blob, offset);
                WhirVerifierUtils4.validatePackedExt4(coeff0);
                WhirVerifierUtils4.validatePackedExt4(coeff1);
                challenger.observeValidatedPackedExt4Pair(coeff0, coeff1);
            }
        }
        pg.observeFinalPoly = g - gasleft();

        uint256 finalPowWitnessOffset = offset;
        unchecked {
            offset += 4;
        }

        g = gasleft();
        offset = WhirVerifierCore4._verifyFinalStirChallengesBlob(
            challenger,
            prevCommitment.root,
            QuarticWhirFixedConfig.FINAL_POW_BITS,
            QuarticWhirFixedConfig.FINAL_NUM_QUERIES,
            16,
            QuarticWhirFixedConfig.FINAL_FOLDED_DOMAIN_GEN,
            blob,
            offset,
            finalDecommLen,
            finalPowWitnessOffset,
            allRandomness,
            finalStirRandomnessOffset,
            1,
            finalPolyOffset
        );
        pg.finalStir = g - gasleft();

        uint256 finalSumcheckStart = randomnessCursor;
        g = gasleft();
        (claimedEval, randomnessCursor, offset) = WhirVerifierCore4._verifySumcheckBlob(
            blob,
            offset,
            challenger,
            claimedEval,
            QuarticWhirFixedConfig.FINAL_SUMCHECK_ROUNDS,
            0,
            allRandomness,
            randomnessCursor
        );
        pg.finalSumcheck = g - gasleft();

        require(randomnessCursor == QuarticWhirFixedConfig.NUM_VARIABLES, "RANDOMNESS_LEN");

        uint256 evaluationOfWeights;
        g = gasleft();
        evaluationOfWeights = WhirVerifierCore4._evaluateConstraintsFixedSelectRaw(
            round0ConstraintChallenge,
            round0EqFlatPoints,
            round0SelVars,
            round1ConstraintChallenge,
            round1EqFlatPoints,
            round1SelVars,
            allRandomness
        );
        pg.constraintRounds = g - gasleft();

        g = gasleft();
        evaluationOfWeights = KoalaBearExt4.add(
            evaluationOfWeights,
            WhirVerifierCore4._hornerStep(
                WhirVerifierCore4._hornerStep(
                    WhirVerifierCore4._hornerStep(
                        0,
                        initialConstraintChallenge,
                        WhirVerifierCore4._eqPolyEvalAt(
                            parsedCommitment.oodFlatPoints,
                            QuarticWhirFixedConfig.NUM_VARIABLES,
                            allRandomness,
                            0,
                            QuarticWhirFixedConfig.NUM_VARIABLES
                        )
                    ),
                    initialConstraintChallenge,
                    WhirVerifierCore4._eqPolyEvalAt(
                        parsedCommitment.oodFlatPoints,
                        0,
                        allRandomness,
                        0,
                        QuarticWhirFixedConfig.NUM_VARIABLES
                    )
                ),
                initialConstraintChallenge,
                WhirVerifierCore4._eqPolyEvalAtBlob(
                    blob,
                    statementPointOffset,
                    allRandomness,
                    0,
                    QuarticWhirFixedConfig.NUM_VARIABLES
                )
            )
        );
        pg.constraintInitial = g - gasleft();

        g = gasleft();
        uint256 finalValue = WhirVerifierUtils4._evaluateExtensionRowDim4BlobWindow(
            blob, finalPolyOffset, allRandomness, finalSumcheckStart
        );
        uint256 expected = KoalaBearExt4.mul(evaluationOfWeights, finalValue);
        require(claimedEval == expected, "FINAL_CHECK");
        require(offset == blob.length, "BLOB_LEN");
        pg.finalValueCheck = g - gasleft();
    }

    function measureOcticNativePhases(bytes32 expectedCommitment, bytes calldata blob)
        external
        view
        returns (OcticPhaseGas memory pg)
    {
        uint256 g;
        uint256 offset;
        KeccakChallenger.State memory challenger;
        uint256 claimedEval;
        uint256[] memory allRandomness = new uint256[](OcticWhirFixedConfig.NUM_VARIABLES);
        uint256 randomnessCursor;
        uint256 round0RandomnessOffset;
        uint256 round1RandomnessOffset;
        uint256 round2RandomnessOffset;
        uint256 finalStirRandomnessOffset;
        uint256 statementPointOffset;
        uint256 initialConstraintChallenge;
        uint256 initialOodPoint;
        uint256 round0ConstraintChallenge;
        uint256 round0OodPoint;
        uint256[] memory round0SelVars;
        uint256 round1ConstraintChallenge;
        uint256 round1OodPoint;
        uint256[] memory round1SelVars;
        uint256 round2ConstraintChallenge;
        uint256 round2OodPoint;
        uint256[] memory round2SelVars;

        g = gasleft();
        (
            uint256 round0DecommLen,
            uint256 round1DecommLen,
            uint256 round2DecommLen,
            uint256 finalDecommLen
        ) = WhirBlobCodec8.validateHeader(blob);

        offset = WhirBlobCodec8.HEADER_BYTES;
        OcticWhirFixedConfig.observePattern(challenger);

        statementPointOffset = offset;
        unchecked {
            for (uint256 i = 0; i < OcticWhirFixedConfig.NUM_VARIABLES; ++i) {
                uint256 pointValue;
                (pointValue, offset) = WhirBlobCodec8.readExt8(blob, offset);
                WhirVerifierUtils8.validatePackedExt8(pointValue);
            }
        }

        uint256 statementEval;
        (statementEval, offset) = WhirBlobCodec8.readExt8(blob, offset);
        WhirVerifierUtils8.validatePackedExt8(statementEval);

        bytes32 prevRoot;
        uint256 initialOodEvaluation;
        uint256 nextOffset;
        (prevRoot, initialOodPoint, initialOodEvaluation, nextOffset) =
            WhirVerifierCore8._parseFixedCommitment22x1Blob(challenger, blob, offset);
        offset = nextOffset;

        require(prevRoot == expectedCommitment, "COMMITMENT");

        initialConstraintChallenge = WhirVerifierUtils8.sampleExt8(challenger);
        claimedEval = WhirVerifierCore8._combineInitialConstraintEvalsSingleRaw(
            initialConstraintChallenge, statementEval, initialOodEvaluation
        );
        pg.setup = g - gasleft();

        round0RandomnessOffset = randomnessCursor;
        g = gasleft();
        (claimedEval, randomnessCursor, offset) = WhirVerifierCore8._verifySumcheckBlob4NoPow(
            blob, offset, challenger, claimedEval, allRandomness, randomnessCursor
        );
        pg.initialSumcheck = g - gasleft();

        g = gasleft();
        bytes32 round0Root;
        uint256 round0OodEvaluation;
        (round0Root, round0OodPoint, round0OodEvaluation, offset) =
            WhirVerifierCore8._parseFixedCommitment18x1Blob(challenger, blob, offset);
        pg.round0Parse = g - gasleft();

        uint256 round0PowWitnessOffset = offset;
        unchecked {
            offset += 4;
        }

        g = gasleft();
        {
            uint256 round0Contribution;
            (round0ConstraintChallenge, round0Contribution, round0SelVars, offset) =
                WhirVerifierCore8._verifyRound0StirAndCombineConstraintBlob(
                    challenger,
                    prevRoot,
                    blob,
                    offset,
                    round0DecommLen,
                    round0PowWitnessOffset,
                    allRandomness,
                    round0RandomnessOffset,
                    round0OodEvaluation
                );
            claimedEval = KoalaBearExt8.add(claimedEval, round0Contribution);
        }
        pg.round0Stir = g - gasleft();

        round1RandomnessOffset = randomnessCursor;
        g = gasleft();
        (claimedEval, randomnessCursor, offset) = WhirVerifierCore8._verifySumcheckBlob4NoPow(
            blob, offset, challenger, claimedEval, allRandomness, randomnessCursor
        );
        pg.round0Sumcheck = g - gasleft();
        prevRoot = round0Root;

        g = gasleft();
        bytes32 round1Root;
        uint256 round1OodEvaluation;
        (round1Root, round1OodPoint, round1OodEvaluation, offset) =
            WhirVerifierCore8._parseFixedCommitment14x1Blob(challenger, blob, offset);
        pg.round1Parse = g - gasleft();

        uint256 round1PowWitnessOffset = offset;
        unchecked {
            offset += 4;
        }

        g = gasleft();
        {
            uint256 round1Contribution;
            (round1ConstraintChallenge, round1Contribution, round1SelVars, offset) =
                WhirVerifierCore8._verifyRound1StirAndCombineConstraintBlob(
                    challenger,
                    prevRoot,
                    blob,
                    offset,
                    round1DecommLen,
                    round1PowWitnessOffset,
                    allRandomness,
                    round1RandomnessOffset,
                    round1OodEvaluation
                );
            claimedEval = KoalaBearExt8.add(claimedEval, round1Contribution);
        }
        pg.round1Stir = g - gasleft();

        round2RandomnessOffset = randomnessCursor;
        g = gasleft();
        (claimedEval, randomnessCursor, offset) = WhirVerifierCore8._verifySumcheckBlob4NoPow(
            blob, offset, challenger, claimedEval, allRandomness, randomnessCursor
        );
        pg.round1Sumcheck = g - gasleft();
        prevRoot = round1Root;

        g = gasleft();
        bytes32 round2Root;
        uint256 round2OodEvaluation;
        (round2Root, round2OodPoint, round2OodEvaluation, offset) =
            WhirVerifierCore8._parseFixedCommitment10x1Blob(challenger, blob, offset);
        pg.round2Parse = g - gasleft();

        uint256 round2PowWitnessOffset = offset;
        unchecked {
            offset += 4;
        }

        g = gasleft();
        {
            uint256 round2Contribution;
            (round2ConstraintChallenge, round2Contribution, round2SelVars, offset) =
                WhirVerifierCore8._verifyRound2StirAndCombineConstraintBlob(
                    challenger,
                    prevRoot,
                    blob,
                    offset,
                    round2DecommLen,
                    round2PowWitnessOffset,
                    allRandomness,
                    round2RandomnessOffset,
                    round2OodEvaluation
                );
            claimedEval = KoalaBearExt8.add(claimedEval, round2Contribution);
        }
        pg.round2Stir = g - gasleft();

        finalStirRandomnessOffset = randomnessCursor;
        g = gasleft();
        (claimedEval, randomnessCursor, offset) = WhirVerifierCore8._verifySumcheckBlob4NoPow(
            blob, offset, challenger, claimedEval, allRandomness, randomnessCursor
        );
        pg.round2Sumcheck = g - gasleft();
        prevRoot = round2Root;

        uint256 finalPolyOffset = offset;
        g = gasleft();
        unchecked {
            for (uint256 i = 0; i < OcticWhirFixedConfig.FINAL_POLY_LENGTH; i += 2) {
                uint256 coeff0;
                uint256 coeff1;
                (coeff0, offset) = WhirBlobCodec8.readExt8(blob, offset);
                (coeff1, offset) = WhirBlobCodec8.readExt8(blob, offset);
                challenger.observeValidatedPackedExt8Pair(coeff0, coeff1);
            }
        }
        pg.observeFinalPoly = g - gasleft();

        uint256 finalPowWitnessOffset = offset;
        unchecked {
            offset += 4;
        }

        g = gasleft();
        offset = WhirVerifierCore8._verifyFinalStirChallengesBlobFixed(
            challenger,
            prevRoot,
            blob,
            offset,
            finalDecommLen,
            finalPowWitnessOffset,
            allRandomness,
            finalStirRandomnessOffset,
            finalPolyOffset
        );
        pg.finalStir = g - gasleft();

        uint256 finalSumcheckStart = randomnessCursor;
        g = gasleft();
        (claimedEval, randomnessCursor, offset) = WhirVerifierCore8._verifySumcheckBlob6NoPow(
            blob, offset, challenger, claimedEval, allRandomness, randomnessCursor
        );
        pg.finalSumcheck = g - gasleft();

        require(randomnessCursor == OcticWhirFixedConfig.NUM_VARIABLES, "RANDOMNESS_LEN");

        uint256 statementEq;
        uint256 initialEq;
        uint256 round0Eq;
        uint256 round1Eq;
        uint256 round2Eq;
        g = gasleft();
        (statementEq, initialEq, round0Eq, round1Eq, round2Eq) =
            WhirVerifierCore8._evaluateFixedEqTermsBlobRaw(
                blob,
                statementPointOffset,
                initialOodPoint,
                round0OodPoint,
                round1OodPoint,
                round2OodPoint,
                allRandomness
            );
        pg.constraintEqTerms = g - gasleft();

        g = gasleft();
        uint256 evaluationOfWeights = WhirVerifierCore8._combineInitialConstraintEvalsSingleRaw(
            initialConstraintChallenge, statementEq, initialEq
        );
        pg.constraintInitial = g - gasleft();

        g = gasleft();
        evaluationOfWeights = KoalaBearExt8.add(
            evaluationOfWeights,
            WhirVerifierCore8._evaluateConstraintSelectRaw18WithPrecomputedEq(
                round0ConstraintChallenge, round0Eq, round0SelVars, allRandomness
            )
        );
        evaluationOfWeights = KoalaBearExt8.add(
            evaluationOfWeights,
            WhirVerifierCore8._evaluateConstraintSelectRaw14WithPrecomputedEq(
                round1ConstraintChallenge, round1Eq, round1SelVars, allRandomness
            )
        );
        evaluationOfWeights = KoalaBearExt8.add(
            evaluationOfWeights,
            WhirVerifierCore8._evaluateConstraintSelectRaw10WithPrecomputedEq(
                round2ConstraintChallenge, round2Eq, round2SelVars, allRandomness
            )
        );
        pg.constraintRounds = g - gasleft();

        g = gasleft();
        uint256 finalValue = WhirVerifierCore8._evaluateFinalValueBlob(
            blob,
            finalPolyOffset,
            OcticWhirFixedConfig.FINAL_POLY_LENGTH,
            allRandomness,
            finalSumcheckStart,
            OcticWhirFixedConfig.FINAL_SUMCHECK_ROUNDS
        );
        uint256 expected = KoalaBearExt8.mul(evaluationOfWeights, finalValue);
        require(claimedEval == expected, "FINAL_CHECK");
        pg.finalValueCheck = g - gasleft();
    }
}

contract GasCalibrationNativeCompareTest is Test {
    string internal constant TESTDATA = "testdata/";

    NativePhaseCalibrationHarness internal harness;
    WhirBlobVerifierNative4 internal quarticNative;
    WhirBlobVerifierNative8 internal octicNative;

    function setUp() external {
        harness = new NativePhaseCalibrationHarness();
        quarticNative = new WhirBlobVerifierNative4();
        octicNative = new WhirBlobVerifierNative8();
    }

    function _logSignedDelta(string memory label, uint256 lhs, uint256 rhs) internal pure {
        if (lhs >= rhs) {
            console.log(label, int256(lhs - rhs));
        } else {
            console.log(label, -int256(rhs - lhs));
        }
    }

    function testCompareNativePhaseBreakdown() external view {
        WhirStructs.WhirProof memory quarticProof = abi.decode(
            vm.readFileBinary(
                string.concat(TESTDATA, "quartic_whir_lir6_ff5_rsv1_success_proof.abi")
            ),
            (WhirStructs.WhirProof)
        );
        bytes memory quarticBlob =
            vm.readFileBinary(string.concat(TESTDATA, "quartic_whir_lir6_ff5_rsv1_success.blob"));

        WhirStructs.WhirProof memory octicProof = abi.decode(
            vm.readFileBinary(
                string.concat(TESTDATA, "octic_whir_k22_jb100_lir6_ff4_rsv1_success_proof.abi")
            ),
            (WhirStructs.WhirProof)
        );
        bytes memory octicBlob = vm.readFileBinary(
            string.concat(TESTDATA, "octic_whir_k22_jb100_lir6_ff4_rsv1_success.blob")
        );

        uint256 g = gasleft();
        bool quarticOk = quarticNative.verify(quarticProof.initialCommitment, quarticBlob);
        uint256 quarticNativeGas = g - gasleft();
        assertTrue(quarticOk);

        g = gasleft();
        bool octicOk = octicNative.verify(octicProof.initialCommitment, octicBlob);
        uint256 octicNativeGas = g - gasleft();
        assertTrue(octicOk);

        NativePhaseCalibrationHarness.QuarticPhaseGas memory q =
            harness.measureQuarticNativePhases(quarticProof.initialCommitment, quarticBlob);
        NativePhaseCalibrationHarness.OcticPhaseGas memory o =
            harness.measureOcticNativePhases(octicProof.initialCommitment, octicBlob);

        uint256 quarticPhaseSum = q.setup + q.initialSumcheck + q.round0Parse + q.round0Stir
            + q.round0Sumcheck + q.round1Parse + q.round1Stir + q.round1Sumcheck
            + q.observeFinalPoly + q.finalStir + q.finalSumcheck + q.constraintRounds
            + q.constraintInitial + q.finalValueCheck;
        uint256 octicPhaseSum = o.setup + o.initialSumcheck + o.round0Parse + o.round0Stir
            + o.round0Sumcheck + o.round1Parse + o.round1Stir + o.round1Sumcheck + o.round2Parse
            + o.round2Stir + o.round2Sumcheck + o.observeFinalPoly + o.finalStir + o.finalSumcheck
            + o.constraintEqTerms + o.constraintRounds + o.constraintInitial + o.finalValueCheck;

        console.log("=== Native verifier totals ===");
        console.log("Quartic native total:", quarticNativeGas);
        console.log("Octic native total:  ", octicNativeGas);
        console.log("Delta (octic-q):     ", octicNativeGas - quarticNativeGas);
        console.log("---");

        console.log("=== Quartic native phase sum ===");
        console.log("Setup:", q.setup);
        console.log("Initial sumcheck:", q.initialSumcheck);
        console.log("Round0 parse:", q.round0Parse);
        console.log("Round0 STIR:", q.round0Stir);
        console.log("Round0 sumcheck:", q.round0Sumcheck);
        console.log("Round1 parse:", q.round1Parse);
        console.log("Round1 STIR:", q.round1Stir);
        console.log("Round1 sumcheck:", q.round1Sumcheck);
        console.log("Observe final poly:", q.observeFinalPoly);
        console.log("Final STIR:", q.finalStir);
        console.log("Final sumcheck:", q.finalSumcheck);
        console.log("Constraint rounds:", q.constraintRounds);
        console.log("Constraint initial:", q.constraintInitial);
        console.log("Final value check:", q.finalValueCheck);
        console.log("Quartic phase sum:", quarticPhaseSum);
        console.log("---");

        console.log("=== Octic native phase sum ===");
        console.log("Setup:", o.setup);
        console.log("Initial sumcheck:", o.initialSumcheck);
        console.log("Round0 parse:", o.round0Parse);
        console.log("Round0 STIR:", o.round0Stir);
        console.log("Round0 sumcheck:", o.round0Sumcheck);
        console.log("Round1 parse:", o.round1Parse);
        console.log("Round1 STIR:", o.round1Stir);
        console.log("Round1 sumcheck:", o.round1Sumcheck);
        console.log("Round2 parse:", o.round2Parse);
        console.log("Round2 STIR:", o.round2Stir);
        console.log("Round2 sumcheck:", o.round2Sumcheck);
        console.log("Observe final poly:", o.observeFinalPoly);
        console.log("Final STIR:", o.finalStir);
        console.log("Final sumcheck:", o.finalSumcheck);
        console.log("Constraint eq terms:", o.constraintEqTerms);
        console.log("Constraint rounds:", o.constraintRounds);
        console.log("Constraint initial:", o.constraintInitial);
        console.log("Final value check:", o.finalValueCheck);
        console.log("Octic phase sum:", octicPhaseSum);
        console.log("---");

        console.log("=== Aggregated comparison ===");
        console.log(
            "STIR total delta:",
            (o.round0Stir + o.round1Stir + o.round2Stir + o.finalStir)
                - (q.round0Stir + q.round1Stir + q.finalStir)
        );
        console.log(
            "Sumcheck total delta:",
            (o.initialSumcheck
                    + o.round0Sumcheck
                    + o.round1Sumcheck
                    + o.round2Sumcheck
                    + o.finalSumcheck)
                - (q.initialSumcheck + q.round0Sumcheck + q.round1Sumcheck + q.finalSumcheck)
        );
        console.log(
            "Constraint total delta:",
            (o.constraintEqTerms + o.constraintRounds + o.constraintInitial)
                - (q.constraintRounds + q.constraintInitial)
        );
        _logSignedDelta("Observe final poly delta:", o.observeFinalPoly, q.observeFinalPoly);
        _logSignedDelta("Setup delta:", o.setup, q.setup);
        _logSignedDelta("Final value delta:", o.finalValueCheck, q.finalValueCheck);
    }
}
