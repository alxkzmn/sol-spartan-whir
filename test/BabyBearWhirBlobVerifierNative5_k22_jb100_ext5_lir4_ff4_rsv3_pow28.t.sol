// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";

import { WhirStructs } from "../src/whir/WhirStructs.sol";
import {
    BabyBearWhirBlobCodec5
} from "../src/whir/babybear_k22_jb100_ext5_lir4_ff4_rsv3_pow28/BabyBearWhirBlobCodec5_k22_jb100_ext5_lir4_ff4_rsv3_pow28.sol";
import {
    BabyBearWhirBlobVerifier5_k22_jb100_ext5_lir4_ff4_rsv3_pow28
} from "../src/whir/babybear_k22_jb100_ext5_lir4_ff4_rsv3_pow28/BabyBearWhirBlobVerifier5_k22_jb100_ext5_lir4_ff4_rsv3_pow28.sol";
import {
    BabyBearWhirBlobVerifierNative5_k22_jb100_ext5_lir4_ff4_rsv3_pow28
} from "../src/whir/babybear_k22_jb100_ext5_lir4_ff4_rsv3_pow28/BabyBearWhirBlobVerifierNative5_k22_jb100_ext5_lir4_ff4_rsv3_pow28.sol";
import {
    BabyBearWhirVerifier5_k22_jb100_ext5_lir4_ff4_rsv3_pow28
} from "../src/whir/babybear_k22_jb100_ext5_lir4_ff4_rsv3_pow28/BabyBearWhirVerifier5_k22_jb100_ext5_lir4_ff4_rsv3_pow28.sol";
import {
    BabyBearWhirVerifierCore5
} from "../src/whir/babybear_k22_jb100_ext5_lir4_ff4_rsv3_pow28/BabyBearWhirVerifierCore5.sol";
import {
    BabyBearWhirVerifierUtils5
} from "../src/whir/babybear_k22_jb100_ext5_lir4_ff4_rsv3_pow28/BabyBearWhirVerifierUtils5.sol";
import {
    BabyBearQuinticWhirFixedConfig_k22_jb100_ext5_lir4_ff4_rsv3_pow28 as BabyBearQuinticWhirFixedConfig
} from "../src/generated/BabyBearQuinticWhirFixedConfig_k22_jb100_ext5_lir4_ff4_rsv3_pow28.sol";
import { BabyBearKeccakChallenger } from "../src/transcript/BabyBearKeccakChallenger.sol";

contract BabyBearQuinticNativePrefixHarnessPow28Rsv3 {
    using BabyBearKeccakChallenger for BabyBearKeccakChallenger.State;

    function round0Samples(bytes32 expectedCommitment, bytes calldata blob)
        external
        pure
        returns (uint256[] memory samples)
    {
        (uint256 round0DecommLen,,,) = BabyBearWhirBlobCodec5.validateHeader(blob);
        round0DecommLen;

        uint256 offset = BabyBearWhirBlobCodec5.HEADER_BYTES;
        BabyBearKeccakChallenger.State memory challenger;
        BabyBearQuinticWhirFixedConfig.observePattern(challenger);

        unchecked {
            for (uint256 i = 0; i < BabyBearQuinticWhirFixedConfig.NUM_VARIABLES; ++i) {
                uint256 pointValue;
                (pointValue, offset) = BabyBearWhirBlobCodec5.readExt5(blob, offset);
                BabyBearWhirVerifierUtils5.validatePackedExt5(pointValue);
            }
        }

        uint256 statementEval;
        (statementEval, offset) = BabyBearWhirBlobCodec5.readExt5(blob, offset);
        BabyBearWhirVerifierUtils5.validatePackedExt5(statementEval);

        (bytes32 prevRoot,, uint256 initialOodEvaluation, uint256 nextOffset) =
            BabyBearWhirVerifierCore5._parseFixedCommitment22x1Blob(challenger, blob, offset);
        offset = nextOffset;

        if (prevRoot != expectedCommitment) {
            revert BabyBearWhirVerifierCore5.CommitmentMismatch(expectedCommitment, prevRoot);
        }

        uint256 initialConstraintChallenge = BabyBearWhirVerifierUtils5.sampleExt5(challenger);
        uint256 claimedEval = BabyBearWhirVerifierCore5._combineInitialConstraintEvalsSingleRaw(
            initialConstraintChallenge, statementEval, initialOodEvaluation
        );

        uint256[] memory allRandomness = new uint256[](BabyBearQuinticWhirFixedConfig.NUM_VARIABLES);
        (claimedEval,, offset) = BabyBearWhirVerifierCore5._verifySumcheckBlob(
            blob, offset, challenger, claimedEval, 4, 27, allRandomness, 0
        );

        (,, uint256 round0OodEvaluation, uint256 roundOffset) =
            BabyBearWhirVerifierCore5._parseFixedCommitment18x1Blob(challenger, blob, offset);
        offset = roundOffset;

        BabyBearWhirVerifierCore5._checkWitnessBaseLeBlob(challenger, 27, blob, offset);
        challenger.sampleBase();
        round0OodEvaluation;

        samples = new uint256[](38);
        unchecked {
            for (uint256 i = 0; i < 38; ++i) {
                samples[i] = challenger.sampleBits(22);
            }
        }
    }
}

contract BabyBearWhirBlobVerifierNative5K22Jb100Ext5Pow28Rsv3Test is Test {
    string internal constant TESTDATA = "testdata/";
    uint256 internal constant MODULUS = 0x78000001;
    uint256 internal constant HEADER_BYTES = 18;
    uint256 internal constant STATEMENT_POINT_ARITY = 22;
    uint256 internal constant RAW_EXT5_BYTES = 20;
    uint256 internal constant BASE_BYTES = 4;
    uint256 internal constant DIGEST_BYTES = 20;

    BabyBearWhirVerifier5_k22_jb100_ext5_lir4_ff4_rsv3_pow28 internal verifier;
    BabyBearWhirBlobVerifier5_k22_jb100_ext5_lir4_ff4_rsv3_pow28 internal blobVerifier;
    BabyBearWhirBlobVerifierNative5_k22_jb100_ext5_lir4_ff4_rsv3_pow28 internal nativeBlobVerifier;
    BabyBearQuinticNativePrefixHarnessPow28Rsv3 internal prefixHarness;

    struct BlobOffsets {
        uint256 statementEval;
        uint256 initialOod;
        uint256 initialSumcheck;
        uint256 finalPoly;
        uint256 finalValues;
    }

    function setUp() external {
        verifier = new BabyBearWhirVerifier5_k22_jb100_ext5_lir4_ff4_rsv3_pow28();
        blobVerifier = new BabyBearWhirBlobVerifier5_k22_jb100_ext5_lir4_ff4_rsv3_pow28(verifier);
        nativeBlobVerifier =
            new BabyBearWhirBlobVerifierNative5_k22_jb100_ext5_lir4_ff4_rsv3_pow28();
        prefixHarness = new BabyBearQuinticNativePrefixHarnessPow28Rsv3();
    }

    function testNativePrefixRound0SamplesMatchTrace() external view {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(
                TESTDATA, "babybear_quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_success.blob"
            )
        );
        uint256[] memory samples = prefixHarness.round0Samples(proof.initialCommitment, blob);

        assertEq(samples[0], 3_256_537);
        assertEq(samples[1], 2_792_883);
        assertEq(samples[2], 2_304_825);
        assertEq(samples[36], 816_546);
        assertEq(samples[37], 3_884_275);
    }

    function testVerifyBabyBearQuinticWhirSuccessTyped() external view {
        (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof) =
            _loadSuccessFixture();
        assertTrue(verifier.verify(proof.initialCommitment, statement, proof));
    }

    function testVerifyBabyBearQuinticWhirSuccessBlob() external view {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(
                TESTDATA, "babybear_quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_success.blob"
            )
        );
        assertTrue(blobVerifier.verify(proof.initialCommitment, blob));
    }

    function testVerifyBabyBearQuinticWhirSuccessBlobNative() external view {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(
                TESTDATA, "babybear_quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_success.blob"
            )
        );
        assertTrue(nativeBlobVerifier.verify(proof.initialCommitment, blob));
    }

    function testGasBabyBearWhirVerifyBlobNativeFixed() external view {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(
                TESTDATA, "babybear_quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_success.blob"
            )
        );
        assertTrue(nativeBlobVerifier.verify(proof.initialCommitment, blob));
    }

    function testRejectsBadCommitmentTyped() external {
        _expectTypedFailure(
            "babybear_quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_failure_bad_commitment_proof.abi"
        );
    }

    function testRejectsBadStirQueryTyped() external {
        _expectTypedFailure(
            "babybear_quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_failure_bad_stir_query_proof.abi"
        );
    }

    function testRejectsBadOodTyped() external {
        _expectTypedFailure(
            "babybear_quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_failure_bad_ood_or_transcript_mismatch_proof.abi"
        );
    }

    function testRejectsBadCommitmentBlobWrapper() external {
        _expectWrapperFailure(
            "babybear_quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_failure_bad_commitment.blob"
        );
    }

    function testRejectsBadStirQueryBlobWrapper() external {
        _expectWrapperFailure(
            "babybear_quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_failure_bad_stir_query.blob"
        );
    }

    function testRejectsBadOodBlobWrapper() external {
        _expectWrapperFailure(
            "babybear_quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_failure_bad_ood_or_transcript_mismatch.blob"
        );
    }

    function testNativeBlobUsesLessGasThanWrapper() external view {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(
                TESTDATA, "babybear_quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_success.blob"
            )
        );

        uint256 gasBeforeNative = gasleft();
        bool nativeOk = nativeBlobVerifier.verify(proof.initialCommitment, blob);
        uint256 nativeGas = gasBeforeNative - gasleft();
        assertTrue(nativeOk);

        uint256 gasBeforeWrapper = gasleft();
        bool wrapperOk = blobVerifier.verify(proof.initialCommitment, blob);
        uint256 wrapperGas = gasBeforeWrapper - gasleft();
        assertTrue(wrapperOk);

        assertLt(nativeGas, wrapperGas);
    }

    function testNativeBlobUsesLessGasThanTypedVerifier() external view {
        (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof) =
            _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(
                TESTDATA, "babybear_quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_success.blob"
            )
        );

        uint256 gasBeforeNative = gasleft();
        bool nativeOk = nativeBlobVerifier.verify(proof.initialCommitment, blob);
        uint256 nativeGas = gasBeforeNative - gasleft();
        assertTrue(nativeOk);

        uint256 gasBeforeTyped = gasleft();
        bool typedOk = verifier.verify(proof.initialCommitment, statement, proof);
        uint256 typedGas = gasBeforeTyped - gasleft();
        assertTrue(typedOk);

        assertLt(nativeGas, typedGas);
    }

    function testRejectsBadCommitmentBlobNative() external {
        (, WhirStructs.WhirProof memory success) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(
                TESTDATA,
                "babybear_quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_failure_bad_commitment.blob"
            )
        );
        vm.expectRevert();
        nativeBlobVerifier.verify(success.initialCommitment, blob);
    }

    function testRejectsBadStirQueryBlobNative() external {
        (, WhirStructs.WhirProof memory success) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(
                TESTDATA,
                "babybear_quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_failure_bad_stir_query.blob"
            )
        );
        vm.expectRevert();
        nativeBlobVerifier.verify(success.initialCommitment, blob);
    }

    function testRejectsBadOodBlobNative() external {
        (, WhirStructs.WhirProof memory success) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(
                TESTDATA,
                "babybear_quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_failure_bad_ood_or_transcript_mismatch.blob"
            )
        );
        vm.expectRevert();
        nativeBlobVerifier.verify(success.initialCommitment, blob);
    }

    function testRejectsBlobWrongMagicNative() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(
                TESTDATA, "babybear_quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_success.blob"
            )
        );
        blob[0] = 0x00;
        vm.expectRevert(BabyBearWhirBlobCodec5.BlobMagicMismatch.selector);
        nativeBlobVerifier.verify(proof.initialCommitment, blob);
    }

    function testRejectsBlobWrongVersionNative() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(
                TESTDATA, "babybear_quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_success.blob"
            )
        );
        blob[5] = 0x02;
        vm.expectRevert(BabyBearWhirBlobCodec5.BlobVersionMismatch.selector);
        nativeBlobVerifier.verify(proof.initialCommitment, blob);
    }

    function testRejectsBlobWrongHeaderFieldsNative() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(
                TESTDATA, "babybear_quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_success.blob"
            )
        );

        bytes memory wrongDigest = _clone(blob);
        wrongDigest[6] = 0x13;
        vm.expectRevert(BabyBearWhirBlobCodec5.BlobDigestWidthMismatch.selector);
        nativeBlobVerifier.verify(proof.initialCommitment, wrongDigest);

        bytes memory wrongExtDegree = _clone(blob);
        wrongExtDegree[7] = 0x04;
        vm.expectRevert(BabyBearWhirBlobCodec5.BlobExtensionDegreeMismatch.selector);
        nativeBlobVerifier.verify(proof.initialCommitment, wrongExtDegree);

        bytes memory wrongRounds = _clone(blob);
        wrongRounds[8] = 0x02;
        vm.expectRevert(BabyBearWhirBlobCodec5.BlobRoundCountMismatch.selector);
        nativeBlobVerifier.verify(proof.initialCommitment, wrongRounds);

        bytes memory wrongFlags = _clone(blob);
        wrongFlags[9] = 0x00;
        vm.expectRevert(BabyBearWhirBlobCodec5.BlobFlagsMismatch.selector);
        nativeBlobVerifier.verify(proof.initialCommitment, wrongFlags);
    }

    function testRejectsTruncatedBlobNative() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(
                TESTDATA, "babybear_quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_success.blob"
            )
        );
        assembly ("memory-safe") {
            mstore(blob, sub(mload(blob), 1))
        }
        vm.expectRevert(BabyBearWhirBlobCodec5.BlobLengthMismatch.selector);
        nativeBlobVerifier.verify(proof.initialCommitment, blob);
    }

    function testRejectsBlobTrailingBytesNative() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(
                TESTDATA, "babybear_quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_success.blob"
            )
        );
        bytes memory extended = bytes.concat(blob, hex"01");
        vm.expectRevert(BabyBearWhirBlobCodec5.BlobLengthMismatch.selector);
        nativeBlobVerifier.verify(proof.initialCommitment, extended);
    }

    function testRejectsMalformedInitialOodAnswersBlobNative() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        BlobOffsets memory offsets = _computeOffsets(proof);

        for (uint256 lane = 0; lane < 5; ++lane) {
            bytes memory blob = vm.readFileBinary(
                string.concat(
                    TESTDATA,
                    "babybear_quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_success.blob"
                )
            );
            _setExt5LaneLe(blob, offsets.initialOod, lane, MODULUS);

            vm.expectRevert();
            nativeBlobVerifier.verify(proof.initialCommitment, blob);
        }
    }

    function testRejectsTamperedInitialSumcheckDataBlobNative() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(
                TESTDATA, "babybear_quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_success.blob"
            )
        );
        BlobOffsets memory offsets = _computeOffsets(proof);

        _incrementExt5LaneLe(blob, offsets.initialSumcheck, 0);

        vm.expectRevert();
        nativeBlobVerifier.verify(proof.initialCommitment, blob);
    }

    function testRejectsMalformedInitialSumcheckEvalsBlobNative() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        BlobOffsets memory offsets = _computeOffsets(proof);

        for (uint256 lane = 0; lane < 5; ++lane) {
            bytes memory blob = vm.readFileBinary(
                string.concat(
                    TESTDATA,
                    "babybear_quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_success.blob"
                )
            );
            _setExt5LaneLe(blob, offsets.initialSumcheck, lane, MODULUS);

            vm.expectPartialRevert(
                BabyBearWhirVerifierUtils5.PackedExtensionElementOutOfRange.selector
            );
            nativeBlobVerifier.verify(proof.initialCommitment, blob);
        }
    }

    function testRejectsFinalConstraintMismatchBlobNative() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(
                TESTDATA, "babybear_quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_success.blob"
            )
        );
        BlobOffsets memory offsets = _computeOffsets(proof);

        _incrementExt5Lane(blob, offsets.statementEval, 0);

        vm.expectPartialRevert(BabyBearWhirVerifierCore5.FinalConstraintMismatch.selector);
        nativeBlobVerifier.verify(proof.initialCommitment, blob);
    }

    function testRejectsMalformedFinalPolyCoefficientsBlobNative() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        BlobOffsets memory offsets = _computeOffsets(proof);

        for (uint256 lane = 0; lane < 5; ++lane) {
            bytes memory blob = vm.readFileBinary(
                string.concat(
                    TESTDATA,
                    "babybear_quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_success.blob"
                )
            );
            _setExt5Lane(blob, offsets.finalPoly, lane, MODULUS);

            vm.expectPartialRevert(
                BabyBearWhirVerifierUtils5.PackedExtensionElementOutOfRange.selector
            );
            nativeBlobVerifier.verify(proof.initialCommitment, blob);
        }
    }

    function testRejectsTamperedFinalMerklePathBlobNative() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(
                TESTDATA, "babybear_quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_success.blob"
            )
        );
        BlobOffsets memory offsets = _computeOffsets(proof);

        _incrementExt5Lane(blob, offsets.finalValues, 0);

        vm.expectPartialRevert(BabyBearWhirVerifierCore5.MerkleRootMismatch.selector);
        nativeBlobVerifier.verify(proof.initialCommitment, blob);
    }

    function _loadSuccessFixture()
        internal
        view
        returns (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof)
    {
        statement = abi.decode(
            vm.readFileBinary(
                string.concat(
                    TESTDATA,
                    "babybear_quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_success_statement.abi"
                )
            ),
            (WhirStructs.WhirStatement)
        );
        proof = abi.decode(
            vm.readFileBinary(
                string.concat(
                    TESTDATA,
                    "babybear_quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_success_proof.abi"
                )
            ),
            (WhirStructs.WhirProof)
        );
    }

    function _expectTypedFailure(string memory proofFile) internal {
        (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory success) =
            _loadSuccessFixture();
        WhirStructs.WhirProof memory failure = abi.decode(
            vm.readFileBinary(string.concat(TESTDATA, proofFile)), (WhirStructs.WhirProof)
        );

        vm.expectRevert();
        verifier.verify(success.initialCommitment, statement, failure);
    }

    function _expectWrapperFailure(string memory blobFile) internal {
        (, WhirStructs.WhirProof memory success) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(string.concat(TESTDATA, blobFile));

        vm.expectRevert();
        blobVerifier.verify(success.initialCommitment, blob);
    }

    function _computeOffsets(WhirStructs.WhirProof memory proof)
        internal
        pure
        returns (BlobOffsets memory offsets)
    {
        uint256 offset = HEADER_BYTES;

        offset += STATEMENT_POINT_ARITY * RAW_EXT5_BYTES;
        offsets.statementEval = offset;
        offset += RAW_EXT5_BYTES;

        offset += DIGEST_BYTES;
        offsets.initialOod = offset;
        offset += RAW_EXT5_BYTES;

        offsets.initialSumcheck = offset;
        offset += proof.initialSumcheck.polynomialEvals.length * RAW_EXT5_BYTES;
        offset += proof.initialSumcheck.powWitnesses.length * BASE_BYTES;

        offset += DIGEST_BYTES;
        offset += RAW_EXT5_BYTES;
        offset += BASE_BYTES;
        offset += proof.rounds[0].queryBatch.values.length * BASE_BYTES;
        offset += proof.rounds[0].queryBatch.decommitments.length * DIGEST_BYTES;
        offset += proof.rounds[0].sumcheck.polynomialEvals.length * RAW_EXT5_BYTES;
        offset += proof.rounds[0].sumcheck.powWitnesses.length * BASE_BYTES;

        offset += DIGEST_BYTES;
        offset += RAW_EXT5_BYTES;
        offset += BASE_BYTES;
        offset += proof.rounds[1].queryBatch.values.length * RAW_EXT5_BYTES;
        offset += proof.rounds[1].queryBatch.decommitments.length * DIGEST_BYTES;
        offset += proof.rounds[1].sumcheck.polynomialEvals.length * RAW_EXT5_BYTES;
        offset += proof.rounds[1].sumcheck.powWitnesses.length * BASE_BYTES;

        offset += DIGEST_BYTES;
        offset += RAW_EXT5_BYTES;
        offset += BASE_BYTES;
        offset += proof.rounds[2].queryBatch.values.length * RAW_EXT5_BYTES;
        offset += proof.rounds[2].queryBatch.decommitments.length * DIGEST_BYTES;
        offset += proof.rounds[2].sumcheck.polynomialEvals.length * RAW_EXT5_BYTES;
        offset += proof.rounds[2].sumcheck.powWitnesses.length * BASE_BYTES;

        offsets.finalPoly = offset;
        offset += proof.finalPoly.length * RAW_EXT5_BYTES;
        offset += BASE_BYTES;

        offsets.finalValues = offset;
    }

    function _clone(bytes memory data) internal pure returns (bytes memory out) {
        out = new bytes(data.length);
        for (uint256 i = 0; i < data.length; ++i) {
            out[i] = data[i];
        }
    }

    function _readU32(bytes memory blob, uint256 offset) internal pure returns (uint256 value) {
        value = (uint8(blob[offset]) << 24) | (uint8(blob[offset + 1]) << 16)
            | (uint8(blob[offset + 2]) << 8) | uint8(blob[offset + 3]);
    }

    function _writeU32(bytes memory blob, uint256 offset, uint256 value) internal pure {
        blob[offset] = bytes1(uint8(value >> 24));
        blob[offset + 1] = bytes1(uint8(value >> 16));
        blob[offset + 2] = bytes1(uint8(value >> 8));
        blob[offset + 3] = bytes1(uint8(value));
    }

    function _readU32Le(bytes memory blob, uint256 offset) internal pure returns (uint256 value) {
        value = uint8(blob[offset]) | (uint8(blob[offset + 1]) << 8)
            | (uint8(blob[offset + 2]) << 16) | (uint8(blob[offset + 3]) << 24);
    }

    function _writeU32Le(bytes memory blob, uint256 offset, uint256 value) internal pure {
        blob[offset] = bytes1(uint8(value));
        blob[offset + 1] = bytes1(uint8(value >> 8));
        blob[offset + 2] = bytes1(uint8(value >> 16));
        blob[offset + 3] = bytes1(uint8(value >> 24));
    }

    function _setExt5Lane(bytes memory blob, uint256 ext5Offset, uint256 lane, uint256 value)
        internal
        pure
    {
        require(lane < 5, "BAD_LANE");
        _writeU32(blob, ext5Offset + lane * 4, value);
    }

    function _incrementExt5Lane(bytes memory blob, uint256 ext5Offset, uint256 lane) internal pure {
        uint256 value = _readU32(blob, ext5Offset + lane * 4);
        value += 1;
        if (value == MODULUS) {
            value = 0;
        }
        _writeU32(blob, ext5Offset + lane * 4, value);
    }

    function _setExt5LaneLe(bytes memory blob, uint256 ext5Offset, uint256 lane, uint256 value)
        internal
        pure
    {
        require(lane < 5, "BAD_LANE");
        _writeU32Le(blob, ext5Offset + lane * 4, value);
    }

    function _incrementExt5LaneLe(bytes memory blob, uint256 ext5Offset, uint256 lane)
        internal
        pure
    {
        uint256 value = _readU32Le(blob, ext5Offset + lane * 4);
        value += 1;
        if (value == MODULUS) {
            value = 0;
        }
        _writeU32Le(blob, ext5Offset + lane * 4, value);
    }
}
