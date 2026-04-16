// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";

import { WhirStructs } from "../src/whir/WhirStructs.sol";
import { WhirBlobCodec4 } from "../src/whir/WhirBlobCodec4_lir6_ff5_rsv1.sol";
import { WhirBlobVerifier4 } from "../src/whir/WhirBlobVerifier4_lir6_ff5_rsv1.sol";
import { WhirBlobVerifierNative4 } from "../src/whir/WhirBlobVerifierNative4_lir6_ff5_rsv1.sol";
import { WhirVerifierCore4 } from "../src/whir/WhirVerifierCore4.sol";
import { WhirVerifierUtils4 } from "../src/whir/WhirVerifierUtils4.sol";
import { WhirVerifier4 } from "../src/whir/WhirVerifier4_lir6_ff5_rsv1.sol";

contract WhirBlobVerifierNative4Test is Test {
    string internal constant TESTDATA = "testdata/";
    uint256 internal constant MODULUS = 0x7f000001;
    uint256 internal constant HEADER_BYTES = 16;
    uint256 internal constant STATEMENT_POINT_ARITY = 16;

    WhirVerifier4 internal verifier;
    WhirBlobVerifier4 internal blobVerifier;
    WhirBlobVerifierNative4 internal nativeBlobVerifier;

    struct BlobOffsets {
        uint256 statementEval;
        uint256 initialOod;
        uint256 initialSumcheck;
        uint256 finalPoly;
        uint256 finalValues;
    }

    function setUp() external {
        verifier = new WhirVerifier4();
        blobVerifier = new WhirBlobVerifier4(verifier);
        nativeBlobVerifier = new WhirBlobVerifierNative4();
    }

    function testVerifyQuarticWhirSuccessBlobNative() external view {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob =
            vm.readFileBinary(string.concat(TESTDATA, "quartic_whir_lir6_ff5_rsv1_success.blob"));

        assertTrue(nativeBlobVerifier.verify(proof.initialCommitment, blob));
    }

    function testGasWhirVerifyBlobNativeFixed() external view {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob =
            vm.readFileBinary(string.concat(TESTDATA, "quartic_whir_lir6_ff5_rsv1_success.blob"));

        assertTrue(nativeBlobVerifier.verify(proof.initialCommitment, blob));
    }

    function testNativeBlobUsesLessGasThanWrapper() external view {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob =
            vm.readFileBinary(string.concat(TESTDATA, "quartic_whir_lir6_ff5_rsv1_success.blob"));

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
        bytes memory blob =
            vm.readFileBinary(string.concat(TESTDATA, "quartic_whir_lir6_ff5_rsv1_success.blob"));

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
            string.concat(TESTDATA, "quartic_whir_lir6_ff5_rsv1_failure_bad_commitment.blob")
        );

        vm.expectRevert();
        nativeBlobVerifier.verify(success.initialCommitment, blob);
    }

    function testRejectsBadStirQueryBlobNative() external {
        (, WhirStructs.WhirProof memory success) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(TESTDATA, "quartic_whir_lir6_ff5_rsv1_failure_bad_stir_query.blob")
        );

        vm.expectRevert();
        nativeBlobVerifier.verify(success.initialCommitment, blob);
    }

    function testRejectsBadOodBlobNative() external {
        (, WhirStructs.WhirProof memory success) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(
                TESTDATA, "quartic_whir_lir6_ff5_rsv1_failure_bad_ood_or_transcript_mismatch.blob"
            )
        );

        vm.expectRevert();
        nativeBlobVerifier.verify(success.initialCommitment, blob);
    }

    function testRejectsBlobWrongMagicNative() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob =
            vm.readFileBinary(string.concat(TESTDATA, "quartic_whir_lir6_ff5_rsv1_success.blob"));
        blob[0] = 0x00;

        vm.expectRevert(WhirBlobCodec4.BlobMagicMismatch.selector);
        nativeBlobVerifier.verify(proof.initialCommitment, blob);
    }

    function testRejectsBlobWrongVersionNative() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob =
            vm.readFileBinary(string.concat(TESTDATA, "quartic_whir_lir6_ff5_rsv1_success.blob"));
        blob[5] = 0x02;

        vm.expectRevert(WhirBlobCodec4.BlobVersionMismatch.selector);
        nativeBlobVerifier.verify(proof.initialCommitment, blob);
    }

    function testRejectsBlobWrongHeaderFieldsNative() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob =
            vm.readFileBinary(string.concat(TESTDATA, "quartic_whir_lir6_ff5_rsv1_success.blob"));

        bytes memory wrongDigest = _clone(blob);
        wrongDigest[6] = 0x13;
        vm.expectRevert(WhirBlobCodec4.BlobDigestWidthMismatch.selector);
        nativeBlobVerifier.verify(proof.initialCommitment, wrongDigest);

        bytes memory wrongExtDegree = _clone(blob);
        wrongExtDegree[7] = 0x08;
        vm.expectRevert(WhirBlobCodec4.BlobExtensionDegreeMismatch.selector);
        nativeBlobVerifier.verify(proof.initialCommitment, wrongExtDegree);

        bytes memory wrongRounds = _clone(blob);
        wrongRounds[8] = 0x03;
        vm.expectRevert(WhirBlobCodec4.BlobRoundCountMismatch.selector);
        nativeBlobVerifier.verify(proof.initialCommitment, wrongRounds);

        bytes memory wrongFlags = _clone(blob);
        wrongFlags[9] = 0x00;
        vm.expectRevert(WhirBlobCodec4.BlobFlagsMismatch.selector);
        nativeBlobVerifier.verify(proof.initialCommitment, wrongFlags);
    }

    function testRejectsTruncatedBlobNative() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob =
            vm.readFileBinary(string.concat(TESTDATA, "quartic_whir_lir6_ff5_rsv1_success.blob"));
        assembly ("memory-safe") {
            mstore(blob, sub(mload(blob), 1))
        }

        vm.expectRevert(WhirBlobCodec4.BlobLengthMismatch.selector);
        nativeBlobVerifier.verify(proof.initialCommitment, blob);
    }

    function testRejectsBlobTrailingBytesNative() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob =
            vm.readFileBinary(string.concat(TESTDATA, "quartic_whir_lir6_ff5_rsv1_success.blob"));
        bytes memory extended = bytes.concat(blob, hex"01");

        vm.expectRevert(WhirBlobCodec4.BlobLengthMismatch.selector);
        nativeBlobVerifier.verify(proof.initialCommitment, extended);
    }

    function testRejectsMalformedInitialOodAnswersBlobNative() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        BlobOffsets memory offsets = _computeOffsets(proof);

        for (uint256 lane = 0; lane < 4; ++lane) {
            bytes memory blob = vm.readFileBinary(
                string.concat(TESTDATA, "quartic_whir_lir6_ff5_rsv1_success.blob")
            );
            _setExt4LaneLe(blob, offsets.initialOod, lane, MODULUS);

            vm.expectPartialRevert(WhirVerifierUtils4.PackedExtensionElementOutOfRange.selector);
            nativeBlobVerifier.verify(proof.initialCommitment, blob);
        }
    }

    function testRejectsTamperedInitialSumcheckDataBlobNative() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob =
            vm.readFileBinary(string.concat(TESTDATA, "quartic_whir_lir6_ff5_rsv1_success.blob"));
        BlobOffsets memory offsets = _computeOffsets(proof);

        _incrementExt4LaneLe(blob, offsets.initialSumcheck, 0);

        vm.expectRevert();
        nativeBlobVerifier.verify(proof.initialCommitment, blob);
    }

    function testRejectsMalformedInitialSumcheckEvalsBlobNative() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        BlobOffsets memory offsets = _computeOffsets(proof);

        for (uint256 lane = 0; lane < 4; ++lane) {
            bytes memory blob = vm.readFileBinary(
                string.concat(TESTDATA, "quartic_whir_lir6_ff5_rsv1_success.blob")
            );
            _setExt4LaneLe(blob, offsets.initialSumcheck, lane, MODULUS);

            vm.expectPartialRevert(WhirVerifierUtils4.PackedExtensionElementOutOfRange.selector);
            nativeBlobVerifier.verify(proof.initialCommitment, blob);
        }
    }

    function testRejectsFinalConstraintMismatchBlobNative() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob =
            vm.readFileBinary(string.concat(TESTDATA, "quartic_whir_lir6_ff5_rsv1_success.blob"));
        BlobOffsets memory offsets = _computeOffsets(proof);

        _incrementExt4Lane(blob, offsets.statementEval, 0);

        vm.expectPartialRevert(WhirVerifierCore4.FinalConstraintMismatch.selector);
        nativeBlobVerifier.verify(proof.initialCommitment, blob);
    }

    function testRejectsMalformedFinalPolyCoefficientsBlobNative() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        BlobOffsets memory offsets = _computeOffsets(proof);

        for (uint256 lane = 0; lane < 4; ++lane) {
            bytes memory blob = vm.readFileBinary(
                string.concat(TESTDATA, "quartic_whir_lir6_ff5_rsv1_success.blob")
            );
            _setExt4Lane(blob, offsets.finalPoly, lane, MODULUS);

            vm.expectPartialRevert(WhirVerifierUtils4.PackedExtensionElementOutOfRange.selector);
            nativeBlobVerifier.verify(proof.initialCommitment, blob);
        }
    }

    function testRejectsTamperedFinalMerklePathBlobNative() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob =
            vm.readFileBinary(string.concat(TESTDATA, "quartic_whir_lir6_ff5_rsv1_success.blob"));
        BlobOffsets memory offsets = _computeOffsets(proof);

        _incrementExt4Lane(blob, offsets.finalValues, 0);

        vm.expectPartialRevert(WhirVerifierCore4.MerkleRootMismatch.selector);
        nativeBlobVerifier.verify(proof.initialCommitment, blob);
    }

    function _loadSuccessFixture()
        internal
        view
        returns (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof)
    {
        statement = abi.decode(
            vm.readFileBinary(
                string.concat(TESTDATA, "quartic_whir_lir6_ff5_rsv1_success_statement.abi")
            ),
            (WhirStructs.WhirStatement)
        );
        proof = abi.decode(
            vm.readFileBinary(
                string.concat(TESTDATA, "quartic_whir_lir6_ff5_rsv1_success_proof.abi")
            ),
            (WhirStructs.WhirProof)
        );
    }

    function _computeOffsets(WhirStructs.WhirProof memory proof)
        internal
        pure
        returns (BlobOffsets memory offsets)
    {
        uint256 offset = HEADER_BYTES;

        offset += STATEMENT_POINT_ARITY * 16;
        offsets.statementEval = offset;
        offset += 16;

        offset += 20; // initial commitment
        offsets.initialOod = offset;
        offset += 2 * 16;

        offsets.initialSumcheck = offset;
        offset += proof.initialSumcheck.polynomialEvals.length * 16;
        offset += proof.initialSumcheck.powWitnesses.length * 4;

        offset += 20; // round0 commitment
        offset += 2 * 16; // round0 ood
        offset += 4; // round0 pow
        offset += proof.rounds[0].queryBatch.values.length * 4;
        offset += proof.rounds[0].queryBatch.decommitments.length * 20;
        offset += proof.rounds[0].sumcheck.polynomialEvals.length * 16;
        offset += proof.rounds[0].sumcheck.powWitnesses.length * 4;

        offsets.finalPoly = offset;
        offset += proof.finalPoly.length * 16;
        offset += 4; // final pow

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

    function _setExt4Lane(bytes memory blob, uint256 ext4Offset, uint256 lane, uint256 value)
        internal
        pure
    {
        require(lane < 4, "BAD_LANE");
        _writeU32(blob, ext4Offset + lane * 4, value);
    }

    function _incrementExt4Lane(bytes memory blob, uint256 ext4Offset, uint256 lane) internal pure {
        uint256 value = _readU32(blob, ext4Offset + lane * 4);
        value += 1;
        if (value == MODULUS) {
            value = 0;
        }
        _writeU32(blob, ext4Offset + lane * 4, value);
    }

    function _setExt4LaneLe(bytes memory blob, uint256 ext4Offset, uint256 lane, uint256 value)
        internal
        pure
    {
        require(lane < 4, "BAD_LANE");
        _writeU32Le(blob, ext4Offset + lane * 4, value);
    }

    function _incrementExt4LaneLe(bytes memory blob, uint256 ext4Offset, uint256 lane)
        internal
        pure
    {
        uint256 value = _readU32Le(blob, ext4Offset + lane * 4);
        value += 1;
        if (value == MODULUS) {
            value = 0;
        }
        _writeU32Le(blob, ext4Offset + lane * 4, value);
    }
}
