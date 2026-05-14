// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";

import { WhirStructs } from "../src/whir/WhirStructs.sol";
import {
    WhirBlobCodec8
} from "../src/whir/k22_jb100_lir6_ff4_rsv1/WhirBlobCodec8_k22_jb100_lir6_ff4_rsv1.sol";
import {
    WhirBlobVerifier8_k22_jb100_lir6_ff4_rsv1 as WhirBlobVerifier8
} from "../src/whir/k22_jb100_lir6_ff4_rsv1/WhirBlobVerifier8_k22_jb100_lir6_ff4_rsv1.sol";
import {
    WhirBlobVerifierNative8_k22_jb100_lir6_ff4_rsv1 as WhirBlobVerifierNative8
} from "../src/whir/k22_jb100_lir6_ff4_rsv1/WhirBlobVerifierNative8_k22_jb100_lir6_ff4_rsv1.sol";
import {
    WhirVerifier8_k22_jb100_lir6_ff4_rsv1 as WhirVerifier8
} from "../src/whir/k22_jb100_lir6_ff4_rsv1/WhirVerifier8_k22_jb100_lir6_ff4_rsv1.sol";
import { WhirVerifierCore8 } from "../src/whir/k22_jb100_lir6_ff4_rsv1/WhirVerifierCore8.sol";
import { WhirVerifierUtils8 } from "../src/whir/k22_jb100_lir6_ff4_rsv1/WhirVerifierUtils8.sol";

contract WhirBlobVerifierNative8K22Jb100Test is Test {
    string internal constant TESTDATA = "testdata/";
    uint256 internal constant MODULUS = 0x7f000001;
    uint256 internal constant HEADER_BYTES = 18;
    uint256 internal constant STATEMENT_POINT_ARITY = 22;

    WhirVerifier8 internal verifier;
    WhirBlobVerifier8 internal blobVerifier;
    WhirBlobVerifierNative8 internal nativeBlobVerifier;

    struct BlobOffsets {
        uint256 statementEval;
        uint256 initialOod;
        uint256 initialSumcheck;
        uint256 finalPoly;
        uint256 finalValues;
    }

    function setUp() external {
        verifier = new WhirVerifier8();
        blobVerifier = new WhirBlobVerifier8(verifier);
        nativeBlobVerifier = new WhirBlobVerifierNative8();
    }

    function testVerifyOcticWhirSuccessBlobNative() external view {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(TESTDATA, "octic_whir_k22_jb100_lir6_ff4_rsv1_success.blob")
        );
        assertTrue(nativeBlobVerifier.verify(proof.initialCommitment, blob));
    }

    function testGasWhirVerifyBlobNativeFixed() external view {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(TESTDATA, "octic_whir_k22_jb100_lir6_ff4_rsv1_success.blob")
        );
        assertTrue(nativeBlobVerifier.verify(proof.initialCommitment, blob));
    }

    function testNativeBlobUsesLessGasThanWrapper() external view {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(TESTDATA, "octic_whir_k22_jb100_lir6_ff4_rsv1_success.blob")
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
            string.concat(TESTDATA, "octic_whir_k22_jb100_lir6_ff4_rsv1_success.blob")
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
                TESTDATA, "octic_whir_k22_jb100_lir6_ff4_rsv1_failure_bad_commitment.blob"
            )
        );
        vm.expectRevert();
        nativeBlobVerifier.verify(success.initialCommitment, blob);
    }

    function testRejectsBadStirQueryBlobNative() external {
        (, WhirStructs.WhirProof memory success) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(
                TESTDATA, "octic_whir_k22_jb100_lir6_ff4_rsv1_failure_bad_stir_query.blob"
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
                "octic_whir_k22_jb100_lir6_ff4_rsv1_failure_bad_ood_or_transcript_mismatch.blob"
            )
        );
        vm.expectRevert();
        nativeBlobVerifier.verify(success.initialCommitment, blob);
    }

    function testRejectsBlobWrongMagicNative() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(TESTDATA, "octic_whir_k22_jb100_lir6_ff4_rsv1_success.blob")
        );
        blob[0] = 0x00;
        vm.expectRevert(WhirBlobCodec8.BlobMagicMismatch.selector);
        nativeBlobVerifier.verify(proof.initialCommitment, blob);
    }

    function testRejectsBlobWrongVersionNative() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(TESTDATA, "octic_whir_k22_jb100_lir6_ff4_rsv1_success.blob")
        );
        blob[5] = 0x02;
        vm.expectRevert(WhirBlobCodec8.BlobVersionMismatch.selector);
        nativeBlobVerifier.verify(proof.initialCommitment, blob);
    }

    function testRejectsBlobWrongHeaderFieldsNative() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(TESTDATA, "octic_whir_k22_jb100_lir6_ff4_rsv1_success.blob")
        );

        bytes memory wrongDigest = _clone(blob);
        wrongDigest[6] = 0x13;
        vm.expectRevert(WhirBlobCodec8.BlobDigestWidthMismatch.selector);
        nativeBlobVerifier.verify(proof.initialCommitment, wrongDigest);

        bytes memory wrongExtDegree = _clone(blob);
        wrongExtDegree[7] = 0x04;
        vm.expectRevert(WhirBlobCodec8.BlobExtensionDegreeMismatch.selector);
        nativeBlobVerifier.verify(proof.initialCommitment, wrongExtDegree);

        bytes memory wrongRounds = _clone(blob);
        wrongRounds[8] = 0x02;
        vm.expectRevert(WhirBlobCodec8.BlobRoundCountMismatch.selector);
        nativeBlobVerifier.verify(proof.initialCommitment, wrongRounds);

        bytes memory wrongFlags = _clone(blob);
        wrongFlags[9] = 0x00;
        vm.expectRevert(WhirBlobCodec8.BlobFlagsMismatch.selector);
        nativeBlobVerifier.verify(proof.initialCommitment, wrongFlags);
    }

    function testRejectsTruncatedBlobNative() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(TESTDATA, "octic_whir_k22_jb100_lir6_ff4_rsv1_success.blob")
        );
        assembly ("memory-safe") {
            mstore(blob, sub(mload(blob), 1))
        }
        vm.expectRevert(WhirBlobCodec8.BlobLengthMismatch.selector);
        nativeBlobVerifier.verify(proof.initialCommitment, blob);
    }

    function testRejectsBlobTrailingBytesNative() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(TESTDATA, "octic_whir_k22_jb100_lir6_ff4_rsv1_success.blob")
        );
        bytes memory extended = bytes.concat(blob, hex"01");
        vm.expectRevert(WhirBlobCodec8.BlobLengthMismatch.selector);
        nativeBlobVerifier.verify(proof.initialCommitment, extended);
    }

    function testRejectsMalformedInitialOodAnswersBlobNative() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        BlobOffsets memory offsets = _computeOffsets(proof);

        for (uint256 lane = 0; lane < 8; ++lane) {
            bytes memory blob = vm.readFileBinary(
                string.concat(TESTDATA, "octic_whir_k22_jb100_lir6_ff4_rsv1_success.blob")
            );
            _setExt8LaneLe(blob, offsets.initialOod, lane, MODULUS);

            vm.expectRevert();
            nativeBlobVerifier.verify(proof.initialCommitment, blob);
        }
    }

    function testRejectsTamperedInitialSumcheckDataBlobNative() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(TESTDATA, "octic_whir_k22_jb100_lir6_ff4_rsv1_success.blob")
        );
        BlobOffsets memory offsets = _computeOffsets(proof);

        _incrementExt8LaneLe(blob, offsets.initialSumcheck, 0);

        vm.expectRevert();
        nativeBlobVerifier.verify(proof.initialCommitment, blob);
    }

    function testRejectsMalformedInitialSumcheckEvalsBlobNative() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        BlobOffsets memory offsets = _computeOffsets(proof);

        for (uint256 lane = 0; lane < 8; ++lane) {
            bytes memory blob = vm.readFileBinary(
                string.concat(TESTDATA, "octic_whir_k22_jb100_lir6_ff4_rsv1_success.blob")
            );
            _setExt8LaneLe(blob, offsets.initialSumcheck, lane, MODULUS);

            vm.expectPartialRevert(WhirVerifierUtils8.PackedExtensionElementOutOfRange.selector);
            nativeBlobVerifier.verify(proof.initialCommitment, blob);
        }
    }

    function testRejectsFinalConstraintMismatchBlobNative() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(TESTDATA, "octic_whir_k22_jb100_lir6_ff4_rsv1_success.blob")
        );
        BlobOffsets memory offsets = _computeOffsets(proof);

        _incrementExt8Lane(blob, offsets.statementEval, 0);

        vm.expectPartialRevert(WhirVerifierCore8.FinalConstraintMismatch.selector);
        nativeBlobVerifier.verify(proof.initialCommitment, blob);
    }

    function testRejectsMalformedFinalPolyCoefficientsBlobNative() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        BlobOffsets memory offsets = _computeOffsets(proof);

        for (uint256 lane = 0; lane < 8; ++lane) {
            bytes memory blob = vm.readFileBinary(
                string.concat(TESTDATA, "octic_whir_k22_jb100_lir6_ff4_rsv1_success.blob")
            );
            _setExt8Lane(blob, offsets.finalPoly, lane, MODULUS);

            vm.expectPartialRevert(WhirVerifierUtils8.PackedExtensionElementOutOfRange.selector);
            nativeBlobVerifier.verify(proof.initialCommitment, blob);
        }
    }

    function testRejectsTamperedFinalMerklePathBlobNative() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(TESTDATA, "octic_whir_k22_jb100_lir6_ff4_rsv1_success.blob")
        );
        BlobOffsets memory offsets = _computeOffsets(proof);

        _incrementExt8Lane(blob, offsets.finalValues, 0);

        vm.expectPartialRevert(WhirVerifierCore8.MerkleRootMismatch.selector);
        nativeBlobVerifier.verify(proof.initialCommitment, blob);
    }

    function _loadSuccessFixture()
        internal
        view
        returns (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof)
    {
        statement = abi.decode(
            vm.readFileBinary(
                string.concat(TESTDATA, "octic_whir_k22_jb100_lir6_ff4_rsv1_success_statement.abi")
            ),
            (WhirStructs.WhirStatement)
        );
        proof = abi.decode(
            vm.readFileBinary(
                string.concat(TESTDATA, "octic_whir_k22_jb100_lir6_ff4_rsv1_success_proof.abi")
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

        offset += STATEMENT_POINT_ARITY * 32;
        offsets.statementEval = offset;
        offset += 32;

        offset += 20;
        offsets.initialOod = offset;
        offset += 32;

        offsets.initialSumcheck = offset;
        offset += proof.initialSumcheck.polynomialEvals.length * 32;

        offset += 20;
        offset += 32;
        offset += 4;
        offset += proof.rounds[0].queryBatch.values.length * 4;
        offset += proof.rounds[0].queryBatch.decommitments.length * 20;
        offset += proof.rounds[0].sumcheck.polynomialEvals.length * 32;

        offset += 20;
        offset += 32;
        offset += 4;
        offset += proof.rounds[1].queryBatch.values.length * 32;
        offset += proof.rounds[1].queryBatch.decommitments.length * 20;
        offset += proof.rounds[1].sumcheck.polynomialEvals.length * 32;

        offset += 20;
        offset += 32;
        offset += 4;
        offset += proof.rounds[2].queryBatch.values.length * 32;
        offset += proof.rounds[2].queryBatch.decommitments.length * 20;
        offset += proof.rounds[2].sumcheck.polynomialEvals.length * 32;

        offsets.finalPoly = offset;
        offset += proof.finalPoly.length * 32;
        offset += 4;

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

    function _setExt8Lane(bytes memory blob, uint256 ext8Offset, uint256 lane, uint256 value)
        internal
        pure
    {
        require(lane < 8, "BAD_LANE");
        _writeU32(blob, ext8Offset + lane * 4, value);
    }

    function _incrementExt8Lane(bytes memory blob, uint256 ext8Offset, uint256 lane) internal pure {
        uint256 value = _readU32(blob, ext8Offset + lane * 4);
        value += 1;
        if (value == MODULUS) {
            value = 0;
        }
        _writeU32(blob, ext8Offset + lane * 4, value);
    }

    function _setExt8LaneLe(bytes memory blob, uint256 ext8Offset, uint256 lane, uint256 value)
        internal
        pure
    {
        require(lane < 8, "BAD_LANE");
        _writeU32Le(blob, ext8Offset + lane * 4, value);
    }

    function _incrementExt8LaneLe(bytes memory blob, uint256 ext8Offset, uint256 lane)
        internal
        pure
    {
        uint256 value = _readU32Le(blob, ext8Offset + lane * 4);
        value += 1;
        if (value == MODULUS) {
            value = 0;
        }
        _writeU32Le(blob, ext8Offset + lane * 4, value);
    }
}
