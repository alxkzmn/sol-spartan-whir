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
    WhirVerifier8_k22_jb100_lir6_ff4_rsv1 as WhirVerifier8
} from "../src/whir/k22_jb100_lir6_ff4_rsv1/WhirVerifier8_k22_jb100_lir6_ff4_rsv1.sol";

contract WhirBlobVerifier8K22Jb100Test is Test {
    string internal constant TESTDATA = "testdata/";

    WhirVerifier8 internal verifier;
    WhirBlobVerifier8 internal blobVerifier;

    function setUp() external {
        verifier = new WhirVerifier8();
        blobVerifier = new WhirBlobVerifier8(verifier);
    }

    function testVerifyOcticWhirSuccessBlob() external view {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(TESTDATA, "octic_whir_k22_jb100_lir6_ff4_rsv1_success.blob")
        );
        assertTrue(blobVerifier.verify(proof.initialCommitment, blob));
    }

    function testGasWhirVerifyBlobFixed() external view {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(TESTDATA, "octic_whir_k22_jb100_lir6_ff4_rsv1_success.blob")
        );
        assertTrue(blobVerifier.verify(proof.initialCommitment, blob));
    }

    function testBlobCalldataIsSmallerThanTypedAbi() external view {
        (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof) =
            _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(TESTDATA, "octic_whir_k22_jb100_lir6_ff4_rsv1_success.blob")
        );

        bytes memory typedCalldata =
            abi.encodeCall(WhirVerifier8.verify, (proof.initialCommitment, statement, proof));
        bytes memory blobCalldata =
            abi.encodeCall(WhirBlobVerifier8.verify, (proof.initialCommitment, blob));
        assertLt(blobCalldata.length, typedCalldata.length);
    }

    function testRejectsBadCommitmentBlob() external {
        (, WhirStructs.WhirProof memory success) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(
                TESTDATA, "octic_whir_k22_jb100_lir6_ff4_rsv1_failure_bad_commitment.blob"
            )
        );
        vm.expectRevert();
        blobVerifier.verify(success.initialCommitment, blob);
    }

    function testRejectsBadStirQueryBlob() external {
        (, WhirStructs.WhirProof memory success) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(
                TESTDATA, "octic_whir_k22_jb100_lir6_ff4_rsv1_failure_bad_stir_query.blob"
            )
        );
        vm.expectRevert();
        blobVerifier.verify(success.initialCommitment, blob);
    }

    function testRejectsBadOodBlob() external {
        (, WhirStructs.WhirProof memory success) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(
                TESTDATA,
                "octic_whir_k22_jb100_lir6_ff4_rsv1_failure_bad_ood_or_transcript_mismatch.blob"
            )
        );
        vm.expectRevert();
        blobVerifier.verify(success.initialCommitment, blob);
    }

    function testRejectsBlobWrongMagic() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(TESTDATA, "octic_whir_k22_jb100_lir6_ff4_rsv1_success.blob")
        );
        blob[0] = 0x00;
        vm.expectRevert(WhirBlobCodec8.BlobMagicMismatch.selector);
        blobVerifier.verify(proof.initialCommitment, blob);
    }

    function testRejectsBlobWrongVersion() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(TESTDATA, "octic_whir_k22_jb100_lir6_ff4_rsv1_success.blob")
        );
        blob[5] = 0x02;
        vm.expectRevert(WhirBlobCodec8.BlobVersionMismatch.selector);
        blobVerifier.verify(proof.initialCommitment, blob);
    }

    function testRejectsBlobWrongHeaderFields() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(TESTDATA, "octic_whir_k22_jb100_lir6_ff4_rsv1_success.blob")
        );

        bytes memory wrongDigest = _clone(blob);
        wrongDigest[6] = 0x13;
        vm.expectRevert(WhirBlobCodec8.BlobDigestWidthMismatch.selector);
        blobVerifier.verify(proof.initialCommitment, wrongDigest);

        bytes memory wrongExtDegree = _clone(blob);
        wrongExtDegree[7] = 0x04;
        vm.expectRevert(WhirBlobCodec8.BlobExtensionDegreeMismatch.selector);
        blobVerifier.verify(proof.initialCommitment, wrongExtDegree);

        bytes memory wrongRounds = _clone(blob);
        wrongRounds[8] = 0x02;
        vm.expectRevert(WhirBlobCodec8.BlobRoundCountMismatch.selector);
        blobVerifier.verify(proof.initialCommitment, wrongRounds);

        bytes memory wrongFlags = _clone(blob);
        wrongFlags[9] = 0x00;
        vm.expectRevert(WhirBlobCodec8.BlobFlagsMismatch.selector);
        blobVerifier.verify(proof.initialCommitment, wrongFlags);
    }

    function testRejectsTruncatedBlob() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(TESTDATA, "octic_whir_k22_jb100_lir6_ff4_rsv1_success.blob")
        );
        assembly ("memory-safe") {
            mstore(blob, sub(mload(blob), 1))
        }
        vm.expectRevert(WhirBlobCodec8.BlobLengthMismatch.selector);
        blobVerifier.verify(proof.initialCommitment, blob);
    }

    function testRejectsBlobTrailingBytes() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(TESTDATA, "octic_whir_k22_jb100_lir6_ff4_rsv1_success.blob")
        );
        bytes memory extended = bytes.concat(blob, hex"01");
        vm.expectRevert(WhirBlobCodec8.BlobLengthMismatch.selector);
        blobVerifier.verify(proof.initialCommitment, extended);
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

    function _clone(bytes memory data) internal pure returns (bytes memory out) {
        out = new bytes(data.length);
        for (uint256 i = 0; i < data.length; ++i) {
            out[i] = data[i];
        }
    }
}
