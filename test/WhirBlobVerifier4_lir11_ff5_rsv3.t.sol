// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";

import { WhirStructs } from "../src/whir/WhirStructs.sol";
import { WhirBlobCodecLir11 } from "../src/whir/lir11/WhirBlobCodec4_lir11_ff5_rsv3.sol";
import { WhirBlobVerifierLir11 } from "../src/whir/lir11/WhirBlobVerifier4_lir11_ff5_rsv3.sol";
import { WhirVerifierLir11 } from "../src/whir/lir11/WhirVerifier4_lir11_ff5_rsv3.sol";

contract WhirBlobVerifierLir11Test is Test {
    string internal constant TESTDATA = "testdata/";

    WhirVerifierLir11 internal verifier;
    WhirBlobVerifierLir11 internal blobVerifier;

    function setUp() external {
        if (
            !vm.isFile(string.concat(TESTDATA, "quartic_whir_lir11_ff5_rsv3_success_statement.abi"))
                || !vm.isFile(
                    string.concat(TESTDATA, "quartic_whir_lir11_ff5_rsv3_success_proof.abi")
                ) || !vm.isFile(string.concat(TESTDATA, "quartic_whir_lir11_ff5_rsv3_success.blob"))
        ) {
            vm.skip(true, "lir11 fixtures not generated");
        }
        verifier = new WhirVerifierLir11();
        blobVerifier = new WhirBlobVerifierLir11(verifier);
    }

    function testVerifyQuarticWhirSuccessBlob() external view {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(TESTDATA, "quartic_whir_lir11_ff5_rsv3_success.blob")
        );

        assertTrue(blobVerifier.verify(proof.initialCommitment, blob));
    }

    function testGasWhirVerifyBlobFixed() external view {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(TESTDATA, "quartic_whir_lir11_ff5_rsv3_success.blob")
        );

        assertTrue(blobVerifier.verify(proof.initialCommitment, blob));
    }

    function testBlobCalldataIsSmallerThanTypedAbi() external view {
        (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof) =
            _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(TESTDATA, "quartic_whir_lir11_ff5_rsv3_success.blob")
        );

        bytes memory typedCalldata =
            abi.encodeCall(WhirVerifierLir11.verify, (proof.initialCommitment, statement, proof));
        bytes memory blobCalldata =
            abi.encodeCall(WhirBlobVerifierLir11.verify, (proof.initialCommitment, blob));

        assertLt(blobCalldata.length, typedCalldata.length);
    }

    function testRejectsBadCommitmentBlob() external {
        (, WhirStructs.WhirProof memory success) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(TESTDATA, "quartic_whir_lir11_ff5_rsv3_failure_bad_commitment.blob")
        );

        vm.expectRevert();
        blobVerifier.verify(success.initialCommitment, blob);
    }

    function testRejectsBadStirQueryBlob() external {
        (, WhirStructs.WhirProof memory success) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(TESTDATA, "quartic_whir_lir11_ff5_rsv3_failure_bad_stir_query.blob")
        );

        vm.expectRevert();
        blobVerifier.verify(success.initialCommitment, blob);
    }

    function testRejectsBadOodBlob() external {
        (, WhirStructs.WhirProof memory success) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(
                TESTDATA, "quartic_whir_lir11_ff5_rsv3_failure_bad_ood_or_transcript_mismatch.blob"
            )
        );

        vm.expectRevert();
        blobVerifier.verify(success.initialCommitment, blob);
    }

    function testRejectsBlobWrongMagic() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(TESTDATA, "quartic_whir_lir11_ff5_rsv3_success.blob")
        );
        blob[0] = 0x00;

        vm.expectRevert(WhirBlobCodecLir11.BlobMagicMismatch.selector);
        blobVerifier.verify(proof.initialCommitment, blob);
    }

    function testRejectsBlobWrongVersion() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(TESTDATA, "quartic_whir_lir11_ff5_rsv3_success.blob")
        );
        blob[5] = 0x02;

        vm.expectRevert(WhirBlobCodecLir11.BlobVersionMismatch.selector);
        blobVerifier.verify(proof.initialCommitment, blob);
    }

    function testRejectsBlobWrongHeaderFields() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(TESTDATA, "quartic_whir_lir11_ff5_rsv3_success.blob")
        );

        bytes memory wrongDigest = _clone(blob);
        wrongDigest[6] = 0x13;
        vm.expectRevert(WhirBlobCodecLir11.BlobDigestWidthMismatch.selector);
        blobVerifier.verify(proof.initialCommitment, wrongDigest);

        bytes memory wrongExtDegree = _clone(blob);
        wrongExtDegree[7] = 0x08;
        vm.expectRevert(WhirBlobCodecLir11.BlobExtensionDegreeMismatch.selector);
        blobVerifier.verify(proof.initialCommitment, wrongExtDegree);

        bytes memory wrongRounds = _clone(blob);
        wrongRounds[8] = 0x03;
        vm.expectRevert(WhirBlobCodecLir11.BlobRoundCountMismatch.selector);
        blobVerifier.verify(proof.initialCommitment, wrongRounds);

        bytes memory wrongFlags = _clone(blob);
        wrongFlags[9] = 0x00;
        vm.expectRevert(WhirBlobCodecLir11.BlobFlagsMismatch.selector);
        blobVerifier.verify(proof.initialCommitment, wrongFlags);
    }

    function testRejectsTruncatedBlob() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(TESTDATA, "quartic_whir_lir11_ff5_rsv3_success.blob")
        );
        bytes memory truncated = new bytes(blob.length - 1);
        for (uint256 i = 0; i < truncated.length; ++i) {
            truncated[i] = blob[i];
        }

        vm.expectRevert(WhirBlobCodecLir11.BlobLengthMismatch.selector);
        blobVerifier.verify(proof.initialCommitment, truncated);
    }

    function testRejectsBlobTrailingBytes() external {
        (, WhirStructs.WhirProof memory proof) = _loadSuccessFixture();
        bytes memory blob = vm.readFileBinary(
            string.concat(TESTDATA, "quartic_whir_lir11_ff5_rsv3_success.blob")
        );
        bytes memory extended = new bytes(blob.length + 1);
        for (uint256 i = 0; i < blob.length; ++i) {
            extended[i] = blob[i];
        }
        extended[extended.length - 1] = 0x01;

        vm.expectRevert(WhirBlobCodecLir11.BlobLengthMismatch.selector);
        blobVerifier.verify(proof.initialCommitment, extended);
    }

    function _loadSuccessFixture()
        internal
        view
        returns (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof)
    {
        statement = abi.decode(
            vm.readFileBinary(
                string.concat(TESTDATA, "quartic_whir_lir11_ff5_rsv3_success_statement.abi")
            ),
            (WhirStructs.WhirStatement)
        );
        proof = abi.decode(
            vm.readFileBinary(
                string.concat(TESTDATA, "quartic_whir_lir11_ff5_rsv3_success_proof.abi")
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
