// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";

import {WhirStructs} from "../src/whir/WhirStructs.sol";
import {WhirVerifierCore4} from "../src/whir/WhirVerifierCore4.sol";
import {WhirVerifierDebug4} from "../src/whir/WhirVerifierDebug4.sol";

contract WhirVerifierDebug4Test is Test {
    string internal constant TESTDATA = "testdata/";

    WhirVerifierDebug4 internal verifier;

    function setUp() external {
        verifier = new WhirVerifierDebug4();
    }

    function testVerifyQuarticWhirSuccessFixture() external view {
        (
            WhirStructs.ExpandedWhirConfig memory config,
            WhirStructs.WhirStatement memory statement,
            WhirStructs.WhirProof memory proof
        ) = _loadSuccessFixture();

        assertTrue(
            verifier.verify(proof.initialCommitment, config, statement, proof)
        );
    }

    function testGasWhirVerify() external view {
        (
            WhirStructs.ExpandedWhirConfig memory config,
            WhirStructs.WhirStatement memory statement,
            WhirStructs.WhirProof memory proof
        ) = _loadSuccessFixture();

        assertTrue(
            verifier.verify(proof.initialCommitment, config, statement, proof)
        );
    }

    function testRejectsBadCommitmentFixture() external {
        (
            WhirStructs.ExpandedWhirConfig memory config,
            WhirStructs.WhirStatement memory statement,
            WhirStructs.WhirProof memory success
        ) = _loadSuccessFixture();

        WhirStructs.WhirProof memory failure = abi.decode(
            vm.readFileBinary(
                string.concat(
                    TESTDATA,
                    "quartic_whir_failure_bad_commitment_proof.abi"
                )
            ),
            (WhirStructs.WhirProof)
        );

        vm.expectRevert();
        verifier.verify(success.initialCommitment, config, statement, failure);
    }

    function testRejectsBadStirQueryFixture() external {
        (
            WhirStructs.ExpandedWhirConfig memory config,
            WhirStructs.WhirStatement memory statement,
            WhirStructs.WhirProof memory success
        ) = _loadSuccessFixture();

        WhirStructs.WhirProof memory failure = abi.decode(
            vm.readFileBinary(
                string.concat(
                    TESTDATA,
                    "quartic_whir_failure_bad_stir_query_proof.abi"
                )
            ),
            (WhirStructs.WhirProof)
        );

        vm.expectRevert();
        verifier.verify(success.initialCommitment, config, statement, failure);
    }

    function testRejectsBadOodFixture() external {
        (
            WhirStructs.ExpandedWhirConfig memory config,
            WhirStructs.WhirStatement memory statement,
            WhirStructs.WhirProof memory success
        ) = _loadSuccessFixture();

        WhirStructs.WhirProof memory failure = abi.decode(
            vm.readFileBinary(
                string.concat(
                    TESTDATA,
                    "quartic_whir_failure_bad_ood_or_transcript_mismatch_proof.abi"
                )
            ),
            (WhirStructs.WhirProof)
        );

        vm.expectRevert();
        verifier.verify(success.initialCommitment, config, statement, failure);
    }

    function testRejectsTamperedInitialSumcheckData() external {
        (
            WhirStructs.ExpandedWhirConfig memory config,
            WhirStructs.WhirStatement memory statement,
            WhirStructs.WhirProof memory proof
        ) = _loadSuccessFixture();

        proof.initialSumcheck.polynomialEvals[0] = _incrementPackedExt4(
            proof.initialSumcheck.polynomialEvals[0]
        );

        vm.expectRevert();
        verifier.verify(proof.initialCommitment, config, statement, proof);
    }

    function testRejectsFinalConstraintMismatch() external {
        (
            WhirStructs.ExpandedWhirConfig memory config,
            WhirStructs.WhirStatement memory statement,
            WhirStructs.WhirProof memory proof
        ) = _loadSuccessFixture();

        statement.evaluations[0] = _incrementPackedExt4(
            statement.evaluations[0]
        );

        vm.expectPartialRevert(
            WhirVerifierCore4.FinalConstraintMismatch.selector
        );
        verifier.verify(proof.initialCommitment, config, statement, proof);
    }

    function testRejectsTamperedFinalMerklePath() external {
        (
            WhirStructs.ExpandedWhirConfig memory config,
            WhirStructs.WhirStatement memory statement,
            WhirStructs.WhirProof memory proof
        ) = _loadSuccessFixture();

        if (proof.finalQueryBatch.kind == 0) {
            proof.finalQueryBatch.values[0] =
                (proof.finalQueryBatch.values[0] + 1) %
                0x7f000001;
        } else {
            proof.finalQueryBatch.values[0] = _incrementPackedExt4(
                proof.finalQueryBatch.values[0]
            );
        }

        vm.expectPartialRevert(WhirVerifierCore4.MerkleRootMismatch.selector);
        verifier.verify(proof.initialCommitment, config, statement, proof);
    }

    function testRejectsWrongWhirFsPattern() external {
        (
            WhirStructs.ExpandedWhirConfig memory config,
            WhirStructs.WhirStatement memory statement,
            WhirStructs.WhirProof memory proof
        ) = _loadSuccessFixture();

        config.whirFsPattern[0] = (config.whirFsPattern[0] + 1) % 0x7f000001;

        vm.expectRevert();
        verifier.verify(proof.initialCommitment, config, statement, proof);
    }

    function testRejectsWrongEffectiveDigestBytes() external {
        (
            WhirStructs.ExpandedWhirConfig memory config,
            WhirStructs.WhirStatement memory statement,
            WhirStructs.WhirProof memory proof
        ) = _loadSuccessFixture();

        config.effectiveDigestBytes -= 1;

        vm.expectRevert();
        verifier.verify(proof.initialCommitment, config, statement, proof);
    }

    function testRejectsFinalQueryBatchPresenceMismatch() external {
        (
            WhirStructs.ExpandedWhirConfig memory config,
            WhirStructs.WhirStatement memory statement,
            WhirStructs.WhirProof memory proof
        ) = _loadSuccessFixture();

        config.finalRoundConfig.numQueries = 0;

        vm.expectRevert();
        verifier.verify(proof.initialCommitment, config, statement, proof);
    }

    function _loadSuccessFixture()
        internal
        view
        returns (
            WhirStructs.ExpandedWhirConfig memory config,
            WhirStructs.WhirStatement memory statement,
            WhirStructs.WhirProof memory proof
        )
    {
        config = abi.decode(
            vm.readFileBinary(
                string.concat(TESTDATA, "quartic_whir_success_config.abi")
            ),
            (WhirStructs.ExpandedWhirConfig)
        );
        statement = abi.decode(
            vm.readFileBinary(
                string.concat(TESTDATA, "quartic_whir_success_statement.abi")
            ),
            (WhirStructs.WhirStatement)
        );
        proof = abi.decode(
            vm.readFileBinary(
                string.concat(TESTDATA, "quartic_whir_success_proof.abi")
            ),
            (WhirStructs.WhirProof)
        );
    }

    function _incrementPackedExt4(
        uint256 packed
    ) internal pure returns (uint256) {
        uint256 c0 = packed >> 224;
        uint256 next = c0 + 1;
        if (next == 0x7f000001) {
            next = 0;
        }
        return (packed & ~(uint256(type(uint32).max) << 224)) | (next << 224);
    }
}
