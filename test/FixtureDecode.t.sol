// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {SpartanStructs} from "../src/spartan/SpartanStructs.sol";
import {WhirStructs} from "../src/whir/WhirStructs.sol";

contract FixtureDecodeTest is Test {
    string internal constant TESTDATA = "testdata/";

    /// @notice Decodes quartic WHIR proof and statement fixtures, then verifies
    ///         ABI round-trip (re-encode == original bytes) and basic structural
    ///         invariants (non-empty polynomials, matching point/eval counts).
    function testDecodeQuarticWhirSuccessFixtures() external view {
        bytes memory proofRaw = vm.readFileBinary(
            string.concat(TESTDATA, "quartic_whir_success_proof.abi")
        );
        bytes memory statementRaw = vm.readFileBinary(
            string.concat(TESTDATA, "quartic_whir_success_statement.abi")
        );

        WhirStructs.WhirProof memory proof = abi.decode(
            proofRaw,
            (WhirStructs.WhirProof)
        );
        WhirStructs.WhirStatement memory statement = abi.decode(
            statementRaw,
            (WhirStructs.WhirStatement)
        );

        // ABI round-trip: re-encode must produce identical bytes.
        assertEq(keccak256(abi.encode(proof)), keccak256(proofRaw));
        assertEq(keccak256(abi.encode(statement)), keccak256(statementRaw));

        assertGt(proof.initialSumcheck.polynomialEvals.length, 0);
        assertGt(proof.finalPoly.length, 0);
        assertEq(proof.initialSumcheck.polynomialEvals.length % 2, 0);
        if (proof.finalSumcheckPresent) {
            assertGt(proof.finalSumcheck.polynomialEvals.length, 0);
            assertEq(proof.finalSumcheck.polynomialEvals.length % 2, 0);
            assertEq(proof.finalPoly.length & (proof.finalPoly.length - 1), 0);
        } else {
            assertEq(proof.finalSumcheck.polynomialEvals.length, 0);
        }
        if (proof.finalQueryBatchPresent) {
            assertGt(proof.finalQueryBatch.numQueries, 0);
            assertGt(proof.finalQueryBatch.rowLen, 0);
        }
        assertEq(statement.points.length, statement.evaluations.length);
    }

    /// @notice Decodes both the success and tampered-commitment failure proof
    ///         fixtures, verifies ABI round-trip for each, and confirms the
    ///         failure fixture has a different initial commitment than success.
    function testDecodeTamperedFailureProof() external view {
        bytes memory successRaw = vm.readFileBinary(
            string.concat(TESTDATA, "quartic_whir_success_proof.abi")
        );
        bytes memory failureRaw = vm.readFileBinary(
            string.concat(
                TESTDATA,
                "quartic_whir_failure_bad_commitment_proof.abi"
            )
        );

        WhirStructs.WhirProof memory success = abi.decode(
            successRaw,
            (WhirStructs.WhirProof)
        );
        WhirStructs.WhirProof memory failure = abi.decode(
            failureRaw,
            (WhirStructs.WhirProof)
        );

        // ABI round-trip.
        assertEq(keccak256(abi.encode(success)), keccak256(successRaw));
        assertEq(keccak256(abi.encode(failure)), keccak256(failureRaw));

        assertGt(failure.initialSumcheck.polynomialEvals.length, 0);
        assertGt(failure.finalPoly.length, 0);
        assertTrue(failure.initialCommitment != success.initialCommitment);
    }

    /// @notice Decodes both the success and tampered-STIR-query failure proof
    ///         fixtures, verifies ABI round-trip for each, and confirms the
    ///         failure fixture keeps the commitment but changes one query batch.
    function testDecodeTamperedStirQueryFailureProof() external view {
        bytes memory successRaw = vm.readFileBinary(
            string.concat(TESTDATA, "quartic_whir_success_proof.abi")
        );
        bytes memory failureRaw = vm.readFileBinary(
            string.concat(
                TESTDATA,
                "quartic_whir_failure_bad_stir_query_proof.abi"
            )
        );

        WhirStructs.WhirProof memory success = abi.decode(
            successRaw,
            (WhirStructs.WhirProof)
        );
        WhirStructs.WhirProof memory failure = abi.decode(
            failureRaw,
            (WhirStructs.WhirProof)
        );

        assertEq(keccak256(abi.encode(success)), keccak256(successRaw));
        assertEq(keccak256(abi.encode(failure)), keccak256(failureRaw));

        assertEq(failure.initialCommitment, success.initialCommitment);
        assertGt(failure.finalPoly.length, 0);
        assertTrue(
            _firstQueryBatchHash(success) != _firstQueryBatchHash(failure)
        );
    }

    /// @notice Decodes both the success and tampered-OOD-or-transcript-mismatch
    ///         failure proof fixtures, verifies ABI round-trip for each, and
    ///         confirms the failure fixture keeps the commitment but changes
    ///         one initial OOD answer.
    function testDecodeTamperedOodOrTranscriptMismatchFailureProof()
        external
        view
    {
        bytes memory successRaw = vm.readFileBinary(
            string.concat(TESTDATA, "quartic_whir_success_proof.abi")
        );
        bytes memory failureRaw = vm.readFileBinary(
            string.concat(
                TESTDATA,
                "quartic_whir_failure_bad_ood_or_transcript_mismatch_proof.abi"
            )
        );

        WhirStructs.WhirProof memory success = abi.decode(
            successRaw,
            (WhirStructs.WhirProof)
        );
        WhirStructs.WhirProof memory failure = abi.decode(
            failureRaw,
            (WhirStructs.WhirProof)
        );

        assertEq(keccak256(abi.encode(success)), keccak256(successRaw));
        assertEq(keccak256(abi.encode(failure)), keccak256(failureRaw));

        assertEq(failure.initialCommitment, success.initialCommitment);
        assertGt(failure.initialOodAnswers.length, 0);
        assertTrue(
            keccak256(abi.encode(failure.initialOodAnswers)) !=
                keccak256(abi.encode(success.initialOodAnswers))
        );
    }

    /// @notice Decodes the Spartan placeholder proof (placeholder outer/inner
    ///         sumcheck fields with a real WHIR PCS proof nested inside),
    ///         verifies ABI round-trip, and checks the nested PCS proof structure.
    function testDecodeSpartanPlaceholderWithRealPcsProof() external view {
        bytes memory proofRaw = vm.readFileBinary(
            string.concat(TESTDATA, "spartan_placeholder_proof.abi")
        );
        SpartanStructs.SpartanProof memory proof = abi.decode(
            proofRaw,
            (SpartanStructs.SpartanProof)
        );

        // ABI round-trip.
        assertEq(keccak256(abi.encode(proof)), keccak256(proofRaw));

        assertGt(proof.pcsProof.initialSumcheck.polynomialEvals.length, 0);
        assertGt(proof.pcsProof.finalPoly.length, 0);
    }

    /// @notice Decodes the Spartan placeholder instance fixture, verifies ABI
    ///         round-trip, and confirms placeholder values (empty public inputs,
    ///         zero witness commitment).
    function testDecodeSpartanPlaceholderInstance() external view {
        bytes memory instanceRaw = vm.readFileBinary(
            string.concat(TESTDATA, "spartan_placeholder_instance.abi")
        );
        SpartanStructs.SpartanInstance memory instance = abi.decode(
            instanceRaw,
            (SpartanStructs.SpartanInstance)
        );

        // ABI round-trip.
        assertEq(keccak256(abi.encode(instance)), keccak256(instanceRaw));

        // Placeholder has empty public inputs and zero commitment.
        assertEq(instance.publicInputs.length, 0);
        assertEq(instance.witnessCommitment, bytes32(0));
    }

    function _firstQueryBatchHash(
        WhirStructs.WhirProof memory proof
    ) internal pure returns (bytes32) {
        if (proof.rounds.length > 0) {
            return keccak256(abi.encode(proof.rounds[0].queryBatch));
        }

        if (proof.finalQueryBatchPresent) {
            return keccak256(abi.encode(proof.finalQueryBatch));
        }

        revert("proof has no STIR query batch");
    }
}
