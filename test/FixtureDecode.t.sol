// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {SpartanStructs} from "../src/spartan/SpartanStructs.sol";
import {WhirStructs} from "../src/whir/WhirStructs.sol";

contract FixtureDecodeTest is Test {
    string internal constant TESTDATA = "testdata/";

    /// @notice Decodes quartic WHIR proof, config, and statement fixtures, then
    ///         verifies ABI round-trip (re-encode == original bytes) and basic
    ///         structural invariants (non-empty polynomials, matching point/eval counts).
    function testDecodeQuarticWhirSuccessFixtures() external view {
        bytes memory proofRaw = vm.readFileBinary(
            string.concat(TESTDATA, "quartic_whir_success_proof.abi")
        );
        bytes memory configRaw = vm.readFileBinary(
            string.concat(TESTDATA, "quartic_whir_success_config.abi")
        );
        bytes memory statementRaw = vm.readFileBinary(
            string.concat(TESTDATA, "quartic_whir_success_statement.abi")
        );

        WhirStructs.WhirProof memory proof = abi.decode(
            proofRaw,
            (WhirStructs.WhirProof)
        );
        WhirStructs.ExpandedWhirConfig memory config = abi.decode(
            configRaw,
            (WhirStructs.ExpandedWhirConfig)
        );
        WhirStructs.WhirStatement memory statement = abi.decode(
            statementRaw,
            (WhirStructs.WhirStatement)
        );

        // ABI round-trip: re-encode must produce identical bytes.
        assertEq(keccak256(abi.encode(proof)), keccak256(proofRaw));
        assertEq(keccak256(abi.encode(config)), keccak256(configRaw));
        assertEq(keccak256(abi.encode(statement)), keccak256(statementRaw));

        // For small-num-variable fixtures, WHIR may have zero explicit round entries.
        assertGt(config.foldingFactor, 0);
        assertGt(config.finalSumcheckRounds, 0);
        assertGt(config.whirFsPattern.length, 0);
        assertGt(proof.initialSumcheck.polynomialEvals.length, 0);
        assertGt(proof.finalPoly.length, 0);
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
}
