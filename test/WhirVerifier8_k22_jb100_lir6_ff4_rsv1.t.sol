// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";

import { WhirStructs } from "../src/whir/WhirStructs.sol";
import { WhirVerifierCore8 } from "../src/whir/k22_jb100_lir6_ff4_rsv1/WhirVerifierCore8.sol";
import {
    WhirVerifier8_k22_jb100_lir6_ff4_rsv1 as WhirVerifier8
} from "../src/whir/k22_jb100_lir6_ff4_rsv1/WhirVerifier8_k22_jb100_lir6_ff4_rsv1.sol";

contract WhirVerifier8K22Jb100Test is Test {
    string internal constant TESTDATA = "testdata/";
    uint256 internal constant MODULUS = 0x7f000001;

    WhirVerifier8 internal verifier;

    function setUp() external {
        verifier = new WhirVerifier8();
    }

    function testVerifyOcticWhirSuccessFixture() external view {
        (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof) =
            _loadSuccessFixture();
        assertTrue(verifier.verify(proof.initialCommitment, statement, proof));
    }

    function testGasWhirVerifyFixed() external view {
        (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof) =
            _loadSuccessFixture();
        assertTrue(verifier.verify(proof.initialCommitment, statement, proof));
    }

    function testRejectsBadCommitmentFixture() external {
        (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory success) =
            _loadSuccessFixture();
        WhirStructs.WhirProof memory failure = abi.decode(
            vm.readFileBinary(
                string.concat(
                    TESTDATA, "octic_whir_k22_jb100_lir6_ff4_rsv1_failure_bad_commitment_proof.abi"
                )
            ),
            (WhirStructs.WhirProof)
        );

        vm.expectRevert();
        verifier.verify(success.initialCommitment, statement, failure);
    }

    function testRejectsBadStirQueryFixture() external {
        (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory success) =
            _loadSuccessFixture();
        WhirStructs.WhirProof memory failure = abi.decode(
            vm.readFileBinary(
                string.concat(
                    TESTDATA, "octic_whir_k22_jb100_lir6_ff4_rsv1_failure_bad_stir_query_proof.abi"
                )
            ),
            (WhirStructs.WhirProof)
        );

        vm.expectRevert();
        verifier.verify(success.initialCommitment, statement, failure);
    }

    function testRejectsBadOodFixture() external {
        (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory success) =
            _loadSuccessFixture();
        WhirStructs.WhirProof memory failure = abi.decode(
            vm.readFileBinary(
                string.concat(
                    TESTDATA,
                    "octic_whir_k22_jb100_lir6_ff4_rsv1_failure_bad_ood_or_transcript_mismatch_proof.abi"
                )
            ),
            (WhirStructs.WhirProof)
        );

        vm.expectRevert();
        verifier.verify(success.initialCommitment, statement, failure);
    }

    function testRejectsMalformedInitialOodAnswers() external {
        for (uint256 lane = 0; lane < 8; ++lane) {
            (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof) =
                _loadSuccessFixture();
            proof.initialOodAnswers[0] = _withLane(proof.initialOodAnswers[0], lane, MODULUS);
            vm.expectRevert();
            verifier.verify(proof.initialCommitment, statement, proof);
        }
    }

    function testRejectsTamperedInitialSumcheckData() external {
        (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof) =
            _loadSuccessFixture();
        proof.initialSumcheck.polynomialEvals[0] =
            _incrementPackedExt8(proof.initialSumcheck.polynomialEvals[0]);
        vm.expectRevert();
        verifier.verify(proof.initialCommitment, statement, proof);
    }

    function testRejectsMalformedInitialSumcheckEvals() external {
        for (uint256 lane = 0; lane < 8; ++lane) {
            (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof) =
                _loadSuccessFixture();
            proof.initialSumcheck.polynomialEvals[0] =
                _withLane(proof.initialSumcheck.polynomialEvals[0], lane, MODULUS);
            vm.expectRevert();
            verifier.verify(proof.initialCommitment, statement, proof);
        }
    }

    function testRejectsFinalConstraintMismatch() external {
        (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof) =
            _loadSuccessFixture();
        statement.evaluations[0] = _incrementPackedExt8(statement.evaluations[0]);
        vm.expectPartialRevert(WhirVerifierCore8.FinalConstraintMismatch.selector);
        verifier.verify(proof.initialCommitment, statement, proof);
    }

    function testRejectsMalformedFinalPolyCoefficients() external {
        for (uint256 lane = 0; lane < 8; ++lane) {
            (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof) =
                _loadSuccessFixture();
            proof.finalPoly[0] = _withLane(proof.finalPoly[0], lane, MODULUS);
            vm.expectRevert();
            verifier.verify(proof.initialCommitment, statement, proof);
        }
    }

    function testRejectsTamperedFinalMerklePath() external {
        (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof) =
            _loadSuccessFixture();
        proof.finalQueryBatch.values[0] = _incrementPackedExt8(proof.finalQueryBatch.values[0]);
        vm.expectPartialRevert(WhirVerifierCore8.MerkleRootMismatch.selector);
        verifier.verify(proof.initialCommitment, statement, proof);
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

    function _incrementPackedExt8(uint256 packed) internal pure returns (uint256) {
        uint256 c0 = packed >> 224;
        uint256 next = c0 + 1;
        if (next == MODULUS) {
            next = 0;
        }
        return (packed & ~(uint256(type(uint32).max) << 224)) | (next << 224);
    }

    function _withLane(uint256 packed, uint256 lane, uint256 value)
        internal
        pure
        returns (uint256)
    {
        require(lane < 8, "BAD_LANE");
        uint256 shift = 224 - (lane * 32);
        uint256 mask = ~(uint256(type(uint32).max) << shift);
        return (packed & mask) | (value << shift);
    }
}
