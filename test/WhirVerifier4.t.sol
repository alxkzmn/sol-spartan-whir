// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";

import {MerkleVerifier} from "../src/merkle/MerkleVerifier.sol";
import {WhirStructs} from "../src/whir/WhirStructs.sol";
import {WhirVerifierCore4} from "../src/whir/WhirVerifierCore4.sol";
import {WhirVerifierUtils4} from "../src/whir/WhirVerifierUtils4.sol";
import {WhirVerifier4} from "../src/whir/WhirVerifier4.sol";

contract WhirVerifier4Test is Test {
    string internal constant TESTDATA = "testdata/";

    WhirVerifier4 internal verifier;

    function setUp() external {
        verifier = new WhirVerifier4();
    }

    function testVerifyQuarticWhirSuccessFixture() external view {
        (
            WhirStructs.WhirStatement memory statement,
            WhirStructs.WhirProof memory proof
        ) = _loadSuccessFixture();

        assertTrue(verifier.verify(proof.initialCommitment, statement, proof));
    }

    function testGasWhirVerifyFixed() external view {
        (
            WhirStructs.WhirStatement memory statement,
            WhirStructs.WhirProof memory proof
        ) = _loadSuccessFixture();

        assertTrue(verifier.verify(proof.initialCommitment, statement, proof));
    }

    function testRejectsBadCommitmentFixture() external {
        (
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
        verifier.verify(success.initialCommitment, statement, failure);
    }

    function testRejectsBadStirQueryFixture() external {
        (
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
        verifier.verify(success.initialCommitment, statement, failure);
    }

    function testRejectsBadOodFixture() external {
        (
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
        verifier.verify(success.initialCommitment, statement, failure);
    }

    function testRejectsMalformedInitialOodAnswers() external {
        _assertRejectsMalformedPackedExt4AtInitialOod(0, 0, 0x7f000001);
        _assertRejectsMalformedPackedExt4AtInitialOod(0, 1, 0x7f000001);
        _assertRejectsMalformedPackedExt4AtInitialOod(0, 2, 2 * 0x7f000001);
        _assertRejectsMalformedPackedExt4AtInitialOod(0, 3, 0xffffffff);
        _assertRejectsMalformedLowBitsAtInitialOod(0);
    }

    function testRejectsTamperedInitialSumcheckData() external {
        (
            WhirStructs.WhirStatement memory statement,
            WhirStructs.WhirProof memory proof
        ) = _loadSuccessFixture();

        proof.initialSumcheck.polynomialEvals[0] = _incrementPackedExt4(
            proof.initialSumcheck.polynomialEvals[0]
        );

        vm.expectRevert();
        verifier.verify(proof.initialCommitment, statement, proof);
    }

    function testRejectsMalformedInitialSumcheckEvals() external {
        _assertRejectsMalformedPackedExt4AtInitialSumcheck(0, 0, 0x7f000001);
        _assertRejectsMalformedPackedExt4AtInitialSumcheck(0, 1, 0x7f000001);
        _assertRejectsMalformedPackedExt4AtInitialSumcheck(
            0,
            2,
            2 * 0x7f000001
        );
        _assertRejectsMalformedPackedExt4AtInitialSumcheck(0, 3, 0xffffffff);
        _assertRejectsMalformedLowBitsAtInitialSumcheck(0);
    }

    function testRejectsFinalConstraintMismatch() external {
        (
            WhirStructs.WhirStatement memory statement,
            WhirStructs.WhirProof memory proof
        ) = _loadSuccessFixture();

        statement.evaluations[0] = _incrementPackedExt4(
            statement.evaluations[0]
        );

        vm.expectPartialRevert(
            WhirVerifierCore4.FinalConstraintMismatch.selector
        );
        verifier.verify(proof.initialCommitment, statement, proof);
    }

    function testRejectsMalformedFinalPolyCoefficients() external {
        _assertRejectsMalformedPackedExt4AtFinalPoly(0, 0, 0x7f000001);
        _assertRejectsMalformedPackedExt4AtFinalPoly(0, 1, 0x7f000001);
        _assertRejectsMalformedPackedExt4AtFinalPoly(0, 2, 2 * 0x7f000001);
        _assertRejectsMalformedPackedExt4AtFinalPoly(0, 3, 0xffffffff);
        _assertRejectsMalformedLowBitsAtFinalPoly(0);
    }

    function testRejectsTamperedFinalMerklePath() external {
        (
            WhirStructs.WhirStatement memory statement,
            WhirStructs.WhirProof memory proof
        ) = _loadSuccessFixture();

        proof.finalQueryBatch.values[0] =
            (proof.finalQueryBatch.values[0] + 1) %
            0x7f000001;

        vm.expectPartialRevert(MerkleVerifier.InvalidFinalLayer.selector);
        verifier.verify(proof.initialCommitment, statement, proof);
    }

    function _loadSuccessFixture()
        internal
        view
        returns (
            WhirStructs.WhirStatement memory statement,
            WhirStructs.WhirProof memory proof
        )
    {
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

    function _assertRejectsMalformedPackedExt4AtInitialOod(
        uint256 index,
        uint256 lane,
        uint256 value
    ) internal {
        (
            WhirStructs.WhirStatement memory statement,
            WhirStructs.WhirProof memory proof
        ) = _loadSuccessFixture();

        proof.initialOodAnswers[index] = _withLane(
            proof.initialOodAnswers[index],
            lane,
            value
        );

        vm.expectPartialRevert(
            WhirVerifierUtils4.PackedExtensionElementOutOfRange.selector
        );
        verifier.verify(proof.initialCommitment, statement, proof);
    }

    function _assertRejectsMalformedLowBitsAtInitialOod(
        uint256 index
    ) internal {
        (
            WhirStructs.WhirStatement memory statement,
            WhirStructs.WhirProof memory proof
        ) = _loadSuccessFixture();

        proof.initialOodAnswers[index] = _withLowBits(
            proof.initialOodAnswers[index]
        );

        vm.expectPartialRevert(
            WhirVerifierUtils4.PackedExtensionElementOutOfRange.selector
        );
        verifier.verify(proof.initialCommitment, statement, proof);
    }

    function _assertRejectsMalformedPackedExt4AtInitialSumcheck(
        uint256 index,
        uint256 lane,
        uint256 value
    ) internal {
        (
            WhirStructs.WhirStatement memory statement,
            WhirStructs.WhirProof memory proof
        ) = _loadSuccessFixture();

        proof.initialSumcheck.polynomialEvals[index] = _withLane(
            proof.initialSumcheck.polynomialEvals[index],
            lane,
            value
        );

        vm.expectPartialRevert(
            WhirVerifierUtils4.PackedExtensionElementOutOfRange.selector
        );
        verifier.verify(proof.initialCommitment, statement, proof);
    }

    function _assertRejectsMalformedLowBitsAtInitialSumcheck(
        uint256 index
    ) internal {
        (
            WhirStructs.WhirStatement memory statement,
            WhirStructs.WhirProof memory proof
        ) = _loadSuccessFixture();

        proof.initialSumcheck.polynomialEvals[index] = _withLowBits(
            proof.initialSumcheck.polynomialEvals[index]
        );

        vm.expectPartialRevert(
            WhirVerifierUtils4.PackedExtensionElementOutOfRange.selector
        );
        verifier.verify(proof.initialCommitment, statement, proof);
    }

    function _assertRejectsMalformedPackedExt4AtFinalPoly(
        uint256 index,
        uint256 lane,
        uint256 value
    ) internal {
        (
            WhirStructs.WhirStatement memory statement,
            WhirStructs.WhirProof memory proof
        ) = _loadSuccessFixture();

        proof.finalPoly[index] = _withLane(proof.finalPoly[index], lane, value);

        vm.expectPartialRevert(
            WhirVerifierUtils4.PackedExtensionElementOutOfRange.selector
        );
        verifier.verify(proof.initialCommitment, statement, proof);
    }

    function _assertRejectsMalformedLowBitsAtFinalPoly(uint256 index) internal {
        (
            WhirStructs.WhirStatement memory statement,
            WhirStructs.WhirProof memory proof
        ) = _loadSuccessFixture();

        proof.finalPoly[index] = _withLowBits(proof.finalPoly[index]);

        vm.expectPartialRevert(
            WhirVerifierUtils4.PackedExtensionElementOutOfRange.selector
        );
        verifier.verify(proof.initialCommitment, statement, proof);
    }

    function _withLane(
        uint256 packed,
        uint256 lane,
        uint256 value
    ) internal pure returns (uint256) {
        require(lane < 4, "BAD_LANE");
        uint256 shift = 224 - (lane * 32);
        uint256 mask = ~(uint256(type(uint32).max) << shift);
        return (packed & mask) | (value << shift);
    }

    function _withLowBits(uint256 packed) internal pure returns (uint256) {
        return packed | 1;
    }
}
