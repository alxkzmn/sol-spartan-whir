// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test, console2 } from "forge-std/Test.sol";
import { LeanVmGroupedTerminalVerifier } from "../src/leanvm/LeanVmGroupedTerminalVerifier.sol";
import {
    LeanVmTwoCommitmentExecution as Execution
} from "../src/leanvm/LeanVmTwoCommitmentExecution.sol";
import {
    LeanVmGroupedTerminal_KeccakPow28T6
} from "../src/leanvm/generated/LeanVmGroupedTerminal_KeccakPow28T6.sol";

contract LeanVmGroupedTerminal_KeccakPow28T6WrongRoot is LeanVmGroupedTerminal_KeccakPow28T6 {
    function fixedProgramConfig()
        internal
        pure
        override
        returns (Execution.TwoCommitmentConfig memory config)
    {
        config = super.fixedProgramConfig();
        config.expectedSecondaryRoot[0] ^= 1;
    }
}

contract LeanVmGroupedTerminal_KeccakPow28T6Test is Test {
    LeanVmGroupedTerminal_KeccakPow28T6 private verifier;

    function setUp() external {
        verifier = new LeanVmGroupedTerminal_KeccakPow28T6();
    }

    function loadProof() internal view returns (LeanVmGroupedTerminalVerifier.Proof memory) {
        return abi.decode(
            vm.readFileBinary("testdata/grouped_logup/proof.abi"),
            (LeanVmGroupedTerminalVerifier.Proof)
        );
    }

    function testCompleteGroupedTerminal() external view {
        uint256 beforeGas = gasleft();
        require(verifier.verifyGroupedLogupV1(loadProof()), "VERIFY");
        console2.log("complete grouped terminal call gas", beforeGas - gasleft());
    }

    function testRejectApplicationRoot() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        proof.applicationRoot[0] ^= 1;
        vm.expectRevert();
        verifier.verifyGroupedLogupV1(proof);
    }

    function testRejectSparkPoint() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        proof.sparkPoint[0] ^= uint256(1) << 224;
        vm.expectRevert();
        verifier.verifyGroupedLogupV1(proof);
    }

    function testRejectSparkValue() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        proof.sparkValue ^= uint256(1) << 224;
        vm.expectRevert();
        verifier.verifyGroupedLogupV1(proof);
    }

    function testRejectLiftPoint() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        proof.liftPoint[0] ^= uint256(1) << 224;
        vm.expectRevert();
        verifier.verifyGroupedLogupV1(proof);
    }

    function testRejectLiftValue() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        proof.liftValue ^= uint256(1) << 224;
        vm.expectRevert();
        verifier.verifyGroupedLogupV1(proof);
    }

    function testRejectRootValue() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        proof.rootValue ^= uint256(1) << 224;
        vm.expectRevert();
        verifier.verifyGroupedLogupV1(proof);
    }

    function testRejectPrimaryCommitment() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        proof.transcript[32] ^= bytes1(0x01);
        vm.expectRevert();
        verifier.verifyGroupedLogupV1(proof);
    }

    function testRejectSecondaryCommitment() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        proof.transcript[64] ^= bytes1(0x01);
        vm.expectRevert("FIXED_PROGRAM_ROOT");
        verifier.verifyGroupedLogupV1(proof);
    }

    function testRejectPrimaryInitialOpening() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        proof.openings[3] ^= bytes1(uint8(1));
        vm.expectRevert("MERKLE_ROOT");
        verifier.verifyGroupedLogupV1(proof);
    }

    function testRejectWrongTrustedRoot() external {
        LeanVmGroupedTerminal_KeccakPow28T6WrongRoot wrong =
            new LeanVmGroupedTerminal_KeccakPow28T6WrongRoot();
        vm.expectRevert("FIXED_PROGRAM_ROOT");
        wrong.verifyGroupedLogupV1(loadProof());
    }

    function testRejectTrailingTranscript() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        proof.transcript = bytes.concat(proof.transcript, new bytes(32));
        vm.expectRevert("UNUSED_TRANSCRIPT");
        verifier.verifyGroupedLogupV1(proof);
    }

    function testRejectTrailingOpenings() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        proof.openings = bytes.concat(proof.openings, new bytes(32));
        vm.expectRevert("UNUSED_OPENINGS");
        verifier.verifyGroupedLogupV1(proof);
    }

    function testCalldataMatchesNativeExport() external view {
        assertEq(
            abi.encodeCall(verifier.verifyGroupedLogupV1, (loadProof())),
            vm.readFileBinary("testdata/grouped_logup/calldata.bin")
        );
    }

    function testRejectHelperCommitment() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        proof.transcript[96] ^= bytes1(0x01);
        vm.expectRevert();
        verifier.verifyGroupedLogupV1(proof);
    }

    function rejectClaims(uint256 start, uint256 count) internal {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        for (uint256 i; i < count; ++i) {
            uint256 at = start + 20 * i;
            proof.transcript[at] ^= bytes1(0x01);
            vm.expectRevert();
            verifier.verifyGroupedLogupV1(proof);
            proof.transcript[at] ^= bytes1(0x01);
        }
    }

    function testRejectEveryExecutionClaim() external {
        rejectClaims(4480, 27);
    }

    function testRejectEveryMemoryClaim() external {
        rejectClaims(5024, 21);
    }

    function testRejectEveryExtensionClaim() external {
        rejectClaims(5472, 52);
    }

    function testRejectEveryBytecodeClaim() external {
        rejectClaims(6528, 21);
    }

    function testRejectEveryPoseidonClaim() external {
        rejectClaims(6976, 135);
    }

    function testRejectEveryCrossValue() external {
        rejectClaims(9696, 6);
    }

    function testRejectCombinedOodValue() external {
        rejectClaims(9856, 1);
    }

    function testRejectInitialBatchingPow() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        proof.transcript[9824] ^= bytes1(0x01);
        vm.expectRevert();
        verifier.verifyGroupedLogupV1(proof);
    }

    function testRejectEachOpeningBatch() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        uint256[6] memory starts = [uint256(0), 16_910, 33_820, 50_730, 64_290, 74_850];
        for (uint256 i; i < 6; ++i) {
            proof.openings[starts[i] + 3] ^= bytes1(0x01);
            vm.expectRevert("MERKLE_ROOT");
            verifier.verifyGroupedLogupV1(proof);
            proof.openings[starts[i] + 3] ^= bytes1(0x01);
        }
    }

    function testRejectEachOpeningFrontier() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        uint256[6] memory ends = [uint256(16_910), 33_820, 50_730, 64_290, 74_850, 83_480];
        for (uint256 i; i < 6; ++i) {
            proof.openings[ends[i] - 1] ^= bytes1(0x01);
            vm.expectRevert();
            verifier.verifyGroupedLogupV1(proof);
            proof.openings[ends[i] - 1] ^= bytes1(0x01);
        }
    }

    function testRejectAirRoundMessages() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        for (uint256 i; i < 17; ++i) {
            proof.transcript[128 + 256 * i] ^= bytes1(0x01);
            vm.expectRevert();
            verifier.verifyGroupedLogupV1(proof);
            proof.transcript[128 + 256 * i] ^= bytes1(0x01);
        }
    }

    function testRejectNoncanonicalApplication() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        proof.applicationRoot[0] = 2_130_706_433;
        vm.expectRevert("PUBLIC_INPUT_RANGE");
        verifier.verifyGroupedLogupV1(proof);
    }

    function testRejectNoncanonicalClaim() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        proof.liftValue = uint256(2_130_706_433) << 224;
        vm.expectRevert();
        verifier.verifyGroupedLogupV1(proof);
    }

    function testRejectInvalidDimensions() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        for (uint256 i; i < 5; ++i) {
            bytes1 old = proof.transcript[4 * i];
            proof.transcript[4 * i] = 0xff;
            vm.expectRevert();
            verifier.verifyGroupedLogupV1(proof);
            proof.transcript[4 * i] = old;
        }
    }

    function testRejectWrongClaimLength() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        proof.sparkPoint = new uint256[](21);
        vm.expectRevert("CARRIED_CLAIM_DIM");
        verifier.verifyGroupedLogupV1(proof);
    }

    function testRejectOldC1Proof() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = abi.decode(
            vm.readFileBinary("testdata/leanvm_terminal/KeccakPublicMemoryC1Pow28T6/proof.abi"),
            (LeanVmGroupedTerminalVerifier.Proof)
        );
        vm.expectRevert();
        verifier.verifyGroupedLogupV1(proof);
    }

    function testRejectTruncatedTranscript() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        bytes memory data = proof.transcript;
        assembly ("memory-safe") { mstore(data, sub(mload(data), 1)) }
        vm.expectRevert();
        verifier.verifyGroupedLogupV1(proof);
    }

    function testRejectTruncatedOpenings() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        bytes memory data = proof.openings;
        assembly ("memory-safe") { mstore(data, sub(mload(data), 1)) }
        vm.expectRevert();
        verifier.verifyGroupedLogupV1(proof);
    }
}
