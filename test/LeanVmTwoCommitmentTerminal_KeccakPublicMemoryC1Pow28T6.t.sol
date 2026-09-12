// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test, console2 } from "forge-std/Test.sol";
import {
    LeanVmTwoCommitmentTerminalVerifier
} from "../src/leanvm/LeanVmTwoCommitmentTerminalVerifier.sol";
import {
    LeanVmTwoCommitmentExecution as Execution
} from "../src/leanvm/LeanVmTwoCommitmentExecution.sol";
import {
    LeanVmTwoCommitmentTerminal_KeccakPublicMemoryC1Pow28T6
} from "../src/leanvm/generated/LeanVmTwoCommitmentTerminal_KeccakPublicMemoryC1Pow28T6.sol";

contract LeanVmTwoCommitmentTerminal_KeccakPublicMemoryC1Pow28T6WrongRoot is
    LeanVmTwoCommitmentTerminal_KeccakPublicMemoryC1Pow28T6
{
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

contract LeanVmTwoCommitmentTerminal_KeccakPublicMemoryC1Pow28T6Test is Test {
    LeanVmTwoCommitmentTerminal_KeccakPublicMemoryC1Pow28T6 private verifier;

    function setUp() external {
        verifier = new LeanVmTwoCommitmentTerminal_KeccakPublicMemoryC1Pow28T6();
    }

    function loadProof() internal view returns (LeanVmTwoCommitmentTerminalVerifier.Proof memory) {
        return abi.decode(
            vm.readFileBinary("testdata/leanvm_terminal/KeccakPublicMemoryC1Pow28T6/proof.abi"),
            (LeanVmTwoCommitmentTerminalVerifier.Proof)
        );
    }

    function testCompleteTwoCommitmentTerminal() external view {
        uint256 beforeGas = gasleft();
        require(verifier.verifyC1V1(loadProof()), "VERIFY");
        console2.log("complete two-commitment terminal call gas", beforeGas - gasleft());
    }

    function testRejectApplicationRoot() external {
        LeanVmTwoCommitmentTerminalVerifier.Proof memory proof = loadProof();
        proof.applicationRoot[0] ^= 1;
        vm.expectRevert();
        verifier.verifyC1V1(proof);
    }

    function testRejectSparkPoint() external {
        LeanVmTwoCommitmentTerminalVerifier.Proof memory proof = loadProof();
        proof.sparkPoint[0] ^= uint256(1) << 224;
        vm.expectRevert();
        verifier.verifyC1V1(proof);
    }

    function testRejectSparkValue() external {
        LeanVmTwoCommitmentTerminalVerifier.Proof memory proof = loadProof();
        proof.sparkValue ^= uint256(1) << 224;
        vm.expectRevert();
        verifier.verifyC1V1(proof);
    }

    function testRejectLiftPoint() external {
        LeanVmTwoCommitmentTerminalVerifier.Proof memory proof = loadProof();
        proof.liftPoint[0] ^= uint256(1) << 224;
        vm.expectRevert();
        verifier.verifyC1V1(proof);
    }

    function testRejectLiftValue() external {
        LeanVmTwoCommitmentTerminalVerifier.Proof memory proof = loadProof();
        proof.liftValue ^= uint256(1) << 224;
        vm.expectRevert();
        verifier.verifyC1V1(proof);
    }

    function testRejectRootValue() external {
        LeanVmTwoCommitmentTerminalVerifier.Proof memory proof = loadProof();
        proof.rootValue ^= uint256(1) << 224;
        vm.expectRevert();
        verifier.verifyC1V1(proof);
    }

    function testRejectPrimaryCommitment() external {
        LeanVmTwoCommitmentTerminalVerifier.Proof memory proof = loadProof();
        proof.transcript[32] ^= bytes1(0x01);
        vm.expectRevert();
        verifier.verifyC1V1(proof);
    }

    function testRejectSecondaryCommitment() external {
        LeanVmTwoCommitmentTerminalVerifier.Proof memory proof = loadProof();
        proof.transcript[64] ^= bytes1(0x01);
        vm.expectRevert("FIXED_PROGRAM_ROOT");
        verifier.verifyC1V1(proof);
    }

    function testRejectPrimaryInitialOpening() external {
        LeanVmTwoCommitmentTerminalVerifier.Proof memory proof = loadProof();
        proof.openings[3] ^= bytes1(uint8(1));
        vm.expectRevert("MERKLE_ROOT");
        verifier.verifyC1V1(proof);
    }

    function testRejectSecondaryInitialOpening() external {
        LeanVmTwoCommitmentTerminalVerifier.Proof memory proof = loadProof();
        proof.openings[17_183] ^= bytes1(uint8(1));
        vm.expectRevert("MERKLE_ROOT");
        verifier.verifyC1V1(proof);
    }

    function testRejectCrossValue() external {
        LeanVmTwoCommitmentTerminalVerifier.Proof memory proof = loadProof();
        proof.transcript[34_592] ^= bytes1(uint8(1));
        vm.expectRevert();
        verifier.verifyC1V1(proof);
    }

    function testRejectCombinedOodValue() external {
        LeanVmTwoCommitmentTerminalVerifier.Proof memory proof = loadProof();
        proof.transcript[34_688] ^= bytes1(uint8(1));
        vm.expectRevert();
        verifier.verifyC1V1(proof);
    }

    function testRejectWrongTrustedRoot() external {
        LeanVmTwoCommitmentTerminal_KeccakPublicMemoryC1Pow28T6WrongRoot wrong =
            new LeanVmTwoCommitmentTerminal_KeccakPublicMemoryC1Pow28T6WrongRoot();
        vm.expectRevert("FIXED_PROGRAM_ROOT");
        wrong.verifyC1V1(loadProof());
    }

    function testRejectTrailingTranscript() external {
        LeanVmTwoCommitmentTerminalVerifier.Proof memory proof = loadProof();
        proof.transcript = bytes.concat(proof.transcript, new bytes(32));
        vm.expectRevert("UNUSED_TRANSCRIPT");
        verifier.verifyC1V1(proof);
    }

    function testRejectTrailingOpenings() external {
        LeanVmTwoCommitmentTerminalVerifier.Proof memory proof = loadProof();
        proof.openings = bytes.concat(proof.openings, new bytes(32));
        vm.expectRevert("UNUSED_OPENINGS");
        verifier.verifyC1V1(proof);
    }
}
