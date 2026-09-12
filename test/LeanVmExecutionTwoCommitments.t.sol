// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { KoalaBearExt5 as EF } from "../src/field/KoalaBearExt5.sol";
import { LeanVmTranscript as Transcript } from "../src/leanvm/LeanVmTranscript.sol";
import {
    LeanVmTwoCommitmentTerminalVerifier as Terminal
} from "../src/leanvm/LeanVmTwoCommitmentTerminalVerifier.sol";
import {
    LeanVmTwoCommitmentExecution as Execution
} from "../src/leanvm/LeanVmTwoCommitmentExecution.sol";

contract LeanVmExecutionTwoCommitmentsHarness {
    function sampleAfterObservation(uint256 variables, Execution.FixedProgramClaims memory claims)
        external
        pure
        returns (uint256)
    {
        uint256[8] memory capacity;
        Transcript.State memory state = Transcript.initialize(capacity);
        Transcript.observe(state, Execution.twoCommitmentStatementObservation(variables, claims));
        return Transcript.sample(state);
    }

    function validate(
        Execution.Config memory executionConfig,
        Execution.TwoCommitmentConfig memory commitmentConfig
    ) external pure {
        Execution.validateTwoCommitmentConfig(executionConfig, commitmentConfig);
    }

    function observation(uint256 variables, Execution.FixedProgramClaims memory claims)
        external
        pure
        returns (uint256[] memory)
    {
        return Execution.twoCommitmentStatementObservation(variables, claims);
    }

    function validatePublicMemory(
        uint256[] memory publicMemory,
        Execution.TwoCommitmentConfig memory commitmentConfig,
        Execution.FixedProgramClaims memory fixedClaims
    ) external pure {
        Execution.validateFixedProgramPublicMemory(publicMemory, commitmentConfig, fixedClaims);
    }
}

contract LeanVmExecutionTwoCommitmentsTest is Test {
    LeanVmExecutionTwoCommitmentsHarness private harness;

    function setUp() external {
        harness = new LeanVmExecutionTwoCommitmentsHarness();
    }

    function testCompleteNativeStatementObservation() external view {
        string memory directory = "testdata/leanvm_terminal/KeccakPublicMemoryC1Pow28T6/";
        Terminal.Proof memory proof =
            abi.decode(vm.readFileBinary(string.concat(directory, "proof.abi")), (Terminal.Proof));
        Execution.FixedProgramClaims memory fixedClaims = Execution.FixedProgramClaims(
            proof.sparkPoint, proof.sparkValue, proof.liftPoint, proof.liftValue
        );
        uint256[] memory expected = abi.decode(
            vm.parseJson(
                vm.readFile(string.concat(directory, "manifest.json")),
                ".two_commitment_whir.statement_observation.fields"
            ),
            (uint256[])
        );
        assertEq(harness.observation(23, fixedClaims), expected);
    }

    function testObservationBindsEveryCoefficientAndRejectsNoncanonicalValues() external {
        uint256 p = 2_130_706_433;
        Execution.FixedProgramClaims memory fixedClaims = claims();
        uint256 baseline = harness.sampleAfterObservation(3, fixedClaims);
        for (uint256 i; i < 5; ++i) {
            uint256 difference = uint256(1) << (224 - 32 * i);
            fixedClaims.sparkPoint[0] = EF.add(EF.fromBase(11), difference);
            assertNotEq(harness.sampleAfterObservation(3, fixedClaims), baseline);
            fixedClaims.sparkPoint[0] = EF.fromBase(11);
            fixedClaims.liftPoint[0] = EF.add(EF.fromBase(14), difference);
            assertNotEq(harness.sampleAfterObservation(3, fixedClaims), baseline);
            fixedClaims.liftPoint[0] = EF.fromBase(14);
            fixedClaims.sparkValue = EF.add(EF.fromBase(13), difference);
            assertNotEq(harness.sampleAfterObservation(3, fixedClaims), baseline);
            fixedClaims.sparkValue = EF.fromBase(13);
            fixedClaims.liftValue = EF.add(EF.fromBase(15), difference);
            assertNotEq(harness.sampleAfterObservation(3, fixedClaims), baseline);
            fixedClaims.liftValue = EF.fromBase(15);

            fixedClaims.sparkPoint[1] = p << (224 - 32 * i);
            vm.expectRevert(
                abi.encodeWithSelector(
                    EF.PackedExtensionElementOutOfRange.selector, fixedClaims.sparkPoint[1]
                )
            );
            harness.observation(3, fixedClaims);
            fixedClaims.sparkPoint[1] = EF.fromBase(12);
        }
        fixedClaims.liftValue |= 1;
        vm.expectRevert(
            abi.encodeWithSelector(
                EF.PackedExtensionElementOutOfRange.selector, fixedClaims.liftValue
            )
        );
        harness.observation(3, fixedClaims);
    }

    function config()
        private
        pure
        returns (
            Execution.Config memory executionConfig,
            Execution.TwoCommitmentConfig memory commitmentConfig
        )
    {
        executionConfig.whir.variables = 3;
        commitmentConfig.modeTag = 0x32570001;
        commitmentConfig.batchingPowBits = 2;
        commitmentConfig.programDimensions = [uint256(2), 1, 1];
        commitmentConfig.secondaryActualDataLength = 8;
        commitmentConfig.secondaryStatementPublicMemoryOffsets = [uint256(32), 8];
        commitmentConfig.secondaryStatementPointPrefixLengths = [uint256(1), 2];
        commitmentConfig.secondaryStatementPointPrefixes = [uint256(0), uint256(1) << 224, 0];
        commitmentConfig.executionBytecodePointPrefix = [uint256(1) << 224, uint256(1) << 224];
    }

    function claims() private pure returns (Execution.FixedProgramClaims memory out) {
        out.sparkPoint = new uint256[](2);
        out.sparkPoint[0] = EF.fromBase(11);
        out.sparkPoint[1] = EF.fromBase(12);
        out.sparkValue = EF.fromBase(13);
        out.liftPoint = new uint256[](1);
        out.liftPoint[0] = EF.fromBase(14);
        out.liftValue = EF.fromBase(15);
    }

    function testAcceptsVersionOneLayout() external view {
        (
            Execution.Config memory executionConfig,
            Execution.TwoCommitmentConfig memory commitmentConfig
        ) = config();
        harness.validate(executionConfig, commitmentConfig);
    }

    function testRejectsWrongMode() external {
        (
            Execution.Config memory executionConfig,
            Execution.TwoCommitmentConfig memory commitmentConfig
        ) = config();
        commitmentConfig.modeTag ^= 1;
        vm.expectRevert("TWO_COMMITMENT_MODE");
        harness.validate(executionConfig, commitmentConfig);
    }

    function testRejectsWrongBatchingBits() external {
        (
            Execution.Config memory executionConfig,
            Execution.TwoCommitmentConfig memory commitmentConfig
        ) = config();
        commitmentConfig.batchingPowBits = 3;
        vm.expectRevert("TWO_COMMITMENT_MODE");
        harness.validate(executionConfig, commitmentConfig);
    }

    function testRejectsWrongProgramDimensions() external {
        (
            Execution.Config memory executionConfig,
            Execution.TwoCommitmentConfig memory commitmentConfig
        ) = config();
        commitmentConfig.programDimensions[2] = 2;
        vm.expectRevert("TWO_COMMITMENT_LAYOUT");
        harness.validate(executionConfig, commitmentConfig);
    }

    function testRejectsWrongActualDataLength() external {
        (
            Execution.Config memory executionConfig,
            Execution.TwoCommitmentConfig memory commitmentConfig
        ) = config();
        commitmentConfig.secondaryActualDataLength = 7;
        vm.expectRevert("TWO_COMMITMENT_LENGTH");
        harness.validate(executionConfig, commitmentConfig);
    }

    function testRejectsWrongPublicMemoryOffsets() external {
        (
            Execution.Config memory executionConfig,
            Execution.TwoCommitmentConfig memory commitmentConfig
        ) = config();
        commitmentConfig.secondaryStatementPublicMemoryOffsets[0] = 31;
        vm.expectRevert("TWO_COMMITMENT_MEMORY");
        harness.validate(executionConfig, commitmentConfig);
    }

    function testRejectsWrongPointPrefixLengths() external {
        (
            Execution.Config memory executionConfig,
            Execution.TwoCommitmentConfig memory commitmentConfig
        ) = config();
        commitmentConfig.secondaryStatementPointPrefixLengths[0] = 0;
        vm.expectRevert("TWO_COMMITMENT_MEMORY");
        harness.validate(executionConfig, commitmentConfig);
    }

    function testRejectsWrongPointPrefixes() external {
        (
            Execution.Config memory executionConfig,
            Execution.TwoCommitmentConfig memory commitmentConfig
        ) = config();
        commitmentConfig.secondaryStatementPointPrefixes[1] = 0;
        vm.expectRevert("TWO_COMMITMENT_MEMORY");
        harness.validate(executionConfig, commitmentConfig);
    }

    function testRejectsWrongExecutionPointPrefix() external {
        (
            Execution.Config memory executionConfig,
            Execution.TwoCommitmentConfig memory commitmentConfig
        ) = config();
        commitmentConfig.executionBytecodePointPrefix[1] = 0;
        vm.expectRevert("TWO_COMMITMENT_MEMORY");
        harness.validate(executionConfig, commitmentConfig);
    }

    function testStatementObservationMatchesRustEncoding() external view {
        uint256[] memory encoded = harness.observation(3, claims());
        assertEq(encoded.length, 54);
        assertEq(encoded[0], 0x32574f31);
        assertEq(encoded[1], 2);
        assertEq(encoded[2], 54);
        assertEq(encoded[3], 0);

        assertEq(encoded[4], 3);
        assertEq(encoded[5], 3);
        assertEq(encoded[6], 1);
        assertEq(encoded[7], 0);
        assertEq(encoded[13], 11);
        assertEq(encoded[18], 12);
        assertEq(encoded[23], 0);
        assertEq(encoded[24], 13);

        assertEq(encoded[29], 3);
        assertEq(encoded[30], 3);
        assertEq(encoded[31], 1);
        assertEq(encoded[32], 0);
        assertEq(encoded[33], 1);
        assertEq(encoded[38], 0);
        assertEq(encoded[43], 14);
        assertEq(encoded[48], 0);
        assertEq(encoded[49], 15);

        for (uint256 i; i < encoded.length; ++i) {
            bool expectedNonzero = i == 0 || i == 1 || i == 2 || i == 4 || i == 5 || i == 6
                || i == 13 || i == 18 || i == 24 || i == 29 || i == 30 || i == 31 || i == 33
                || i == 43 || i == 49;
            if (!expectedNonzero) assertEq(encoded[i], 0);
        }
    }

    function testObservationRejectsWrongPointDimension() external {
        Execution.FixedProgramClaims memory fixedClaims = claims();
        fixedClaims.liftPoint = new uint256[](2);
        vm.expectRevert("FIXED_PROGRAM_CLAIM_DIM");
        harness.observation(3, fixedClaims);
    }

    function testClaimsMatchConfiguredPublicMemorySlices() external view {
        (, Execution.TwoCommitmentConfig memory commitmentConfig) = config();
        Execution.FixedProgramClaims memory fixedClaims = claims();
        uint256[] memory publicMemory = new uint256[](56);
        publicMemory[32] = 11;
        publicMemory[37] = 12;
        publicMemory[42] = 13;
        publicMemory[8] = 14;
        publicMemory[13] = 15;
        harness.validatePublicMemory(publicMemory, commitmentConfig, fixedClaims);
    }

    function testRejectsClaimDifferentFromPublicMemory() external {
        (, Execution.TwoCommitmentConfig memory commitmentConfig) = config();
        Execution.FixedProgramClaims memory fixedClaims = claims();
        uint256[] memory publicMemory = new uint256[](56);
        publicMemory[32] = 10;
        vm.expectRevert("FIXED_PROGRAM_MEMORY");
        harness.validatePublicMemory(publicMemory, commitmentConfig, fixedClaims);
    }
}
