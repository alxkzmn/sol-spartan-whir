// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { LeanVmGroupedTerminalVerifier } from "../LeanVmGroupedTerminalVerifier.sol";
import { LeanVmTwoCommitmentExecution as Execution } from "../LeanVmTwoCommitmentExecution.sol";
import { LeanVmWhir as Whir } from "../LeanVmWhir.sol";

contract LeanVmGroupedTerminal_KeccakPow28T6 is LeanVmGroupedTerminalVerifier {
    function rootConfig() internal pure virtual override returns (Execution.Config memory config) {
        config.bytecodeLog = 17;
        config.endingPc = 131_071;
        config.rate = 6;
        config.capacity = [
            uint256(201_076_413),
            1_376_297_359,
            1_693_489_495,
            479_934_901,
            113_757_364,
            1_359_467_769,
            776_561_868,
            967_105_175
        ];
        config.whir.variables = 23;
        config.whir.firstFold = 5;
        config.whir.nextFold = 4;
        config.whir.commitmentOod = 1;
        config.whir.firstPow = 0;
        config.whir.finalRounds = 6;
        config.whir.rounds = new Whir.Round[](3);
        config.whir.rounds[0] = Whir.Round(18, 5, 536_870_912, 1_791_270_792, 25, 1, 28, 0);
        config.whir.rounds[1] = Whir.Round(14, 4, 268_435_456, 1_791_270_792, 15, 1, 28, 0);
        config.whir.rounds[2] = Whir.Round(10, 4, 134_217_728, 1_760_025_929, 12, 1, 25, 4);
        config.whir.finalRound = Whir.Round(6, 4, 67_108_864, 542_991_299, 10, 1, 23, 0);
        config.whir.openingsCodec = 1;
    }

    function fixedProgramConfig()
        internal
        pure
        virtual
        override
        returns (Execution.TwoCommitmentConfig memory config)
    {
        config.modeTag = 844_562_433;
        config.batchingPowBits = 2;
        config.programDimensions = [uint256(22), 21, 21];
        config.secondaryActualDataLength = 8_388_608;
        config.secondaryStatementPublicMemoryOffsets = [uint256(128), 8];
        config.secondaryStatementPointPrefixLengths = [uint256(1), 2];
        config.secondaryStatementPointPrefixes = [
            uint256(0),
            26_959_946_667_150_639_794_667_015_087_019_630_673_637_144_422_540_572_481_103_610_249_216,
            0
        ];
        config.executionBytecodePointPrefix = [
            uint256(
                26_959_946_667_150_639_794_667_015_087_019_630_673_637_144_422_540_572_481_103_610_249_216
            ),
            26_959_946_667_150_639_794_667_015_087_019_630_673_637_144_422_540_572_481_103_610_249_216
        ];
        config.expectedSecondaryRoot = [
            uint256(195_414_443),
            355_672_050,
            575_330_136,
            197_499_168,
            871_225_560,
            299_717_124,
            884_218_482,
            593_264_179
        ];
    }

    function liftedCapacity() internal pure virtual override returns (uint256[8] memory) {
        return [
            uint256(292_120_851),
            1_834_781_869,
            538_063_231,
            46_288_679,
            1_784_790_716,
            2_077_655_571,
            68_020_209,
            712_230_306
        ];
    }
}
