// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import { Test } from "forge-std/Test.sol";
import { LeanVmTranscript } from "../src/leanvm/LeanVmTranscript.sol";

contract LeanVmTranscriptTest is Test {
    using LeanVmTranscript for LeanVmTranscript.State;

    function testNativeTranscriptVector() external {
        this.checkVector(
            hex"0100000064000000000000000000000000000000000000000000000000000000c102000000000000000000000000000000000000000000000000000000000000"
        );
    }

    function testRejectNonzeroRecorderPadding() external {
        bytes memory raw =
            hex"0100000064000000000000000000000000000000000000000000000000000000c102000000000000000000000000000000000000000000000000000000000000";
        raw[8] = 0x01;
        vm.expectRevert("TRANSCRIPT_PADDING");
        this.checkVector(raw);
    }

    function checkVector(bytes calldata raw) external pure {
        uint256[8] memory cap = [uint256(7), 7, 7, 7, 7, 7, 7, 7];
        LeanVmTranscript.State memory state = LeanVmTranscript.initialize(cap);
        uint256[] memory observed = new uint256[](2);
        observed[0] = 1;
        observed[1] = 100;
        state.observe(observed);
        uint256[] memory received = state.readBase(raw, 2);
        require(received[0] == 1 && received[1] == 100, "READ");
        uint256[] memory first = state.sampleMany(3);
        require(
            first[0]
                    == 39_142_501_417_557_330_462_801_179_550_371_393_365_833_392_911_183_571_945_820_137_280_723_992_182_784
                && first[1]
                    == 29_274_805_446_669_199_038_155_229_233_984_631_331_682_115_103_242_585_979_355_753_897_424_249_159_680
                && first[2]
                    == 39_075_771_021_244_368_747_366_607_031_445_533_169_520_539_092_711_496_738_910_224_667_788_957_450_240,
            "FIRST"
        );
        state.duplex();
        uint256[13] memory indices =
            [uint256(2359), 3446, 1377, 2994, 3208, 2016, 2115, 1354, 687, 979, 1009, 2219, 1812];
        for (uint256 i; i < 13; ++i) {
            require(state.sampleIndex(12) == indices[i], "INDEX");
        }
        state.checkPow(raw, 8);
        uint256[] memory last = state.sampleMany(2);
        require(
            last[0]
                    == 50_040_281_258_816_971_005_033_510_733_445_205_150_012_564_766_728_605_667_884_570_006_181_814_206_464
                && last[1]
                    == 34_380_319_444_235_223_235_291_254_518_858_412_983_421_893_958_501_387_612_017_616_957_207_604_101_120,
            "LAST"
        );
        state.finish(raw);
    }
}
