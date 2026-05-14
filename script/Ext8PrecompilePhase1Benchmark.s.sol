// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Script, console2 } from "forge-std/Script.sol";

import { KoalaBear } from "../src/field/KoalaBear.sol";
import { KoalaBearExt8 } from "../src/field/KoalaBearExt8.sol";
import { Ext8PrecompileHarness } from "../test/helpers/Ext8PrecompileHarness.sol";

contract Ext8PrecompilePhase1BenchmarkScript is Script {
    function run() external returns (address harnessAddress) {
        uint256[] memory fullPoint = _buildFullPoint();
        uint256[] memory selVars = _buildSelectVars();
        uint256 challenge = KoalaBearExt8.fromBase(7);
        uint256 oodPoint = KoalaBearExt8.fromBase(5);
        uint256 eqEval = KoalaBearExt8.fromBase(11);

        vm.startBroadcast();

        Ext8PrecompileHarness harness = new Ext8PrecompileHarness();
        harnessAddress = address(harness);

        harness.benchmarkNoopMulClean(oodPoint, eqEval);
        harness.benchmarkNoopSquareClean(oodPoint);

        harness.benchmarkEqExpanded22Software(oodPoint, fullPoint);
        harness.benchmarkEqExpanded22Noop(oodPoint, fullPoint);
        harness.benchmarkEqExpanded22Precompile(oodPoint, fullPoint);

        harness.benchmarkRound0SelectOnlySoftware(challenge, eqEval, selVars, fullPoint);
        harness.benchmarkRound0SelectOnlyNoop(challenge, eqEval, selVars, fullPoint);
        harness.benchmarkRound0SelectOnlyPrecompile(challenge, eqEval, selVars, fullPoint);

        harness.benchmarkRound0EqSelectSoftware(challenge, oodPoint, selVars, fullPoint);
        harness.benchmarkRound0EqSelectNoop(challenge, oodPoint, selVars, fullPoint);
        harness.benchmarkRound0EqSelectPrecompile(challenge, oodPoint, selVars, fullPoint);

        vm.stopBroadcast();

        console2.log("ext8PrecompileHarness", harnessAddress);
    }

    function _buildFullPoint() internal pure returns (uint256[] memory fullPoint) {
        fullPoint = new uint256[](22);
        unchecked {
            for (uint256 i = 0; i < 22; ++i) {
                fullPoint[i] = KoalaBearExt8.fromBase((i % 17) + 1);
            }
        }
    }

    function _buildSelectVars() internal pure returns (uint256[] memory selVars) {
        selVars = new uint256[](24);
        unchecked {
            for (uint256 i = 0; i < 24; ++i) {
                selVars[i] = ((i + 1) * 7 % (KoalaBear.MODULUS - 1)) + 1;
            }
        }
    }
}
