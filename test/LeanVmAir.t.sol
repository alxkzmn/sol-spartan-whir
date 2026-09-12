// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { KoalaBearExt5 as E } from "../src/field/KoalaBearExt5.sol";
import { LeanVmAir } from "../src/leanvm/LeanVmAir.sol";

// JSON object members are ABI encoded alphabetically by vm.parseJson.
struct LeanVmAirVector {
    uint256[][] alphas;
    uint256[][] beta_eq;
    uint256[] expected;
    uint256[][] flat;
    string id;
    uint256[][] shift;
    string table;
}

contract LeanVmAirHarness {
    function evaluate(
        uint256 table,
        uint256[] memory flat,
        uint256[] memory shift,
        uint256[] memory alphas,
        uint256[] memory betaEq
    ) external pure returns (uint256) {
        if (table == 0) {
            return LeanVmAir.evalExecution(flat, shift, alphas, betaEq);
        }
        if (table == 1) return LeanVmAir.evalExtension(flat, shift, alphas, betaEq);
        require(table == 2, "TABLE");
        return LeanVmAir.evalPoseidon(flat, shift, alphas, betaEq);
    }
}

contract LeanVmAirTest is Test {
    LeanVmAirHarness private harness;

    function setUp() public {
        harness = new LeanVmAirHarness();
    }

    function testExecutionAirPythonVectors() public {
        _vectors("execution", 0);
    }

    function testExtensionAirPythonVectors() public {
        _vectors("extension", 1);
    }

    function testPoseidonAirPythonVectors() public {
        _vectors("poseidon", 2);
    }

    function _vectors(string memory name, uint256 table) private view {
        string memory json = vm.readFile("testdata/leanvm_air/vectors.json");
        LeanVmAirVector[] memory vectors =
            abi.decode(vm.parseJson(json, ".vectors"), (LeanVmAirVector[]));
        uint256 count;
        for (uint256 i; i < vectors.length; ++i) {
            LeanVmAirVector memory vector = vectors[i];
            if (keccak256(bytes(vector.table)) != keccak256(bytes(name))) continue;
            assertEq(
                harness.evaluate(
                    table,
                    _pack(vector.flat),
                    _pack(vector.shift),
                    _pack(vector.alphas),
                    _pack(vector.beta_eq)
                ),
                _packOne(vector.expected),
                string.concat(name, ":", vector.id)
            );
            ++count;
        }
        assertGt(count, 20);
    }

    function testAirRejectsWrongDimensionsAndNoncanonicalWords() public {
        uint256[] memory flat = new uint256[](20);
        uint256[] memory shift = new uint256[](2);
        uint256[] memory alphas = new uint256[](14);
        uint256[] memory beta = new uint256[](16);
        vm.expectRevert(LeanVmAir.AirInputLength.selector);
        harness.evaluate(0, new uint256[](19), shift, alphas, beta);
        vm.expectRevert(LeanVmAir.AirInputLength.selector);
        harness.evaluate(0, flat, shift, new uint256[](15), beta);
        flat[0] = uint256(2_130_706_433) << 224;
        vm.expectRevert();
        harness.evaluate(0, flat, shift, alphas, beta);
        flat[0] = 1;
        vm.expectRevert();
        harness.evaluate(0, flat, shift, alphas, beta);
    }

    function _pack(uint256[][] memory values) private pure returns (uint256[] memory result) {
        result = new uint256[](values.length);
        for (uint256 i; i < values.length; ++i) {
            result[i] = _packOne(values[i]);
        }
    }

    function _packOne(uint256[] memory value) private pure returns (uint256) {
        require(value.length == 5, "WIDTH");
        uint256[5] memory fixedValue;
        for (uint256 i; i < 5; ++i) {
            fixedValue[i] = value[i];
        }
        return E.pack(fixedValue);
    }
}
