// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";

import {KoalaBear} from "../src/field/KoalaBear.sol";
import {KoalaBearExt4} from "../src/field/KoalaBearExt4.sol";
import {MerkleVerifier} from "../src/merkle/MerkleVerifier.sol";
import {KeccakChallenger} from "../src/transcript/KeccakChallenger.sol";
import {WhirStructs} from "../src/whir/WhirStructs.sol";
import {WhirVerifierCore4} from "../src/whir/WhirVerifierCore4.sol";
import {WhirVerifierUtils4} from "../src/whir/WhirVerifierUtils4.sol";

/// @dev Wrapper contract whose external functions accept calldata structs,
///      letting us measure gas for parseCommitment / finalize separately.
contract WhirProfileHarness {
    using KeccakChallenger for KeccakChallenger.State;

    function profilePhases(
        bytes32 expectedCommitment,
        WhirStructs.ExpandedWhirConfig calldata config,
        WhirStructs.WhirStatement calldata statement,
        WhirStructs.WhirProof calldata proof
    ) external view returns (uint256 gasParseCommitment, uint256 gasFinalize) {
        uint256 g;

        KeccakChallenger.State memory challenger;
        g = gasleft();
        WhirVerifierCore4.ParsedCommitment memory parsed = WhirVerifierCore4
            .parseCommitment(expectedCommitment, config, proof, challenger);
        gasParseCommitment = g - gasleft();

        g = gasleft();
        WhirVerifierCore4.finalize(
            config,
            statement,
            proof,
            challenger,
            parsed
        );
        gasFinalize = g - gasleft();
    }
}

/// @dev Temporary test to profile gas across WHIR verification phases.
contract WhirGasProfileTest is Test {
    using KeccakChallenger for KeccakChallenger.State;

    string internal constant TESTDATA = "testdata/";
    WhirProfileHarness internal harness;

    function setUp() external {
        harness = new WhirProfileHarness();
    }

    function testProfileWhirVerify() external view {
        (
            WhirStructs.ExpandedWhirConfig memory config,
            WhirStructs.WhirStatement memory statement,
            WhirStructs.WhirProof memory proof
        ) = _loadSuccessFixture();

        (uint256 gasParseCommitment, uint256 gasFinalize) = harness
            .profilePhases(proof.initialCommitment, config, statement, proof);

        console.log("=== WHIR Verification Gas Profile ===");
        console.log("Parse commitment:     ", gasParseCommitment);
        console.log("Finalize:             ", gasFinalize);
        console.log("Total (measured):     ", gasParseCommitment + gasFinalize);
    }

    function testProfileMicroBenchmarks() external view {
        // --- Ext4 mul benchmark (100 iterations) ---
        uint256 a = 0x12345678_23456789_34567890_45678901;
        uint256 b = 0x56789012_67890123_78901234_89012345;
        uint256 gasCheck = gasleft();
        for (uint256 i = 0; i < 100; ++i) {
            a = KoalaBearExt4.mul(a, b);
        }
        uint256 gasMul100 = gasCheck - gasleft();

        // --- Ext4 square benchmark (100 iterations) ---
        a = 0x12345678_23456789_34567890_45678901;
        gasCheck = gasleft();
        for (uint256 i = 0; i < 100; ++i) {
            a = KoalaBearExt4.square(a);
        }
        uint256 gasSquare100 = gasCheck - gasleft();

        // --- eq_poly_eval benchmark (6 variables, 100 iterations) ---
        uint256[] memory p = new uint256[](6);
        uint256[] memory q = new uint256[](6);
        for (uint256 i = 0; i < 6; ++i) {
            p[i] = KoalaBearExt4.fromBase((i + 1) * 100);
            q[i] = KoalaBearExt4.fromBase((i + 1) * 200);
        }
        gasCheck = gasleft();
        for (uint256 i = 0; i < 100; ++i) {
            KoalaBearExt4.eq_poly_eval(p, q);
        }
        uint256 gasEqPoly100 = gasCheck - gasleft();

        // --- evaluate_hypercube benchmark (16 elements, 4 variables) ---
        uint256[] memory evals = new uint256[](16);
        uint256[] memory point = new uint256[](4);
        for (uint256 i = 0; i < 16; ++i) {
            evals[i] = KoalaBearExt4.fromBase(i + 1);
        }
        for (uint256 i = 0; i < 4; ++i) {
            point[i] = KoalaBearExt4.fromBase((i + 1) * 50);
        }
        gasCheck = gasleft();
        for (uint256 i = 0; i < 10; ++i) {
            KoalaBearExt4.evaluate_hypercube(evals, point);
        }
        uint256 gasHypercube10 = gasCheck - gasleft();

        // --- Keccak challenger sampleBase benchmark (100 iterations) ---
        KeccakChallenger.State memory ch2;
        ch2.observeBytes(abi.encodePacked(bytes32(uint256(42))));
        gasCheck = gasleft();
        for (uint256 i = 0; i < 100; ++i) {
            ch2.sampleBase();
        }
        uint256 gasSampleBase100 = gasCheck - gasleft();

        // --- Keccak challenger sampleExt4 benchmark (100 iterations) ---
        ch2.observeBytes(abi.encodePacked(bytes32(uint256(42))));
        gasCheck = gasleft();
        for (uint256 i = 0; i < 100; ++i) {
            WhirVerifierUtils4.sampleExt4(ch2);
        }
        uint256 gasSampleExt4_100 = gasCheck - gasleft();

        // --- Keccak challenger observeBase benchmark (100 iterations) ---
        gasCheck = gasleft();
        for (uint256 i = 0; i < 100; ++i) {
            ch2.observeBase(uint32(i));
        }
        uint256 gasObserveBase100 = gasCheck - gasleft();

        // --- Ext4 evaluate_hypercube benchmark (64 elements, 6 variables) ---
        uint256[] memory evals64 = new uint256[](64);
        uint256[] memory point6 = new uint256[](6);
        for (uint256 i = 0; i < 64; ++i) {
            evals64[i] = KoalaBearExt4.fromBase(i + 1);
        }
        for (uint256 i = 0; i < 6; ++i) {
            point6[i] = KoalaBearExt4.fromBase((i + 1) * 50);
        }
        gasCheck = gasleft();
        for (uint256 i = 0; i < 10; ++i) {
            KoalaBearExt4.evaluate_hypercube(evals64, point6);
        }
        uint256 gasHypercube64_10 = gasCheck - gasleft();

        console.log("=== Micro-benchmarks (per-op, averaged) ===");
        console.log("Ext4 mul:               ", gasMul100 / 100);
        console.log("Ext4 square:            ", gasSquare100 / 100);
        console.log("eq_poly_eval (6 vars):  ", gasEqPoly100 / 100);
        console.log("evaluate_hypercube(16): ", gasHypercube10 / 10);
        console.log("evaluate_hypercube(64): ", gasHypercube64_10 / 10);
        console.log("sampleBase:             ", gasSampleBase100 / 100);
        console.log("sampleExt4:             ", gasSampleExt4_100 / 100);
        console.log("observeBase:            ", gasObserveBase100 / 100);
    }

    function _loadSuccessFixture()
        internal
        view
        returns (
            WhirStructs.ExpandedWhirConfig memory config,
            WhirStructs.WhirStatement memory statement,
            WhirStructs.WhirProof memory proof
        )
    {
        config = abi.decode(
            vm.readFileBinary(
                string.concat(TESTDATA, "quartic_whir_success_config.abi")
            ),
            (WhirStructs.ExpandedWhirConfig)
        );
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
}
