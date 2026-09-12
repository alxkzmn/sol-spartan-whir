// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import { Test, console2 } from "forge-std/Test.sol";
import { KoalaBearExt5 as EF } from "../src/field/KoalaBearExt5.sol";
import { KoalaBearPackedField as Packed } from "../src/field/KoalaBearPackedField.sol";
import { KeccakChallenger } from "../src/transcript/KeccakChallenger.sol";
import { LeanVmTranscript as Transcript } from "../src/leanvm/LeanVmTranscript.sol";
import { LeanVmGkrSumcheck as Cubic } from "../src/leanvm/LeanVmGkrSumcheck.sol";
import { LeanVmPolynomial as Poly } from "../src/leanvm/LeanVmPolynomial.sol";
import { LeanVmWhirWeight as Weight } from "../src/leanvm/LeanVmWhirWeight.sol";
import { LeanVmAir } from "../src/leanvm/LeanVmAir.sol";
import { LeanVmLogUp as LogUp } from "../src/leanvm/LeanVmLogUp.sol";
import { LeanVmPackedPolynomial as PackedPoly } from "../src/leanvm/LeanVmPackedPolynomial.sol";

struct LeanVmAirVector {
    uint256[][] alphas;
    uint256[][] beta_eq;
    uint256[] expected;
    uint256[][] flat;
    string id;
    uint256[][] shift;
    string table;
}

/// @dev Scratch micro-benchmarks for the LeanVM verifier primitives. Synthetic
/// sumcheck transcripts halve the target every round (c0 = target/2, c1..c3 = 0).
contract LeanVmPrimitiveBenchHarness {
    using Transcript for Transcript.State;
    using KeccakChallenger for KeccakChallenger.State;
    uint256 internal constant P = 2_130_706_433;
    uint256 internal constant HALF = (P + 1) / 2;

    function mulLoop(uint256 a, uint256 b, uint256 n) external view returns (uint256 gas, uint256 out) {
        gas = gasleft();
        out = a;
        for (uint256 i; i < n; ++i) out = Packed.mul(out, b);
        gas -= gasleft();
    }

    function eqPoly(uint256[] memory a, uint256[] memory b, uint256 n) external view returns (uint256 gas, uint256 out) {
        gas = gasleft();
        for (uint256 i; i < n; ++i) out = EF.add(out, EF.eq_poly_eval(a, b));
        gas -= gasleft();
    }

    function observeBase(uint256 n) external view returns (uint256 gas) {
        Transcript.State memory state;
        state.challenger.observeBytes(bytes("bench"));
        gas = gasleft();
        for (uint256 i; i < n; ++i) state.challenger.observeBase(i);
        gas -= gasleft();
    }

    function sampleBase(uint256 n) external view returns (uint256 gas, uint256 acc) {
        Transcript.State memory state;
        state.challenger.observeBytes(bytes("bench"));
        gas = gasleft();
        for (uint256 i; i < n; ++i) acc ^= state.challenger.sampleBase();
        gas -= gasleft();
    }

    function sampleExt(uint256 n) external view returns (uint256 gas, uint256 acc) {
        Transcript.State memory state;
        state.challenger.observeBytes(bytes("bench"));
        gas = gasleft();
        for (uint256 i; i < n; ++i) acc ^= state.sample();
        gas -= gasleft();
    }

    function halve(uint256 packed) internal pure returns (uint256 out) {
        for (uint256 k; k < 5; ++k) {
            uint256 c = (packed >> (224 - 32 * k)) & 0xffffffff;
            out |= mulmod(c, HALF, P) << (224 - 32 * k);
        }
    }

    function encodeLe(uint256 packed) internal pure returns (bytes memory out) {
        out = new bytes(20);
        for (uint256 k; k < 5; ++k) {
            uint256 c = (packed >> (224 - 32 * k)) & 0xffffffff;
            out[4 * k] = bytes1(uint8(c));
            out[4 * k + 1] = bytes1(uint8(c >> 8));
            out[4 * k + 2] = bytes1(uint8(c >> 16));
            out[4 * k + 3] = bytes1(uint8(c >> 24));
        }
    }

    /// @dev Cubic GKR rounds: 4 coefficients + 16 zero bytes per round.
    function gkrTranscript(uint256 target, uint256 rounds) external view returns (bytes memory out) {
        for (uint256 i; i < rounds; ++i) {
            uint256 c0 = halve(target);
            out = bytes.concat(out, encodeLe(c0), new bytes(60), new bytes(16));
            target = c0;
        }
    }

    function gkrRounds(bytes calldata transcript, uint256 target, uint256 rounds) external view returns (uint256 gas) {
        Transcript.State memory state;
        state.challenger.observeBytes(bytes("bench"));
        gas = gasleft();
        Cubic.verify(state, transcript, target, rounds);
        gas -= gasleft();
    }

    /// @dev Generic degree-d rounds: d+1 coefficients padded to eight scalars.
    function genericTranscript(uint256 target, uint256 rounds, uint256 degree) external view returns (bytes memory out) {
        uint256 scalars = (degree + 1) * 5;
        uint256 padded = (scalars + 7) & ~uint256(7);
        for (uint256 i; i < rounds; ++i) {
            uint256 c0 = halve(target);
            out = bytes.concat(out, encodeLe(c0), new bytes(padded * 4 - 20));
            target = c0;
        }
    }

    function genericRounds(bytes calldata transcript, uint256 target, uint256 rounds, uint256 degree) external view returns (uint256 gas) {
        Transcript.State memory state;
        state.challenger.observeBytes(bytes("bench"));
        gas = gasleft();
        Poly.sumcheck(state, transcript, target, rounds, degree, 0);
        gas -= gasleft();
    }

    function readExtension(bytes calldata transcript, uint256 count) external view returns (uint256 gas) {
        Transcript.State memory state;
        state.challenger.observeBytes(bytes("bench"));
        gas = gasleft();
        state.readExtension(transcript, count);
        gas -= gasleft();
    }

    function selectorWeights(uint256[] memory point, uint256 base, uint256 count, uint256 depth) external view returns (uint256 gas, uint256 acc) {
        Weight.Cache memory cache = Weight.initialize(depth);
        gas = gasleft();
        for (uint256 i; i < count; ++i) acc = EF.add(acc, Weight.selector(cache, point, base + i, depth));
        gas -= gasleft();
    }

    function air(uint256 table, uint256[] memory flat, uint256[] memory shift, uint256[] memory alphas, uint256[] memory betaEq) external view returns (uint256 gas) {
        gas = gasleft();
        if (table == 0) LeanVmAir.evalExecution(flat, shift, alphas, betaEq);
        else if (table == 1) LeanVmAir.evalExtension(flat, shift, alphas, betaEq);
        else LeanVmAir.evalPoseidon(flat, shift, alphas, betaEq);
        gas -= gasleft();
    }

    /// @dev Instrumented copy of LeanVmLogUp.verifyGkr. Slots: 0 top layer (read 64 + quotient +
    /// two 32-evals), 1 duplex+alpha sample, 2 cubic rounds, 3 reverse + child read + step +
    /// eqPolynomial check, 4 beta sample + fold + point rebuild.
    function gkrLayers(bytes calldata transcript, uint256[8] memory capacity, uint256 variables)
        external view returns (uint256[5] memory costs)
    {
        Transcript.State memory state = Transcript.initialize(capacity);
        state.sample();
        state.duplex();
        state.sampleMany(4);
        uint256 g = gasleft();
        uint256[] memory numerators = state.readExtension(transcript, 32);
        uint256[] memory denominators = state.readExtension(transcript, 32);
        (uint256 balance, uint256 combinedDenominator) = LogUp.combinedFraction(numerators, denominators);
        require(balance == 0 && combinedDenominator != 0, "Q");
        uint256[] memory rpoint = state.sampleMany(5);
        uint256 numerator = PackedPoly.evaluateHypercube(numerators, rpoint);
        uint256 denominator = PackedPoly.evaluateHypercube(denominators, rpoint);
        costs[0] += g - gasleft(); g = gasleft();
        for (uint256 layer = 5; layer < variables; ++layer) {
            state.duplex();
            uint256 alpha = state.sample();
            costs[1] += g - gasleft(); g = gasleft();
            (uint256[] memory point, uint256 value) =
                Cubic.verify(state, transcript, EF.add(numerator, Packed.mul(alpha, denominator)), layer);
            costs[2] += g - gasleft(); g = gasleft();
            point = Poly.reverse(point);
            uint256[] memory child = state.readExtension(transcript, 4);
            uint256 step = EF.add(
                Packed.mul(alpha, Packed.mul(child[2], child[3])),
                EF.add(Packed.mul(child[0], child[3]), Packed.mul(child[1], child[2]))
            );
            require(value == Packed.mul(PackedPoly.eqPolynomial(rpoint, point), step), "GKR_STEP");
            costs[3] += g - gasleft(); g = gasleft();
            uint256 beta = state.sample();
            numerator = EF.add(Packed.mul(EF.sub(ONE, beta), child[0]), Packed.mul(beta, child[1]));
            denominator = EF.add(Packed.mul(EF.sub(ONE, beta), child[2]), Packed.mul(beta, child[3]));
            rpoint = new uint256[](point.length + 1);
            for (uint256 i; i < point.length; ++i) rpoint[i] = point[i];
            rpoint[point.length] = beta;
            costs[4] += g - gasleft(); g = gasleft();
        }
    }
    uint256 internal constant ONE = uint256(1) << 224;
}

contract LeanVmPrimitiveBenchTest is Test {
    LeanVmPrimitiveBenchHarness h;
    uint256 constant P = 2_130_706_433;

    function setUp() public { h = new LeanVmPrimitiveBenchHarness(); }

    function el(uint256 seed) internal pure returns (uint256 out) {
        for (uint256 k; k < 5; ++k) out |= (uint256(keccak256(abi.encode(seed, k))) % P) << (224 - 32 * k);
    }

    function point(uint256 n, uint256 seed) internal pure returns (uint256[] memory out) {
        out = new uint256[](n);
        for (uint256 i; i < n; ++i) out[i] = el(seed * 1000 + i);
    }

    function testPrimitives() public view {
        (uint256 g,) = h.mulLoop(el(1), el(2), 1000);
        console2.log("Packed.mul x1000", g);
        (g,) = h.eqPoly(point(18, 1), point(18, 2), 10);
        console2.log("eq_poly_eval 18 vars x10", g);
        console2.log("observeBase x1000", h.observeBase(1000));
        (g,) = h.sampleBase(1000);
        console2.log("sampleBase x1000", g);
        (g,) = h.sampleExt(200);
        console2.log("sample ext5 x200", g);
        bytes memory t = h.gkrTranscript(el(3), 100);
        console2.log("GKR cubic rounds x100", h.gkrRounds(t, el(3), 100));
        t = h.genericTranscript(el(4), 20, 2);
        console2.log("generic degree-2 rounds x20", h.genericRounds(t, el(4), 20, 2));
        t = h.genericTranscript(el(5), 17, 11);
        console2.log("generic degree-11 rounds x17", h.genericRounds(t, el(5), 17, 11));
        t = h.genericTranscript(el(6), 1, 109);
        console2.log("readExtension x110", h.readExtension(t, 110));
        (g,) = h.selectorWeights(point(23, 7), 8, 110, 7);
        console2.log("Weight.selector x110 depth 7", g);
        (g,) = h.selectorWeights(point(23, 7), 0, 64, 6);
        console2.log("Weight.selector x64 depth 6", g);
    }

    function testGkrLayers() public view {
        string memory fixture = vm.readFile("testdata/leanvm_logup/vectors.json");
        bytes memory transcript = abi.decode(vm.parseJson(fixture, ".vectors[0].gkr_transcript"), (bytes));
        uint256[] memory cap = abi.decode(vm.parseJson(fixture, ".vectors[0].capacity"), (uint256[]));
        uint256[8] memory capacity;
        for (uint256 i; i < 8; ++i) capacity[i] = cap[i];
        uint256 variables = abi.decode(vm.parseJson(fixture, ".vectors[0].gkr_n_vars"), (uint256));
        uint256[5] memory costs = h.gkrLayers(transcript, capacity, variables);
        console2.log("gkr n_vars (layers 5..n-1)", variables);
        console2.log("gkr top layer: read 64 + quotient + 2x32 evals", costs[0]);
        console2.log("gkr per-layer duplex + alpha", costs[1]);
        console2.log("gkr cubic rounds total", costs[2]);
        console2.log("gkr reverse + child read + step + eq check", costs[3]);
        console2.log("gkr beta sample + fold + point rebuild", costs[4]);
    }

    function testAirVectors() public view {
        string memory json = vm.readFile("testdata/leanvm_air/vectors.json");
        LeanVmAirVector[] memory vectors = abi.decode(vm.parseJson(json, ".vectors"), (LeanVmAirVector[]));
        string[3] memory names = ["execution", "extension", "poseidon"];
        for (uint256 table; table < 3; ++table) {
            for (uint256 i; i < vectors.length; ++i) {
                if (keccak256(bytes(vectors[i].table)) != keccak256(bytes(names[table]))) continue;
                console2.log(names[table], h.air(table, _pack(vectors[i].flat), _pack(vectors[i].shift), _pack(vectors[i].alphas), _pack(vectors[i].beta_eq)));
                break;
            }
        }
    }

    function _pack(uint256[][] memory words) private pure returns (uint256[] memory out) {
        out = new uint256[](words.length);
        for (uint256 i; i < words.length; ++i) {
            uint256[5] memory c;
            for (uint256 k; k < 5; ++k) c[k] = words[i][k];
            out[i] = EF.pack(c);
        }
    }
}
