// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { KoalaBearExt5 as EF } from "../src/field/KoalaBearExt5.sol";
import { LeanVmLogUp as LogUp } from "../src/leanvm/LeanVmLogUp.sol";
import { LeanVmTranscript as Transcript } from "../src/leanvm/LeanVmTranscript.sol";
import { LeanVmPolynomial as Poly } from "../src/leanvm/LeanVmPolynomial.sol";

contract LeanVmLogUpHarness {
    using Transcript for Transcript.State;

    function sumQuotients(uint256[] memory numerators, uint256[] memory denominators)
        external
        pure
        returns (uint256)
    {
        return LogUp.sumQuotients(numerators, denominators);
    }

    function sumQuotientsSeparateInverses(
        uint256[] memory numerators,
        uint256[] memory denominators
    ) external pure returns (uint256 result) {
        for (uint256 i; i < 32; ++i) {
            result = EF.add(result, EF.mul(numerators[i], EF.inv(denominators[i])));
        }
    }

    function verify(
        bytes calldata transcript,
        uint256[8] memory capacity,
        uint256 bytecodeLog,
        uint256 memoryLog,
        uint256[3] memory heights,
        uint256 fixedBytecodeValue
    ) external pure returns (LogUp.Result memory result, uint256 followingSample) {
        Transcript.State memory state = Transcript.initialize(capacity);
        uint256 gamma = state.sample();
        state.duplex();
        uint256[] memory beta = state.sampleMany(4);
        uint256[] memory betaEq = new uint256[](16);
        for (uint256 i; i < 16; ++i) {
            betaEq[i] = Poly.eqIndex(beta, i, 4);
        }
        LogUp.Layout memory layout;
        layout.memoryLog = memoryLog;
        layout.heights = heights;
        for (uint256 i; i < 3; ++i) {
            layout.sorted[i] = i;
            if (heights[i] > layout.maximum) layout.maximum = heights[i];
        }
        for (uint256 i; i < 3; ++i) {
            for (uint256 j = i + 1; j < 3; ++j) {
                uint256 a = layout.sorted[i];
                uint256 b = layout.sorted[j];
                if (heights[b] > heights[a] || (heights[a] == heights[b] && b < a)) {
                    (layout.sorted[i], layout.sorted[j]) = (b, a);
                }
            }
        }
        result = LogUp.verify(
            state, transcript, bytecodeLog, layout, gamma, beta, betaEq, fixedBytecodeValue
        );
        state.finish(transcript);
        followingSample = state.sample();
    }

    function verifyGkr(bytes calldata transcript, uint256[8] memory capacity, uint256 variables)
        external
        pure
        returns (LogUp.Gkr memory result, uint256 followingSample)
    {
        Transcript.State memory state = Transcript.initialize(capacity);
        state.sample();
        state.duplex();
        state.sampleMany(4);
        result = LogUp.verifyGkr(state, transcript, variables);
        state.finish(transcript);
        followingSample = state.sample();
    }
}

contract LeanVmLogUpTest is Test {
    LeanVmLogUpHarness private harness;
    string private fixture;

    function setUp() public {
        harness = new LeanVmLogUpHarness();
        fixture = vm.readFile("testdata/leanvm_logup/vectors.json");
    }

    function testNativeLogUpProofsAndAllReturnedClaims() public view {
        for (uint256 i; i < 4; ++i) {
            string memory root = string.concat(".vectors[", vm.toString(i), "]");
            (LogUp.Result memory result, uint256 following) =
                _verify(root, _bytes(root, ".transcript"), _ef(root, ".fixed_bytecode_value"));
            assertEq(result.memoryValue, _ef(root, ".memory_value"));
            assertEq(result.memoryAcc, _ef(root, ".memory_acc"));
            assertEq(result.bytecodeAcc, _ef(root, ".value_bytecode_acc"));
            assertEq(result.point, _efs(root, ".gkr_point"));
            assertEq(result.bytecodePoint, _efs(root, ".fixed_bytecode_point"));
            assertEq(following, _ef(root, ".post_logup_sample"));
            uint256[] memory numerators = _efs(root, ".numerators");
            uint256[] memory denominators = _efs(root, ".denominators");
            uint256[][] memory indices = abi.decode(
                vm.parseJson(fixture, string.concat(root, ".column_indices")), (uint256[][])
            );
            uint256[][][] memory values =
                abi.decode(vm.parseJson(fixture, string.concat(root, ".columns")), (uint256[][][]));
            for (uint256 table; table < 3; ++table) {
                assertEq(result.numerators[table], numerators[table]);
                assertEq(result.denominators[table], denominators[table]);
                uint256 seen;
                for (uint256 k; k < indices[table].length; ++k) {
                    uint256 column = indices[table][k];
                    seen |= uint256(1) << column;
                    assertEq(result.columns[table][column], _packOne(values[table][k]));
                }
                assertEq(result.seen[table], seen);
            }
        }
    }

    function testNativeGkrProofsAndTranscriptContinuation() public view {
        for (uint256 i; i < 4; ++i) {
            string memory root = string.concat(".vectors[", vm.toString(i), "]");
            (LogUp.Gkr memory result, uint256 following) = harness.verifyGkr(
                _bytes(root, ".gkr_transcript"), _capacity(root), _uint(root, ".gkr_n_vars")
            );
            assertEq(result.balance, _ef(root, ".gkr_quotient"));
            assertEq(result.numerator, _ef(root, ".gkr_numerator"));
            assertEq(result.denominator, _ef(root, ".gkr_denominator"));
            assertEq(result.point, _efs(root, ".gkr_point"));
            assertEq(following, _ef(root, ".post_gkr_sample"));
        }
    }

    function testLogUpCallGas() public {
        string memory root = ".vectors[0]";
        bytes memory transcript = _bytes(root, ".transcript");
        uint256[8] memory capacity = _capacity(root);
        uint256 bytecodeLog = _uint(root, ".bytecode_log");
        uint256 memoryLog = _uint(root, ".memory_log");
        uint256 fixedValue = _ef(root, ".fixed_bytecode_value");
        uint256[] memory heights =
            abi.decode(vm.parseJson(fixture, string.concat(root, ".heights")), (uint256[]));
        uint256[3] memory fixedHeights = [heights[0], heights[1], heights[2]];
        uint256 before = gasleft();
        harness.verify(transcript, capacity, bytecodeLog, memoryLog, fixedHeights, fixedValue);
        emit log_named_uint("LogUp call gas", before - gasleft());
    }

    function testGkrCallGas() public {
        string memory root = ".vectors[0]";
        bytes memory transcript = _bytes(root, ".gkr_transcript");
        uint256[8] memory capacity = _capacity(root);
        uint256 variables = _uint(root, ".gkr_n_vars");
        uint256 before = gasleft();
        harness.verifyGkr(transcript, capacity, variables);
        emit log_named_uint("GKR call gas", before - gasleft());
    }

    function testQuotientAccumulationParityAndGas() public {
        bytes memory transcript = _bytes(".vectors[0]", ".gkr_transcript");
        uint256[] memory numerators = new uint256[](32);
        uint256[] memory denominators = new uint256[](32);
        for (uint256 element; element < 64; ++element) {
            uint256[5] memory words;
            for (uint256 coordinate; coordinate < 5; ++coordinate) {
                uint256 offset = (element * 5 + coordinate) * 4;
                for (uint256 byteIndex; byteIndex < 4; ++byteIndex) {
                    words[coordinate] |= uint256(uint8(transcript[offset + byteIndex]))
                    << (byteIndex * 8);
                }
            }
            if (element < 32) numerators[element] = EF.pack(words);
            else denominators[element - 32] = EF.pack(words);
        }
        uint256 before = gasleft();
        uint256 original = harness.sumQuotientsSeparateInverses(numerators, denominators);
        emit log_named_uint("32 separate inverses gas", before - gasleft());
        before = gasleft();
        uint256 combined = harness.sumQuotients(numerators, denominators);
        emit log_named_uint("Common denominator gas", before - gasleft());
        assertEq(combined, original);
        assertEq(combined, 0);

        for (uint256 sample; sample < 2; ++sample) {
            for (uint256 element; element < 32; ++element) {
                uint256[5] memory num;
                uint256[5] memory den;
                for (uint256 coordinate; coordinate < 5; ++coordinate) {
                    num[coordinate] = uint256(
                        keccak256(abi.encode(sample, element, coordinate, uint256(1)))
                    ) % 2_130_706_433;
                    den[coordinate] = sample == 0
                        ? (coordinate == element % 5 ? element + 1 : 0)
                        : uint256(keccak256(abi.encode(sample, element, coordinate, uint256(2))))
                            % 2_130_706_433;
                }
                numerators[element] = EF.pack(num);
                denominators[element] = EF.pack(den);
            }
            assertEq(
                harness.sumQuotients(numerators, denominators),
                harness.sumQuotientsSeparateInverses(numerators, denominators)
            );
        }
        denominators[31] = 0;
        vm.expectRevert();
        harness.sumQuotients(numerators, denominators);
    }

    function testNeutralFractionsAndZeroDenominator() public {
        uint256[] memory numerators = new uint256[](32);
        uint256[] memory denominators = new uint256[](32);
        for (uint256 i; i < 32; ++i) {
            denominators[i] = EF.fromBase(1);
        }
        assertEq(harness.sumQuotients(numerators, denominators), 0);
        numerators[2] = EF.fromBase(17);
        numerators[17] = EF.fromBase(23);
        denominators[17] = EF.fromBase(3);
        assertEq(
            harness.sumQuotients(numerators, denominators),
            harness.sumQuotientsSeparateInverses(numerators, denominators)
        );
        // A zero numerator does not make a zero denominator a neutral fraction.
        denominators[31] = 0;
        vm.expectRevert();
        harness.sumQuotients(numerators, denominators);
    }

    function testGkrRejectsChangedSumcheckAndDeferredClaims() public {
        string memory root = ".vectors[0]";
        bytes memory original = _bytes(root, ".gkr_transcript");
        uint256 variables = _uint(root, ".gkr_n_vars");
        uint256[8] memory capacity = _capacity(root);
        bytes memory changed = _changeWord(original, 320);
        vm.expectRevert();
        harness.verifyGkr(changed, capacity, variables);
        changed = _changeWord(original, original.length / 4 - 24);
        vm.expectRevert();
        harness.verifyGkr(changed, capacity, variables);
        capacity[0] += 1;
        vm.expectRevert();
        harness.verifyGkr(original, capacity, variables);
    }

    function testGkrRejectsZeroDenominatorsAndInvalidEncoding() public {
        string memory root = ".vectors[0]";
        bytes memory original = _bytes(root, ".gkr_transcript");
        uint256 variables = _uint(root, ".gkr_n_vars");
        uint256[8] memory capacity = _capacity(root);
        bytes memory changed = bytes.concat(original);
        for (uint256 i; i < 5; ++i) {
            _setWord(changed, 160 + i, 0);
        }
        vm.expectRevert();
        harness.verifyGkr(changed, capacity, variables);
        changed = bytes.concat(original);
        _setWord(changed, 0, 2_130_706_433);
        vm.expectRevert();
        harness.verifyGkr(changed, capacity, variables);
        changed = bytes.concat(original);
        _setWord(changed, 340, 1);
        vm.expectRevert();
        harness.verifyGkr(changed, capacity, variables);
        changed = bytes.concat(original, hex"00000000");
        vm.expectRevert();
        harness.verifyGkr(changed, capacity, variables);
    }

    function testLogUpRejectsMemoryAccumulatorAndFixedProgramChanges() public {
        string memory root = ".vectors[0]";
        bytes memory original = _bytes(root, ".transcript");
        uint256 gkrWords = _bytes(root, ".gkr_transcript").length / 4;
        uint256 fixedValue = _ef(root, ".fixed_bytecode_value");
        for (uint256 word; word < 5; ++word) {
            bytes memory changed = _changeWord(original, gkrWords + word * 8);
            vm.expectRevert();
            _verify(root, changed, fixedValue);
        }
        vm.expectRevert();
        _verify(root, original, EF.add(fixedValue, EF.ONE));
    }

    function _verify(string memory root, bytes memory transcript, uint256 fixedValue)
        private
        view
        returns (LogUp.Result memory, uint256)
    {
        uint256[] memory heights =
            abi.decode(vm.parseJson(fixture, string.concat(root, ".heights")), (uint256[]));
        uint256[3] memory fixedHeights = [heights[0], heights[1], heights[2]];
        return harness.verify(
            transcript,
            _capacity(root),
            _uint(root, ".bytecode_log"),
            _uint(root, ".memory_log"),
            fixedHeights,
            fixedValue
        );
    }

    function _capacity(string memory root) private view returns (uint256[8] memory out) {
        uint256[] memory values =
            abi.decode(vm.parseJson(fixture, string.concat(root, ".capacity")), (uint256[]));
        for (uint256 i; i < 8; ++i) {
            out[i] = values[i];
        }
    }

    function _bytes(string memory root, string memory key) private view returns (bytes memory) {
        return vm.parseJsonBytes(fixture, string.concat(root, key));
    }

    function _uint(string memory root, string memory key) private view returns (uint256) {
        return vm.parseJsonUint(fixture, string.concat(root, key));
    }

    function _ef(string memory root, string memory key) private view returns (uint256) {
        return _packOne(abi.decode(vm.parseJson(fixture, string.concat(root, key)), (uint256[])));
    }

    function _efs(string memory root, string memory key)
        private
        view
        returns (uint256[] memory out)
    {
        uint256[][] memory values = abi.decode(
            vm.parseJson(fixture, string.concat(root, key)), (uint256[][])
        );
        out = new uint256[](values.length);
        for (uint256 i; i < values.length; ++i) {
            out[i] = _packOne(values[i]);
        }
    }

    function _packOne(uint256[] memory value) private pure returns (uint256) {
        require(value.length == 5, "WIDTH");
        uint256[5] memory words = [value[0], value[1], value[2], value[3], value[4]];
        return EF.pack(words);
    }

    function _setWord(bytes memory input, uint256 index, uint256 value) private pure {
        for (uint256 i; i < 4; ++i) {
            input[index * 4 + i] = bytes1(uint8(value >> (i * 8)));
        }
    }

    function _changeWord(bytes memory input, uint256 index)
        private
        pure
        returns (bytes memory out)
    {
        out = bytes.concat(input);
        uint256 value;
        for (uint256 i; i < 4; ++i) {
            value |= uint256(uint8(out[index * 4 + i])) << (i * 8);
        }
        _setWord(out, index, (value + 1) % 2_130_706_433);
    }
}
