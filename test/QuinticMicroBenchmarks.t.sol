// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test, console } from "forge-std/Test.sol";

import { KoalaBear } from "../src/field/KoalaBear.sol";
import { KoalaBearExt4 } from "../src/field/KoalaBearExt4.sol";
import { KoalaBearExt5 } from "../src/field/KoalaBearExt5.sol";
import { KoalaBearExt8 } from "../src/field/KoalaBearExt8.sol";
import { MerkleVerifier } from "../src/merkle/MerkleVerifier.sol";
import { KeccakChallenger } from "../src/transcript/KeccakChallenger.sol";
import { WhirVerifierUtils4 } from "../src/whir/WhirVerifierUtils4.sol";
import { WhirVerifierUtils8 } from "../src/whir/k22_jb100_lir6_ff4_rsv1/WhirVerifierUtils8.sol";

contract QuinticMicroBenchmarksTest is Test {
    using KeccakChallenger for KeccakChallenger.State;

    uint256 internal constant REPS = 40;

    function testEmitQuinticMicroBenchmarks() external {
        _emitSettings();
        _emitExt5Arithmetic();
        _emitExt8ComparisonArithmetic();
        _emitPackingValidation();
        _emitHypercubeRows();
        _emitTranscript();
        _emitMerkle();
        _emitSamplingAndPow();
        _emitCalibrationReferenceKernels();
        _emitEqPolyDepthMetrics();
    }

    function benchObserveExt5Slice(uint256[] calldata values) external view returns (uint256) {
        uint256 gasStart = gasleft();
        uint256 sink;
        unchecked {
            for (uint256 i = 0; i < 10; ++i) {
                KeccakChallenger.State memory ch;
                ch.observeBytes(abi.encodePacked(bytes32(uint256(0x55 + i))));
                ch.observeValidatedPackedExt5Slice(values);
                sink |= ch.inputLen;
            }
        }
        require(sink != 0, "SINK");
        return (gasStart - gasleft()) / 10;
    }

    function benchObserveExt4Slice(uint256[] calldata values) external view returns (uint256) {
        uint256 gasStart = gasleft();
        uint256 sink;
        unchecked {
            for (uint256 i = 0; i < 10; ++i) {
                KeccakChallenger.State memory ch;
                ch.observeBytes(abi.encodePacked(bytes32(uint256(0x45 + i))));
                ch.observeValidatedPackedExt4Slice(values);
                sink |= ch.inputLen;
            }
        }
        require(sink != 0, "SINK");
        return (gasStart - gasleft()) / 10;
    }

    function benchObserveExt8Slice(uint256[] calldata values) external view returns (uint256) {
        uint256 gasStart = gasleft();
        uint256 sink;
        unchecked {
            for (uint256 i = 0; i < 10; ++i) {
                KeccakChallenger.State memory ch;
                ch.observeBytes(abi.encodePacked(bytes32(uint256(0x85 + i))));
                ch.observeValidatedPackedExt8Slice(values);
                sink |= ch.inputLen;
            }
        }
        require(sink != 0, "SINK");
        return (gasStart - gasleft()) / 10;
    }

    function benchObserveBaseBatch(uint256 count) external view returns (uint256) {
        uint256 gasStart = gasleft();
        uint256 sink;
        unchecked {
            for (uint256 i = 0; i < 10; ++i) {
                KeccakChallenger.State memory ch;
                ch.observeBytes(abi.encodePacked(bytes32(uint256(0x65 + i))));
                for (uint256 j = 0; j < count; ++j) {
                    ch.observeBase(_base(2000 + i * 100 + j));
                }
                sink |= ch.inputLen;
            }
        }
        require(sink != 0, "SINK");
        return (gasStart - gasleft()) / 10;
    }

    function benchObserveHashU64Batch(uint256 count) external view returns (uint256) {
        uint256 gasStart = gasleft();
        uint256 sink;
        unchecked {
            for (uint256 i = 0; i < 10; ++i) {
                KeccakChallenger.State memory ch;
                ch.observeBytes(abi.encodePacked(bytes32(uint256(0x75 + i))));
                for (uint256 j = 0; j < count; ++j) {
                    ch.observeHashU64Digest(bytes32(uint256(3000 + i * 100 + j)));
                }
                sink |= ch.inputLen;
            }
        }
        require(sink != 0, "SINK");
        return (gasStart - gasleft()) / 10;
    }

    function benchHashLeafBase(uint256[] calldata values, uint256 rowLen)
        external
        view
        returns (uint256)
    {
        uint256 gasStart = gasleft();
        bytes32 sink;
        unchecked {
            for (uint256 i = 0; i < 10; ++i) {
                sink |= MerkleVerifier.hashLeafBaseSlice(values, 0, rowLen, 20);
            }
        }
        require(sink != bytes32(0), "SINK");
        return (gasStart - gasleft()) / 10;
    }

    function benchHashLeafExt5(uint256[] calldata values, uint256 rowLen)
        external
        view
        returns (uint256)
    {
        uint256 gasStart = gasleft();
        bytes32 sink;
        unchecked {
            for (uint256 i = 0; i < 10; ++i) {
                sink |= MerkleVerifier.hashLeafExtension5Slice20(values, 0, rowLen);
            }
        }
        require(sink != bytes32(0), "SINK");
        return (gasStart - gasleft()) / 10;
    }

    function benchHashLeafExt4(uint256[] calldata values, uint256 rowLen)
        external
        view
        returns (uint256)
    {
        uint256 gasStart = gasleft();
        bytes32 sink;
        unchecked {
            for (uint256 i = 0; i < 10; ++i) {
                sink |= MerkleVerifier.hashLeafExtensionSlice20(values, 0, rowLen);
            }
        }
        require(sink != bytes32(0), "SINK");
        return (gasStart - gasleft()) / 10;
    }

    function benchHashLeafExt8(uint256[] calldata values, uint256 rowLen)
        external
        view
        returns (uint256)
    {
        uint256 gasStart = gasleft();
        bytes32 sink;
        unchecked {
            for (uint256 i = 0; i < 10; ++i) {
                sink |= MerkleVerifier.hashLeafExtension8Slice20(values, 0, rowLen);
            }
        }
        require(sink != bytes32(0), "SINK");
        return (gasStart - gasleft()) / 10;
    }

    function _emitSettings() internal {
        console.log(
            "BENCH:{\"schema_version\":1,\"metric\":\"compiler_settings\",\"solc_version\":\"0.8.28\",\"via_ir\":true,\"optimizer_runs\":833}"
        );
    }

    function _emitExt5Arithmetic() internal {
        uint256[8] memory inputs = _makeExt5Inputs(1);
        _emitGas("ext5_add", "folding", "operation", REPS, _gasExt5Add(inputs));
        _emitGas("ext5_sub", "folding", "operation", REPS, _gasExt5Sub(inputs));
        _emitGas("ext5_mul", "folding", "operation", REPS, _gasExt5Mul(inputs));
        _emitGas("ext5_square", "folding", "operation", REPS, _gasExt5Square(inputs));
        _emitGas("ext5_mul_base", "folding", "operation", REPS, _gasExt5MulBase(inputs));
        _emitGas("ext5_inv", "folding", "operation", 5, _gasExt5Inv(inputs));
        _emitGas("ext5_extrapolate_012", "sumcheck", "operation", REPS, _gasExt5Extrapolate(inputs));
    }

    function _emitExt8ComparisonArithmetic() internal {
        uint256[8] memory inputs = _makeExt8Inputs(21);
        _emitGas("ext8_mul", "folding", "operation", REPS, _gasExt8Mul(inputs));
        _emitGas("ext8_square", "folding", "operation", REPS, _gasExt8Square(inputs));
        _emitGas("ext8_inv", "folding", "operation", 5, _gasExt8Inv(inputs));
    }

    function _emitPackingValidation() internal {
        uint256[8] memory inputs = _makeExt5Inputs(101);
        uint256 gasStart = gasleft();
        uint256 sink;
        unchecked {
            for (uint256 i = 0; i < REPS; ++i) {
                KoalaBearExt5.validatePacked(inputs[i & 7]);
                sink |= inputs[i & 7];
            }
        }
        require(sink != 0, "SINK");
        _emitGas(
            "ext5_validate_packed", "calldata", "operation", REPS, (gasStart - gasleft()) / REPS
        );
    }

    function _emitHypercubeRows() internal {
        for (uint256 dim = 1; dim <= 9; ++dim) {
            _emitGas(
                _withUint("ext5_hypercube_dim", dim),
                "folding",
                _withUint("row_len_", uint256(1) << dim),
                1,
                _gasExt5Hypercube(dim)
            );
            _emitGas(
                _withUint("base_to_ext5_hypercube_dim", dim),
                "folding",
                _withUint("row_len_", uint256(1) << dim),
                1,
                _gasBaseHypercubeAsExt5(dim)
            );
        }
    }

    function _emitTranscript() internal {
        for (uint256 count = 1; count <= 16; count <<= 1) {
            uint256[] memory values = _makeExt5Array(700 + count, count);
            _emitGas(
                _withUint("observe_ext5_batch_", count),
                "transcript",
                "batch",
                count,
                this.benchObserveExt5Slice(values)
            );
            _emitGas(
                _withUint("observe_base_batch_", count),
                "transcript",
                "batch",
                count,
                this.benchObserveBaseBatch(count)
            );
            _emitGas(
                _withUint("observe_hash_u64_batch_", count),
                "transcript",
                "batch",
                count,
                this.benchObserveHashU64Batch(count)
            );
        }

        uint256 gasStart = gasleft();
        uint256 sink;
        unchecked {
            for (uint256 i = 0; i < REPS; ++i) {
                KeccakChallenger.State memory ch;
                ch.observeBytes(abi.encodePacked(bytes32(uint256(100 + i))));
                sink += ch.sampleBase();
            }
        }
        require(sink != 0, "SINK");
        _emitGas("sample_base", "transcript", "operation", REPS, (gasStart - gasleft()) / REPS);

        gasStart = gasleft();
        uint256 extSink;
        unchecked {
            for (uint256 i = 0; i < REPS; ++i) {
                extSink |= _sampleExt5(123 + i);
            }
        }
        require(extSink != 0, "SINK");
        _emitGas("sample_ext5", "transcript", "operation", REPS, (gasStart - gasleft()) / REPS);

        for (uint256 bits = 8; bits <= 24; bits += 8) {
            _emitGas(
                _withUint("sample_bits_", bits),
                "transcript",
                "operation",
                REPS,
                _gasSampleBits(bits)
            );
        }
    }

    function _emitMerkle() internal {
        _emitGas(
            "hash_leaf_base_row_len_1",
            "merkle",
            "row_len_1",
            1,
            this.benchHashLeafBase(_makeBaseArray(899, 1), 1)
        );
        _emitGas(
            "hash_leaf_ext5_row_len_1",
            "merkle",
            "row_len_1",
            1,
            this.benchHashLeafExt5(_makeExt5Array(999, 1), 1)
        );
        for (uint256 dim = 1; dim <= 9; ++dim) {
            uint256 rowLen = uint256(1) << dim;
            _emitGas(
                _withUint("hash_leaf_base_row_len_", rowLen),
                "merkle",
                _withUint("row_len_", rowLen),
                rowLen,
                this.benchHashLeafBase(_makeBaseArray(900 + dim, rowLen), rowLen)
            );
            _emitGas(
                _withUint("hash_leaf_ext5_row_len_", rowLen),
                "merkle",
                _withUint("row_len_", rowLen),
                rowLen,
                this.benchHashLeafExt5(_makeExt5Array(1000 + dim, rowLen), rowLen)
            );
        }

        uint256 gasStart = gasleft();
        bytes32 sink;
        unchecked {
            for (uint256 i = 0; i < REPS; ++i) {
                sink |= MerkleVerifier.compressNode(
                    bytes32(uint256(i + 1)), bytes32(uint256(i + 100)), 20
                );
            }
        }
        require(sink != bytes32(0), "SINK");
        _emitGas("merkle_compress_node", "merkle", "operation", REPS, (gasStart - gasleft()) / REPS);
    }

    function _emitSamplingAndPow() internal {
        for (uint256 bits = 8; bits <= 24; bits += 8) {
            _emitGas(
                _withUint("sample_stir_queries_bits_", bits),
                "transcript",
                "operation",
                10,
                _gasSampleStirQueries(bits, 16)
            );
        }

        for (uint256 bits = 8; bits <= 24; bits += 8) {
            _emitGas(
                _withUint("verify_pow_bits_", bits),
                "transcript",
                "operation",
                REPS,
                _gasVerifyPow(bits)
            );
        }
    }

    function _emitCalibrationReferenceKernels() internal {
        _emitGas(
            "hash_leaf_ext4_row_len_1",
            "merkle",
            "row_len_1",
            1,
            this.benchHashLeafExt4(_makeExt4Array(1899, 1), 1)
        );
        _emitGas(
            "hash_leaf_ext8_row_len_1",
            "merkle",
            "row_len_1",
            1,
            this.benchHashLeafExt8(_makeExt8Array(1999, 1), 1)
        );
        for (uint256 dim = 1; dim <= 9; ++dim) {
            uint256 rowLen = uint256(1) << dim;
            _emitGas(
                _withUint("ext4_hypercube_dim", dim),
                "folding",
                _withUint("row_len_", rowLen),
                1,
                _gasExt4Hypercube(dim)
            );
            _emitGas(
                _withUint("base_to_ext4_hypercube_dim", dim),
                "folding",
                _withUint("row_len_", rowLen),
                1,
                _gasBaseHypercubeAsExt4(dim)
            );
            _emitGas(
                _withUint("ext8_hypercube_dim", dim),
                "folding",
                _withUint("row_len_", rowLen),
                1,
                _gasExt8Hypercube(dim)
            );
            _emitGas(
                _withUint("base_to_ext8_hypercube_dim", dim),
                "folding",
                _withUint("row_len_", rowLen),
                1,
                _gasBaseHypercubeAsExt8(dim)
            );
            _emitGas(
                _withUint("hash_leaf_ext4_row_len_", rowLen),
                "merkle",
                _withUint("row_len_", rowLen),
                rowLen,
                this.benchHashLeafExt4(_makeExt4Array(1900 + dim, rowLen), rowLen)
            );
            _emitGas(
                _withUint("hash_leaf_ext8_row_len_", rowLen),
                "merkle",
                _withUint("row_len_", rowLen),
                rowLen,
                this.benchHashLeafExt8(_makeExt8Array(2000 + dim, rowLen), rowLen)
            );
        }

        uint256[8] memory ext4Inputs = _makeExt4Inputs(1700);
        uint256[8] memory ext8Inputs = _makeExt8Inputs(1800);
        _emitGas(
            "ext4_extrapolate_012", "sumcheck", "operation", REPS, _gasExt4Extrapolate(ext4Inputs)
        );
        _emitGas(
            "ext8_extrapolate_012", "sumcheck", "operation", REPS, _gasExt8Extrapolate(ext8Inputs)
        );

        _emitReferenceObserveBatch("observe_ext4_batch_", 4);
        _emitReferenceObserveBatch("observe_ext8_batch_", 8);
        _emitReferenceValidation();
    }

    function _emitEqPolyDepthMetrics() internal {
        uint256[8] memory ext5Inputs = _makeExt5Inputs(1600);
        uint256[8] memory ext4Inputs = _makeExt4Inputs(1700);
        uint256[8] memory ext8Inputs = _makeExt8Inputs(1800);
        _emitGas("ext5_eq_poly_step", "folding", "operation", REPS, _gasExt5EqPolyStep(ext5Inputs));
        _emitGas("ext4_eq_poly_step", "folding", "operation", REPS, _gasExt4EqPolyStep(ext4Inputs));
        _emitGas("ext8_eq_poly_step", "folding", "operation", REPS, _gasExt8EqPolyStep(ext8Inputs));
        for (uint256 depth = 1; depth <= 22; ++depth) {
            _emitGas(
                _withUint("ext5_eq_poly_", depth),
                "sumcheck",
                "operation",
                3,
                _gasExt5EqPolyDepth(ext5Inputs, depth, 3)
            );
            _emitGas(
                _withUint("ext4_eq_poly_", depth),
                "sumcheck",
                "operation",
                3,
                _gasExt4EqPolyDepth(ext4Inputs, depth, 3)
            );
            _emitGas(
                _withUint("ext8_eq_poly_", depth),
                "sumcheck",
                "operation",
                3,
                _gasExt8EqPolyDepth(ext8Inputs, depth, 3)
            );
        }
    }

    function _emitReferenceObserveBatch(string memory prefix, uint256 degree) internal {
        uint256[] memory values1 = degree == 4 ? _makeExt4Array(2100, 1) : _makeExt8Array(2200, 1);
        uint256[] memory values16 =
            degree == 4 ? _makeExt4Array(2300, 16) : _makeExt8Array(2400, 16);
        _emitGas(
            _withUint(prefix, 1),
            "transcript",
            "batch",
            1,
            degree == 4 ? this.benchObserveExt4Slice(values1) : this.benchObserveExt8Slice(values1)
        );
        _emitGas(
            _withUint(prefix, 16),
            "transcript",
            "batch",
            16,
            degree == 4
                ? this.benchObserveExt4Slice(values16)
                : this.benchObserveExt8Slice(values16)
        );
    }

    function _emitReferenceValidation() internal {
        uint256[8] memory ext4Inputs = _makeExt4Inputs(2500);
        uint256[8] memory ext8Inputs = _makeExt8Inputs(2600);

        uint256 gasStart = gasleft();
        uint256 sink;
        unchecked {
            for (uint256 i = 0; i < REPS; ++i) {
                WhirVerifierUtils4.validatePackedExt4(ext4Inputs[i & 7]);
                sink |= ext4Inputs[i & 7];
            }
        }
        require(sink != 0, "SINK");
        _emitGas(
            "ext4_validate_packed", "calldata", "operation", REPS, (gasStart - gasleft()) / REPS
        );

        gasStart = gasleft();
        sink = 0;
        unchecked {
            for (uint256 i = 0; i < REPS; ++i) {
                WhirVerifierUtils8.validatePackedExt8(ext8Inputs[i & 7]);
                sink |= ext8Inputs[i & 7];
            }
        }
        require(sink != 0, "SINK");
        _emitGas(
            "ext8_validate_packed", "calldata", "operation", REPS, (gasStart - gasleft()) / REPS
        );
    }

    function _gasExt5Add(uint256[8] memory inputs) internal view returns (uint256) {
        uint256 gasStart = gasleft();
        uint256 sink;
        unchecked {
            for (uint256 i = 0; i < REPS; ++i) {
                sink |= KoalaBearExt5.add(inputs[i & 7], inputs[(i + 3) & 7]);
            }
        }
        require(sink != 0, "SINK");
        return (gasStart - gasleft()) / REPS;
    }

    function _gasExt5Sub(uint256[8] memory inputs) internal view returns (uint256) {
        uint256 gasStart = gasleft();
        uint256 sink;
        unchecked {
            for (uint256 i = 0; i < REPS; ++i) {
                sink |= KoalaBearExt5.sub(inputs[i & 7], inputs[(i + 3) & 7]);
            }
        }
        require(sink != 0, "SINK");
        return (gasStart - gasleft()) / REPS;
    }

    function _gasExt5Mul(uint256[8] memory inputs) internal view returns (uint256) {
        uint256 gasStart = gasleft();
        uint256 sink;
        unchecked {
            for (uint256 i = 0; i < REPS; ++i) {
                sink |= KoalaBearExt5.mul(inputs[i & 7], inputs[(i + 3) & 7]);
            }
        }
        require(sink != 0, "SINK");
        return (gasStart - gasleft()) / REPS;
    }

    function _gasExt5Square(uint256[8] memory inputs) internal view returns (uint256) {
        uint256 gasStart = gasleft();
        uint256 sink;
        unchecked {
            for (uint256 i = 0; i < REPS; ++i) {
                sink |= KoalaBearExt5.square(inputs[i & 7]);
            }
        }
        require(sink != 0, "SINK");
        return (gasStart - gasleft()) / REPS;
    }

    function _gasExt5MulBase(uint256[8] memory inputs) internal view returns (uint256) {
        uint256 gasStart = gasleft();
        uint256 sink;
        unchecked {
            for (uint256 i = 0; i < REPS; ++i) {
                sink |= KoalaBearExt5.mulBase(inputs[i & 7], _base(4000 + i));
            }
        }
        require(sink != 0, "SINK");
        return (gasStart - gasleft()) / REPS;
    }

    function _gasExt5Inv(uint256[8] memory inputs) internal view returns (uint256) {
        uint256 gasStart = gasleft();
        uint256 sink;
        unchecked {
            for (uint256 i = 0; i < 5; ++i) {
                sink |= KoalaBearExt5.inv(inputs[i]);
            }
        }
        require(sink != 0, "SINK");
        return (gasStart - gasleft()) / 5;
    }

    function _gasExt5Extrapolate(uint256[8] memory inputs) internal view returns (uint256) {
        uint256 gasStart = gasleft();
        uint256 sink;
        unchecked {
            for (uint256 i = 0; i < REPS; ++i) {
                sink |= KoalaBearExt5.extrapolate_012(
                    inputs[i & 7], inputs[(i + 1) & 7], inputs[(i + 2) & 7], inputs[(i + 3) & 7]
                );
            }
        }
        require(sink != 0, "SINK");
        return (gasStart - gasleft()) / REPS;
    }

    function _gasExt4Extrapolate(uint256[8] memory inputs) internal view returns (uint256) {
        uint256 gasStart = gasleft();
        uint256 sink;
        unchecked {
            for (uint256 i = 0; i < REPS; ++i) {
                sink |= KoalaBearExt4.extrapolate_012(
                    inputs[i & 7], inputs[(i + 1) & 7], inputs[(i + 2) & 7], inputs[(i + 3) & 7]
                );
            }
        }
        require(sink != 0, "SINK");
        return (gasStart - gasleft()) / REPS;
    }

    function _gasExt8Extrapolate(uint256[8] memory inputs) internal view returns (uint256) {
        uint256 gasStart = gasleft();
        uint256 sink;
        unchecked {
            for (uint256 i = 0; i < REPS; ++i) {
                sink |= KoalaBearExt8.extrapolate_012(
                    inputs[i & 7], inputs[(i + 1) & 7], inputs[(i + 2) & 7], inputs[(i + 3) & 7]
                );
            }
        }
        require(sink != 0, "SINK");
        return (gasStart - gasleft()) / REPS;
    }

    function _gasExt5EqPolyDepth(uint256[8] memory inputs, uint256 depth, uint256 reps)
        internal
        view
        returns (uint256)
    {
        uint256 gasStart = gasleft();
        uint256 sink;
        unchecked {
            for (uint256 i = 0; i < reps; ++i) {
                uint256[] memory lhs = new uint256[](depth);
                uint256[] memory rhs = new uint256[](depth);
                for (uint256 j = 0; j < depth; ++j) {
                    lhs[j] = inputs[(i + j) & 7];
                    rhs[j] = inputs[(i + j + 2) & 7];
                }
                sink |= KoalaBearExt5.eq_poly_eval(lhs, rhs);
            }
        }
        require(sink != 0, "SINK");
        return (gasStart - gasleft()) / reps;
    }

    function _gasExt4EqPolyDepth(uint256[8] memory inputs, uint256 depth, uint256 reps)
        internal
        view
        returns (uint256)
    {
        uint256 gasStart = gasleft();
        uint256 sink;
        unchecked {
            for (uint256 i = 0; i < reps; ++i) {
                uint256[] memory lhs = new uint256[](depth);
                uint256[] memory rhs = new uint256[](depth);
                for (uint256 j = 0; j < depth; ++j) {
                    lhs[j] = inputs[(i + j) & 7];
                    rhs[j] = inputs[(i + j + 2) & 7];
                }
                sink |= KoalaBearExt4.eq_poly_eval(lhs, rhs);
            }
        }
        require(sink != 0, "SINK");
        return (gasStart - gasleft()) / reps;
    }

    function _gasExt8EqPolyDepth(uint256[8] memory inputs, uint256 depth, uint256 reps)
        internal
        view
        returns (uint256)
    {
        uint256 gasStart = gasleft();
        uint256 sink;
        unchecked {
            for (uint256 i = 0; i < reps; ++i) {
                uint256[] memory lhs = new uint256[](depth);
                uint256[] memory rhs = new uint256[](depth);
                for (uint256 j = 0; j < depth; ++j) {
                    lhs[j] = inputs[(i + j) & 7];
                    rhs[j] = inputs[(i + j + 2) & 7];
                }
                sink |= KoalaBearExt8.eq_poly_eval(lhs, rhs);
            }
        }
        require(sink != 0, "SINK");
        return (gasStart - gasleft()) / reps;
    }

    function _gasExt5EqPolyStep(uint256[8] memory inputs) internal view returns (uint256) {
        uint256 gasStart = gasleft();
        uint256 acc = KoalaBearExt5.ONE;
        unchecked {
            for (uint256 i = 0; i < REPS; ++i) {
                uint256 p = inputs[i & 7];
                uint256 q = inputs[(i + 2) & 7];
                uint256 term = KoalaBearExt5.add(
                    KoalaBearExt5.ONE,
                    KoalaBearExt5.sub(
                        KoalaBearExt5.sub(KoalaBearExt5.mulBase(KoalaBearExt5.mul(p, q), 2), p), q
                    )
                );
                acc = KoalaBearExt5.mul(acc, term);
            }
        }
        require(acc != 0, "SINK");
        return (gasStart - gasleft()) / REPS;
    }

    function _gasExt4EqPolyStep(uint256[8] memory inputs) internal view returns (uint256) {
        uint256 gasStart = gasleft();
        uint256 acc = KoalaBearExt4.ONE;
        unchecked {
            for (uint256 i = 0; i < REPS; ++i) {
                uint256 p = inputs[i & 7];
                uint256 q = inputs[(i + 2) & 7];
                uint256 term = KoalaBearExt4.add(
                    KoalaBearExt4.ONE,
                    KoalaBearExt4.sub(
                        KoalaBearExt4.sub(KoalaBearExt4.mulBase(KoalaBearExt4.mul(p, q), 2), p), q
                    )
                );
                acc = KoalaBearExt4.mul(acc, term);
            }
        }
        require(acc != 0, "SINK");
        return (gasStart - gasleft()) / REPS;
    }

    function _gasExt8EqPolyStep(uint256[8] memory inputs) internal view returns (uint256) {
        uint256 gasStart = gasleft();
        uint256 acc = KoalaBearExt8.ONE;
        unchecked {
            for (uint256 i = 0; i < REPS; ++i) {
                uint256 p = inputs[i & 7];
                uint256 q = inputs[(i + 2) & 7];
                uint256 term = KoalaBearExt8.add(
                    KoalaBearExt8.ONE,
                    KoalaBearExt8.sub(
                        KoalaBearExt8.sub(KoalaBearExt8.mulBase(KoalaBearExt8.mul(p, q), 2), p), q
                    )
                );
                acc = KoalaBearExt8.mul(acc, term);
            }
        }
        require(acc != 0, "SINK");
        return (gasStart - gasleft()) / REPS;
    }

    function _gasExt8Mul(uint256[8] memory inputs) internal view returns (uint256) {
        uint256 gasStart = gasleft();
        uint256 sink;
        unchecked {
            for (uint256 i = 0; i < REPS; ++i) {
                sink |= KoalaBearExt8.mul(inputs[i & 7], inputs[(i + 3) & 7]);
            }
        }
        require(sink != 0, "SINK");
        return (gasStart - gasleft()) / REPS;
    }

    function _gasExt8Square(uint256[8] memory inputs) internal view returns (uint256) {
        uint256 gasStart = gasleft();
        uint256 sink;
        unchecked {
            for (uint256 i = 0; i < REPS; ++i) {
                sink |= KoalaBearExt8.square(inputs[i & 7]);
            }
        }
        require(sink != 0, "SINK");
        return (gasStart - gasleft()) / REPS;
    }

    function _gasExt8Inv(uint256[8] memory inputs) internal view returns (uint256) {
        uint256 gasStart = gasleft();
        uint256 sink;
        unchecked {
            for (uint256 i = 0; i < 5; ++i) {
                sink |= KoalaBearExt8.inv(inputs[i]);
            }
        }
        require(sink != 0, "SINK");
        return (gasStart - gasleft()) / 5;
    }

    function _gasExt5Hypercube(uint256 dim) internal view returns (uint256) {
        uint256 len = uint256(1) << dim;
        uint256[] memory evals = _makeExt5Array(200 + dim, len);
        uint256[] memory point = _makeExt5Array(300 + dim, dim);
        uint256 gasStart = gasleft();
        uint256 sink = KoalaBearExt5.evaluate_hypercube(evals, point);
        require(sink != 0, "SINK");
        return gasStart - gasleft();
    }

    function _gasExt4Hypercube(uint256 dim) internal view returns (uint256) {
        uint256 len = uint256(1) << dim;
        uint256[] memory evals = _makeExt4Array(2700 + dim, len);
        uint256[] memory point = _makeExt4Array(2800 + dim, dim);
        uint256 gasStart = gasleft();
        uint256 sink = KoalaBearExt4.evaluate_hypercube(evals, point);
        require(sink != 0, "SINK");
        return gasStart - gasleft();
    }

    function _gasExt8Hypercube(uint256 dim) internal view returns (uint256) {
        uint256 len = uint256(1) << dim;
        uint256[] memory evals = _makeExt8Array(2900 + dim, len);
        uint256[] memory point = _makeExt8Array(3000 + dim, dim);
        uint256 gasStart = gasleft();
        uint256 sink = KoalaBearExt8.evaluate_hypercube(evals, point);
        require(sink != 0, "SINK");
        return gasStart - gasleft();
    }

    function _gasBaseHypercubeAsExt5(uint256 dim) internal view returns (uint256) {
        uint256 len = uint256(1) << dim;
        uint256[] memory evals = new uint256[](len);
        uint256[] memory point = _makeExt5Array(500 + dim, dim);
        unchecked {
            for (uint256 i = 0; i < len; ++i) {
                evals[i] = KoalaBearExt5.fromBase(_base(600 + dim * 1000 + i));
            }
        }
        uint256 gasStart = gasleft();
        uint256 sink = KoalaBearExt5.evaluate_hypercube(evals, point);
        require(sink != 0, "SINK");
        return gasStart - gasleft();
    }

    function _gasBaseHypercubeAsExt4(uint256 dim) internal view returns (uint256) {
        uint256 len = uint256(1) << dim;
        uint256[] memory evals = new uint256[](len);
        uint256[] memory point = _makeExt4Array(3100 + dim, dim);
        unchecked {
            for (uint256 i = 0; i < len; ++i) {
                evals[i] = KoalaBearExt4.fromBase(_base(3200 + dim * 1000 + i));
            }
        }
        uint256 gasStart = gasleft();
        uint256 sink = KoalaBearExt4.evaluate_hypercube(evals, point);
        require(sink != 0, "SINK");
        return gasStart - gasleft();
    }

    function _gasBaseHypercubeAsExt8(uint256 dim) internal view returns (uint256) {
        uint256 len = uint256(1) << dim;
        uint256[] memory evals = new uint256[](len);
        uint256[] memory point = _makeExt8Array(3300 + dim, dim);
        unchecked {
            for (uint256 i = 0; i < len; ++i) {
                evals[i] = KoalaBearExt8.fromBase(_base(3400 + dim * 1000 + i));
            }
        }
        uint256 gasStart = gasleft();
        uint256 sink = KoalaBearExt8.evaluate_hypercube(evals, point);
        require(sink != 0, "SINK");
        return gasStart - gasleft();
    }

    function _gasSampleBits(uint256 bits) internal view returns (uint256) {
        uint256 gasStart = gasleft();
        uint256 sink;
        unchecked {
            for (uint256 i = 0; i < REPS; ++i) {
                KeccakChallenger.State memory ch;
                ch.observeBytes(abi.encodePacked(bytes32(uint256(1100 + i))));
                sink += ch.sampleBits(bits);
            }
        }
        require(sink != 0, "SINK");
        return (gasStart - gasleft()) / REPS;
    }

    function _gasSampleStirQueries(uint256 domainBits, uint256 numQueries)
        internal
        view
        returns (uint256)
    {
        uint256 domainSize = uint256(1) << domainBits;
        uint256 gasStart = gasleft();
        uint256 sink;
        unchecked {
            for (uint256 i = 0; i < 10; ++i) {
                KeccakChallenger.State memory ch;
                ch.observeBytes(abi.encodePacked(bytes32(uint256(1200 + i))));
                uint256[] memory queries =
                    WhirVerifierUtils8.sampleStirQueries(ch, domainSize, 0, numQueries);
                sink += queries.length;
            }
        }
        require(sink != 0, "SINK");
        return (gasStart - gasleft()) / 10;
    }

    function _gasVerifyPow(uint256 bits) internal view returns (uint256) {
        uint256 gasStart = gasleft();
        uint256 sink;
        unchecked {
            for (uint256 i = 0; i < REPS; ++i) {
                KeccakChallenger.State memory ch;
                ch.observeBytes(abi.encodePacked(bytes32(uint256(1300 + i))));
                if (ch.checkWitness(bits, _base(1400 + i))) {
                    sink += 1;
                } else {
                    sink += 2;
                }
            }
        }
        require(sink != 0, "SINK");
        return (gasStart - gasleft()) / REPS;
    }

    function _sampleExt5(uint256 seed) internal view returns (uint256) {
        KeccakChallenger.State memory ch;
        ch.observeBytes(abi.encodePacked(bytes32(seed)));
        uint256[5] memory coeffs;
        unchecked {
            for (uint256 i = 0; i < 5; ++i) {
                coeffs[i] = ch.sampleBase();
            }
        }
        return KoalaBearExt5.pack(coeffs);
    }

    function _makeExt5Inputs(uint256 seed) internal view returns (uint256[8] memory inputs) {
        unchecked {
            for (uint256 i = 0; i < 8; ++i) {
                inputs[i] = _packedExt5(seed + i * 17);
            }
        }
    }

    function _makeExt8Inputs(uint256 seed) internal view returns (uint256[8] memory inputs) {
        unchecked {
            for (uint256 i = 0; i < 8; ++i) {
                uint256[8] memory coeffs;
                for (uint256 j = 0; j < 8; ++j) {
                    coeffs[j] = _base(seed + i * 17 + j * 13);
                }
                inputs[i] = KoalaBearExt8.pack(coeffs);
            }
        }
    }

    function _makeExt4Inputs(uint256 seed) internal view returns (uint256[8] memory inputs) {
        unchecked {
            for (uint256 i = 0; i < 8; ++i) {
                inputs[i] = _packedExt4(seed + i * 17);
            }
        }
    }

    function _makeExt5Array(uint256 seed, uint256 len)
        internal
        view
        returns (uint256[] memory out)
    {
        out = new uint256[](len);
        unchecked {
            for (uint256 i = 0; i < len; ++i) {
                out[i] = _packedExt5(seed + i * 19);
            }
        }
    }

    function _makeExt4Array(uint256 seed, uint256 len)
        internal
        view
        returns (uint256[] memory out)
    {
        out = new uint256[](len);
        unchecked {
            for (uint256 i = 0; i < len; ++i) {
                out[i] = _packedExt4(seed + i * 19);
            }
        }
    }

    function _makeExt8Array(uint256 seed, uint256 len)
        internal
        view
        returns (uint256[] memory out)
    {
        out = new uint256[](len);
        unchecked {
            for (uint256 i = 0; i < len; ++i) {
                uint256[8] memory coeffs;
                for (uint256 j = 0; j < 8; ++j) {
                    coeffs[j] = _base(seed + i * 19 + j * 11);
                }
                out[i] = KoalaBearExt8.pack(coeffs);
            }
        }
    }

    function _makeBaseArray(uint256 seed, uint256 len)
        internal
        view
        returns (uint256[] memory out)
    {
        out = new uint256[](len);
        unchecked {
            for (uint256 i = 0; i < len; ++i) {
                out[i] = _base(seed + i * 23);
            }
        }
    }

    function _packedExt5(uint256 seed) internal view returns (uint256) {
        uint256[5] memory coeffs;
        unchecked {
            for (uint256 i = 0; i < 5; ++i) {
                coeffs[i] = _base(seed + i * 11);
            }
        }
        return KoalaBearExt5.pack(coeffs);
    }

    function _packedExt4(uint256 seed) internal view returns (uint256) {
        uint256[4] memory coeffs;
        unchecked {
            for (uint256 i = 0; i < 4; ++i) {
                coeffs[i] = _base(seed + i * 11);
            }
        }
        return KoalaBearExt4.pack(coeffs);
    }

    function _base(uint256 value) internal view returns (uint256) {
        return (value * 1_315_423_911 + 17) % KoalaBear.MODULUS;
    }

    function _emitGas(
        string memory metric,
        string memory bucket,
        string memory unit,
        uint256 count,
        uint256 gasValue
    ) internal {
        console.log(
            string.concat(
                "BENCH:{\"schema_version\":1,\"metric\":\"",
                metric,
                "\",\"bucket\":\"",
                bucket,
                "\",\"unit\":\"",
                unit,
                "\",\"count\":",
                vm.toString(count),
                ",\"gas\":",
                vm.toString(gasValue),
                "}"
            )
        );
    }

    function _withUint(string memory prefix, uint256 value) internal view returns (string memory) {
        return string.concat(prefix, vm.toString(value));
    }
}
