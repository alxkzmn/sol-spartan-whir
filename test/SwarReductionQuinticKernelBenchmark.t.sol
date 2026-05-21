// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test, console } from "forge-std/Test.sol";

// Benchmarks the SWAR/lazy-reduction ideas against kernels shaped like the
// quintic verifier. M31 is included as a comparison field because its Mersenne
// reduction is the cleanest version of the suggested bitfold trick; the useful
// batched packed add/sub and validation wins below are not M31-specific.
contract SwarReductionQuinticKernelHarness {
    uint256 internal constant KB_MODULUS = 0x7f000001;
    uint256 internal constant M31_MODULUS = 0x7fffffff;
    uint256 internal constant COEFF_MASK = 0xffffffff;
    uint256 internal constant KB_FOLD_FACTOR = 0x00ffffff;
    uint256 internal constant M31_MASK = 0x7fffffff;
    uint256 internal constant ITERS = 64;
    uint256 internal constant DOT_ITERS = 16;
    uint256 internal constant DIM4_ROW_FOLDS = 15;
    uint256 internal constant DIM4_ROW_VALUES = 16;
    uint256 internal constant EXT5_BATCH_LANES = 80;
    uint256 internal constant EXT5_LOW_96_MASK = (uint256(1) << 96) - 1;
    uint256 internal constant PACKED_HIGH_BIT_5 = uint256(0x80000000) << 224 | uint256(0x80000000)
        << 192 | uint256(0x80000000) << 160 | uint256(0x80000000) << 128 | uint256(0x80000000)
        << 96;
    uint256 internal constant PACKED_LOW_31_5 = uint256(0x7fffffff) << 224 | uint256(0x7fffffff)
        << 192 | uint256(0x7fffffff) << 160 | uint256(0x7fffffff) << 128 | uint256(0x7fffffff)
        << 96;

    function benchKbFoldMod(uint256 salt) external view returns (uint256 gasPerFold, uint256 acc) {
        (uint256 a0, uint256 a1, uint256 r0, uint256 r1, uint256 r2, uint256 r3, uint256 r4) =
            _seeds(salt, KB_MODULUS);
        uint256 g = gasleft();
        unchecked {
            for (uint256 i = 0; i < ITERS; ++i) {
                a0 = _foldKbMod(a0, a1, r0, r1, r2, r3, r4);
                acc ^= a0;
            }
        }
        gasPerFold = (g - gasleft()) / ITERS;
    }

    function benchKbFoldBitfold(uint256 salt)
        external
        view
        returns (uint256 gasPerFold, uint256 acc)
    {
        (uint256 a0, uint256 a1, uint256 r0, uint256 r1, uint256 r2, uint256 r3, uint256 r4) =
            _seeds(salt, KB_MODULUS);
        uint256 g = gasleft();
        unchecked {
            for (uint256 i = 0; i < ITERS; ++i) {
                a0 = _foldKbBitfold(a0, a1, r0, r1, r2, r3, r4);
                acc ^= a0;
            }
        }
        gasPerFold = (g - gasleft()) / ITERS;
    }

    function benchKbFoldModSol(uint256 salt)
        external
        view
        returns (uint256 gasPerFold, uint256 acc)
    {
        (uint256 a0, uint256 a1, uint256 r0, uint256 r1, uint256 r2, uint256 r3, uint256 r4) =
            _seeds(salt, KB_MODULUS);
        uint256 g = gasleft();
        unchecked {
            for (uint256 i = 0; i < ITERS; ++i) {
                a0 = _foldModSol(a0, a1, r0, r1, r2, r3, r4);
                acc ^= a0;
            }
        }
        gasPerFold = (g - gasleft()) / ITERS;
    }

    function benchM31FoldMod(uint256 salt) external view returns (uint256 gasPerFold, uint256 acc) {
        (uint256 a0, uint256 a1, uint256 r0, uint256 r1, uint256 r2, uint256 r3, uint256 r4) =
            _seeds(salt, M31_MODULUS);
        uint256 g = gasleft();
        unchecked {
            for (uint256 i = 0; i < ITERS; ++i) {
                a0 = _foldM31Mod(a0, a1, r0, r1, r2, r3, r4);
                acc ^= a0;
            }
        }
        gasPerFold = (g - gasleft()) / ITERS;
    }

    function benchM31FoldBitfold(uint256 salt)
        external
        view
        returns (uint256 gasPerFold, uint256 acc)
    {
        (uint256 a0, uint256 a1, uint256 r0, uint256 r1, uint256 r2, uint256 r3, uint256 r4) =
            _seeds(salt, M31_MODULUS);
        uint256 g = gasleft();
        unchecked {
            for (uint256 i = 0; i < ITERS; ++i) {
                a0 = _foldM31Bitfold(a0, a1, r0, r1, r2, r3, r4);
                acc ^= a0;
            }
        }
        gasPerFold = (g - gasleft()) / ITERS;
    }

    function foldKbModPublic(
        uint256 a0,
        uint256 a1,
        uint256 r0,
        uint256 r1,
        uint256 r2,
        uint256 r3,
        uint256 r4
    ) external pure returns (uint256) {
        return _foldKbMod(a0, a1, r0, r1, r2, r3, r4);
    }

    function foldKbBitfoldPublic(
        uint256 a0,
        uint256 a1,
        uint256 r0,
        uint256 r1,
        uint256 r2,
        uint256 r3,
        uint256 r4
    ) external pure returns (uint256) {
        return _foldKbBitfold(a0, a1, r0, r1, r2, r3, r4);
    }

    function foldKbModSolPublic(
        uint256 a0,
        uint256 a1,
        uint256 r0,
        uint256 r1,
        uint256 r2,
        uint256 r3,
        uint256 r4
    ) external pure returns (uint256) {
        return _foldModSol(a0, a1, r0, r1, r2, r3, r4);
    }

    function foldM31ModPublic(
        uint256 a0,
        uint256 a1,
        uint256 r0,
        uint256 r1,
        uint256 r2,
        uint256 r3,
        uint256 r4
    ) external pure returns (uint256) {
        return _foldM31Mod(a0, a1, r0, r1, r2, r3, r4);
    }

    function foldM31BitfoldPublic(
        uint256 a0,
        uint256 a1,
        uint256 r0,
        uint256 r1,
        uint256 r2,
        uint256 r3,
        uint256 r4
    ) external pure returns (uint256) {
        return _foldM31Bitfold(a0, a1, r0, r1, r2, r3, r4);
    }

    function reduceKbBitfoldPublic(uint256 value) external pure returns (uint256) {
        return _reduceKbBitfold(value);
    }

    function reduceM31BitfoldPublic(uint256 value) external pure returns (uint256) {
        return _reduceM31Bitfold(value);
    }

    function addPackedMaskPublic(uint256 a, uint256 b, uint256 modulus)
        external
        pure
        returns (uint256)
    {
        return _addPackedMask(a, b, modulus);
    }

    function addPackedModPublic(uint256 a, uint256 b, uint256 modulus)
        external
        pure
        returns (uint256)
    {
        return _addPackedMod(a, b, modulus);
    }

    function subPackedMaskPublic(uint256 a, uint256 b, uint256 modulus)
        external
        pure
        returns (uint256)
    {
        return _subPackedMask(a, b, modulus);
    }

    function subPackedModPublic(uint256 a, uint256 b, uint256 modulus)
        external
        pure
        returns (uint256)
    {
        return _subPackedMod(a, b, modulus);
    }

    function validatePackedExt5ScalarPublic(uint256 packed) external pure returns (bool) {
        return _isValidPackedExt5Scalar(packed);
    }

    function validatePackedExt5MaskPublic(uint256 packed) external pure returns (bool) {
        return _isValidPackedExt5Mask(packed);
    }

    function mulPackedAsmPublic(uint256 a, uint256 b) external pure returns (uint256) {
        return _mulPackedAsm(a, b);
    }

    function mulPackedSolPublic(uint256 a, uint256 b) external pure returns (uint256) {
        return _mulPackedSol(a, b);
    }

    function squarePackedAsmPublic(uint256 a) external pure returns (uint256) {
        return _squarePackedAsm(a);
    }

    function squarePackedSolPublic(uint256 a) external pure returns (uint256) {
        return _squarePackedSol(a);
    }

    function scalarMulAsmPublic(uint256 a, uint256 scalar) external pure returns (uint256) {
        return _scalarMulAsm(a, scalar);
    }

    function scalarMulSolPublic(uint256 a, uint256 scalar) external pure returns (uint256) {
        return _scalarMulSol(a, scalar);
    }

    function benchKbDim4RowFoldMod(uint256 salt)
        external
        view
        returns (uint256 gasPerRow, uint256 acc)
    {
        uint256 g = gasleft();
        unchecked {
            for (uint256 i = 0; i < DOT_ITERS; ++i) {
                acc ^= _dim4RowFoldKbMod(salt + i);
            }
        }
        gasPerRow = (g - gasleft()) / DOT_ITERS;
    }

    function benchKbDim4RowFoldBitfold(uint256 salt)
        external
        view
        returns (uint256 gasPerRow, uint256 acc)
    {
        uint256 g = gasleft();
        unchecked {
            for (uint256 i = 0; i < DOT_ITERS; ++i) {
                acc ^= _dim4RowFoldKbBitfold(salt + i);
            }
        }
        gasPerRow = (g - gasleft()) / DOT_ITERS;
    }

    function benchM31Dim4RowFoldMod(uint256 salt)
        external
        view
        returns (uint256 gasPerRow, uint256 acc)
    {
        uint256 g = gasleft();
        unchecked {
            for (uint256 i = 0; i < DOT_ITERS; ++i) {
                acc ^= _dim4RowFoldM31Mod(salt + i);
            }
        }
        gasPerRow = (g - gasleft()) / DOT_ITERS;
    }

    function benchM31Dim4RowFoldBitfold(uint256 salt)
        external
        view
        returns (uint256 gasPerRow, uint256 acc)
    {
        uint256 g = gasleft();
        unchecked {
            for (uint256 i = 0; i < DOT_ITERS; ++i) {
                acc ^= _dim4RowFoldM31Bitfold(salt + i);
            }
        }
        gasPerRow = (g - gasleft()) / DOT_ITERS;
    }

    function benchKbDot16Eager(uint256 salt)
        external
        view
        returns (uint256 gasPerDot, uint256 acc)
    {
        uint256 g = gasleft();
        unchecked {
            for (uint256 i = 0; i < DOT_ITERS; ++i) {
                acc ^= _dot16Eager(salt + i, KB_MODULUS);
            }
        }
        gasPerDot = (g - gasleft()) / DOT_ITERS;
    }

    function benchKbDot16Lazy(uint256 salt) external view returns (uint256 gasPerDot, uint256 acc) {
        uint256 g = gasleft();
        unchecked {
            for (uint256 i = 0; i < DOT_ITERS; ++i) {
                acc ^= _dot16Lazy(salt + i, KB_MODULUS);
            }
        }
        gasPerDot = (g - gasleft()) / DOT_ITERS;
    }

    function benchM31Dot16Eager(uint256 salt)
        external
        view
        returns (uint256 gasPerDot, uint256 acc)
    {
        uint256 g = gasleft();
        unchecked {
            for (uint256 i = 0; i < DOT_ITERS; ++i) {
                acc ^= _dot16Eager(salt + i, M31_MODULUS);
            }
        }
        gasPerDot = (g - gasleft()) / DOT_ITERS;
    }

    function benchM31Dot16Lazy(uint256 salt)
        external
        view
        returns (uint256 gasPerDot, uint256 acc)
    {
        uint256 g = gasleft();
        unchecked {
            for (uint256 i = 0; i < DOT_ITERS; ++i) {
                acc ^= _dot16Lazy(salt + i, M31_MODULUS);
            }
        }
        gasPerDot = (g - gasleft()) / DOT_ITERS;
    }

    function benchKbPackedAddSub16Mod(uint256 salt)
        external
        view
        returns (uint256 gasPerBatch, uint256 acc)
    {
        uint256 g = gasleft();
        unchecked {
            for (uint256 i = 0; i < ITERS; ++i) {
                acc ^= _packedAddSub16(salt + i, KB_MODULUS, false);
            }
        }
        gasPerBatch = (g - gasleft()) / ITERS;
    }

    function benchKbPackedAddSub16Mask(uint256 salt)
        external
        view
        returns (uint256 gasPerBatch, uint256 acc)
    {
        uint256 g = gasleft();
        unchecked {
            for (uint256 i = 0; i < ITERS; ++i) {
                acc ^= _packedAddSub16(salt + i, KB_MODULUS, true);
            }
        }
        gasPerBatch = (g - gasleft()) / ITERS;
    }

    function benchM31PackedAddSub16Mod(uint256 salt)
        external
        view
        returns (uint256 gasPerBatch, uint256 acc)
    {
        uint256 g = gasleft();
        unchecked {
            for (uint256 i = 0; i < ITERS; ++i) {
                acc ^= _packedAddSub16(salt + i, M31_MODULUS, false);
            }
        }
        gasPerBatch = (g - gasleft()) / ITERS;
    }

    function benchM31PackedAddSub16Mask(uint256 salt)
        external
        view
        returns (uint256 gasPerBatch, uint256 acc)
    {
        uint256 g = gasleft();
        unchecked {
            for (uint256 i = 0; i < ITERS; ++i) {
                acc ^= _packedAddSub16(salt + i, M31_MODULUS, true);
            }
        }
        gasPerBatch = (g - gasleft()) / ITERS;
    }

    function benchValidatePackedExt5Scalar16(uint256 salt)
        external
        view
        returns (uint256 gasPerBatch, uint256 acc)
    {
        uint256 g = gasleft();
        unchecked {
            for (uint256 i = 0; i < ITERS; ++i) {
                acc ^= _validatePackedExt5Batch(salt + i, false);
            }
        }
        gasPerBatch = (g - gasleft()) / ITERS;
    }

    function benchValidatePackedExt5Mask16(uint256 salt)
        external
        view
        returns (uint256 gasPerBatch, uint256 acc)
    {
        uint256 g = gasleft();
        unchecked {
            for (uint256 i = 0; i < ITERS; ++i) {
                acc ^= _validatePackedExt5Batch(salt + i, true);
            }
        }
        gasPerBatch = (g - gasleft()) / ITERS;
    }

    function benchKbMulPackedAsm16(uint256 salt)
        external
        view
        returns (uint256 gasPerBatch, uint256 acc)
    {
        uint256[16] memory left = _packed16(salt, KB_MODULUS);
        uint256[16] memory right = _packed16(salt ^ 0xabcdef, KB_MODULUS);
        uint256 g = gasleft();
        unchecked {
            for (uint256 i = 0; i < ITERS; ++i) {
                acc ^= _mulPackedAsm(left[i & 15], right[(i + 5) & 15]);
            }
        }
        gasPerBatch = (g - gasleft()) / ITERS;
    }

    function benchKbMulPackedSol16(uint256 salt)
        external
        view
        returns (uint256 gasPerBatch, uint256 acc)
    {
        uint256[16] memory left = _packed16(salt, KB_MODULUS);
        uint256[16] memory right = _packed16(salt ^ 0xabcdef, KB_MODULUS);
        uint256 g = gasleft();
        unchecked {
            for (uint256 i = 0; i < ITERS; ++i) {
                acc ^= _mulPackedSol(left[i & 15], right[(i + 5) & 15]);
            }
        }
        gasPerBatch = (g - gasleft()) / ITERS;
    }

    function benchKbSquarePackedAsm16(uint256 salt)
        external
        view
        returns (uint256 gasPerBatch, uint256 acc)
    {
        uint256[16] memory values = _packed16(salt, KB_MODULUS);
        uint256 g = gasleft();
        unchecked {
            for (uint256 i = 0; i < ITERS; ++i) {
                acc ^= _squarePackedAsm(values[i & 15]);
            }
        }
        gasPerBatch = (g - gasleft()) / ITERS;
    }

    function benchKbSquarePackedSol16(uint256 salt)
        external
        view
        returns (uint256 gasPerBatch, uint256 acc)
    {
        uint256[16] memory values = _packed16(salt, KB_MODULUS);
        uint256 g = gasleft();
        unchecked {
            for (uint256 i = 0; i < ITERS; ++i) {
                acc ^= _squarePackedSol(values[i & 15]);
            }
        }
        gasPerBatch = (g - gasleft()) / ITERS;
    }

    function benchKbScalarMulAsm16(uint256 salt)
        external
        view
        returns (uint256 gasPerBatch, uint256 acc)
    {
        uint256[16] memory values = _packed16(salt, KB_MODULUS);
        uint256 scalar = (salt + 0x12345) % KB_MODULUS;
        uint256 g = gasleft();
        unchecked {
            for (uint256 i = 0; i < ITERS; ++i) {
                acc ^= _scalarMulAsm(values[i & 15], scalar);
            }
        }
        gasPerBatch = (g - gasleft()) / ITERS;
    }

    function benchKbScalarMulSol16(uint256 salt)
        external
        view
        returns (uint256 gasPerBatch, uint256 acc)
    {
        uint256[16] memory values = _packed16(salt, KB_MODULUS);
        uint256 scalar = (salt + 0x12345) % KB_MODULUS;
        uint256 g = gasleft();
        unchecked {
            for (uint256 i = 0; i < ITERS; ++i) {
                acc ^= _scalarMulSol(values[i & 15], scalar);
            }
        }
        gasPerBatch = (g - gasleft()) / ITERS;
    }

    function _foldKbMod(
        uint256 a0,
        uint256 a1,
        uint256 r0,
        uint256 r1,
        uint256 r2,
        uint256 r3,
        uint256 r4
    ) private pure returns (uint256) {
        return _foldMod(a0, a1, r0, r1, r2, r3, r4, KB_MODULUS);
    }

    function _foldM31Mod(
        uint256 a0,
        uint256 a1,
        uint256 r0,
        uint256 r1,
        uint256 r2,
        uint256 r3,
        uint256 r4
    ) private pure returns (uint256) {
        return _foldMod(a0, a1, r0, r1, r2, r3, r4, M31_MODULUS);
    }

    function _foldMod(
        uint256 a0,
        uint256 a1,
        uint256 r0,
        uint256 r1,
        uint256 r2,
        uint256 r3,
        uint256 r4,
        uint256 modulus
    ) private pure returns (uint256 out) {
        assembly ("memory-safe") {
            let m := 0xffffffff

            let a00 := shr(224, a0)
            let a01 := and(shr(192, a0), m)
            let a02 := and(shr(160, a0), m)
            let a03 := and(shr(128, a0), m)
            let a04 := and(shr(96, a0), m)

            let d0 := sub(add(shr(224, a1), modulus), a00)
            let d1 := sub(add(and(shr(192, a1), m), modulus), a01)
            let d2 := sub(add(and(shr(160, a1), m), modulus), a02)
            let d3 := sub(add(and(shr(128, a1), m), modulus), a03)
            let d4 := sub(add(and(shr(96, a1), m), modulus), a04)

            let c0 := mul(r0, d0)
            let c1 := add(mul(r0, d1), mul(r1, d0))
            let c2 := add(add(mul(r0, d2), mul(r1, d1)), mul(r2, d0))
            let c3 := add(add(add(mul(r0, d3), mul(r1, d2)), mul(r2, d1)), mul(r3, d0))
            let c4 :=
                add(add(add(add(mul(r0, d4), mul(r1, d3)), mul(r2, d2)), mul(r3, d1)), mul(r4, d0))
            let c5 := add(add(add(mul(r1, d4), mul(r2, d3)), mul(r3, d2)), mul(r4, d1))
            let c6 := add(add(mul(r2, d4), mul(r3, d3)), mul(r4, d2))
            let c7 := add(mul(r3, d4), mul(r4, d3))
            let c8 := mul(r4, d4)

            let bias := shl(35, modulus)

            let rOut0 := mod(add(add(add(a00, c0), c5), sub(bias, c8)), modulus)
            let rOut1 := mod(add(add(a01, c1), c6), modulus)
            let rOut2 := mod(add(add(add(add(a02, c2), sub(bias, c5)), c7), c8), modulus)
            let rOut3 := mod(add(add(add(a03, c3), sub(bias, c6)), c8), modulus)
            let rOut4 := mod(add(add(a04, c4), sub(bias, c7)), modulus)

            out := or(
                or(or(shl(224, rOut0), shl(192, rOut1)), or(shl(160, rOut2), shl(128, rOut3))),
                shl(96, rOut4)
            )
        }
    }

    function _foldModSol(
        uint256 a0,
        uint256 a1,
        uint256 r0,
        uint256 r1,
        uint256 r2,
        uint256 r3,
        uint256 r4
    ) private pure returns (uint256 out) {
        unchecked {
            uint256 a00 = a0 >> 224;
            uint256 a01 = (a0 >> 192) & COEFF_MASK;
            uint256 a02 = (a0 >> 160) & COEFF_MASK;
            uint256 a03 = (a0 >> 128) & COEFF_MASK;
            uint256 a04 = (a0 >> 96) & COEFF_MASK;

            uint256 d0 = (a1 >> 224) + KB_MODULUS - a00;
            uint256 d1 = ((a1 >> 192) & COEFF_MASK) + KB_MODULUS - a01;
            uint256 d2 = ((a1 >> 160) & COEFF_MASK) + KB_MODULUS - a02;
            uint256 d3 = ((a1 >> 128) & COEFF_MASK) + KB_MODULUS - a03;
            uint256 d4 = ((a1 >> 96) & COEFF_MASK) + KB_MODULUS - a04;

            uint256 c0 = r0 * d0;
            uint256 c1 = r0 * d1 + r1 * d0;
            uint256 c2 = r0 * d2 + r1 * d1 + r2 * d0;
            uint256 c3 = r0 * d3 + r1 * d2 + r2 * d1 + r3 * d0;
            uint256 c4 = r0 * d4 + r1 * d3 + r2 * d2 + r3 * d1 + r4 * d0;
            uint256 c5 = r1 * d4 + r2 * d3 + r3 * d2 + r4 * d1;
            uint256 c6 = r2 * d4 + r3 * d3 + r4 * d2;
            uint256 c7 = r3 * d4 + r4 * d3;
            uint256 c8 = r4 * d4;
            uint256 bias = KB_MODULUS << 35;

            uint256 rOut0 = (a00 + c0 + c5 + bias - c8) % KB_MODULUS;
            uint256 rOut1 = (a01 + c1 + c6) % KB_MODULUS;
            uint256 rOut2 = (a02 + c2 + bias - c5 + c7 + c8) % KB_MODULUS;
            uint256 rOut3 = (a03 + c3 + bias - c6 + c8) % KB_MODULUS;
            uint256 rOut4 = (a04 + c4 + bias - c7) % KB_MODULUS;

            out = (rOut0 << 224) | (rOut1 << 192) | (rOut2 << 160) | (rOut3 << 128) | (rOut4 << 96);
        }
    }

    function _foldKbBitfold(
        uint256 a0,
        uint256 a1,
        uint256 r0,
        uint256 r1,
        uint256 r2,
        uint256 r3,
        uint256 r4
    ) private pure returns (uint256 out) {
        return _foldBitfold(a0, a1, r0, r1, r2, r3, r4, KB_MODULUS, true);
    }

    function _foldM31Bitfold(
        uint256 a0,
        uint256 a1,
        uint256 r0,
        uint256 r1,
        uint256 r2,
        uint256 r3,
        uint256 r4
    ) private pure returns (uint256 out) {
        return _foldBitfold(a0, a1, r0, r1, r2, r3, r4, M31_MODULUS, false);
    }

    function _foldBitfold(
        uint256 a0,
        uint256 a1,
        uint256 r0,
        uint256 r1,
        uint256 r2,
        uint256 r3,
        uint256 r4,
        uint256 modulus,
        bool isKoalaBear
    ) private pure returns (uint256 out) {
        uint256 a00 = a0 >> 224;
        uint256 a01 = (a0 >> 192) & COEFF_MASK;
        uint256 a02 = (a0 >> 160) & COEFF_MASK;
        uint256 a03 = (a0 >> 128) & COEFF_MASK;
        uint256 a04 = (a0 >> 96) & COEFF_MASK;

        unchecked {
            uint256 d0 = (a1 >> 224) + modulus - a00;
            uint256 d1 = ((a1 >> 192) & COEFF_MASK) + modulus - a01;
            uint256 d2 = ((a1 >> 160) & COEFF_MASK) + modulus - a02;
            uint256 d3 = ((a1 >> 128) & COEFF_MASK) + modulus - a03;
            uint256 d4 = ((a1 >> 96) & COEFF_MASK) + modulus - a04;

            uint256 c0 = r0 * d0;
            uint256 c1 = r0 * d1 + r1 * d0;
            uint256 c2 = r0 * d2 + r1 * d1 + r2 * d0;
            uint256 c3 = r0 * d3 + r1 * d2 + r2 * d1 + r3 * d0;
            uint256 c4 = r0 * d4 + r1 * d3 + r2 * d2 + r3 * d1 + r4 * d0;
            uint256 c5 = r1 * d4 + r2 * d3 + r3 * d2 + r4 * d1;
            uint256 c6 = r2 * d4 + r3 * d3 + r4 * d2;
            uint256 c7 = r3 * d4 + r4 * d3;
            uint256 c8 = r4 * d4;
            uint256 bias = modulus << 35;

            uint256 rOut0 = isKoalaBear
                ? _reduceKbBitfold(a00 + c0 + c5 + bias - c8)
                : _reduceM31Bitfold(a00 + c0 + c5 + bias - c8);
            uint256 rOut1 =
                isKoalaBear ? _reduceKbBitfold(a01 + c1 + c6) : _reduceM31Bitfold(a01 + c1 + c6);
            uint256 rOut2 = isKoalaBear
                ? _reduceKbBitfold(a02 + c2 + bias - c5 + c7 + c8)
                : _reduceM31Bitfold(a02 + c2 + bias - c5 + c7 + c8);
            uint256 rOut3 = isKoalaBear
                ? _reduceKbBitfold(a03 + c3 + bias - c6 + c8)
                : _reduceM31Bitfold(a03 + c3 + bias - c6 + c8);
            uint256 rOut4 = isKoalaBear
                ? _reduceKbBitfold(a04 + c4 + bias - c7)
                : _reduceM31Bitfold(a04 + c4 + bias - c7);

            out = (rOut0 << 224) | (rOut1 << 192) | (rOut2 << 160) | (rOut3 << 128) | (rOut4 << 96);
        }
    }

    function _reduceKbBitfold(uint256 x) private pure returns (uint256) {
        unchecked {
            x = (x & M31_MASK) + (x >> 31) * KB_FOLD_FACTOR;
            x = (x & M31_MASK) + (x >> 31) * KB_FOLD_FACTOR;
            x = (x & M31_MASK) + (x >> 31) * KB_FOLD_FACTOR;
            x = (x & M31_MASK) + (x >> 31) * KB_FOLD_FACTOR;
            x = (x & M31_MASK) + (x >> 31) * KB_FOLD_FACTOR;
            x = (x & M31_MASK) + (x >> 31) * KB_FOLD_FACTOR;
            return x >= KB_MODULUS ? x - KB_MODULUS : x;
        }
    }

    function _reduceM31Bitfold(uint256 x) private pure returns (uint256) {
        unchecked {
            x = (x & M31_MASK) + (x >> 31);
            x = (x & M31_MASK) + (x >> 31);
            x = (x & M31_MASK) + (x >> 31);
            return x >= M31_MODULUS ? x - M31_MODULUS : x;
        }
    }

    function _dim4RowFold(uint256 salt, uint256 modulus, bool bitfold)
        private
        pure
        returns (uint256)
    {
        uint256[16] memory row = _packed16(salt, modulus);
        (uint256 r0, uint256 r1, uint256 r2, uint256 r3, uint256 r4) = _point(salt, modulus, 0);
        uint256 l0 = bitfold
            ? _foldBitfold(row[0], row[8], r0, r1, r2, r3, r4, modulus, modulus == KB_MODULUS)
            : _foldMod(row[0], row[8], r0, r1, r2, r3, r4, modulus);
        uint256 l1 = bitfold
            ? _foldBitfold(row[1], row[9], r0, r1, r2, r3, r4, modulus, modulus == KB_MODULUS)
            : _foldMod(row[1], row[9], r0, r1, r2, r3, r4, modulus);
        uint256 l2 = bitfold
            ? _foldBitfold(row[2], row[10], r0, r1, r2, r3, r4, modulus, modulus == KB_MODULUS)
            : _foldMod(row[2], row[10], r0, r1, r2, r3, r4, modulus);
        uint256 l3 = bitfold
            ? _foldBitfold(row[3], row[11], r0, r1, r2, r3, r4, modulus, modulus == KB_MODULUS)
            : _foldMod(row[3], row[11], r0, r1, r2, r3, r4, modulus);
        uint256 l4 = bitfold
            ? _foldBitfold(row[4], row[12], r0, r1, r2, r3, r4, modulus, modulus == KB_MODULUS)
            : _foldMod(row[4], row[12], r0, r1, r2, r3, r4, modulus);
        uint256 l5 = bitfold
            ? _foldBitfold(row[5], row[13], r0, r1, r2, r3, r4, modulus, modulus == KB_MODULUS)
            : _foldMod(row[5], row[13], r0, r1, r2, r3, r4, modulus);
        uint256 l6 = bitfold
            ? _foldBitfold(row[6], row[14], r0, r1, r2, r3, r4, modulus, modulus == KB_MODULUS)
            : _foldMod(row[6], row[14], r0, r1, r2, r3, r4, modulus);
        uint256 l7 = bitfold
            ? _foldBitfold(row[7], row[15], r0, r1, r2, r3, r4, modulus, modulus == KB_MODULUS)
            : _foldMod(row[7], row[15], r0, r1, r2, r3, r4, modulus);

        (r0, r1, r2, r3, r4) = _point(salt, modulus, 1);
        uint256 m0 = bitfold
            ? _foldBitfold(l0, l4, r0, r1, r2, r3, r4, modulus, modulus == KB_MODULUS)
            : _foldMod(l0, l4, r0, r1, r2, r3, r4, modulus);
        uint256 m1 = bitfold
            ? _foldBitfold(l1, l5, r0, r1, r2, r3, r4, modulus, modulus == KB_MODULUS)
            : _foldMod(l1, l5, r0, r1, r2, r3, r4, modulus);
        uint256 m2 = bitfold
            ? _foldBitfold(l2, l6, r0, r1, r2, r3, r4, modulus, modulus == KB_MODULUS)
            : _foldMod(l2, l6, r0, r1, r2, r3, r4, modulus);
        uint256 m3 = bitfold
            ? _foldBitfold(l3, l7, r0, r1, r2, r3, r4, modulus, modulus == KB_MODULUS)
            : _foldMod(l3, l7, r0, r1, r2, r3, r4, modulus);

        (r0, r1, r2, r3, r4) = _point(salt, modulus, 2);
        uint256 n0 = bitfold
            ? _foldBitfold(m0, m2, r0, r1, r2, r3, r4, modulus, modulus == KB_MODULUS)
            : _foldMod(m0, m2, r0, r1, r2, r3, r4, modulus);
        uint256 n1 = bitfold
            ? _foldBitfold(m1, m3, r0, r1, r2, r3, r4, modulus, modulus == KB_MODULUS)
            : _foldMod(m1, m3, r0, r1, r2, r3, r4, modulus);

        (r0, r1, r2, r3, r4) = _point(salt, modulus, 3);
        return bitfold
            ? _foldBitfold(n0, n1, r0, r1, r2, r3, r4, modulus, modulus == KB_MODULUS)
            : _foldMod(n0, n1, r0, r1, r2, r3, r4, modulus);
    }

    function _dim4RowFoldKbMod(uint256 salt) private pure returns (uint256) {
        uint256[16] memory row = _packed16(salt, KB_MODULUS);
        _foldRowLayerKbMod(row, salt, 0, 8);
        _foldRowLayerKbMod(row, salt, 1, 4);
        _foldRowLayerKbMod(row, salt, 2, 2);
        (uint256 r0, uint256 r1, uint256 r2, uint256 r3, uint256 r4) = _point(salt, KB_MODULUS, 3);
        return _foldKbMod(row[0], row[1], r0, r1, r2, r3, r4);
    }

    function _dim4RowFoldKbBitfold(uint256 salt) private pure returns (uint256) {
        uint256[16] memory row = _packed16(salt, KB_MODULUS);
        _foldRowLayerKbBitfold(row, salt, 0, 8);
        _foldRowLayerKbBitfold(row, salt, 1, 4);
        _foldRowLayerKbBitfold(row, salt, 2, 2);
        (uint256 r0, uint256 r1, uint256 r2, uint256 r3, uint256 r4) = _point(salt, KB_MODULUS, 3);
        return _foldKbBitfold(row[0], row[1], r0, r1, r2, r3, r4);
    }

    function _dim4RowFoldM31Mod(uint256 salt) private pure returns (uint256) {
        uint256[16] memory row = _packed16(salt, M31_MODULUS);
        _foldRowLayerM31Mod(row, salt, 0, 8);
        _foldRowLayerM31Mod(row, salt, 1, 4);
        _foldRowLayerM31Mod(row, salt, 2, 2);
        (uint256 r0, uint256 r1, uint256 r2, uint256 r3, uint256 r4) = _point(salt, M31_MODULUS, 3);
        return _foldM31Mod(row[0], row[1], r0, r1, r2, r3, r4);
    }

    function _dim4RowFoldM31Bitfold(uint256 salt) private pure returns (uint256) {
        uint256[16] memory row = _packed16(salt, M31_MODULUS);
        _foldRowLayerM31Bitfold(row, salt, 0, 8);
        _foldRowLayerM31Bitfold(row, salt, 1, 4);
        _foldRowLayerM31Bitfold(row, salt, 2, 2);
        (uint256 r0, uint256 r1, uint256 r2, uint256 r3, uint256 r4) = _point(salt, M31_MODULUS, 3);
        return _foldM31Bitfold(row[0], row[1], r0, r1, r2, r3, r4);
    }

    function _foldRowLayerKbMod(uint256[16] memory row, uint256 salt, uint256 round, uint256 half)
        private
        pure
    {
        (uint256 r0, uint256 r1, uint256 r2, uint256 r3, uint256 r4) =
            _point(salt, KB_MODULUS, round);
        unchecked {
            for (uint256 i = 0; i < half; ++i) {
                row[i] = _foldKbMod(row[i], row[i + half], r0, r1, r2, r3, r4);
            }
        }
    }

    function _foldRowLayerKbBitfold(
        uint256[16] memory row,
        uint256 salt,
        uint256 round,
        uint256 half
    ) private pure {
        (uint256 r0, uint256 r1, uint256 r2, uint256 r3, uint256 r4) =
            _point(salt, KB_MODULUS, round);
        unchecked {
            for (uint256 i = 0; i < half; ++i) {
                row[i] = _foldKbBitfold(row[i], row[i + half], r0, r1, r2, r3, r4);
            }
        }
    }

    function _foldRowLayerM31Mod(uint256[16] memory row, uint256 salt, uint256 round, uint256 half)
        private
        pure
    {
        (uint256 r0, uint256 r1, uint256 r2, uint256 r3, uint256 r4) =
            _point(salt, M31_MODULUS, round);
        unchecked {
            for (uint256 i = 0; i < half; ++i) {
                row[i] = _foldM31Mod(row[i], row[i + half], r0, r1, r2, r3, r4);
            }
        }
    }

    function _foldRowLayerM31Bitfold(
        uint256[16] memory row,
        uint256 salt,
        uint256 round,
        uint256 half
    ) private pure {
        (uint256 r0, uint256 r1, uint256 r2, uint256 r3, uint256 r4) =
            _point(salt, M31_MODULUS, round);
        unchecked {
            for (uint256 i = 0; i < half; ++i) {
                row[i] = _foldM31Bitfold(row[i], row[i + half], r0, r1, r2, r3, r4);
            }
        }
    }

    function _dot16Eager(uint256 salt, uint256 modulus) private pure returns (uint256 acc) {
        uint256[16] memory values = _packed16(salt, modulus);
        uint256[16] memory weights = _packed16(salt ^ 0x987654, modulus);
        unchecked {
            for (uint256 i = 0; i < DIM4_ROW_VALUES; ++i) {
                acc = _addPackedMod(acc, _mulPackedMod(values[i], weights[i], modulus), modulus);
            }
        }
    }

    function _dot16Lazy(uint256 salt, uint256 modulus) private pure returns (uint256 out) {
        uint256[16] memory values = _packed16(salt, modulus);
        uint256[16] memory weights = _packed16(salt ^ 0x987654, modulus);
        uint256 c0;
        uint256 c1;
        uint256 c2;
        uint256 c3;
        uint256 c4;
        uint256 c5;
        uint256 c6;
        uint256 c7;
        uint256 c8;

        unchecked {
            for (uint256 i = 0; i < DIM4_ROW_VALUES; ++i) {
                (uint256 a0, uint256 a1, uint256 a2, uint256 a3, uint256 a4) = _unpack5(values[i]);
                (uint256 b0, uint256 b1, uint256 b2, uint256 b3, uint256 b4) = _unpack5(weights[i]);
                c0 += a0 * b0;
                c1 += a0 * b1 + a1 * b0;
                c2 += a0 * b2 + a1 * b1 + a2 * b0;
                c3 += a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0;
                c4 += a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;
                c5 += a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1;
                c6 += a2 * b4 + a3 * b3 + a4 * b2;
                c7 += a3 * b4 + a4 * b3;
                c8 += a4 * b4;
            }

            uint256 bias = modulus << 35;
            out = ((c0 + c5 + bias - c8) % modulus) << 224 | ((c1 + c6) % modulus) << 192
                | ((c2 + bias - c5 + c7 + c8) % modulus) << 160 | ((c3 + bias - c6 + c8) % modulus)
                << 128 | ((c4 + bias - c7) % modulus) << 96;
        }
    }

    function _packedAddSub16(uint256 salt, uint256 modulus, bool mask)
        private
        pure
        returns (uint256 acc)
    {
        uint256[16] memory left = _packed16(salt, modulus);
        uint256[16] memory right = _packed16(salt ^ 0x123456, modulus);
        unchecked {
            for (uint256 i = 0; i < DIM4_ROW_VALUES; ++i) {
                uint256 sum = mask
                    ? _addPackedMask(left[i], right[i], modulus)
                    : _addPackedMod(left[i], right[i], modulus);
                uint256 diff = mask
                    ? _subPackedMask(sum, right[i], modulus)
                    : _subPackedMod(sum, right[i], modulus);
                acc ^= diff;
            }
        }
    }

    function _validatePackedExt5Batch(uint256 salt, bool mask) private pure returns (uint256 acc) {
        uint256[16] memory values = _packed16(salt, KB_MODULUS);
        unchecked {
            for (uint256 i = 0; i < DIM4_ROW_VALUES; ++i) {
                bool valid =
                    mask ? _isValidPackedExt5Mask(values[i]) : _isValidPackedExt5Scalar(values[i]);
                acc ^= valid ? values[i] : uint256(1);
            }
        }
    }

    function _isValidPackedExt5Scalar(uint256 packed) private pure returns (bool) {
        return (packed >> 224) < KB_MODULUS && ((packed >> 192) & COEFF_MASK) < KB_MODULUS
            && ((packed >> 160) & COEFF_MASK) < KB_MODULUS
            && ((packed >> 128) & COEFF_MASK) < KB_MODULUS
            && ((packed >> 96) & COEFF_MASK) < KB_MODULUS && (packed & EXT5_LOW_96_MASK) == 0;
    }

    function _isValidPackedExt5Mask(uint256 packed) private pure returns (bool) {
        unchecked {
            uint256 invalidHighBits = packed & PACKED_HIGH_BIT_5;
            uint256 invalidLow31 =
                ((packed & PACKED_LOW_31_5) + _packedModulus(KB_FOLD_FACTOR)) & PACKED_HIGH_BIT_5;
            return ((packed & EXT5_LOW_96_MASK) | invalidHighBits | invalidLow31) == 0;
        }
    }

    function _mulPackedMod(uint256 a, uint256 b, uint256 modulus)
        private
        pure
        returns (uint256 out)
    {
        (uint256 a0, uint256 a1, uint256 a2, uint256 a3, uint256 a4) = _unpack5(a);
        (uint256 b0, uint256 b1, uint256 b2, uint256 b3, uint256 b4) = _unpack5(b);

        unchecked {
            uint256 c0 = a0 * b0;
            uint256 c1 = a0 * b1 + a1 * b0;
            uint256 c2 = a0 * b2 + a1 * b1 + a2 * b0;
            uint256 c3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0;
            uint256 c4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;
            uint256 c5 = a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1;
            uint256 c6 = a2 * b4 + a3 * b3 + a4 * b2;
            uint256 c7 = a3 * b4 + a4 * b3;
            uint256 c8 = a4 * b4;
            uint256 bias = modulus << 35;
            out = ((c0 + c5 + bias - c8) % modulus) << 224 | ((c1 + c6) % modulus) << 192
                | ((c2 + bias - c5 + c7 + c8) % modulus) << 160 | ((c3 + bias - c6 + c8) % modulus)
                << 128 | ((c4 + bias - c7) % modulus) << 96;
        }
    }

    function _mulPackedAsm(uint256 a, uint256 b) private pure returns (uint256 out) {
        assembly ("memory-safe") {
            let M := 0x7f000001
            let mask := 0xffffffff

            let a0 := shr(224, a)
            let a1 := and(shr(192, a), mask)
            let a2 := and(shr(160, a), mask)
            let a3 := and(shr(128, a), mask)
            let a4 := and(shr(96, a), mask)

            let b0 := shr(224, b)
            let b1 := and(shr(192, b), mask)
            let b2 := and(shr(160, b), mask)
            let b3 := and(shr(128, b), mask)
            let b4 := and(shr(96, b), mask)

            let c0 := mul(a0, b0)
            let c1 := add(mul(a0, b1), mul(a1, b0))
            let c2 := add(add(mul(a0, b2), mul(a1, b1)), mul(a2, b0))
            let c3 := add(add(add(mul(a0, b3), mul(a1, b2)), mul(a2, b1)), mul(a3, b0))
            let c4 :=
                add(add(add(add(mul(a0, b4), mul(a1, b3)), mul(a2, b2)), mul(a3, b1)), mul(a4, b0))
            let c5 := add(add(add(mul(a1, b4), mul(a2, b3)), mul(a3, b2)), mul(a4, b1))
            let c6 := add(add(mul(a2, b4), mul(a3, b3)), mul(a4, b2))
            let c7 := add(mul(a3, b4), mul(a4, b3))
            let c8 := mul(a4, b4)
            let bias := shl(35, M)

            out := or(
                or(
                    or(
                        shl(224, mod(add(add(c0, c5), sub(bias, c8)), M)),
                        shl(192, mod(add(c1, c6), M))
                    ),
                    or(
                        shl(160, mod(add(add(add(c2, sub(bias, c5)), c7), c8), M)),
                        shl(128, mod(add(add(c3, sub(bias, c6)), c8), M))
                    )
                ),
                shl(96, mod(add(c4, sub(bias, c7)), M))
            )
        }
    }

    function _mulPackedSol(uint256 a, uint256 b) private pure returns (uint256 out) {
        unchecked {
            uint256 a0 = a >> 224;
            uint256 a1 = (a >> 192) & COEFF_MASK;
            uint256 a2 = (a >> 160) & COEFF_MASK;
            uint256 a3 = (a >> 128) & COEFF_MASK;
            uint256 a4 = (a >> 96) & COEFF_MASK;

            uint256 b0 = b >> 224;
            uint256 b1 = (b >> 192) & COEFF_MASK;
            uint256 b2 = (b >> 160) & COEFF_MASK;
            uint256 b3 = (b >> 128) & COEFF_MASK;
            uint256 b4 = (b >> 96) & COEFF_MASK;

            uint256 c0 = a0 * b0;
            uint256 c1 = a0 * b1 + a1 * b0;
            uint256 c2 = a0 * b2 + a1 * b1 + a2 * b0;
            uint256 c3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0;
            uint256 c4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;
            uint256 c5 = a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1;
            uint256 c6 = a2 * b4 + a3 * b3 + a4 * b2;
            uint256 c7 = a3 * b4 + a4 * b3;
            uint256 c8 = a4 * b4;
            uint256 bias = KB_MODULUS << 35;

            out = (((c0 + c5 + bias - c8) % KB_MODULUS) << 224) | (((c1 + c6) % KB_MODULUS) << 192)
                | (((c2 + bias - c5 + c7 + c8) % KB_MODULUS) << 160)
                | (((c3 + bias - c6 + c8) % KB_MODULUS) << 128)
                | (((c4 + bias - c7) % KB_MODULUS) << 96);
        }
    }

    function _squarePackedAsm(uint256 a) private pure returns (uint256 out) {
        assembly ("memory-safe") {
            let M := 0x7f000001
            let mask := 0xffffffff

            let a0 := shr(224, a)
            let a1 := and(shr(192, a), mask)
            let a2 := and(shr(160, a), mask)
            let a3 := and(shr(128, a), mask)
            let a4 := and(shr(96, a), mask)

            let a0a0 := mul(a0, a0)
            let a0a1 := mul(a0, a1)
            let a0a2 := mul(a0, a2)
            let a0a3 := mul(a0, a3)
            let a0a4 := mul(a0, a4)
            let a1a1 := mul(a1, a1)
            let a1a2 := mul(a1, a2)
            let a1a3 := mul(a1, a3)
            let a1a4 := mul(a1, a4)
            let a2a2 := mul(a2, a2)
            let a2a3 := mul(a2, a3)
            let a2a4 := mul(a2, a4)
            let a3a3 := mul(a3, a3)
            let a3a4 := mul(a3, a4)
            let a4a4 := mul(a4, a4)

            let c0 := a0a0
            let c1 := shl(1, a0a1)
            let c2 := add(shl(1, a0a2), a1a1)
            let c3 := add(shl(1, a0a3), shl(1, a1a2))
            let c4 := add(add(shl(1, a0a4), shl(1, a1a3)), a2a2)
            let c5 := add(shl(1, a1a4), shl(1, a2a3))
            let c6 := add(shl(1, a2a4), a3a3)
            let c7 := shl(1, a3a4)
            let c8 := a4a4
            let bias := shl(35, M)

            out := or(
                or(
                    or(
                        shl(224, mod(add(add(c0, c5), sub(bias, c8)), M)),
                        shl(192, mod(add(c1, c6), M))
                    ),
                    or(
                        shl(160, mod(add(add(add(c2, sub(bias, c5)), c7), c8), M)),
                        shl(128, mod(add(add(c3, sub(bias, c6)), c8), M))
                    )
                ),
                shl(96, mod(add(c4, sub(bias, c7)), M))
            )
        }
    }

    function _squarePackedSol(uint256 a) private pure returns (uint256 out) {
        unchecked {
            uint256 a0 = a >> 224;
            uint256 a1 = (a >> 192) & COEFF_MASK;
            uint256 a2 = (a >> 160) & COEFF_MASK;
            uint256 a3 = (a >> 128) & COEFF_MASK;
            uint256 a4 = (a >> 96) & COEFF_MASK;

            uint256 a0a0 = a0 * a0;
            uint256 a0a1 = a0 * a1;
            uint256 a0a2 = a0 * a2;
            uint256 a0a3 = a0 * a3;
            uint256 a0a4 = a0 * a4;
            uint256 a1a1 = a1 * a1;
            uint256 a1a2 = a1 * a2;
            uint256 a1a3 = a1 * a3;
            uint256 a1a4 = a1 * a4;
            uint256 a2a2 = a2 * a2;
            uint256 a2a3 = a2 * a3;
            uint256 a2a4 = a2 * a4;
            uint256 a3a3 = a3 * a3;
            uint256 a3a4 = a3 * a4;
            uint256 a4a4 = a4 * a4;

            uint256 c0 = a0a0;
            uint256 c1 = a0a1 << 1;
            uint256 c2 = (a0a2 << 1) + a1a1;
            uint256 c3 = (a0a3 << 1) + (a1a2 << 1);
            uint256 c4 = (a0a4 << 1) + (a1a3 << 1) + a2a2;
            uint256 c5 = (a1a4 << 1) + (a2a3 << 1);
            uint256 c6 = (a2a4 << 1) + a3a3;
            uint256 c7 = a3a4 << 1;
            uint256 c8 = a4a4;
            uint256 bias = KB_MODULUS << 35;

            out = (((c0 + c5 + bias - c8) % KB_MODULUS) << 224) | (((c1 + c6) % KB_MODULUS) << 192)
                | (((c2 + bias - c5 + c7 + c8) % KB_MODULUS) << 160)
                | (((c3 + bias - c6 + c8) % KB_MODULUS) << 128)
                | (((c4 + bias - c7) % KB_MODULUS) << 96);
        }
    }

    function _scalarMulAsm(uint256 a, uint256 scalar) private pure returns (uint256 out) {
        assembly ("memory-safe") {
            let modulus := 0x7f000001
            let mask := 0xffffffff
            out := or(
                or(
                    or(
                        shl(224, mulmod(shr(224, a), scalar, modulus)),
                        shl(192, mulmod(and(shr(192, a), mask), scalar, modulus))
                    ),
                    or(
                        shl(160, mulmod(and(shr(160, a), mask), scalar, modulus)),
                        shl(128, mulmod(and(shr(128, a), mask), scalar, modulus))
                    )
                ),
                shl(96, mulmod(and(shr(96, a), mask), scalar, modulus))
            )
        }
    }

    function _scalarMulSol(uint256 a, uint256 scalar) private pure returns (uint256 out) {
        unchecked {
            out = ((((a >> 224) * scalar) % KB_MODULUS) << 224)
                | (((((a >> 192) & COEFF_MASK) * scalar) % KB_MODULUS) << 192)
                | (((((a >> 160) & COEFF_MASK) * scalar) % KB_MODULUS) << 160)
                | (((((a >> 128) & COEFF_MASK) * scalar) % KB_MODULUS) << 128)
                | (((((a >> 96) & COEFF_MASK) * scalar) % KB_MODULUS) << 96);
        }
    }

    function _addPackedMod(uint256 a, uint256 b, uint256 modulus)
        private
        pure
        returns (uint256 out)
    {
        uint256 sum = a + b;
        out = ((sum >> 224) % modulus) << 224 | (((sum >> 192) & COEFF_MASK) % modulus) << 192
            | (((sum >> 160) & COEFF_MASK) % modulus) << 160
            | (((sum >> 128) & COEFF_MASK) % modulus) << 128
            | (((sum >> 96) & COEFF_MASK) % modulus) << 96;
    }

    function _subPackedMod(uint256 a, uint256 b, uint256 modulus)
        private
        pure
        returns (uint256 out)
    {
        uint256 tmp = a + _packedModulus(modulus) - b;
        out = ((tmp >> 224) % modulus) << 224 | (((tmp >> 192) & COEFF_MASK) % modulus) << 192
            | (((tmp >> 160) & COEFF_MASK) % modulus) << 160
            | (((tmp >> 128) & COEFF_MASK) % modulus) << 128
            | (((tmp >> 96) & COEFF_MASK) % modulus) << 96;
    }

    function _addPackedMask(uint256 a, uint256 b, uint256 modulus) private pure returns (uint256) {
        return _canonicalizePackedSmall(a + b, modulus);
    }

    function _subPackedMask(uint256 a, uint256 b, uint256 modulus) private pure returns (uint256) {
        return _canonicalizePackedSmall(a + _packedModulus(modulus) - b, modulus);
    }

    function _canonicalizePackedSmall(uint256 packed, uint256 modulus)
        private
        pure
        returns (uint256 out)
    {
        unchecked {
            uint256 bias = _packedModulus(0x80000000 - modulus);
            uint256 highBits = (packed + bias) & PACKED_HIGH_BIT_5;
            uint256 subtract = (highBits >> 31) * modulus;
            out = (packed - subtract) & ~EXT5_LOW_96_MASK;
        }
    }

    function _packedModulus(uint256 modulus) private pure returns (uint256) {
        return
            (modulus << 224) | (modulus << 192) | (modulus << 160) | (modulus << 128)
                | (modulus << 96);
    }

    function _packed16(uint256 salt, uint256 modulus)
        private
        pure
        returns (uint256[16] memory out)
    {
        unchecked {
            for (uint256 i = 0; i < DIM4_ROW_VALUES; ++i) {
                uint256 s = uint256(keccak256(abi.encodePacked(salt, i, modulus)));
                out[i] = _pack5(
                    (s + 0x11) % modulus,
                    (s >> 17) % modulus,
                    (s >> 29) % modulus,
                    (s >> 41) % modulus,
                    (s >> 53) % modulus
                );
            }
        }
    }

    function _point(uint256 salt, uint256 modulus, uint256 idx)
        private
        pure
        returns (uint256 r0, uint256 r1, uint256 r2, uint256 r3, uint256 r4)
    {
        uint256 s = uint256(keccak256(abi.encodePacked("point", salt, idx, modulus)));
        unchecked {
            r0 = (s >> 3) % modulus;
            r1 = (s >> 5) % modulus;
            r2 = (s >> 9) % modulus;
            r3 = (s >> 13) % modulus;
            r4 = (s >> 21) % modulus;
        }
    }

    function _unpack5(uint256 packed)
        private
        pure
        returns (uint256 c0, uint256 c1, uint256 c2, uint256 c3, uint256 c4)
    {
        c0 = packed >> 224;
        c1 = (packed >> 192) & COEFF_MASK;
        c2 = (packed >> 160) & COEFF_MASK;
        c3 = (packed >> 128) & COEFF_MASK;
        c4 = (packed >> 96) & COEFF_MASK;
    }

    function _seeds(uint256 salt, uint256 modulus)
        private
        pure
        returns (uint256 a0, uint256 a1, uint256 r0, uint256 r1, uint256 r2, uint256 r3, uint256 r4)
    {
        unchecked {
            uint256 s = uint256(keccak256(abi.encodePacked(salt, modulus)));
            a0 = _pack5(
                (s + 0x11) % modulus,
                (s >> 17) % modulus,
                (s >> 29) % modulus,
                (s >> 41) % modulus,
                (s >> 53) % modulus
            );
            a1 = _pack5(
                (s >> 7) % modulus,
                (s >> 19) % modulus,
                (s >> 31) % modulus,
                (s >> 43) % modulus,
                (s >> 59) % modulus
            );
            r0 = (s >> 3) % modulus;
            r1 = (s >> 5) % modulus;
            r2 = (s >> 9) % modulus;
            r3 = (s >> 13) % modulus;
            r4 = (s >> 21) % modulus;
        }
    }

    function _pack5(uint256 c0, uint256 c1, uint256 c2, uint256 c3, uint256 c4)
        private
        pure
        returns (uint256)
    {
        return (c0 << 224) | (c1 << 192) | (c2 << 160) | (c3 << 128) | (c4 << 96);
    }
}

contract SwarReductionQuinticKernelBenchmarkTest is Test {
    SwarReductionQuinticKernelHarness internal harness;

    function setUp() external {
        harness = new SwarReductionQuinticKernelHarness();
    }

    function testBitfoldReducersMatchModOnKernelBounds() external view {
        uint256[8] memory values = [
            uint256(0),
            uint256(1),
            uint256(0x7f000000),
            uint256(0x7f000001),
            uint256(0x7fffffff),
            uint256(1 << 62),
            uint256(1 << 67) - 1,
            uint256(1 << 68) - 1
        ];

        for (uint256 i = 0; i < values.length; ++i) {
            assertEq(harness.reduceKbBitfoldPublic(values[i]), values[i] % 0x7f000001);
            assertEq(harness.reduceM31BitfoldPublic(values[i]), values[i] % 0x7fffffff);
        }
    }

    function testBitfoldFoldsMatchModFolds() external view {
        for (uint256 i = 0; i < 16; ++i) {
            (
                uint256 kbA0,
                uint256 kbA1,
                uint256 kbR0,
                uint256 kbR1,
                uint256 kbR2,
                uint256 kbR3,
                uint256 kbR4
            ) = _seedsForTest(i, 0x7f000001);
            assertEq(
                harness.foldKbBitfoldPublic(kbA0, kbA1, kbR0, kbR1, kbR2, kbR3, kbR4),
                harness.foldKbModPublic(kbA0, kbA1, kbR0, kbR1, kbR2, kbR3, kbR4)
            );

            (
                uint256 m31A0,
                uint256 m31A1,
                uint256 m31R0,
                uint256 m31R1,
                uint256 m31R2,
                uint256 m31R3,
                uint256 m31R4
            ) = _seedsForTest(i, 0x7fffffff);
            assertEq(
                harness.foldM31BitfoldPublic(m31A0, m31A1, m31R0, m31R1, m31R2, m31R3, m31R4),
                harness.foldM31ModPublic(m31A0, m31A1, m31R0, m31R1, m31R2, m31R3, m31R4)
            );
        }
    }

    function testPackedMaskAddSubMatchesMod() external view {
        for (uint256 i = 0; i < 16; ++i) {
            (uint256 kbA0, uint256 kbA1,,,,,) = _seedsForTest(i, 0x7f000001);
            assertEq(
                harness.addPackedMaskPublic(kbA0, kbA1, 0x7f000001),
                harness.addPackedModPublic(kbA0, kbA1, 0x7f000001)
            );
            assertEq(
                harness.subPackedMaskPublic(kbA0, kbA1, 0x7f000001),
                harness.subPackedModPublic(kbA0, kbA1, 0x7f000001)
            );

            (uint256 m31A0, uint256 m31A1,,,,,) = _seedsForTest(i, 0x7fffffff);
            assertEq(
                harness.addPackedMaskPublic(m31A0, m31A1, 0x7fffffff),
                harness.addPackedModPublic(m31A0, m31A1, 0x7fffffff)
            );
            assertEq(
                harness.subPackedMaskPublic(m31A0, m31A1, 0x7fffffff),
                harness.subPackedModPublic(m31A0, m31A1, 0x7fffffff)
            );
        }
    }

    function testPackedExt5MaskValidationMatchesScalar() external view {
        uint256 modulus = 0x7f000001;
        uint256[8] memory cases = [
            _pack5(0, 1, 2, 3, 4),
            _pack5(modulus - 1, modulus - 1, modulus - 1, modulus - 1, modulus - 1),
            _pack5(modulus, 0, 0, 0, 0),
            _pack5(0, 0x7fffffff, 0, 0, 0),
            _pack5(0, 0, 0x80000000, 0, 0),
            _pack5(0, 0, 0, 0xffffffff, 0),
            _pack5(0, 0, 0, 0, modulus) | 1,
            _pack5(0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff)
                | ((uint256(1) << 96) - 1)
        ];

        for (uint256 i = 0; i < cases.length; ++i) {
            assertEq(
                harness.validatePackedExt5MaskPublic(cases[i]),
                harness.validatePackedExt5ScalarPublic(cases[i])
            );
        }

        for (uint256 i = 0; i < 32; ++i) {
            uint256 s = uint256(keccak256(abi.encodePacked("invalid", i)));
            uint256 packed = _pack5(s, s >> 32, s >> 64, s >> 96, s >> 128) | (s >> 160);
            assertEq(
                harness.validatePackedExt5MaskPublic(packed),
                harness.validatePackedExt5ScalarPublic(packed)
            );
        }
    }

    function testSolidityTwinsMatchAssemblyArithmetic() external view {
        for (uint256 i = 0; i < 16; ++i) {
            (uint256 a, uint256 b, uint256 r0, uint256 r1, uint256 r2, uint256 r3, uint256 r4) =
                _seedsForTest(i, 0x7f000001);
            assertEq(harness.mulPackedSolPublic(a, b), harness.mulPackedAsmPublic(a, b));
            assertEq(harness.squarePackedSolPublic(a), harness.squarePackedAsmPublic(a));
            assertEq(harness.scalarMulSolPublic(a, r0), harness.scalarMulAsmPublic(a, r0));
            assertEq(
                harness.foldKbModSolPublic(a, b, r0, r1, r2, r3, r4),
                harness.foldKbModPublic(a, b, r0, r1, r2, r3, r4)
            );
        }
    }

    function testProfileQuinticFoldKernelReducers() external view {
        (uint256 kbModGas, uint256 kbModAcc) = harness.benchKbFoldMod(0xabc123);
        (uint256 kbBitfoldGas, uint256 kbBitfoldAcc) = harness.benchKbFoldBitfold(0xabc123);
        (uint256 m31ModGas, uint256 m31ModAcc) = harness.benchM31FoldMod(0xabc123);
        (uint256 m31BitfoldGas, uint256 m31BitfoldAcc) = harness.benchM31FoldBitfold(0xabc123);

        assertEq(kbBitfoldAcc, kbModAcc);
        assertEq(m31BitfoldAcc, m31ModAcc);

        console.log("quintic fold KB mod:       ", kbModGas);
        console.log("quintic fold KB bitfold:   ", kbBitfoldGas);
        console.log("quintic fold M31 mod:      ", m31ModGas);
        console.log("quintic fold M31 bitfold:  ", m31BitfoldGas);
    }

    function testProfileDim4RowFoldReducers() external view {
        (uint256 kbModGas, uint256 kbModAcc) = harness.benchKbDim4RowFoldMod(0xabc123);
        (uint256 kbBitfoldGas, uint256 kbBitfoldAcc) = harness.benchKbDim4RowFoldBitfold(0xabc123);
        (uint256 m31ModGas, uint256 m31ModAcc) = harness.benchM31Dim4RowFoldMod(0xabc123);
        (uint256 m31BitfoldGas, uint256 m31BitfoldAcc) =
            harness.benchM31Dim4RowFoldBitfold(0xabc123);

        assertEq(kbBitfoldAcc, kbModAcc);
        assertEq(m31BitfoldAcc, m31ModAcc);

        console.log("dim4 row folds:            ", uint256(15));
        console.log("dim4 row values:           ", uint256(16));
        console.log("dim4 row KB mod:           ", kbModGas);
        console.log("dim4 row KB bitfold:       ", kbBitfoldGas);
        console.log("dim4 row M31 mod:          ", m31ModGas);
        console.log("dim4 row M31 bitfold:      ", m31BitfoldGas);
    }

    function testProfileDot16LazyReduction() external view {
        (uint256 kbEagerGas, uint256 kbEagerAcc) = harness.benchKbDot16Eager(0xabc123);
        (uint256 kbLazyGas, uint256 kbLazyAcc) = harness.benchKbDot16Lazy(0xabc123);
        (uint256 m31EagerGas, uint256 m31EagerAcc) = harness.benchM31Dot16Eager(0xabc123);
        (uint256 m31LazyGas, uint256 m31LazyAcc) = harness.benchM31Dot16Lazy(0xabc123);

        assertEq(kbLazyAcc, kbEagerAcc);
        assertEq(m31LazyAcc, m31EagerAcc);

        console.log("dot batch values:          ", uint256(16));
        console.log("dot KB eager:              ", kbEagerGas);
        console.log("dot KB lazy:               ", kbLazyGas);
        console.log("dot M31 eager:             ", m31EagerGas);
        console.log("dot M31 lazy:              ", m31LazyGas);
    }

    function testProfilePackedAddSubBatch16() external view {
        (uint256 kbModGas, uint256 kbModAcc) = harness.benchKbPackedAddSub16Mod(0xabc123);
        (uint256 kbMaskGas, uint256 kbMaskAcc) = harness.benchKbPackedAddSub16Mask(0xabc123);
        (uint256 m31ModGas, uint256 m31ModAcc) = harness.benchM31PackedAddSub16Mod(0xabc123);
        (uint256 m31MaskGas, uint256 m31MaskAcc) = harness.benchM31PackedAddSub16Mask(0xabc123);

        assertEq(kbMaskAcc, kbModAcc);
        assertEq(m31MaskAcc, m31ModAcc);

        console.log("packed add/sub values:     ", uint256(16));
        console.log("packed add/sub coeff lanes:", uint256(80));
        console.log("packed add/sub KB mod:     ", kbModGas);
        console.log("packed add/sub KB mask:    ", kbMaskGas);
        console.log("packed add/sub M31 mod:    ", m31ModGas);
        console.log("packed add/sub M31 mask:   ", m31MaskGas);
    }

    function testProfilePackedExt5ValidationBatch16() external view {
        (uint256 scalarGas, uint256 scalarAcc) = harness.benchValidatePackedExt5Scalar16(0xabc123);
        (uint256 maskGas, uint256 maskAcc) = harness.benchValidatePackedExt5Mask16(0xabc123);

        assertEq(maskAcc, scalarAcc);

        console.log("packed ext5 validation values:", uint256(16));
        console.log("packed ext5 validation lanes: ", uint256(80));
        console.log("packed ext5 validation scalar:", scalarGas);
        console.log("packed ext5 validation mask:  ", maskGas);
    }

    function testProfileAsmVsSolidityExt5Arithmetic() external view {
        (uint256 mulAsmGas, uint256 mulAsmAcc) = harness.benchKbMulPackedAsm16(0xabc123);
        (uint256 mulSolGas, uint256 mulSolAcc) = harness.benchKbMulPackedSol16(0xabc123);
        (uint256 squareAsmGas, uint256 squareAsmAcc) = harness.benchKbSquarePackedAsm16(0xabc123);
        (uint256 squareSolGas, uint256 squareSolAcc) = harness.benchKbSquarePackedSol16(0xabc123);
        (uint256 scalarAsmGas, uint256 scalarAsmAcc) = harness.benchKbScalarMulAsm16(0xabc123);
        (uint256 scalarSolGas, uint256 scalarSolAcc) = harness.benchKbScalarMulSol16(0xabc123);
        (uint256 foldAsmGas, uint256 foldAsmAcc) = harness.benchKbFoldMod(0xabc123);
        (uint256 foldSolGas, uint256 foldSolAcc) = harness.benchKbFoldModSol(0xabc123);

        assertEq(mulSolAcc, mulAsmAcc);
        assertEq(squareSolAcc, squareAsmAcc);
        assertEq(scalarSolAcc, scalarAsmAcc);
        assertEq(foldSolAcc, foldAsmAcc);

        console.log("ext5 mul asm:               ", mulAsmGas);
        console.log("ext5 mul solidity:          ", mulSolGas);
        console.log("ext5 square asm:            ", squareAsmGas);
        console.log("ext5 square solidity:       ", squareSolGas);
        console.log("ext5 scalar mul asm:        ", scalarAsmGas);
        console.log("ext5 scalar mul solidity:   ", scalarSolGas);
        console.log("ext5 fold asm:              ", foldAsmGas);
        console.log("ext5 fold solidity:         ", foldSolGas);
    }

    function _seedsForTest(uint256 salt, uint256 modulus)
        private
        pure
        returns (uint256 a0, uint256 a1, uint256 r0, uint256 r1, uint256 r2, uint256 r3, uint256 r4)
    {
        unchecked {
            uint256 s = uint256(keccak256(abi.encodePacked("test", salt, modulus)));
            a0 = _pack5(
                (s + 0x11) % modulus,
                (s >> 17) % modulus,
                (s >> 29) % modulus,
                (s >> 41) % modulus,
                (s >> 53) % modulus
            );
            a1 = _pack5(
                (s >> 7) % modulus,
                (s >> 19) % modulus,
                (s >> 31) % modulus,
                (s >> 43) % modulus,
                (s >> 59) % modulus
            );
            r0 = (s >> 3) % modulus;
            r1 = (s >> 5) % modulus;
            r2 = (s >> 9) % modulus;
            r3 = (s >> 13) % modulus;
            r4 = (s >> 21) % modulus;
        }
    }

    function _pack5(uint256 c0, uint256 c1, uint256 c2, uint256 c3, uint256 c4)
        private
        pure
        returns (uint256)
    {
        return (c0 << 224) | (c1 << 192) | (c2 << 160) | (c3 << 128) | (c4 << 96);
    }
}
