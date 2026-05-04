// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { KoalaBearExt5 } from "../../src/field/KoalaBearExt5.sol";
import { KoalaBearExt5Precompile } from "../../src/field/KoalaBearExt5Precompile.sol";

contract Ext5PrecompileHarness {
    uint256 public lastResult;

    function softwareMul(uint256 a, uint256 b) external pure returns (uint256) {
        return KoalaBearExt5.mul(a, b);
    }

    function precompileMul(uint256 a, uint256 b) external view returns (uint256) {
        return KoalaBearExt5Precompile.mul(a, b);
    }

    function softwareSquare(uint256 a) external pure returns (uint256) {
        return KoalaBearExt5.square(a);
    }

    function precompileSquare(uint256 a) external view returns (uint256) {
        return KoalaBearExt5Precompile.square(a);
    }

    function noopMulClean(uint256 a, uint256 b) external view returns (uint256) {
        return KoalaBearExt5Precompile.noopMul(a, b);
    }

    function noopSquareClean(uint256 a) external view returns (uint256) {
        return KoalaBearExt5Precompile.noopSquare(a);
    }

    function benchmarkNoopMulClean(uint256 a, uint256 b) external {
        lastResult = KoalaBearExt5Precompile.noopMul(a, b);
    }

    function benchmarkNoopSquareClean(uint256 a) external {
        lastResult = KoalaBearExt5Precompile.noopSquare(a);
    }

    function benchmarkMulClean(uint256 a, uint256 b) external {
        lastResult = KoalaBearExt5Precompile.mul(a, b);
    }

    function benchmarkSquareClean(uint256 a) external {
        lastResult = KoalaBearExt5Precompile.square(a);
    }

    function checkArithmeticVectorsTx(
        uint256[] calldata packedA,
        uint256[] calldata packedB,
        uint256[] calldata expectedMul,
        uint256[] calldata expectedSquareA
    ) external returns (bool) {
        bool ok = _checkArithmeticVectors(packedA, packedB, expectedMul, expectedSquareA);
        lastResult = ok ? KoalaBearExt5.ONE : 0;
        return ok;
    }

    function checkExtendedArithmeticVectorsTx(
        uint256[] calldata packedA,
        uint256[] calldata packedB,
        uint256[] calldata scalars,
        uint256[] calldata expectedAdd,
        uint256[] calldata expectedSub,
        uint256[] calldata expectedMul,
        uint256[] calldata expectedSquareA,
        uint256[] calldata expectedMulBase
    ) external returns (bool) {
        bool ok = _checkExtendedArithmeticVectors(
            packedA,
            packedB,
            scalars,
            expectedAdd,
            expectedSub,
            expectedMul,
            expectedSquareA,
            expectedMulBase
        );
        lastResult = ok ? KoalaBearExt5.ONE : 0;
        return ok;
    }

    function benchmarkMulBatch(uint256[] calldata packedA, uint256[] calldata packedB) external {
        lastResult =
            _consumeBatchOutput(KoalaBearExt5Precompile.mulBatch(_packPairs(packedA, packedB)));
    }

    function benchmarkNoopMulBatch(uint256[] calldata packedA, uint256[] calldata packedB)
        external
    {
        lastResult = _consumeBatchOutput(
            KoalaBearExt5Precompile.noopBatch64To32(_packPairs(packedA, packedB))
        );
    }

    function benchmarkSquareBatch(uint256[] calldata packedA) external {
        lastResult = _consumeBatchOutput(KoalaBearExt5Precompile.squareBatch(_packSingles(packedA)));
    }

    function benchmarkNoopSquareBatch(uint256[] calldata packedA) external {
        lastResult =
            _consumeBatchOutput(KoalaBearExt5Precompile.noopBatch32To32(_packSingles(packedA)));
    }

    function _checkArithmeticVectors(
        uint256[] calldata packedA,
        uint256[] calldata packedB,
        uint256[] calldata expectedMul,
        uint256[] calldata expectedSquareA
    ) internal view returns (bool) {
        uint256 len = packedA.length;
        require(len == packedB.length, "LEN_B");
        require(len == expectedMul.length, "LEN_MUL");
        require(len == expectedSquareA.length, "LEN_SQ");

        unchecked {
            for (uint256 i = 0; i < len; ++i) {
                if (KoalaBearExt5.mul(packedA[i], packedB[i]) != expectedMul[i]) {
                    revert("SOFTWARE_MUL");
                }
                if (KoalaBearExt5Precompile.mul(packedA[i], packedB[i]) != expectedMul[i]) {
                    revert("PRECOMPILE_MUL");
                }
                if (KoalaBearExt5.square(packedA[i]) != expectedSquareA[i]) {
                    revert("SOFTWARE_SQUARE");
                }
                if (KoalaBearExt5Precompile.square(packedA[i]) != expectedSquareA[i]) {
                    revert("PRECOMPILE_SQUARE");
                }
            }
        }
        return true;
    }

    function _checkExtendedArithmeticVectors(
        uint256[] calldata packedA,
        uint256[] calldata packedB,
        uint256[] calldata scalars,
        uint256[] calldata expectedAdd,
        uint256[] calldata expectedSub,
        uint256[] calldata expectedMul,
        uint256[] calldata expectedSquareA,
        uint256[] calldata expectedMulBase
    ) internal view returns (bool) {
        uint256 len = packedA.length;
        require(len == packedB.length, "LEN_B");
        require(len == scalars.length, "LEN_SCALAR");
        require(len == expectedAdd.length, "LEN_ADD");
        require(len == expectedSub.length, "LEN_SUB");
        require(len == expectedMul.length, "LEN_MUL");
        require(len == expectedSquareA.length, "LEN_SQ");
        require(len == expectedMulBase.length, "LEN_MUL_BASE");

        unchecked {
            for (uint256 i = 0; i < len; ++i) {
                uint256 a = packedA[i];
                uint256 b = packedB[i];
                uint256 scalar = scalars[i];
                if (KoalaBearExt5.add(a, b) != expectedAdd[i]) revert("SOFTWARE_ADD");
                if (KoalaBearExt5Precompile.addViaPrecompile(a, b) != expectedAdd[i]) {
                    revert("PRECOMPILE_ADD");
                }
                if (KoalaBearExt5.sub(a, b) != expectedSub[i]) revert("SOFTWARE_SUB");
                if (KoalaBearExt5Precompile.subViaPrecompile(a, b) != expectedSub[i]) {
                    revert("PRECOMPILE_SUB");
                }
                if (KoalaBearExt5.mul(a, b) != expectedMul[i]) revert("SOFTWARE_MUL");
                if (KoalaBearExt5Precompile.mul(a, b) != expectedMul[i]) {
                    revert("PRECOMPILE_MUL");
                }
                if (KoalaBearExt5.square(a) != expectedSquareA[i]) revert("SOFTWARE_SQUARE");
                if (KoalaBearExt5Precompile.square(a) != expectedSquareA[i]) {
                    revert("PRECOMPILE_SQUARE");
                }
                if (KoalaBearExt5.mulBase(a, scalar) != expectedMulBase[i]) {
                    revert("SOFTWARE_MUL_BASE");
                }
                if (KoalaBearExt5Precompile.mulBaseViaPrecompile(a, scalar) != expectedMulBase[i]) {
                    revert("PRECOMPILE_MUL_BASE");
                }
            }
        }

        _checkBatchOutput(
            KoalaBearExt5Precompile.mulBatch(_packPairs(packedA, packedB)), expectedMul
        );
        _checkBatchOutput(
            KoalaBearExt5Precompile.squareBatch(_packSingles(packedA)), expectedSquareA
        );
        _checkBatchOutput(
            KoalaBearExt5Precompile.mulBaseBatch(_packPairs(packedA, scalars)), expectedMulBase
        );
        return true;
    }

    function _packPairs(uint256[] calldata left, uint256[] calldata right)
        internal
        pure
        returns (bytes memory out)
    {
        uint256 len = left.length;
        require(len == right.length, "LEN_PAIR");
        out = new bytes(len << 6);
        assembly ("memory-safe") {
            let dst := add(out, 0x20)
            let leftOffset := left.offset
            let rightOffset := right.offset
            for { let i := 0 } lt(i, len) { i := add(i, 1) } {
                mstore(dst, calldataload(add(leftOffset, shl(5, i))))
                mstore(add(dst, 0x20), calldataload(add(rightOffset, shl(5, i))))
                dst := add(dst, 0x40)
            }
        }
    }

    function _packSingles(uint256[] calldata values) internal pure returns (bytes memory out) {
        uint256 len = values.length;
        out = new bytes(len << 5);
        assembly ("memory-safe") {
            calldatacopy(add(out, 0x20), values.offset, shl(5, len))
        }
    }

    function _checkBatchOutput(bytes memory output, uint256[] calldata expected) internal pure {
        uint256 len = expected.length;
        require(output.length == len << 5, "OUT_LEN");
        assembly ("memory-safe") {
            let ptr := add(output, 0x20)
            let expectedOffset := expected.offset
            for { let i := 0 } lt(i, len) { i := add(i, 1) } {
                if iszero(
                    eq(mload(add(ptr, shl(5, i))), calldataload(add(expectedOffset, shl(5, i))))
                ) {
                    mstore(0, 0x4f55545055540000000000000000000000000000000000000000000000000000)
                    revert(0, 0x20)
                }
            }
        }
    }

    function _consumeBatchOutput(bytes memory output) internal pure returns (uint256 acc) {
        uint256 len = output.length >> 5;
        unchecked {
            for (uint256 i = 0; i < len; ++i) {
                uint256 value;
                assembly ("memory-safe") {
                    value := mload(add(add(output, 0x20), shl(5, i)))
                }
                acc = KoalaBearExt5.add(acc, value);
            }
        }
    }
}
