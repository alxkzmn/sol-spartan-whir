// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { KoalaBear } from "../../src/field/KoalaBear.sol";
import { KoalaBearExt8 } from "../../src/field/KoalaBearExt8.sol";
import { KoalaBearExt8Precompile } from "../../src/field/KoalaBearExt8Precompile.sol";
import { WhirVerifierCore8 } from "../../src/whir/k22_jb100_lir6_ff4_rsv1/WhirVerifierCore8.sol";
import {
    WhirVerifierCore8PrecompilePhase1
} from "../../src/whir/k22_jb100_lir6_ff4_rsv1_precompile_phase1/WhirVerifierCore8PrecompilePhase1.sol";
import { WhirVerifierUtils8 } from "../../src/whir/k22_jb100_lir6_ff4_rsv1/WhirVerifierUtils8.sol";

contract Ext8PrecompileHarness {
    uint256 internal constant EXT8_ROW_BYTES = 512;

    uint256 public lastResult;

    function softwareMul(uint256 a, uint256 b) external pure returns (uint256) {
        return KoalaBearExt8.mul(a, b);
    }

    function precompileMul(uint256 a, uint256 b) external view returns (uint256) {
        return KoalaBearExt8Precompile.mul(a, b);
    }

    function softwareSquare(uint256 a) external pure returns (uint256) {
        return KoalaBearExt8.square(a);
    }

    function precompileSquare(uint256 a) external view returns (uint256) {
        return KoalaBearExt8Precompile.square(a);
    }

    function noopMulClean(uint256 a, uint256 b) external view returns (uint256) {
        return KoalaBearExt8Precompile.noopMul(a, b);
    }

    function noopSquareClean(uint256 a) external view returns (uint256) {
        return KoalaBearExt8Precompile.noopSquare(a);
    }

    function benchmarkNoopMulClean(uint256 a, uint256 b) external {
        lastResult = KoalaBearExt8Precompile.noopMul(a, b);
    }

    function benchmarkNoopSquareClean(uint256 a) external {
        lastResult = KoalaBearExt8Precompile.noopSquare(a);
    }

    function benchmarkEqExpanded22Software(uint256 point, uint256[] memory fullPoint) external {
        lastResult = WhirVerifierCore8._eqPolyEvalExpandedPointAt22At0(point, fullPoint);
    }

    function benchmarkEqExpanded22Precompile(uint256 point, uint256[] memory fullPoint) external {
        lastResult =
            WhirVerifierCore8PrecompilePhase1._eqPolyEvalExpandedPointAt22At0(point, fullPoint);
    }

    function benchmarkEqExpanded22Noop(uint256 point, uint256[] memory fullPoint) external {
        lastResult = _eqExpanded22Noop(point, fullPoint);
    }

    function benchmarkEqExpanded18Software(uint256 point, uint256[] memory fullPoint) external {
        lastResult = WhirVerifierCore8._eqPolyEvalExpandedPointAt18At4(point, fullPoint);
    }

    function benchmarkEqExpanded18Precompile(uint256 point, uint256[] memory fullPoint) external {
        lastResult =
            WhirVerifierCore8PrecompilePhase1._eqPolyEvalExpandedPointAt18At4(point, fullPoint);
    }

    function benchmarkEqExpanded18Noop(uint256 point, uint256[] memory fullPoint) external {
        lastResult = _eqExpanded18Noop(point, fullPoint, 4);
    }

    function benchmarkEqExpanded14Software(uint256 point, uint256[] memory fullPoint) external {
        lastResult = WhirVerifierCore8._eqPolyEvalExpandedPointAt14At8(point, fullPoint);
    }

    function benchmarkEqExpanded14Precompile(uint256 point, uint256[] memory fullPoint) external {
        lastResult =
            WhirVerifierCore8PrecompilePhase1._eqPolyEvalExpandedPointAt14At8(point, fullPoint);
    }

    function benchmarkEqExpanded14Noop(uint256 point, uint256[] memory fullPoint) external {
        lastResult = _eqExpanded18Noop(point, fullPoint, 8);
    }

    function benchmarkEqExpanded10Software(uint256 point, uint256[] memory fullPoint) external {
        lastResult = WhirVerifierCore8._eqPolyEvalExpandedPointAt10At12(point, fullPoint);
    }

    function benchmarkEqExpanded10Precompile(uint256 point, uint256[] memory fullPoint) external {
        lastResult =
            WhirVerifierCore8PrecompilePhase1._eqPolyEvalExpandedPointAt10At12(point, fullPoint);
    }

    function benchmarkEqExpanded10Noop(uint256 point, uint256[] memory fullPoint) external {
        lastResult = _eqExpanded18Noop(point, fullPoint, 12);
    }

    function benchmarkRound0SelectOnlySoftware(
        uint256 challenge,
        uint256 eqEval,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) external {
        lastResult = WhirVerifierCore8._evaluateConstraintSelectRaw18WithPrecomputedEq(
            challenge, eqEval, selVars, fullPoint
        );
    }

    function benchmarkRound0SelectOnlyPrecompile(
        uint256 challenge,
        uint256 eqEval,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) external {
        lastResult = WhirVerifierCore8PrecompilePhase1._evaluateConstraintSelectRaw18WithPrecomputedEq(
            challenge, eqEval, selVars, fullPoint
        );
    }

    function benchmarkRound0SelectOnlyNoop(
        uint256 challenge,
        uint256 eqEval,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) external {
        lastResult = _round0SelectOnlyNoop(challenge, eqEval, selVars, fullPoint);
    }

    function benchmarkRound0EqSelectSoftware(
        uint256 challenge,
        uint256 oodPoint,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) external {
        lastResult = WhirVerifierCore8._evaluateConstraintSelectRaw18(
            challenge, oodPoint, selVars, fullPoint
        );
    }

    function benchmarkRound0EqSelectPrecompile(
        uint256 challenge,
        uint256 oodPoint,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) external {
        lastResult =
            WhirVerifierCore8PrecompilePhase1._evaluateConstraintSelectRaw18(
                challenge, oodPoint, selVars, fullPoint
            );
    }

    function benchmarkRound0EqSelectNoop(
        uint256 challenge,
        uint256 oodPoint,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) external {
        uint256 eqEval = _eqExpanded18Noop(oodPoint, fullPoint, 4);
        lastResult = _round0SelectOnlyNoop(challenge, eqEval, selVars, fullPoint);
    }

    function benchmarkRound1SelectOnlySoftware(
        uint256 challenge,
        uint256 eqEval,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) external {
        lastResult = WhirVerifierCore8._evaluateConstraintSelectRaw14WithPrecomputedEq(
            challenge, eqEval, selVars, fullPoint
        );
    }

    function benchmarkRound1SelectOnlyPrecompile(
        uint256 challenge,
        uint256 eqEval,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) external {
        lastResult = WhirVerifierCore8PrecompilePhase1._evaluateConstraintSelectRaw14WithPrecomputedEq(
            challenge, eqEval, selVars, fullPoint
        );
    }

    function benchmarkRound1SelectOnlyNoop(
        uint256 challenge,
        uint256 eqEval,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) external {
        lastResult = _selectOnlyNoop(challenge, eqEval, selVars, fullPoint, 16, 14, 8);
    }

    function benchmarkRound1EqSelectSoftware(
        uint256 challenge,
        uint256 oodPoint,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) external {
        lastResult = WhirVerifierCore8._evaluateConstraintSelectRaw14(
            challenge, oodPoint, selVars, fullPoint
        );
    }

    function benchmarkRound1EqSelectPrecompile(
        uint256 challenge,
        uint256 oodPoint,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) external {
        lastResult =
            WhirVerifierCore8PrecompilePhase1._evaluateConstraintSelectRaw14(
                challenge, oodPoint, selVars, fullPoint
            );
    }

    function benchmarkRound1EqSelectNoop(
        uint256 challenge,
        uint256 oodPoint,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) external {
        uint256 eqEval = _eqExpanded18Noop(oodPoint, fullPoint, 8);
        lastResult = _selectOnlyNoop(challenge, eqEval, selVars, fullPoint, 16, 14, 8);
    }

    function benchmarkRound2SelectOnlySoftware(
        uint256 challenge,
        uint256 eqEval,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) external {
        lastResult = WhirVerifierCore8._evaluateConstraintSelectRaw10WithPrecomputedEq(
            challenge, eqEval, selVars, fullPoint
        );
    }

    function benchmarkRound2SelectOnlyPrecompile(
        uint256 challenge,
        uint256 eqEval,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) external {
        lastResult = WhirVerifierCore8PrecompilePhase1._evaluateConstraintSelectRaw10WithPrecomputedEq(
            challenge, eqEval, selVars, fullPoint
        );
    }

    function benchmarkRound2SelectOnlyNoop(
        uint256 challenge,
        uint256 eqEval,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) external {
        lastResult = _selectOnlyNoop(challenge, eqEval, selVars, fullPoint, 12, 10, 12);
    }

    function benchmarkRound2EqSelectSoftware(
        uint256 challenge,
        uint256 oodPoint,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) external {
        lastResult = WhirVerifierCore8._evaluateConstraintSelectRaw10(
            challenge, oodPoint, selVars, fullPoint
        );
    }

    function benchmarkRound2EqSelectPrecompile(
        uint256 challenge,
        uint256 oodPoint,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) external {
        lastResult =
            WhirVerifierCore8PrecompilePhase1._evaluateConstraintSelectRaw10(
                challenge, oodPoint, selVars, fullPoint
            );
    }

    function benchmarkRound2EqSelectNoop(
        uint256 challenge,
        uint256 oodPoint,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) external {
        uint256 eqEval = _eqExpanded18Noop(oodPoint, fullPoint, 12);
        lastResult = _selectOnlyNoop(challenge, eqEval, selVars, fullPoint, 12, 10, 12);
    }

    function benchmarkStirRowsSoftware(
        bytes calldata rows,
        uint256 p0,
        uint256 p1,
        uint256 p2,
        uint256 p3
    ) external {
        lastResult = _stirRowsSoftware(rows, p0, p1, p2, p3);
    }

    function benchmarkStirRowsNoop(
        bytes calldata rows,
        uint256 p0,
        uint256 p1,
        uint256 p2,
        uint256 p3
    ) external {
        lastResult = _stirRowsNoop(rows, p0, p1, p2, p3);
    }

    function benchmarkStirRowsPrecompile(
        bytes calldata rows,
        uint256 p0,
        uint256 p1,
        uint256 p2,
        uint256 p3
    ) external {
        lastResult = _stirRowsPrecompile(rows, p0, p1, p2, p3);
    }

    function benchmarkAddLoopSoftware(uint256[] calldata packedA, uint256[] calldata packedB)
        external
    {
        lastResult = _binaryLoopSoftware(packedA, packedB, 0);
    }

    function benchmarkAddLoopNoop(uint256[] calldata packedA, uint256[] calldata packedB) external {
        lastResult = _binaryLoopNoop(packedA, packedB);
    }

    function benchmarkAddLoopPrecompile(uint256[] calldata packedA, uint256[] calldata packedB)
        external
    {
        lastResult = _binaryLoopPrecompile(packedA, packedB, 0);
    }

    function benchmarkSubLoopSoftware(uint256[] calldata packedA, uint256[] calldata packedB)
        external
    {
        lastResult = _binaryLoopSoftware(packedA, packedB, 1);
    }

    function benchmarkSubLoopNoop(uint256[] calldata packedA, uint256[] calldata packedB) external {
        lastResult = _binaryLoopNoop(packedA, packedB);
    }

    function benchmarkSubLoopPrecompile(uint256[] calldata packedA, uint256[] calldata packedB)
        external
    {
        lastResult = _binaryLoopPrecompile(packedA, packedB, 1);
    }

    function benchmarkMulBaseLoopSoftware(uint256[] calldata packedA, uint256[] calldata scalars)
        external
    {
        lastResult = _mulBaseLoopSoftware(packedA, scalars);
    }

    function benchmarkMulBaseLoopNoop(uint256[] calldata packedA, uint256[] calldata scalars)
        external
    {
        lastResult = _binaryLoopNoop(packedA, scalars);
    }

    function benchmarkMulBaseLoopPrecompile(uint256[] calldata packedA, uint256[] calldata scalars)
        external
    {
        lastResult = _mulBaseLoopPrecompile(packedA, scalars);
    }

    function benchmarkMulLoopSoftware(uint256[] calldata packedA, uint256[] calldata packedB)
        external
    {
        lastResult = _binaryLoopSoftware(packedA, packedB, 2);
    }

    function benchmarkMulLoopNoop(uint256[] calldata packedA, uint256[] calldata packedB) external {
        lastResult = _binaryLoopNoop(packedA, packedB);
    }

    function benchmarkMulLoopPrecompile(uint256[] calldata packedA, uint256[] calldata packedB)
        external
    {
        lastResult = _binaryLoopPrecompile(packedA, packedB, 2);
    }

    function benchmarkSquareLoopSoftware(uint256[] calldata packedA) external {
        lastResult = _squareLoopSoftware(packedA);
    }

    function benchmarkSquareLoopNoop(uint256[] calldata packedA) external {
        lastResult = _squareLoopNoop(packedA);
    }

    function benchmarkSquareLoopPrecompile(uint256[] calldata packedA) external {
        lastResult = _squareLoopPrecompile(packedA);
    }

    function benchmarkMulBatchSoftware(uint256[] calldata packedA, uint256[] calldata packedB)
        external
    {
        lastResult = _binaryLoopSoftware(packedA, packedB, 2);
    }

    function benchmarkMulBatchNoop(uint256[] calldata packedA, uint256[] calldata packedB)
        external
    {
        lastResult = _consumeBatchOutput(
            KoalaBearExt8Precompile.noopBatch64To32(_packPairs(packedA, packedB))
        );
    }

    function benchmarkMulBatchPrecompile(uint256[] calldata packedA, uint256[] calldata packedB)
        external
    {
        lastResult =
            _consumeBatchOutput(KoalaBearExt8Precompile.mulBatch(_packPairs(packedA, packedB)));
    }

    function benchmarkSquareBatchSoftware(uint256[] calldata packedA) external {
        lastResult = _squareLoopSoftware(packedA);
    }

    function benchmarkSquareBatchNoop(uint256[] calldata packedA) external {
        lastResult =
            _consumeBatchOutput(KoalaBearExt8Precompile.noopBatch32To32(_packSingles(packedA)));
    }

    function benchmarkSquareBatchPrecompile(uint256[] calldata packedA) external {
        lastResult = _consumeBatchOutput(KoalaBearExt8Precompile.squareBatch(_packSingles(packedA)));
    }

    function benchmarkMulBaseBatchSoftware(uint256[] calldata packedA, uint256[] calldata scalars)
        external
    {
        lastResult = _mulBaseLoopSoftware(packedA, scalars);
    }

    function benchmarkMulBaseBatchNoop(uint256[] calldata packedA, uint256[] calldata scalars)
        external
    {
        lastResult = _consumeBatchOutput(
            KoalaBearExt8Precompile.noopBatch64To32(_packPairs(packedA, scalars))
        );
    }

    function benchmarkMulBaseBatchPrecompile(uint256[] calldata packedA, uint256[] calldata scalars)
        external
    {
        lastResult =
            _consumeBatchOutput(KoalaBearExt8Precompile.mulBaseBatch(_packPairs(packedA, scalars)));
    }

    function checkArithmeticVectors(
        uint256[] calldata packedA,
        uint256[] calldata packedB,
        uint256[] calldata expectedMul,
        uint256[] calldata expectedSquareA
    ) external view returns (bool) {
        return _checkArithmeticVectors(packedA, packedB, expectedMul, expectedSquareA);
    }

    function checkArithmeticVectorsTx(
        uint256[] calldata packedA,
        uint256[] calldata packedB,
        uint256[] calldata expectedMul,
        uint256[] calldata expectedSquareA
    ) external returns (bool) {
        bool ok = _checkArithmeticVectors(packedA, packedB, expectedMul, expectedSquareA);
        lastResult = ok ? 1 : 0;
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
        lastResult = ok ? 1 : 0;
        return ok;
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
                if (KoalaBearExt8.mul(packedA[i], packedB[i]) != expectedMul[i]) {
                    revert("SOFTWARE_MUL");
                }
                if (KoalaBearExt8Precompile.mul(packedA[i], packedB[i]) != expectedMul[i]) {
                    revert("PRECOMPILE_MUL");
                }
                if (KoalaBearExt8.square(packedA[i]) != expectedSquareA[i]) {
                    revert("SOFTWARE_SQUARE");
                }
                if (KoalaBearExt8Precompile.square(packedA[i]) != expectedSquareA[i]) {
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
                if (KoalaBearExt8.add(a, b) != expectedAdd[i]) revert("SOFTWARE_ADD");
                if (KoalaBearExt8Precompile.addViaPrecompile(a, b) != expectedAdd[i]) {
                    revert("PRECOMPILE_ADD");
                }
                if (KoalaBearExt8.sub(a, b) != expectedSub[i]) revert("SOFTWARE_SUB");
                if (KoalaBearExt8Precompile.subViaPrecompile(a, b) != expectedSub[i]) {
                    revert("PRECOMPILE_SUB");
                }
                if (KoalaBearExt8.mul(a, b) != expectedMul[i]) revert("SOFTWARE_MUL");
                if (KoalaBearExt8Precompile.mul(a, b) != expectedMul[i]) {
                    revert("PRECOMPILE_MUL");
                }
                if (KoalaBearExt8.square(a) != expectedSquareA[i]) revert("SOFTWARE_SQUARE");
                if (KoalaBearExt8Precompile.square(a) != expectedSquareA[i]) {
                    revert("PRECOMPILE_SQUARE");
                }
                if (KoalaBearExt8.mulBase(a, scalar) != expectedMulBase[i]) {
                    revert("SOFTWARE_MUL_BASE");
                }
                if (KoalaBearExt8Precompile.mulBaseViaPrecompile(a, scalar) != expectedMulBase[i]) {
                    revert("PRECOMPILE_MUL_BASE");
                }
            }
        }

        _checkBatchOutput(
            KoalaBearExt8Precompile.mulBatch(_packPairs(packedA, packedB)), expectedMul
        );
        _checkBatchOutput(
            KoalaBearExt8Precompile.squareBatch(_packSingles(packedA)), expectedSquareA
        );
        _checkBatchOutput(
            KoalaBearExt8Precompile.mulBaseBatch(_packPairs(packedA, scalars)), expectedMulBase
        );
        return true;
    }

    function _binaryLoopSoftware(uint256[] calldata packedA, uint256[] calldata packedB, uint256 op)
        internal
        pure
        returns (uint256 acc)
    {
        _checkSameLength(packedA.length, packedB.length);
        unchecked {
            for (uint256 i = 0; i < packedA.length; ++i) {
                uint256 result;
                if (op == 0) {
                    result = KoalaBearExt8.add(packedA[i], packedB[i]);
                } else if (op == 1) {
                    result = KoalaBearExt8.sub(packedA[i], packedB[i]);
                } else {
                    result = KoalaBearExt8.mul(packedA[i], packedB[i]);
                }
                acc = KoalaBearExt8.add(acc, result);
            }
        }
    }

    function _binaryLoopNoop(uint256[] calldata packedA, uint256[] calldata packedB)
        internal
        view
        returns (uint256 acc)
    {
        _checkSameLength(packedA.length, packedB.length);
        unchecked {
            for (uint256 i = 0; i < packedA.length; ++i) {
                acc =
                    KoalaBearExt8.add(acc, KoalaBearExt8Precompile.noopMul(packedA[i], packedB[i]));
            }
        }
    }

    function _binaryLoopPrecompile(
        uint256[] calldata packedA,
        uint256[] calldata packedB,
        uint256 op
    ) internal view returns (uint256 acc) {
        _checkSameLength(packedA.length, packedB.length);
        unchecked {
            for (uint256 i = 0; i < packedA.length; ++i) {
                uint256 result;
                if (op == 0) {
                    result = KoalaBearExt8Precompile.addViaPrecompile(packedA[i], packedB[i]);
                } else if (op == 1) {
                    result = KoalaBearExt8Precompile.subViaPrecompile(packedA[i], packedB[i]);
                } else {
                    result = KoalaBearExt8Precompile.mul(packedA[i], packedB[i]);
                }
                acc = KoalaBearExt8.add(acc, result);
            }
        }
    }

    function _mulBaseLoopSoftware(uint256[] calldata packedA, uint256[] calldata scalars)
        internal
        pure
        returns (uint256 acc)
    {
        _checkSameLength(packedA.length, scalars.length);
        unchecked {
            for (uint256 i = 0; i < packedA.length; ++i) {
                acc = KoalaBearExt8.add(acc, KoalaBearExt8.mulBase(packedA[i], scalars[i]));
            }
        }
    }

    function _mulBaseLoopPrecompile(uint256[] calldata packedA, uint256[] calldata scalars)
        internal
        view
        returns (uint256 acc)
    {
        _checkSameLength(packedA.length, scalars.length);
        unchecked {
            for (uint256 i = 0; i < packedA.length; ++i) {
                acc = KoalaBearExt8.add(
                    acc, KoalaBearExt8Precompile.mulBaseViaPrecompile(packedA[i], scalars[i])
                );
            }
        }
    }

    function _squareLoopSoftware(uint256[] calldata packedA) internal pure returns (uint256 acc) {
        unchecked {
            for (uint256 i = 0; i < packedA.length; ++i) {
                acc = KoalaBearExt8.add(acc, KoalaBearExt8.square(packedA[i]));
            }
        }
    }

    function _squareLoopNoop(uint256[] calldata packedA) internal view returns (uint256 acc) {
        unchecked {
            for (uint256 i = 0; i < packedA.length; ++i) {
                acc = KoalaBearExt8.add(acc, KoalaBearExt8Precompile.noopSquare(packedA[i]));
            }
        }
    }

    function _squareLoopPrecompile(uint256[] calldata packedA) internal view returns (uint256 acc) {
        unchecked {
            for (uint256 i = 0; i < packedA.length; ++i) {
                acc = KoalaBearExt8.add(acc, KoalaBearExt8Precompile.square(packedA[i]));
            }
        }
    }

    function _packPairs(uint256[] calldata lhs, uint256[] calldata rhs)
        internal
        pure
        returns (bytes memory input)
    {
        _checkSameLength(lhs.length, rhs.length);
        input = new bytes(lhs.length * 64);
        unchecked {
            for (uint256 i = 0; i < lhs.length; ++i) {
                uint256 a = lhs[i];
                uint256 b = rhs[i];
                assembly ("memory-safe") {
                    let dst := add(add(input, 0x20), mul(i, 0x40))
                    mstore(dst, a)
                    mstore(add(dst, 0x20), b)
                }
            }
        }
    }

    function _packSingles(uint256[] calldata values) internal pure returns (bytes memory input) {
        input = new bytes(values.length * 32);
        unchecked {
            for (uint256 i = 0; i < values.length; ++i) {
                uint256 value = values[i];
                assembly ("memory-safe") {
                    mstore(add(add(input, 0x20), shl(5, i)), value)
                }
            }
        }
    }

    function _consumeBatchOutput(bytes memory output) internal pure returns (uint256 acc) {
        require(output.length % 32 == 0, "BATCH_OUT_LEN");
        unchecked {
            for (uint256 offset = 0; offset < output.length; offset += 32) {
                uint256 value;
                assembly ("memory-safe") {
                    value := mload(add(add(output, 0x20), offset))
                }
                acc = KoalaBearExt8.add(acc, value);
            }
        }
    }

    function _checkBatchOutput(bytes memory output, uint256[] calldata expected) internal pure {
        require(output.length == expected.length * 32, "BATCH_EXPECTED_LEN");
        unchecked {
            for (uint256 i = 0; i < expected.length; ++i) {
                uint256 value;
                assembly ("memory-safe") {
                    value := mload(add(add(output, 0x20), shl(5, i)))
                }
                if (value != expected[i]) revert("BATCH_OUTPUT");
            }
        }
    }

    function _checkSameLength(uint256 lhs, uint256 rhs) internal pure {
        require(lhs == rhs, "LEN");
    }

    function _stirRowsSoftware(bytes calldata rows, uint256 p0, uint256 p1, uint256 p2, uint256 p3)
        internal
        pure
        returns (uint256 acc)
    {
        _checkRowsLength(rows);

        (
            uint256 r00,
            uint256 r01,
            uint256 r02,
            uint256 r03,
            uint256 r04,
            uint256 r05,
            uint256 r06,
            uint256 r07
        ) = WhirVerifierUtils8._unpackCoeffs(p0);
        (
            uint256 r10,
            uint256 r11,
            uint256 r12,
            uint256 r13,
            uint256 r14,
            uint256 r15,
            uint256 r16,
            uint256 r17
        ) = WhirVerifierUtils8._unpackCoeffs(p1);
        (
            uint256 r20,
            uint256 r21,
            uint256 r22,
            uint256 r23,
            uint256 r24,
            uint256 r25,
            uint256 r26,
            uint256 r27
        ) = WhirVerifierUtils8._unpackCoeffs(p2);
        (
            uint256 r30,
            uint256 r31,
            uint256 r32,
            uint256 r33,
            uint256 r34,
            uint256 r35,
            uint256 r36,
            uint256 r37
        ) = WhirVerifierUtils8._unpackCoeffs(p3);

        bytes32 hashAcc;
        unchecked {
            for (uint256 offset = 0; offset < rows.length; offset += EXT8_ROW_BYTES) {
                (bytes32 digest, uint256 evalValue) = WhirVerifierUtils8._hashAndEvaluateExtensionRowDim4BlobUnpacked(
                    rows,
                    offset,
                    r00,
                    r01,
                    r02,
                    r03,
                    r04,
                    r05,
                    r06,
                    r07,
                    r10,
                    r11,
                    r12,
                    r13,
                    r14,
                    r15,
                    r16,
                    r17,
                    r20,
                    r21,
                    r22,
                    r23,
                    r24,
                    r25,
                    r26,
                    r27,
                    r30,
                    r31,
                    r32,
                    r33,
                    r34,
                    r35,
                    r36,
                    r37
                );
                hashAcc = bytes32(uint256(hashAcc) ^ uint256(digest));
                acc = KoalaBearExt8.add(acc, evalValue);
            }
        }
        acc ^= uint256(hashAcc);
    }

    function _stirRowsNoop(bytes calldata rows, uint256 p0, uint256 p1, uint256 p2, uint256 p3)
        internal
        view
        returns (uint256 acc)
    {
        _checkRowsLength(rows);
        bytes32 hashAcc;
        unchecked {
            for (uint256 offset = 0; offset < rows.length; offset += EXT8_ROW_BYTES) {
                (bytes32 digest, uint256 evalValue) =
                    _hashAndEvaluateExtensionRowDim4BlobNoop(rows, offset, p0, p1, p2, p3);
                hashAcc = bytes32(uint256(hashAcc) ^ uint256(digest));
                acc = KoalaBearExt8.add(acc, evalValue);
            }
        }
        acc ^= uint256(hashAcc);
    }

    function _stirRowsPrecompile(
        bytes calldata rows,
        uint256 p0,
        uint256 p1,
        uint256 p2,
        uint256 p3
    ) internal view returns (uint256 acc) {
        _checkRowsLength(rows);
        bytes32 hashAcc;
        unchecked {
            for (uint256 offset = 0; offset < rows.length; offset += EXT8_ROW_BYTES) {
                (bytes32 digest, uint256 evalValue) =
                    _hashAndEvaluateExtensionRowDim4BlobPrecompile(rows, offset, p0, p1, p2, p3);
                hashAcc = bytes32(uint256(hashAcc) ^ uint256(digest));
                acc = KoalaBearExt8.add(acc, evalValue);
            }
        }
        acc ^= uint256(hashAcc);
    }

    function _hashAndEvaluateExtensionRowDim4BlobNoop(
        bytes calldata rows,
        uint256 offset,
        uint256 p0,
        uint256 p1,
        uint256 p2,
        uint256 p3
    ) internal view returns (bytes32 digest, uint256 evalValue) {
        uint256 rowBase = _copyHashAndValidateRow(rows, offset);
        digest = _hashCopiedRow(rowBase);
        evalValue = _foldRowNoop(rowBase, p0, p1, p2, p3);
    }

    function _hashAndEvaluateExtensionRowDim4BlobPrecompile(
        bytes calldata rows,
        uint256 offset,
        uint256 p0,
        uint256 p1,
        uint256 p2,
        uint256 p3
    ) internal view returns (bytes32 digest, uint256 evalValue) {
        uint256 rowBase = _copyHashAndValidateRow(rows, offset);
        digest = _hashCopiedRow(rowBase);
        evalValue = _foldRowPrecompile(rowBase, p0, p1, p2, p3);
    }

    function _copyHashAndValidateRow(bytes calldata rows, uint256 offset)
        internal
        pure
        returns (uint256 rowBase)
    {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore8(ptr, 0x00)
            rowBase := add(ptr, 0x01)
            calldatacopy(rowBase, add(rows.offset, offset), 0x200)
            mstore(0x40, add(ptr, 0x240))
        }

        unchecked {
            for (uint256 i = 0; i < 16; ++i) {
                WhirVerifierUtils8.validatePackedExt8(_rowWord(rowBase, i));
            }
        }
    }

    function _hashCopiedRow(uint256 rowBase) internal pure returns (bytes32 digest) {
        assembly ("memory-safe") {
            digest := and(keccak256(sub(rowBase, 1), 513), not(sub(shl(96, 1), 1)))
        }
    }

    function _foldRowNoop(uint256 rowBase, uint256 p0, uint256 p1, uint256 p2, uint256 p3)
        internal
        view
        returns (uint256)
    {
        uint256 m0 = _foldNoop(
            _foldNoop(_rowWord(rowBase, 0), _rowWord(rowBase, 8), p0),
            _foldNoop(_rowWord(rowBase, 4), _rowWord(rowBase, 12), p0),
            p1
        );
        uint256 m1 = _foldNoop(
            _foldNoop(_rowWord(rowBase, 1), _rowWord(rowBase, 9), p0),
            _foldNoop(_rowWord(rowBase, 5), _rowWord(rowBase, 13), p0),
            p1
        );
        uint256 m2 = _foldNoop(
            _foldNoop(_rowWord(rowBase, 2), _rowWord(rowBase, 10), p0),
            _foldNoop(_rowWord(rowBase, 6), _rowWord(rowBase, 14), p0),
            p1
        );
        uint256 m3 = _foldNoop(
            _foldNoop(_rowWord(rowBase, 3), _rowWord(rowBase, 11), p0),
            _foldNoop(_rowWord(rowBase, 7), _rowWord(rowBase, 15), p0),
            p1
        );
        return _foldNoop(_foldNoop(m0, m2, p2), _foldNoop(m1, m3, p2), p3);
    }

    function _foldRowPrecompile(uint256 rowBase, uint256 p0, uint256 p1, uint256 p2, uint256 p3)
        internal
        view
        returns (uint256)
    {
        uint256 m0 = _foldPrecompile(
            _foldPrecompile(_rowWord(rowBase, 0), _rowWord(rowBase, 8), p0),
            _foldPrecompile(_rowWord(rowBase, 4), _rowWord(rowBase, 12), p0),
            p1
        );
        uint256 m1 = _foldPrecompile(
            _foldPrecompile(_rowWord(rowBase, 1), _rowWord(rowBase, 9), p0),
            _foldPrecompile(_rowWord(rowBase, 5), _rowWord(rowBase, 13), p0),
            p1
        );
        uint256 m2 = _foldPrecompile(
            _foldPrecompile(_rowWord(rowBase, 2), _rowWord(rowBase, 10), p0),
            _foldPrecompile(_rowWord(rowBase, 6), _rowWord(rowBase, 14), p0),
            p1
        );
        uint256 m3 = _foldPrecompile(
            _foldPrecompile(_rowWord(rowBase, 3), _rowWord(rowBase, 11), p0),
            _foldPrecompile(_rowWord(rowBase, 7), _rowWord(rowBase, 15), p0),
            p1
        );
        return _foldPrecompile(_foldPrecompile(m0, m2, p2), _foldPrecompile(m1, m3, p2), p3);
    }

    function _rowWord(uint256 rowBase, uint256 i) internal pure returns (uint256 word) {
        assembly ("memory-safe") {
            word := mload(add(rowBase, shl(5, i)))
        }
    }

    function _foldNoop(uint256 a0, uint256 a1, uint256 r) internal view returns (uint256) {
        return KoalaBearExt8.add(a0, KoalaBearExt8Precompile.noopMul(KoalaBearExt8.sub(a1, a0), r));
    }

    function _foldPrecompile(uint256 a0, uint256 a1, uint256 r) internal view returns (uint256) {
        return KoalaBearExt8.add(a0, KoalaBearExt8Precompile.mul(KoalaBearExt8.sub(a1, a0), r));
    }

    function _checkRowsLength(bytes calldata rows) internal pure {
        require(rows.length != 0 && rows.length % EXT8_ROW_BYTES == 0, "ROWS_LEN");
    }

    function _eqExpanded22Noop(uint256 point, uint256[] memory fullPoint)
        internal
        view
        returns (uint256 acc)
    {
        return _eqExpanded18Noop(point, fullPoint, 0);
    }

    function _eqExpanded18Noop(uint256 point, uint256[] memory fullPoint, uint256 pointOffset)
        internal
        view
        returns (uint256 acc)
    {
        uint256 numVariables = fullPoint.length - pointOffset;
        acc = KoalaBearExt8.ONE;
        uint256 current = point;
        unchecked {
            for (uint256 i = numVariables; i > 0; --i) {
                uint256 q = fullPoint[pointOffset + i - 1];
                acc = KoalaBearExt8.mul(acc, _eqTermNoop(current, q));
                current = KoalaBearExt8Precompile.noopSquare(current);
            }
        }
    }

    function _round0SelectOnlyNoop(
        uint256 challenge,
        uint256 eqEval,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) internal view returns (uint256 total) {
        return _selectOnlyNoop(challenge, eqEval, selVars, fullPoint, 24, 18, 4);
    }

    function _selectOnlyNoop(
        uint256 challenge,
        uint256 eqEval,
        uint256[] memory selVars,
        uint256[] memory fullPoint,
        uint256 queryCount,
        uint256 selectVarCount,
        uint256 pointOffset
    ) internal view returns (uint256 total) {
        uint256 ch0;
        uint256 ch1;
        uint256 ch2;
        uint256 ch3;
        uint256 ch4;
        uint256 ch5;
        uint256 ch6;
        uint256 ch7;
        assembly ("memory-safe") {
            ch0 := shr(224, challenge)
            ch1 := and(shr(192, challenge), 0xffffffff)
            ch2 := and(shr(160, challenge), 0xffffffff)
            ch3 := and(shr(128, challenge), 0xffffffff)
            ch4 := and(shr(96, challenge), 0xffffffff)
            ch5 := and(shr(64, challenge), 0xffffffff)
            ch6 := and(shr(32, challenge), 0xffffffff)
            ch7 := and(challenge, 0xffffffff)
        }
        unchecked {
            for (uint256 i = queryCount; i > 0; --i) {
                total = WhirVerifierCore8._hornerStepWithChallengeCoeffs(
                    total,
                    _selectPolyEvalNoop(selVars[i - 1], fullPoint, selectVarCount, pointOffset),
                    ch0,
                    ch1,
                    ch2,
                    ch3,
                    ch4,
                    ch5,
                    ch6,
                    ch7
                );
            }
        }
        total = WhirVerifierCore8._hornerStepWithChallengeCoeffs(
            total, eqEval, ch0, ch1, ch2, ch3, ch4, ch5, ch6, ch7
        );
    }

    function _selectPolyEval18Noop(uint256 var_, uint256[] memory fullPoint)
        internal
        view
        returns (uint256 acc)
    {
        return _selectPolyEvalNoop(var_, fullPoint, 18, 4);
    }

    function _selectPolyEvalNoop(
        uint256 var_,
        uint256[] memory fullPoint,
        uint256 count,
        uint256 pointOffset
    ) internal view returns (uint256 acc) {
        acc = KoalaBearExt8.ONE;
        uint256 current = var_;
        unchecked {
            for (uint256 i = count; i > 0; --i) {
                uint256 scalar = current == 0 ? KoalaBear.MODULUS - 1 : current - 1;
                uint256 term = KoalaBearExt8.add(
                    KoalaBearExt8.ONE, KoalaBearExt8.mulBase(fullPoint[pointOffset + i - 1], scalar)
                );
                acc = KoalaBearExt8Precompile.noopMul(acc, term);
                current = KoalaBear.mul(current, current);
            }
        }
    }

    function _eqTermNoop(uint256 p, uint256 q) internal view returns (uint256) {
        return KoalaBearExt8.sub(
            KoalaBearExt8.sub(
                KoalaBearExt8.add(
                    KoalaBearExt8.mulBase(KoalaBearExt8Precompile.noopMul(p, q), 2),
                    KoalaBearExt8.ONE
                ),
                p
            ),
            q
        );
    }
}
