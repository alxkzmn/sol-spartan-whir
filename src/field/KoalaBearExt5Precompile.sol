// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { KoalaBearExt5 } from "./KoalaBearExt5.sol";

library KoalaBearExt5Precompile {
    error InvalidExt5BatchInputLength(uint256 inputLength, uint256 itemLength);
    error InvalidExt5PrecompileReturnData(
        uint256 precompile, uint256 expectedLength, uint256 actualLength
    );

    uint256 internal constant ONE = KoalaBearExt5.ONE;
    uint256 internal constant EXTFIELD_MAC_FIELD_ID_KOALABEAR_EXT5 = 0x0005;

    uint256 internal constant EXT5_MUL_PRECOMPILE = 0x0501;
    uint256 internal constant EXT5_SQUARE_PRECOMPILE = 0x0502;
    uint256 internal constant EXT5_ADD_PRECOMPILE = 0x0503;
    uint256 internal constant EXT5_SUB_PRECOMPILE = 0x0504;
    uint256 internal constant EXT5_MUL_BASE_PRECOMPILE = 0x0505;
    uint256 internal constant EXT5_MUL_BATCH_PRECOMPILE = 0x0511;
    uint256 internal constant EXT5_SQUARE_BATCH_PRECOMPILE = 0x0512;
    uint256 internal constant EXT5_MUL_BASE_BATCH_PRECOMPILE = 0x0513;
    uint256 internal constant EXTFIELD_MAC_PRECOMPILE = 0x0f01;
    uint256 internal constant NOOP_64_TO_32_PRECOMPILE = 0x05f1;
    uint256 internal constant NOOP_32_TO_32_PRECOMPILE = 0x05f2;
    uint256 internal constant NOOP_BATCH_64_TO_32_PRECOMPILE = 0x05f3;
    uint256 internal constant NOOP_BATCH_32_TO_32_PRECOMPILE = 0x05f4;
    uint256 internal constant NOOP_EXTFIELD_MAC_PRECOMPILE = 0x0ff1;

    // Add/sub/base-scalar operations stay in Solidity on the verifier path: their arithmetic is
    // cheaper than paying a standalone STATICCALL. The corresponding precompile entry points are
    // kept below as measurement controls for EIP-candidate benchmarking.
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        return KoalaBearExt5.add(a, b);
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        return KoalaBearExt5.sub(a, b);
    }

    function mulBase(uint256 a, uint256 scalar) internal pure returns (uint256) {
        return KoalaBearExt5.mulBase(a, scalar);
    }

    function fromBase(uint256 value) internal pure returns (uint256) {
        return KoalaBearExt5.fromBase(value);
    }

    function mul(uint256 a, uint256 b) internal view returns (uint256 out) {
        return _callBinary(EXT5_MUL_PRECOMPILE, a, b);
    }

    function addViaPrecompile(uint256 a, uint256 b) internal view returns (uint256 out) {
        return _callBinary(EXT5_ADD_PRECOMPILE, a, b);
    }

    function subViaPrecompile(uint256 a, uint256 b) internal view returns (uint256 out) {
        return _callBinary(EXT5_SUB_PRECOMPILE, a, b);
    }

    /// @dev Measurement control. The verifier path uses pure Solidity for base-scalar products
    /// because standalone STATICCALL overhead is larger than the arithmetic it replaces.
    function mulBaseViaPrecompile(uint256 a, uint256 scalar) internal view returns (uint256 out) {
        return _callBinary(EXT5_MUL_BASE_PRECOMPILE, a, scalar);
    }

    function square(uint256 a) internal view returns (uint256 out) {
        return _callUnary(EXT5_SQUARE_PRECOMPILE, a);
    }

    function mulBatch(bytes memory input) internal view returns (bytes memory out) {
        _validateBatchInputLength(input.length, 0x40);
        return _callBatch(EXT5_MUL_BATCH_PRECOMPILE, input, input.length / 2);
    }

    /// @dev Raw-memory variant for generated kernels that already own a scratch buffer.
    function mulBatchInto(uint256 inputPtr, uint256 inputLen, uint256 outputPtr) internal view {
        _validateBatchInputLength(inputLen, 0x40);
        _callBatchInto(EXT5_MUL_BATCH_PRECOMPILE, inputPtr, inputLen, outputPtr, inputLen / 2);
    }

    function squareBatch(bytes memory input) internal view returns (bytes memory out) {
        _validateBatchInputLength(input.length, 0x20);
        return _callBatch(EXT5_SQUARE_BATCH_PRECOMPILE, input, input.length);
    }

    function mulBaseBatch(bytes memory input) internal view returns (bytes memory out) {
        _validateBatchInputLength(input.length, 0x40);
        return _callBatch(EXT5_MUL_BASE_BATCH_PRECOMPILE, input, input.length / 2);
    }

    function mac(bytes memory input) internal view returns (uint256 out) {
        return _callRaw32(EXTFIELD_MAC_PRECOMPILE, input);
    }

    function macInto(uint256 inputPtr, uint256 inputLen, uint256 outputPtr) internal view {
        _callBatchInto(EXTFIELD_MAC_PRECOMPILE, inputPtr, inputLen, outputPtr, 0x20);
    }

    function noopMul(uint256 a, uint256 b) internal view returns (uint256 out) {
        return _callBinary(NOOP_64_TO_32_PRECOMPILE, a, b);
    }

    function noopSquare(uint256 a) internal view returns (uint256 out) {
        return _callUnary(NOOP_32_TO_32_PRECOMPILE, a);
    }

    function noopBatch64To32(bytes memory input) internal view returns (bytes memory out) {
        _validateBatchInputLength(input.length, 0x40);
        return _callBatch(NOOP_BATCH_64_TO_32_PRECOMPILE, input, input.length / 2);
    }

    function noopBatch32To32(bytes memory input) internal view returns (bytes memory out) {
        _validateBatchInputLength(input.length, 0x20);
        return _callBatch(NOOP_BATCH_32_TO_32_PRECOMPILE, input, input.length);
    }

    function noopMac(bytes memory input) internal view returns (uint256 out) {
        return _callRaw32(NOOP_EXTFIELD_MAC_PRECOMPILE, input);
    }

    function noopMacInto(uint256 inputPtr, uint256 inputLen, uint256 outputPtr) internal view {
        _callBatchInto(NOOP_EXTFIELD_MAC_PRECOMPILE, inputPtr, inputLen, outputPtr, 0x20);
    }

    function _validateBatchInputLength(uint256 inputLength, uint256 itemLength) private pure {
        if (inputLength % itemLength != 0) {
            revert InvalidExt5BatchInputLength(inputLength, itemLength);
        }
    }

    function _checkReturnDataLength(
        uint256 precompile,
        uint256 expectedLength,
        uint256 actualLength
    ) private pure {
        if (actualLength != expectedLength) {
            revert InvalidExt5PrecompileReturnData(precompile, expectedLength, actualLength);
        }
    }

    function _callBinary(uint256 precompile, uint256 a, uint256 b)
        private
        view
        returns (uint256 out)
    {
        uint256 actualLength;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, a)
            mstore(add(ptr, 0x20), b)
            if iszero(staticcall(gas(), precompile, ptr, 0x40, ptr, 0x20)) {
                let size := returndatasize()
                returndatacopy(ptr, 0, size)
                revert(ptr, size)
            }
            actualLength := returndatasize()
            out := mload(ptr)
        }
        _checkReturnDataLength(precompile, 0x20, actualLength);
    }

    function _callUnary(uint256 precompile, uint256 a) private view returns (uint256 out) {
        uint256 actualLength;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, a)
            if iszero(staticcall(gas(), precompile, ptr, 0x20, ptr, 0x20)) {
                let size := returndatasize()
                returndatacopy(ptr, 0, size)
                revert(ptr, size)
            }
            actualLength := returndatasize()
            out := mload(ptr)
        }
        _checkReturnDataLength(precompile, 0x20, actualLength);
    }

    function _callBatch(uint256 precompile, bytes memory input, uint256 outputLen)
        private
        view
        returns (bytes memory out)
    {
        out = new bytes(outputLen);
        uint256 actualLength;
        assembly ("memory-safe") {
            if iszero(
                staticcall(
                    gas(),
                    precompile,
                    add(input, 0x20),
                    mload(input),
                    add(out, 0x20),
                    outputLen
                )
            ) {
                let size := returndatasize()
                let ptr := mload(0x40)
                returndatacopy(ptr, 0, size)
                revert(ptr, size)
            }
            actualLength := returndatasize()
        }
        _checkReturnDataLength(precompile, outputLen, actualLength);
    }

    function _callRaw32(uint256 precompile, bytes memory input) private view returns (uint256 out) {
        uint256 actualLength;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            if iszero(staticcall(gas(), precompile, add(input, 0x20), mload(input), ptr, 0x20)) {
                let size := returndatasize()
                returndatacopy(ptr, 0, size)
                revert(ptr, size)
            }
            actualLength := returndatasize()
            out := mload(ptr)
        }
        _checkReturnDataLength(precompile, 0x20, actualLength);
    }

    function _callBatchInto(
        uint256 precompile,
        uint256 inputPtr,
        uint256 inputLen,
        uint256 outputPtr,
        uint256 outputLen
    ) private view {
        uint256 actualLength;
        assembly ("memory-safe") {
            if iszero(staticcall(gas(), precompile, inputPtr, inputLen, outputPtr, outputLen)) {
                let size := returndatasize()
                let ptr := mload(0x40)
                returndatacopy(ptr, 0, size)
                revert(ptr, size)
            }
            actualLength := returndatasize()
        }
        _checkReturnDataLength(precompile, outputLen, actualLength);
    }
}
