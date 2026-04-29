// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Script, console2 } from "forge-std/Script.sol";

import { WhirStructs } from "../src/whir/WhirStructs.sol";
import {
    WhirBlobVerifierNativeLir11
} from "../src/whir/lir11/WhirBlobVerifierNative4_lir11_ff5_rsv3.sol";

contract WhirBlobNativeTxBenchmarkLir11Script is Script {
    string internal constant TESTDATA = "testdata/";

    function run() external returns (address nativeVerifierAddress) {
        WhirStructs.WhirProof memory proof = abi.decode(
            vm.readFileBinary(
                string.concat(TESTDATA, "quartic_whir_lir11_ff5_rsv3_success_proof.abi")
            ),
            (WhirStructs.WhirProof)
        );
        bytes memory blob = vm.readFileBinary(
            string.concat(TESTDATA, "quartic_whir_lir11_ff5_rsv3_success.blob")
        );

        bytes memory verifyCalldata =
            abi.encodeCall(WhirBlobVerifierNativeLir11.verify, (proof.initialCommitment, blob));

        uint256 zeroBytes;
        uint256 nonZeroBytes;
        uint256 calldataGas;
        (zeroBytes, nonZeroBytes, calldataGas) = _calldataBreakdown(verifyCalldata);

        console2.log("native blob verify calldata bytes", verifyCalldata.length);
        console2.log("native blob verify calldata zero bytes", zeroBytes);
        console2.log("native blob verify calldata non-zero bytes", nonZeroBytes);
        console2.log("native blob verify calldata intrinsic gas", uint256(21_000));
        console2.log("native blob verify calldata gas", calldataGas);

        vm.startBroadcast();

        WhirBlobVerifierNativeLir11 nativeVerifier = new WhirBlobVerifierNativeLir11();
        nativeVerifierAddress = address(nativeVerifier);

        (bool ok, bytes memory ret) = nativeVerifierAddress.call(verifyCalldata);
        require(ok && abi.decode(ret, (bool)), "VERIFY_FAILED");

        vm.stopBroadcast();

        console2.log("nativeBlobVerifier", nativeVerifierAddress);
    }

    function _calldataBreakdown(bytes memory data)
        internal
        pure
        returns (uint256 zeroBytes, uint256 nonZeroBytes, uint256 calldataGas)
    {
        unchecked {
            for (uint256 i = 0; i < data.length; ++i) {
                if (data[i] == 0) {
                    ++zeroBytes;
                    calldataGas += 4;
                } else {
                    ++nonZeroBytes;
                    calldataGas += 16;
                }
            }
        }
    }
}
