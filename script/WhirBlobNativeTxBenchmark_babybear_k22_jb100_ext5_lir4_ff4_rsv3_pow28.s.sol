// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Script, console2 } from "forge-std/Script.sol";

import { WhirStructs } from "../src/whir/WhirStructs.sol";
import {
    BabyBearWhirBlobVerifierNative5_k22_jb100_ext5_lir4_ff4_rsv3_pow28 as BabyBearWhirBlobVerifierNative5
} from "../src/whir/babybear_k22_jb100_ext5_lir4_ff4_rsv3_pow28/BabyBearWhirBlobVerifierNative5_k22_jb100_ext5_lir4_ff4_rsv3_pow28.sol";

contract BabyBearWhirBlobNativeTxBenchmark5Pow28Rsv3Script is Script {
    string internal constant TESTDATA = "testdata/";

    function run() external returns (address nativeVerifierAddress) {
        WhirStructs.WhirProof memory proof = abi.decode(
            vm.readFileBinary(
                string.concat(
                    TESTDATA,
                    "babybear_quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_success_proof.abi"
                )
            ),
            (WhirStructs.WhirProof)
        );
        bytes memory blob = vm.readFileBinary(
            string.concat(
                TESTDATA, "babybear_quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_success.blob"
            )
        );

        bytes memory verifyCalldata =
            abi.encodeCall(BabyBearWhirBlobVerifierNative5.verify, (proof.initialCommitment, blob));

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

        BabyBearWhirBlobVerifierNative5 nativeVerifier = new BabyBearWhirBlobVerifierNative5();
        nativeVerifierAddress = address(nativeVerifier);

        (bool ok, bytes memory ret) = nativeVerifierAddress.call(verifyCalldata);
        require(ok && abi.decode(ret, (bool)), "VERIFY_FAILED");

        vm.stopBroadcast();

        console2.log("babyBearNativeBlobVerifier", nativeVerifierAddress);
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
