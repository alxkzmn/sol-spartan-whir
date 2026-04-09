// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console2} from "forge-std/Script.sol";

import {WhirStructs} from "../src/whir/WhirStructs.sol";
import {WhirBlobVerifier4} from "../src/whir/WhirBlobVerifier4.sol";
import {WhirVerifier4} from "../src/whir/WhirVerifier4.sol";

contract WhirBlobTxBenchmarkScript is Script {
    string internal constant TESTDATA = "testdata/";

    function run()
        external
        returns (address verifierAddress, address blobVerifierAddress)
    {
        WhirStructs.WhirProof memory proof = abi.decode(
            vm.readFileBinary(
                string.concat(TESTDATA, "quartic_whir_success_proof.abi")
            ),
            (WhirStructs.WhirProof)
        );
        bytes memory blob = vm.readFileBinary(
            string.concat(TESTDATA, "quartic_whir_success.blob")
        );

        bytes memory verifyCalldata = abi.encodeCall(
            WhirBlobVerifier4.verify,
            (proof.initialCommitment, blob)
        );

        uint256 zeroBytes;
        uint256 nonZeroBytes;
        uint256 calldataGas;
        (zeroBytes, nonZeroBytes, calldataGas) = _calldataBreakdown(
            verifyCalldata
        );

        console2.log("blob verify calldata bytes", verifyCalldata.length);
        console2.log("blob verify calldata zero bytes", zeroBytes);
        console2.log("blob verify calldata non-zero bytes", nonZeroBytes);
        console2.log("blob verify calldata intrinsic gas", uint256(21_000));
        console2.log("blob verify calldata gas", calldataGas);

        vm.startBroadcast();

        WhirVerifier4 verifier = new WhirVerifier4();
        verifierAddress = address(verifier);
        WhirBlobVerifier4 blobVerifier = new WhirBlobVerifier4(verifier);
        blobVerifierAddress = address(blobVerifier);

        (bool ok, bytes memory ret) = blobVerifierAddress.call(verifyCalldata);
        require(ok && abi.decode(ret, (bool)), "VERIFY_FAILED");

        vm.stopBroadcast();

        console2.log("verifier", verifierAddress);
        console2.log("blobVerifier", blobVerifierAddress);
    }

    function _calldataBreakdown(
        bytes memory data
    )
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
