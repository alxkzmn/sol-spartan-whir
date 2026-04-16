// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Script, console2 } from "forge-std/Script.sol";

import { WhirStructs } from "../src/whir/WhirStructs.sol";
import { WhirVerifier4 } from "../src/whir/WhirVerifier4_lir6_ff5_rsv1.sol";

contract WhirTxBenchmarkScript is Script {
    string internal constant TESTDATA = "testdata/";

    function run() external returns (address verifierAddress) {
        (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof) =
            _loadSuccessFixture();

        bytes memory verifyCalldata =
            abi.encodeCall(WhirVerifier4.verify, (proof.initialCommitment, statement, proof));

        uint256 zeroBytes;
        uint256 nonZeroBytes;
        uint256 calldataGas;
        (zeroBytes, nonZeroBytes, calldataGas) = _calldataBreakdown(verifyCalldata);

        console2.log("verify calldata bytes", verifyCalldata.length);
        console2.log("verify calldata zero bytes", zeroBytes);
        console2.log("verify calldata non-zero bytes", nonZeroBytes);
        console2.log("verify calldata intrinsic gas", uint256(21_000));
        console2.log("verify calldata gas", calldataGas);

        vm.startBroadcast();

        WhirVerifier4 verifier = new WhirVerifier4();
        verifierAddress = address(verifier);
        (bool ok, bytes memory ret) = verifierAddress.call(verifyCalldata);
        require(ok && abi.decode(ret, (bool)), "VERIFY_FAILED");

        vm.stopBroadcast();

        console2.log("verifier", verifierAddress);
    }

    function _loadSuccessFixture()
        internal
        view
        returns (WhirStructs.WhirStatement memory statement, WhirStructs.WhirProof memory proof)
    {
        statement = abi.decode(
            vm.readFileBinary(
                string.concat(TESTDATA, "quartic_whir_lir6_ff5_rsv1_success_statement.abi")
            ),
            (WhirStructs.WhirStatement)
        );
        proof = abi.decode(
            vm.readFileBinary(
                string.concat(TESTDATA, "quartic_whir_lir6_ff5_rsv1_success_proof.abi")
            ),
            (WhirStructs.WhirProof)
        );
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
