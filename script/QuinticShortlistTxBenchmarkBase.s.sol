// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Script, console2 } from "forge-std/Script.sol";

import { WhirStructs } from "../src/whir/WhirStructs.sol";

interface IQuinticShortlistNativeVerifier {
    function verify(bytes32 expectedCommitment, bytes calldata blob) external pure returns (bool);
}

abstract contract QuinticShortlistTxBenchmarkBase is Script {
    function _load(string memory label)
        internal
        view
        returns (bytes32 commitment, bytes memory blob)
    {
        WhirStructs.WhirProof memory proof = abi.decode(
            vm.readFileBinary(
                string.concat(
                    "testdata/quintic_shortlist/quintic_whir_", label, "_success_proof.abi"
                )
            ),
            (WhirStructs.WhirProof)
        );
        commitment = proof.initialCommitment;
        blob = vm.readFileBinary(
            string.concat("testdata/quintic_shortlist/quintic_whir_", label, "_success.blob")
        );
    }

    function _verify(address verifier, bytes32 commitment, bytes memory blob) internal {
        bytes memory verifyCalldata =
            abi.encodeCall(IQuinticShortlistNativeVerifier.verify, (commitment, blob));
        (uint256 zeroBytes, uint256 nonZeroBytes, uint256 calldataGas) =
            _calldataBreakdown(verifyCalldata);
        console2.log("native blob verify calldata bytes", verifyCalldata.length);
        console2.log("native blob verify calldata zero bytes", zeroBytes);
        console2.log("native blob verify calldata non-zero bytes", nonZeroBytes);
        console2.log("native blob verify calldata intrinsic gas", uint256(21_000));
        console2.log("native blob verify calldata gas", calldataGas);

        (bool ok, bytes memory ret) = verifier.call(verifyCalldata);
        require(ok && abi.decode(ret, (bool)), "VERIFY_FAILED");
    }

    function _calldataBreakdown(bytes memory data)
        private
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
