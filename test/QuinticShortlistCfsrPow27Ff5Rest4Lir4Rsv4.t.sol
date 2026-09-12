// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";

import { WhirStructs } from "../src/whir/WhirStructs.sol";
import { KoalaBear } from "../src/field/KoalaBear.sol";
import { KoalaBearExt5 } from "../src/field/KoalaBearExt5.sol";
import { MerkleVerifier } from "../src/merkle/MerkleVerifier.sol";
import {
    WhirBlobVerifierNative5_cfsr_pow27_ff5_rest4_lir4_rsv4
} from "../src/whir/quintic_shortlist_cfsr_pow27_ff5_rest4_lir4_rsv4/WhirBlobVerifierNative5_cfsr_pow27_ff5_rest4_lir4_rsv4.sol";
import {
    WhirVerifierUtils5
} from "../src/whir/quintic_shortlist_cfsr_pow27_ff5_rest4_lir4_rsv4/WhirVerifierUtils5.sol";

contract QuinticShortlistBaseRowDim5Harness {
    function evaluateBoth(bytes calldata row, uint256[] memory point)
        external
        pure
        returns (uint256 specialized, uint256 expected)
    {
        MerkleVerifier.hashLeafBaseSlice20Blob(row, 0, 32);
        specialized = WhirVerifierUtils5.evaluateBaseRowDim5BlobAfterHash(row, 0, point, 0);
        expected = WhirVerifierUtils5.evaluateBaseRowAsExt5Blob(row, 0, 32, point, 0, 5);
    }
}

contract QuinticShortlistCfsrPow27Ff5Rest4Lir4Rsv4Test is Test {
    WhirBlobVerifierNative5_cfsr_pow27_ff5_rest4_lir4_rsv4 private verifier;
    QuinticShortlistBaseRowDim5Harness private rowHarness;

    function setUp() external {
        verifier = new WhirBlobVerifierNative5_cfsr_pow27_ff5_rest4_lir4_rsv4();
        rowHarness = new QuinticShortlistBaseRowDim5Harness();
    }

    function testGasShortlistCfsrPow27Ff5Rest4Lir4Rsv4() external view {
        WhirStructs.WhirProof memory proof = abi.decode(
            vm.readFileBinary(
                "testdata/quintic_shortlist/quintic_whir_cfsr_pow27_ff5_rest4_lir4_rsv4_success_proof.abi"
            ),
            (WhirStructs.WhirProof)
        );
        bytes memory blob = vm.readFileBinary(
            "testdata/quintic_shortlist/quintic_whir_cfsr_pow27_ff5_rest4_lir4_rsv4_success.blob"
        );
        assertTrue(verifier.verify(proof.initialCommitment, blob));
    }

    function testFuzzBaseRowDim5Specialization(bytes32 rowSeed, bytes32 pointSeed) external view {
        bytes memory row = new bytes(32 * 4 + 28);
        uint256[] memory point = new uint256[](5);
        for (uint256 i; i < 32; ++i) {
            uint256 value = uint256(keccak256(abi.encode(rowSeed, i))) % KoalaBear.MODULUS;
            assembly ("memory-safe") {
                mstore(add(add(row, 32), shl(2, i)), shl(224, value))
            }
        }
        assembly ("memory-safe") {
            mstore(row, 128)
        }
        for (uint256 i; i < 5; ++i) {
            uint256[5] memory coefficients;
            for (uint256 j; j < 5; ++j) {
                coefficients[j] =
                    uint256(keccak256(abi.encode(pointSeed, i, j))) % KoalaBear.MODULUS;
            }
            point[i] = KoalaBearExt5.pack(coefficients);
        }

        (uint256 specialized, uint256 expected) = rowHarness.evaluateBoth(row, point);
        assertEq(specialized, expected);
    }
}
