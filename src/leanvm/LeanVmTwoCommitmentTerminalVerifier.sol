// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { KoalaBearExt5 as EF } from "../field/KoalaBearExt5.sol";
import { LeanVmTwoCommitmentExecution as Execution } from "./LeanVmTwoCommitmentExecution.sol";

/// @dev Version-one terminal C1 verifier. Generated contracts pin the execution
/// profile, fixed-program commitment, program layout, and lifted verifier capacity.
abstract contract LeanVmTwoCommitmentTerminalVerifier {
    uint256 internal constant PUBLIC_MEMORY_OFFSET = 4096;
    uint256 internal constant PUBLIC_MEMORY_LENGTH = 256;
    uint256 internal constant MODULUS = 2_130_706_433;

    struct Proof {
        bytes transcript;
        bytes openings;
        uint256[8] applicationRoot;
        uint256[] sparkPoint;
        uint256 sparkValue;
        uint256[] liftPoint;
        uint256 liftValue;
        uint256 rootValue;
    }

    function rootConfig() internal pure virtual returns (Execution.Config memory);
    function fixedProgramConfig()
        internal
        pure
        virtual
        returns (Execution.TwoCommitmentConfig memory);
    function liftedCapacity() internal pure virtual returns (uint256[8] memory);

    function flattenClaim(uint256[] memory point, uint256 value)
        internal
        pure
        returns (uint256[] memory fields)
    {
        uint256 count = (point.length + 1) * 5;
        fields = new uint256[]((count + 7) & ~uint256(7));
        for (uint256 i; i <= point.length; ++i) {
            uint256 element = i == point.length ? value : point[i];
            EF.validatePacked(element);
            // The allocation contains at least five fields for every point/value.
            assembly ("memory-safe") {
                let destination := add(add(fields, 32), mul(i, 160))
                mstore(destination, shr(224, element))
                mstore(add(destination, 32), and(shr(192, element), 0xffffffff))
                mstore(add(destination, 64), and(shr(160, element), 0xffffffff))
                mstore(add(destination, 96), and(shr(128, element), 0xffffffff))
                mstore(add(destination, 128), and(shr(96, element), 0xffffffff))
            }
        }
    }

    function publicNodeInfo(Proof calldata proof) internal pure returns (uint256[] memory info) {
        uint256[] memory spark = flattenClaim(proof.sparkPoint, proof.sparkValue);
        uint256[] memory lift = flattenClaim(proof.liftPoint, proof.liftValue);
        info = new uint256[](24 + spark.length + lift.length);
        info[0] = 1_313_817_649;
        info[1] = 2;
        uint256 at = 8;
        for (uint256 i; i < lift.length; ++i) {
            info[at++] = lift[i];
        }
        uint256[8] memory capacity = liftedCapacity();
        for (uint256 i; i < 8; ++i) {
            info[at++] = capacity[i];
        }
        for (uint256 i; i < spark.length; ++i) {
            info[at++] = spark[i];
        }
        for (uint256 i; i < 8; ++i) {
            require(proof.applicationRoot[i] < MODULUS, "PUBLIC_INPUT_RANGE");
            info[at++] = proof.applicationRoot[i];
        }
        require(at == info.length, "PUBLIC_MEMORY_LAYOUT");
    }

    /// @notice Verify the compact version-one terminal C1 proof.
    function verifyC1V1(Proof calldata proof) external pure returns (bool) {
        Execution.Config memory executionConfig = rootConfig();
        Execution.TwoCommitmentConfig memory commitmentConfig = fixedProgramConfig();
        require(
            proof.sparkPoint.length == commitmentConfig.programDimensions[0]
                && proof.liftPoint.length == commitmentConfig.programDimensions[1],
            "CARRIED_CLAIM_DIM"
        );
        uint256[] memory info = publicNodeInfo(proof);
        require(info.length == PUBLIC_MEMORY_LENGTH, "PUBLIC_MEMORY_PROFILE");
        Execution.FixedProgramClaims memory claims = Execution.FixedProgramClaims({
            sparkPoint: proof.sparkPoint,
            sparkValue: proof.sparkValue,
            liftPoint: proof.liftPoint,
            liftValue: proof.liftValue
        });
        Execution.verifyTwoCommitmentsWithPublicMemory(
            proof.transcript,
            proof.openings,
            proof.applicationRoot,
            executionConfig,
            proof.rootValue,
            info,
            PUBLIC_MEMORY_OFFSET,
            commitmentConfig,
            claims
        );
        return true;
    }
}
