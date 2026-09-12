// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { BabyBearBenchChallenger as Challenger } from "./helpers/BabyBearBenchChallenger.sol";

contract BabyBearSecurityGasTest is Test {
    using Challenger for Challenger.State;

    function checks(bytes32 seed, uint256 witness0, uint256 witness2, bool adjusted)
        external
        view
        returns (uint256 used, uint256 result)
    {
        // Construct two independent transcript states outside the measurement.
        Challenger.State memory round0;
        Challenger.State memory round2;
        round0.observeBytes(abi.encodePacked(seed, uint256(0)));
        round2.observeBytes(abi.encodePacked(seed, uint256(2)));
        uint256 bits0 = adjusted ? 23 : 22;
        uint256 bits2 = adjusted ? 28 : 27;
        uint256 start = gasleft();
        bool first = round0.checkWitness(bits0, witness0);
        bool second = round2.checkWitness(bits2, witness2);
        used = start - gasleft();
        result = (first ? 1 : 0) | (second ? 2 : 0);
    }

    function testSecurityAdjustmentGas() external {
        uint256 maxIncrease;
        for (uint256 i; i < 16; ++i) {
            // checkWitness executes the same operations for accepted and rejected
            // witnesses. Its caller's rejection branch is outside this comparison.
            (uint256 original,) = this.checks(bytes32(i), i, i + 1, false);
            (uint256 adjusted,) = this.checks(bytes32(i), i, i + 1, true);
            if (adjusted > original && adjusted - original > maxIncrease) {
                maxIncrease = adjusted - original;
            }
            assertLe(adjusted, original * 105 / 100, "PoW check increase exceeds 5%");
            if (i == 0) {
                emit log_named_uint("pow.original_two_checks", original);
                emit log_named_uint("pow.adjusted_two_checks", adjusted);
            }
        }
        emit log_named_uint("pow.max_check_increase", maxIncrease);
    }

    function testFuzzWitnessResultMatchesTranscript(bytes32 seed, uint256 witness, uint8 width)
        external
        pure
    {
        witness %= 0x78000001;
        uint256 bits = 1 + uint256(width) % 28;
        Challenger.State memory transcript;
        transcript.observeBytes(abi.encodePacked(seed));
        bool actual = transcript.checkWitness(bits, witness);
        // Independent byte-level oracle: observe seed, append a little-endian
        // 32-bit witness, hash once, then take the low bits of the digest.
        bytes memory preimage = new bytes(36);
        for (uint256 i; i < 32; ++i) {
            preimage[i] = seed[i];
        }
        for (uint256 i; i < 4; ++i) {
            preimage[32 + i] = bytes1(uint8(witness >> (8 * i)));
        }
        uint256 candidate = uint256(keccak256(preimage));
        assertEq(actual, (candidate & ((uint256(1) << bits) - 1)) == 0);
    }
}
