// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {KeccakChallenger} from "./KeccakChallenger.sol";

library SpartanTranscript {
    using KeccakChallenger for KeccakChallenger.State;

    bytes15 internal constant PROTOCOL_ID = 0x7370617274616e2d776869722d7630;

    struct DomainSeparator {
        uint256 numCons;
        uint256 numVars;
        uint256 numIo;
        uint32 securityLevelBits;
        uint32 merkleSecurityBits;
        uint8 soundnessAssumption;
        uint32 powBits;
        uint256 foldingFactor;
        uint256 startingLogInvRate;
        uint256 rsDomainInitialReductionFactor;
    }

    function domainSeparatorPreimage(
        DomainSeparator memory domainSeparator
    ) internal pure returns (bytes memory out) {
        bytes memory protocolId = abi.encodePacked(PROTOCOL_ID);

        out = bytes.concat(
            protocolId,
            _u64LE(domainSeparator.numCons),
            _u64LE(domainSeparator.numVars),
            _u64LE(domainSeparator.numIo),
            _u32LE(domainSeparator.securityLevelBits),
            _u32LE(domainSeparator.merkleSecurityBits),
            abi.encodePacked(domainSeparator.soundnessAssumption),
            _u32LE(domainSeparator.powBits),
            _u64LE(domainSeparator.foldingFactor),
            _u64LE(domainSeparator.startingLogInvRate),
            _u64LE(domainSeparator.rsDomainInitialReductionFactor)
        );
    }

    function domainSeparatorDigest(
        DomainSeparator memory domainSeparator
    ) internal pure returns (bytes32) {
        return keccak256(domainSeparatorPreimage(domainSeparator));
    }

    function observeSpartanContext(
        KeccakChallenger.State memory challenger,
        DomainSeparator memory domainSeparator,
        uint256[] memory publicInputs
    )
        internal
        pure
        returns (KeccakChallenger.State memory updatedChallenger, bytes32 digest)
    {
        updatedChallenger = challenger;
        digest = domainSeparatorDigest(domainSeparator);
        updatedChallenger.observeHashU8Digest(digest);

        unchecked {
            for (uint256 i = 0; i < publicInputs.length; ++i) {
                updatedChallenger.observeBase(publicInputs[i]);
            }
        }
    }

    function _u32LE(uint32 value) private pure returns (bytes memory out) {
        out = new bytes(4);
        out[0] = bytes1(uint8(value));
        out[1] = bytes1(uint8(value >> 8));
        out[2] = bytes1(uint8(value >> 16));
        out[3] = bytes1(uint8(value >> 24));
    }

    function _u64LE(uint256 value) private pure returns (bytes memory out) {
        require(value <= type(uint64).max, "U64_WIDTH");

        out = new bytes(8);
        unchecked {
            out[0] = bytes1(uint8(value));
            out[1] = bytes1(uint8(value >> 8));
            out[2] = bytes1(uint8(value >> 16));
            out[3] = bytes1(uint8(value >> 24));
            out[4] = bytes1(uint8(value >> 32));
            out[5] = bytes1(uint8(value >> 40));
            out[6] = bytes1(uint8(value >> 48));
            out[7] = bytes1(uint8(value >> 56));
        }
    }
}
