// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {KoalaBearExt4} from "../field/KoalaBearExt4.sol";
import {KeccakChallenger} from "./KeccakChallenger.sol";

library WhirTranscript {
    using KeccakChallenger for KeccakChallenger.State;

    function observeWhirFsPattern(
        KeccakChallenger.State memory self,
        uint256[] memory pattern
    ) internal pure {
        unchecked {
            for (uint256 i = 0; i < pattern.length; ++i) {
                self.observeBase(pattern[i]);
            }
        }
    }

    function observeExt4Element(
        KeccakChallenger.State memory self,
        uint256 packed
    ) internal pure {
        uint256[4] memory coeffs = KoalaBearExt4.unpack(packed);

        unchecked {
            for (uint256 i = 0; i < 4; ++i) {
                self.observeBase(coeffs[i]);
            }
        }
    }

    function observeExt4Slice(
        KeccakChallenger.State memory self,
        uint256[] memory packedValues
    ) internal pure {
        unchecked {
            for (uint256 i = 0; i < packedValues.length; ++i) {
                observeExt4Element(self, packedValues[i]);
            }
        }
    }

    function observeSumcheckRoundPolyExt4(
        KeccakChallenger.State memory self,
        uint256 c0,
        uint256 c2
    ) internal pure {
        observeExt4Element(self, c0);
        observeExt4Element(self, c2);
    }
}
