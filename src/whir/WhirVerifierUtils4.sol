// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {LibSort} from "solady/utils/LibSort.sol";

import {KoalaBear} from "../field/KoalaBear.sol";
import {KoalaBearExt4} from "../field/KoalaBearExt4.sol";
import {KeccakChallenger} from "../transcript/KeccakChallenger.sol";

library WhirVerifierUtils4 {
    using KeccakChallenger for KeccakChallenger.State;

    error BaseFieldElementOutOfRange(uint256 value);
    error PackedExtensionElementOutOfRange(uint256 value);
    error NotPowerOfTwo(uint256 value);

    function observePattern(
        KeccakChallenger.State memory challenger,
        uint256[] calldata pattern
    ) internal pure {
        unchecked {
            for (uint256 i = 0; i < pattern.length; ++i) {
                uint256 value = pattern[i];
                if (value >= KoalaBear.MODULUS) {
                    revert BaseFieldElementOutOfRange(value);
                }
                challenger.observeBase(value);
            }
        }
    }

    function observeExt4(
        KeccakChallenger.State memory challenger,
        uint256 packed
    ) internal pure {
        uint256[4] memory coeffs = KoalaBearExt4.unpack(packed);
        unchecked {
            for (uint256 i = 0; i < 4; ++i) {
                challenger.observeBase(coeffs[i]);
            }
        }
    }

    function sampleExt4(
        KeccakChallenger.State memory challenger
    ) internal pure returns (uint256) {
        return KoalaBearExt4.pack(challenger.sampleExt4Coeffs());
    }

    function validateBaseCalldata(uint256[] calldata values) internal pure {
        unchecked {
            for (uint256 i = 0; i < values.length; ++i) {
                if (values[i] >= KoalaBear.MODULUS) {
                    revert BaseFieldElementOutOfRange(values[i]);
                }
            }
        }
    }

    function validatePackedExt4Calldata(
        uint256[] calldata values
    ) internal pure {
        unchecked {
            for (uint256 i = 0; i < values.length; ++i) {
                validatePackedExt4(values[i]);
            }
        }
    }

    function validatePackedExt4(uint256 packed) internal pure {
        uint256[4] memory coeffs = KoalaBearExt4.unpack(packed);
        unchecked {
            for (uint256 i = 0; i < 4; ++i) {
                if (coeffs[i] >= KoalaBear.MODULUS) {
                    revert PackedExtensionElementOutOfRange(packed);
                }
            }
        }
    }

    function expandFromUnivariateExt(
        uint256 value,
        uint256 numVariables
    ) internal pure returns (uint256[] memory point) {
        point = new uint256[](numVariables);
        uint256 current = value;

        for (uint256 i = numVariables; i > 0; --i) {
            point[i - 1] = current;
            current = KoalaBearExt4.square(current);
        }
    }

    function hornerBase(
        uint256[] calldata coeffs,
        uint256 var_
    ) internal pure returns (uint256 acc) {
        unchecked {
            for (uint256 i = coeffs.length; i > 0; --i) {
                validatePackedExt4(coeffs[i - 1]);
                acc = KoalaBearExt4.add(
                    KoalaBearExt4.mulBase(acc, var_),
                    coeffs[i - 1]
                );
            }
        }
    }

    function sampleStirQueries(
        KeccakChallenger.State memory challenger,
        uint256 domainSize,
        uint256 foldingFactor,
        uint256 numQueries
    ) internal pure returns (uint256[] memory queries) {
        uint256 foldedDomainSize = domainSize >> foldingFactor;
        uint256 domainBits = log2Strict(foldedDomainSize);
        uint256 maxBitsPerCall = 20;
        uint256 totalBitsNeeded = numQueries * domainBits;

        queries = new uint256[](numQueries);

        if (totalBitsNeeded <= maxBitsPerCall) {
            uint256 allBits = challenger.sampleBits(totalBitsNeeded);
            uint256 mask = domainBits == 0
                ? 0
                : ((uint256(1) << domainBits) - 1);
            unchecked {
                for (uint256 i = 0; i < numQueries; ++i) {
                    queries[i] = (allBits & mask) % foldedDomainSize;
                    allBits >>= domainBits;
                }
            }
        } else {
            uint256 queriesPerBatch = maxBitsPerCall / domainBits;
            if (queriesPerBatch >= 2) {
                uint256 remaining = numQueries;
                uint256 cursor = 0;
                uint256 mask = (uint256(1) << domainBits) - 1;
                while (remaining > 0) {
                    uint256 batchSize = remaining < queriesPerBatch
                        ? remaining
                        : queriesPerBatch;
                    uint256 batchBits = batchSize * domainBits;
                    uint256 allBits = challenger.sampleBits(batchBits);

                    unchecked {
                        for (uint256 i = 0; i < batchSize; ++i) {
                            queries[cursor] =
                                (allBits & mask) %
                                foldedDomainSize;
                            allBits >>= domainBits;
                            cursor += 1;
                        }
                    }

                    remaining -= batchSize;
                }
            } else {
                unchecked {
                    for (uint256 i = 0; i < numQueries; ++i) {
                        queries[i] = challenger.sampleBits(domainBits);
                    }
                }
            }
        }

        if (queries.length > 1) {
            LibSort.sort(queries);
            LibSort.uniquifySorted(queries);
        }
    }

    function evaluateBaseRowAsExt4(
        uint256[] calldata flatValues,
        uint256 start,
        uint256 rowLen,
        uint256[] memory point
    ) internal pure returns (uint256) {
        uint256[] memory evals = new uint256[](rowLen);
        unchecked {
            for (uint256 i = 0; i < rowLen; ++i) {
                uint256 value = flatValues[start + i];
                if (value >= KoalaBear.MODULUS) {
                    revert BaseFieldElementOutOfRange(value);
                }
                evals[i] = KoalaBearExt4.fromBase(value);
            }
        }
        return KoalaBearExt4.evaluate_hypercube(evals, point);
    }

    function evaluateExtensionRowAsExt4(
        uint256[] calldata flatValues,
        uint256 start,
        uint256 rowLen,
        uint256[] memory point
    ) internal pure returns (uint256) {
        uint256[] memory evals = new uint256[](rowLen);
        unchecked {
            for (uint256 i = 0; i < rowLen; ++i) {
                uint256 value = flatValues[start + i];
                validatePackedExt4(value);
                evals[i] = value;
            }
        }
        return KoalaBearExt4.evaluate_hypercube(evals, point);
    }

    function log2Strict(uint256 x) internal pure returns (uint256 result) {
        if (x == 0 || (x & (x - 1)) != 0) {
            revert NotPowerOfTwo(x);
        }

        while (x > 1) {
            x >>= 1;
            result += 1;
        }
    }
}
