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
        challenger.observePackedExt4(packed);
    }

    function sampleExt4(
        KeccakChallenger.State memory challenger
    ) internal pure returns (uint256) {
        unchecked {
            return
                (challenger.sampleBase() << 224) |
                (challenger.sampleBase() << 192) |
                (challenger.sampleBase() << 160) |
                (challenger.sampleBase() << 128);
        }
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
        assembly ("memory-safe") {
            let modulus := 0x7f000001
            let mask := 0xffffffff

            let src := add(coeffs.offset, shl(5, coeffs.length))
            let end := coeffs.offset

            for {

            } gt(src, end) {

            } {
                src := sub(src, 0x20)
                let packed := calldataload(src)

                let a0 := shr(224, acc)
                let a1 := and(shr(192, acc), mask)
                let a2 := and(shr(160, acc), mask)
                let a3 := and(shr(128, acc), mask)

                let c0 := shr(224, packed)
                let c1 := and(shr(192, packed), mask)
                let c2 := and(shr(160, packed), mask)
                let c3 := and(shr(128, packed), mask)

                let r0 := add(mulmod(a0, var_, modulus), c0)
                if iszero(lt(r0, modulus)) {
                    r0 := sub(r0, modulus)
                }
                let r1 := add(mulmod(a1, var_, modulus), c1)
                if iszero(lt(r1, modulus)) {
                    r1 := sub(r1, modulus)
                }
                let r2 := add(mulmod(a2, var_, modulus), c2)
                if iszero(lt(r2, modulus)) {
                    r2 := sub(r2, modulus)
                }
                let r3 := add(mulmod(a3, var_, modulus), c3)
                if iszero(lt(r3, modulus)) {
                    r3 := sub(r3, modulus)
                }

                acc := or(
                    or(shl(224, r0), shl(192, r1)),
                    or(shl(160, r2), shl(128, r3))
                )
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
        if (point.length == 0) {
            return _loadBaseAsExt4Unchecked(flatValues, start);
        }
        if (point.length == 1) {
            return
                _foldOnce(
                    _loadBaseAsExt4Unchecked(flatValues, start),
                    _loadBaseAsExt4Unchecked(flatValues, start + 1),
                    point[0]
                );
        }
        if (point.length == 2) {
            uint256 l0 = _foldOnce(
                _loadBaseAsExt4Unchecked(flatValues, start),
                _loadBaseAsExt4Unchecked(flatValues, start + 2),
                point[0]
            );
            uint256 l1 = _foldOnce(
                _loadBaseAsExt4Unchecked(flatValues, start + 1),
                _loadBaseAsExt4Unchecked(flatValues, start + 3),
                point[0]
            );
            return _foldOnce(l0, l1, point[1]);
        }
        if (point.length == 3) {
            return _evaluateBaseRowDim3(flatValues, start, point);
        }
        if (point.length == 4) {
            return _evaluateBaseRowDim4(flatValues, start, point);
        }

        uint256[] memory evals = new uint256[](rowLen);
        unchecked {
            for (uint256 i = 0; i < rowLen; ++i) {
                evals[i] = _loadBaseAsExt4Unchecked(flatValues, start + i);
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
        if (point.length == 0) {
            return _loadPackedExt4Unchecked(flatValues, start);
        }
        if (point.length == 1) {
            return
                _foldOnce(
                    _loadPackedExt4Unchecked(flatValues, start),
                    _loadPackedExt4Unchecked(flatValues, start + 1),
                    point[0]
                );
        }
        if (point.length == 2) {
            uint256 l0 = _foldOnce(
                _loadPackedExt4Unchecked(flatValues, start),
                _loadPackedExt4Unchecked(flatValues, start + 2),
                point[0]
            );
            uint256 l1 = _foldOnce(
                _loadPackedExt4Unchecked(flatValues, start + 1),
                _loadPackedExt4Unchecked(flatValues, start + 3),
                point[0]
            );
            return _foldOnce(l0, l1, point[1]);
        }
        if (point.length == 3) {
            return _evaluateExtensionRowDim3(flatValues, start, point);
        }
        if (point.length == 4) {
            return _evaluateExtensionRowDim4(flatValues, start, point);
        }

        uint256[] memory evals = new uint256[](rowLen);
        unchecked {
            for (uint256 i = 0; i < rowLen; ++i) {
                evals[i] = _loadPackedExt4Unchecked(flatValues, start + i);
            }
        }
        return KoalaBearExt4.evaluate_hypercube(evals, point);
    }

    function _evaluateBaseRowDim3(
        uint256[] calldata flatValues,
        uint256 start,
        uint256[] memory point
    ) private pure returns (uint256) {
        uint256 l0 = _foldOnce(
            _loadBaseAsExt4Unchecked(flatValues, start),
            _loadBaseAsExt4Unchecked(flatValues, start + 4),
            point[0]
        );
        uint256 l1 = _foldOnce(
            _loadBaseAsExt4Unchecked(flatValues, start + 1),
            _loadBaseAsExt4Unchecked(flatValues, start + 5),
            point[0]
        );
        uint256 l2 = _foldOnce(
            _loadBaseAsExt4Unchecked(flatValues, start + 2),
            _loadBaseAsExt4Unchecked(flatValues, start + 6),
            point[0]
        );
        uint256 l3 = _foldOnce(
            _loadBaseAsExt4Unchecked(flatValues, start + 3),
            _loadBaseAsExt4Unchecked(flatValues, start + 7),
            point[0]
        );
        uint256 m0 = _foldOnce(l0, l2, point[1]);
        uint256 m1 = _foldOnce(l1, l3, point[1]);
        return _foldOnce(m0, m1, point[2]);
    }

    function _evaluateBaseRowDim4(
        uint256[] calldata flatValues,
        uint256 start,
        uint256[] memory point
    ) private pure returns (uint256) {
        uint256 l0 = _foldOnce(
            _loadBaseAsExt4Unchecked(flatValues, start),
            _loadBaseAsExt4Unchecked(flatValues, start + 8),
            point[0]
        );
        uint256 l1 = _foldOnce(
            _loadBaseAsExt4Unchecked(flatValues, start + 1),
            _loadBaseAsExt4Unchecked(flatValues, start + 9),
            point[0]
        );
        uint256 l2 = _foldOnce(
            _loadBaseAsExt4Unchecked(flatValues, start + 2),
            _loadBaseAsExt4Unchecked(flatValues, start + 10),
            point[0]
        );
        uint256 l3 = _foldOnce(
            _loadBaseAsExt4Unchecked(flatValues, start + 3),
            _loadBaseAsExt4Unchecked(flatValues, start + 11),
            point[0]
        );
        uint256 l4 = _foldOnce(
            _loadBaseAsExt4Unchecked(flatValues, start + 4),
            _loadBaseAsExt4Unchecked(flatValues, start + 12),
            point[0]
        );
        uint256 l5 = _foldOnce(
            _loadBaseAsExt4Unchecked(flatValues, start + 5),
            _loadBaseAsExt4Unchecked(flatValues, start + 13),
            point[0]
        );
        uint256 l6 = _foldOnce(
            _loadBaseAsExt4Unchecked(flatValues, start + 6),
            _loadBaseAsExt4Unchecked(flatValues, start + 14),
            point[0]
        );
        uint256 l7 = _foldOnce(
            _loadBaseAsExt4Unchecked(flatValues, start + 7),
            _loadBaseAsExt4Unchecked(flatValues, start + 15),
            point[0]
        );
        uint256 m0 = _foldOnce(l0, l4, point[1]);
        uint256 m1 = _foldOnce(l1, l5, point[1]);
        uint256 m2 = _foldOnce(l2, l6, point[1]);
        uint256 m3 = _foldOnce(l3, l7, point[1]);
        uint256 n0 = _foldOnce(m0, m2, point[2]);
        uint256 n1 = _foldOnce(m1, m3, point[2]);
        return _foldOnce(n0, n1, point[3]);
    }

    function _evaluateExtensionRowDim3(
        uint256[] calldata flatValues,
        uint256 start,
        uint256[] memory point
    ) private pure returns (uint256) {
        uint256 l0 = _foldOnce(
            _loadPackedExt4Unchecked(flatValues, start),
            _loadPackedExt4Unchecked(flatValues, start + 4),
            point[0]
        );
        uint256 l1 = _foldOnce(
            _loadPackedExt4Unchecked(flatValues, start + 1),
            _loadPackedExt4Unchecked(flatValues, start + 5),
            point[0]
        );
        uint256 l2 = _foldOnce(
            _loadPackedExt4Unchecked(flatValues, start + 2),
            _loadPackedExt4Unchecked(flatValues, start + 6),
            point[0]
        );
        uint256 l3 = _foldOnce(
            _loadPackedExt4Unchecked(flatValues, start + 3),
            _loadPackedExt4Unchecked(flatValues, start + 7),
            point[0]
        );
        uint256 m0 = _foldOnce(l0, l2, point[1]);
        uint256 m1 = _foldOnce(l1, l3, point[1]);
        return _foldOnce(m0, m1, point[2]);
    }

    function _evaluateExtensionRowDim4(
        uint256[] calldata flatValues,
        uint256 start,
        uint256[] memory point
    ) private pure returns (uint256) {
        uint256 l0 = _foldOnce(
            _loadPackedExt4Unchecked(flatValues, start),
            _loadPackedExt4Unchecked(flatValues, start + 8),
            point[0]
        );
        uint256 l1 = _foldOnce(
            _loadPackedExt4Unchecked(flatValues, start + 1),
            _loadPackedExt4Unchecked(flatValues, start + 9),
            point[0]
        );
        uint256 l2 = _foldOnce(
            _loadPackedExt4Unchecked(flatValues, start + 2),
            _loadPackedExt4Unchecked(flatValues, start + 10),
            point[0]
        );
        uint256 l3 = _foldOnce(
            _loadPackedExt4Unchecked(flatValues, start + 3),
            _loadPackedExt4Unchecked(flatValues, start + 11),
            point[0]
        );
        uint256 l4 = _foldOnce(
            _loadPackedExt4Unchecked(flatValues, start + 4),
            _loadPackedExt4Unchecked(flatValues, start + 12),
            point[0]
        );
        uint256 l5 = _foldOnce(
            _loadPackedExt4Unchecked(flatValues, start + 5),
            _loadPackedExt4Unchecked(flatValues, start + 13),
            point[0]
        );
        uint256 l6 = _foldOnce(
            _loadPackedExt4Unchecked(flatValues, start + 6),
            _loadPackedExt4Unchecked(flatValues, start + 14),
            point[0]
        );
        uint256 l7 = _foldOnce(
            _loadPackedExt4Unchecked(flatValues, start + 7),
            _loadPackedExt4Unchecked(flatValues, start + 15),
            point[0]
        );
        uint256 m0 = _foldOnce(l0, l4, point[1]);
        uint256 m1 = _foldOnce(l1, l5, point[1]);
        uint256 m2 = _foldOnce(l2, l6, point[1]);
        uint256 m3 = _foldOnce(l3, l7, point[1]);
        uint256 n0 = _foldOnce(m0, m2, point[2]);
        uint256 n1 = _foldOnce(m1, m3, point[2]);
        return _foldOnce(n0, n1, point[3]);
    }

    function _loadBaseAsExt4Unchecked(
        uint256[] calldata flatValues,
        uint256 index
    ) private pure returns (uint256) {
        return flatValues[index] << 224;
    }

    function _loadPackedExt4Unchecked(
        uint256[] calldata flatValues,
        uint256 index
    ) private pure returns (uint256 value) {
        value = flatValues[index];
    }

    function _foldOnce(
        uint256 a0,
        uint256 a1,
        uint256 r
    ) private pure returns (uint256) {
        return
            KoalaBearExt4.add(
                a0,
                KoalaBearExt4.mul(r, KoalaBearExt4.sub(a1, a0))
            );
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
