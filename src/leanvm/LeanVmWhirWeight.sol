// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { KoalaBearExt5 as EF } from "../field/KoalaBearExt5.sol";
import { KoalaBearPackedField as Packed } from "../field/KoalaBearPackedField.sol";

/// @dev One cache belongs to one immutable evaluation point. Canonical packed
/// quintic elements have zero low bits, so bit zero records computed zero values.
library LeanVmWhirWeight {
    uint256 internal constant ONE = uint256(1) << 224;
    uint256 internal constant MAX_CACHE_DEPTH = 10;

    struct Cache {
        uint256 depth;
        uint256[] nodes;
    }

    function initialize(uint256 depth) internal pure returns (Cache memory cache) {
        require(depth <= MAX_CACHE_DEPTH, "WEIGHT_CACHE_DEPTH");
        cache.depth = depth;
        if (depth == 0) {
            cache.nodes = new uint256[](0);
        } else {
            cache.nodes = new uint256[](uint256(1) << (depth + 1));
            cache.nodes[1] = ONE | 1;
        }
    }

    /// @dev The binary heap node (1 << depth) + index stores the product of the
    /// selected first depth coordinates. Descendants share these exact factors.
    /// Heap keys stay below the node count by construction, so reads and the
    /// descent writes skip the array bounds checks.
    function selector(Cache memory cache, uint256[] memory point, uint256 index, uint256 count)
        internal
        pure
        returns (uint256 out)
    {
        require(count <= point.length && index < (uint256(1) << count), "SELECTOR");
        uint256 cached = count < cache.depth ? count : cache.depth;
        uint256 depth;
        out = ONE;
        if (cached != 0) {
            uint256 nodesPtr;
            {
                uint256[] memory nodes = cache.nodes;
                assembly ("memory-safe") { nodesPtr := add(nodes, 32) }
            }
            uint256 key = (uint256(1) << cached) + (index >> (count - cached));
            uint256 node;
            assembly ("memory-safe") { node := mload(add(nodesPtr, shl(5, key))) }
            depth = cached;
            while (node == 0) {
                key >>= 1;
                --depth;
                assembly ("memory-safe") { node := mload(add(nodesPtr, shl(5, key))) }
            }
            out = node & ~uint256(1);
            while (depth < cached) {
                uint256 bit = (index >> (count - depth - 1)) & 1;
                key = (key << 1) | bit;
                uint256 factor = bit == 0 ? EF.sub(ONE, point[depth]) : point[depth];
                out = Packed.mul(out, factor);
                uint256 stored = out | 1;
                assembly ("memory-safe") { mstore(add(nodesPtr, shl(5, key)), stored) }
                ++depth;
            }
        }
        // Large boundary selectors share the cached prefix and evaluate only
        // their remaining suffix. No exponential allocation follows count.
        for (; depth < count; ++depth) {
            uint256 factor =
                (index >> (count - depth - 1)) & 1 == 0 ? EF.sub(ONE, point[depth]) : point[depth];
            out = Packed.mul(out, factor);
        }
    }

    /// @dev Sum gamma^i times selector(first+i), using aligned binary intervals.
    /// A full k-bit interval factors into k linear terms; no field division is used.
    function rangeSum(
        Cache memory cache,
        uint256[] memory point,
        uint256 first,
        uint256 count,
        uint256 depth,
        uint256[8] memory gammaSquares
    ) internal pure returns (uint256 sum) {
        require(depth <= point.length && depth < 256 && count < 256, "SELECTOR");
        uint256 limit = uint256(1) << depth;
        require(first <= limit && count <= limit - first, "SELECTOR");
        uint256[8] memory suffixWeights;
        suffixWeights[0] = ONE;
        for (uint256 k = 1; (uint256(1) << k) <= count; ++k) {
            suffixWeights[k] = Packed.mul(
                suffixWeights[k - 1],
                EF.add(ONE, Packed.mul(point[depth - k], EF.sub(gammaSquares[k - 1], ONE)))
            );
        }
        uint256 gammaPower = ONE;
        while (count != 0) {
            uint256 k;
            uint256 width = 1;
            while ((width << 1) <= count && (first & ((width << 1) - 1)) == 0) {
                width <<= 1;
                ++k;
            }
            uint256 weight =
                Packed.mul(selector(cache, point, first >> k, depth - k), suffixWeights[k]);
            sum = EF.add(sum, Packed.mul(gammaPower, weight));
            gammaPower = Packed.mul(gammaPower, gammaSquares[k]);
            first += width;
            count -= width;
        }
    }
}
