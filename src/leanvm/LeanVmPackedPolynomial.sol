// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import { KoalaBearExt5 as EF } from "../field/KoalaBearExt5.sol";
import { KoalaBearPackedField as Packed } from "../field/KoalaBearPackedField.sol";

/// @dev Callers validate all inputs as canonical packed quintic elements.
library LeanVmPackedPolynomial {
    uint256 internal constant ONE = uint256(1) << 224;

    function eqPolynomial(uint256[] memory p, uint256[] memory q)
        internal
        pure
        returns (uint256 acc)
    {
        require(p.length == q.length, "LEN");
        acc = ONE;
        for (uint256 i; i < p.length; ++i) {
            acc = Packed.mul(acc, Packed.eq(p[i], q[i]));
        }
    }

    /// @dev Mutates the working evaluation array, in most-significant-coordinate order.
    function evaluateHypercube(uint256[] memory evaluations, uint256[] memory point)
        internal
        pure
        returns (uint256)
    {
        uint256 size = evaluations.length;
        require(size != 0 && (size & (size - 1)) == 0, "BAD_EVALS");
        require(size == (uint256(1) << point.length), "DIM");
        for (uint256 i; i < point.length; ++i) {
            size >>= 1;
            for (uint256 j; j < size; ++j) {
                evaluations[j] = EF.add(
                    evaluations[j],
                    Packed.mul(point[i], EF.sub(evaluations[j + size], evaluations[j]))
                );
            }
        }
        return evaluations[0];
    }

    /// @dev Base-field inputs make the first fold a scalar-extension product.
    /// The input array is preserved; the working array holds only the first-fold results.
    function evaluateBaseHypercube(uint256[] memory evaluations, uint256[] memory point)
        internal
        pure
        returns (uint256)
    {
        uint256 size = evaluations.length;
        require(size != 0 && (size & (size - 1)) == 0, "BAD_EVALS");
        require(size == (uint256(1) << point.length), "DIM");
        if (size == 1) return EF.fromBase(evaluations[0]);
        size >>= 1;
        uint256[] memory work = new uint256[](size);
        for (uint256 j; j < size; ++j) {
            uint256 left = EF.fromBase(evaluations[j]);
            uint256 right = EF.fromBase(evaluations[j + size]);
            uint256 difference = EF.sub(right, left) >> 224;
            work[j] = EF.add(left, EF.mulBase(point[0], difference));
        }
        for (uint256 i = 1; i < point.length; ++i) {
            size >>= 1;
            for (uint256 j; j < size; ++j) {
                work[j] = EF.add(work[j], Packed.mul(point[i], EF.sub(work[j + size], work[j])));
            }
        }
        return work[0];
    }

    /// @dev Evaluate consecutive Boolean prefix selectors at one immutable point.
    /// Binary increment preserves the prefix before the changed bit. The new
    /// right child is parent minus the preceding left child, including at zero.
    function eqIndexRange(uint256[] memory point, uint256 first, uint256 count, uint256 depth)
        internal
        pure
        returns (uint256[] memory weights)
    {
        require(depth <= point.length && depth < 256, "SELECTOR");
        uint256 limit = uint256(1) << depth;
        require(first <= limit && count <= limit - first, "SELECTOR");
        weights = new uint256[](count);
        if (count == 0) return weights;
        uint256[] memory prefixes = new uint256[](depth + 1);
        prefixes[0] = ONE;
        for (uint256 d; d < depth; ++d) {
            uint256 factor = (first >> (depth - 1 - d)) & 1 == 0 ? EF.sub(ONE, point[d]) : point[d];
            prefixes[d + 1] = Packed.mul(prefixes[d], factor);
        }
        weights[0] = prefixes[depth];
        for (uint256 i = 1; i < count; ++i) {
            uint256 index = first + i;
            uint256 d = depth;
            while ((index & 1) == 0) {
                --d;
                index >>= 1;
            }
            --d;
            prefixes[d + 1] = EF.sub(prefixes[d], prefixes[d + 1]);
            for (uint256 j = d + 1; j < depth; ++j) {
                prefixes[j + 1] = Packed.mul(prefixes[j], EF.sub(ONE, point[j]));
            }
            weights[i] = prefixes[depth];
        }
    }
}
