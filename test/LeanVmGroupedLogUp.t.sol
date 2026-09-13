// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import { Test } from "forge-std/Test.sol";
import { KoalaBearExt5 as EF } from "../src/field/KoalaBearExt5.sol";
import { LeanVmGroupedLogUp as Grouped } from "../src/leanvm/LeanVmGroupedLogUp.sol";
import { LeanVmPolynomial as Poly } from "../src/leanvm/LeanVmPolynomial.sol";

// JSON members are ABI encoded alphabetically by Foundry.
struct GroupedVector {
    uint256[] alpha;
    uint256[] balance;
    uint256[][] beta;
    uint256[][][] claims;
    uint256[] dimensions;
    uint256[][] equality;
    uint256[] expected;
    uint256[] gamma;
    uint256[][] point;
    uint256 variables;
}

contract LeanVmGroupedLogUpTest is Test {
    function packOne(uint256[] memory value) private pure returns (uint256) {
        uint256[5] memory x;
        require(value.length == 5);
        for (uint256 i; i < 5; ++i) {
            x[i] = value[i];
        }
        return EF.pack(x);
    }

    function pack(uint256[][] memory value) private pure returns (uint256[] memory x) {
        x = new uint256[](value.length);
        for (uint256 i; i < x.length; ++i) {
            x[i] = packOne(value[i]);
        }
    }

    function testNativeGroupedAlgebraVectors() external view {
        string memory json = vm.readFile("testdata/grouped_logup/algebra-vectors.json");
        GroupedVector[] memory vectors = abi.decode(vm.parseJson(json, ".cases"), (GroupedVector[]));
        assertEq(vectors.length, 36);
        for (uint256 i; i < vectors.length; ++i) {
            GroupedVector memory v = vectors[i];
            Grouped.Layout memory l = Grouped.layout(v.dimensions, 17, v.variables);
            Grouped.Challenges memory c = Grouped.Challenges(
                packOne(v.gamma),
                Grouped.eqValues(pack(v.beta)),
                pack(v.equality),
                packOne(v.alpha),
                packOne(v.balance)
            );
            Grouped.Claims memory claims;
            uint256[] memory point = pack(v.point);
            for (uint256 kind; kind < 5; ++kind) {
                claims.values[kind] = pack(v.claims[kind]);
                claims.points[kind] = Poly.reverse(
                    Poly.slice(point, point.length - l.heights[kind], l.heights[kind])
                );
            }
            assertEq(Grouped.evaluate(l, claims, c, point), packOne(v.expected), vm.toString(i));
        }
    }
}
