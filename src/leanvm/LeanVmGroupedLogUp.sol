// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import { KoalaBearExt5 as EF } from "../field/KoalaBearExt5.sol";
import { KoalaBearPackedField as Packed } from "../field/KoalaBearPackedField.sol";
import { LeanVmAir as Air } from "./LeanVmAir.sol";
import { LeanVmPolynomial as Poly } from "./LeanVmPolynomial.sol";
import { LeanVmPackedPolynomial as PackedPoly } from "./LeanVmPackedPolynomial.sol";

/// @dev Group kinds are memory, bytecode, execution, extension operations and Poseidon.
/// All values are canonical packed quintic elements authenticated by the enclosing PCS.
library LeanVmGroupedLogUp {
    using { EF.add, EF.sub, EF.mulBase, EF.square, Packed.mul } for uint256;
    uint256 internal constant ONE = uint256(1) << 224;

    struct Layout {
        uint256[5] heights;
        uint256[5] order;
        uint256[5] helperOffsets;
        uint256[3] tableOffsets;
        uint256 maximum;
        uint256 memoryLog;
        uint256 bytecodeLog;
        uint256 variables;
    }

    struct Challenges {
        uint256 gamma;
        uint256[] betaEq;
        uint256[] equality;
        uint256 alpha;
        uint256 balance;
    }

    struct Claims {
        uint256[][5] values;
        uint256[][5] points;
    }

    function columns(uint256 table) internal pure returns (uint256) {
        return table == 0 ? 20 : (table == 1 ? 29 : 110);
    }

    function shifts(uint256 table) internal pure returns (uint256) {
        return table == 0 ? 2 : (table == 1 ? 13 : 0);
    }

    function groups(uint256 kind) internal pure returns (uint256) {
        return kind == 3 ? 2 : (kind == 4 ? 5 : 1);
    }

    function helperStart(uint256 kind) internal pure returns (uint256) {
        return kind < 2 ? 16 : columns(kind - 2);
    }

    function claimCount(uint256 kind) internal pure returns (uint256) {
        return helperStart(kind) + 5 * groups(kind) + (kind < 2 ? 0 : shifts(kind - 2));
    }

    function max(uint256 a, uint256 b) private pure returns (uint256) {
        return a > b ? a : b;
    }

    function layout(uint256[] memory dimensions, uint256 bytecodeLog, uint256 variables)
        internal
        pure
        returns (Layout memory out)
    {
        out.memoryLog = dimensions[1];
        out.bytecodeLog = bytecodeLog;
        out.variables = variables;
        require(
            out.memoryLog >= 16 && out.memoryLog <= 26 && bytecodeLog >= 8 && bytecodeLog <= 22,
            "GROUPED_DIM"
        );
        out.heights[0] = out.memoryLog - 3;
        out.heights[1] = bytecodeLog - 3;
        uint256 maximumTable;
        for (uint256 table; table < 3; ++table) {
            uint256 h = dimensions[table + 2];
            require(h >= 8 && h <= (table == 0 ? 26 : 22), "GROUPED_TABLE_DIM");
            out.heights[table + 2] = h;
            maximumTable = max(maximumTable, h);
        }
        require(out.memoryLog >= max(maximumTable, bytecodeLog), "GROUPED_MEMORY_HEIGHT");
        for (uint256 i; i < 5; ++i) {
            out.order[i] = i;
        }
        for (uint256 i; i < 5; ++i) {
            for (uint256 j = i + 1; j < 5; ++j) {
                uint256 a = out.order[i];
                uint256 b = out.order[j];
                if (out.heights[b] > out.heights[a] || (out.heights[a] == out.heights[b] && b < a))
                {
                    out.order[i] = b;
                    out.order[j] = a;
                }
            }
        }
        out.maximum = out.heights[out.order[0]];
        uint256 helperOffset;
        uint256 tableOffset =
            (uint256(2) << out.memoryLog) + (uint256(1) << max(maximumTable, bytecodeLog));
        for (uint256 i; i < 5; ++i) {
            uint256 kind = out.order[i];
            uint256 h = out.heights[kind];
            out.helperOffsets[kind] = helperOffset;
            helperOffset += (5 * groups(kind)) << h;
            if (kind >= 2) {
                out.tableOffsets[kind - 2] = tableOffset;
                tableOffset += columns(kind - 2) << h;
            }
        }
        require(
            variables > 0 && variables < 32 && helperOffset <= uint256(1) << variables,
            "GROUPED_HELPER_SIZE"
        );
        require(
            tableOffset > uint256(1) << (variables - 1) && tableOffset <= uint256(1) << variables,
            "GROUPED_STACK_SIZE"
        );
    }

    function eqValues(uint256[] memory point) internal pure returns (uint256[] memory out) {
        out = new uint256[](uint256(1) << point.length);
        out[0] = ONE;
        uint256 size = 1;
        for (uint256 i; i < point.length; ++i) {
            for (uint256 j = size; j != 0; --j) {
                uint256 right = out[j - 1].mul(point[i]);
                out[2 * j - 2] = out[j - 1].sub(right);
                out[2 * j - 1] = right;
            }
            size <<= 1;
        }
    }

    function integerMle(uint256[] memory point) private pure returns (uint256 out) {
        for (uint256 i; i < point.length; ++i) {
            out = out.add(point[i].mulBase(uint256(1) << (point.length - i - 1)));
        }
    }

    function helper(uint256[] memory values, uint256 start) private pure returns (uint256 out) {
        out = values[start];
        for (uint256 k = 1; k < 5; ++k) {
            out = out.add(values[start + k].mul(uint256(1) << (224 - 32 * k)));
        }
    }

    function fingerprint(uint256 a, uint256 b, uint256 c, uint256 domain, uint256[] memory beta)
        private
        pure
        returns (uint256)
    {
        return beta[0].mul(a).add(beta[1].mul(b)).add(beta[2].mul(c)).add(beta[15].mul(domain));
    }

    function virtualBus(uint256 kind, uint256[] memory f, uint256[] memory beta)
        private
        pure
        returns (uint256 numerator, uint256 fp)
    {
        if (kind == 2) {
            uint256[3] memory nu;
            for (uint256 i; i < 3; ++i) {
                uint256 flag = f[i == 2 ? 14 : 15];
                uint256 nf = ONE.sub(f[11 + i]).sub(flag);
                nu[i] =
                    f[11 + i].mul(f[8 + i]).add(nf.mul(f[5 + i])).add(flag.mul(f[1].add(f[8 + i])));
            }
            uint256 add = f[18].mulBase(2).sub(f[18].square());
            uint256 deref = f[18].mul(f[18].sub(ONE)).mulBase(1_065_353_217);
            numerator = ONE.sub(add).sub(f[16]).sub(deref).sub(f[17]);
            fp = fingerprint(nu[0], nu[1], nu[2], f[19], beta);
        } else if (kind == 3) {
            numerator = EF.sub(0, f[1].mul(f[3].add(f[4]).add(f[5])));
            uint256 domain = f[0].mulBase(4).add(f[3].mulBase(8)).add(f[4].mulBase(16))
                .add(f[5].mulBase(32)).add(f[2].mulBase(64));
            fp = fingerprint(f[6], f[7], f[13], domain, beta);
        } else {
            numerator = EF.sub(0, f[0]);
            uint256 domain = EF.fromBase(3).add(f[9].mulBase(2)).add(f[4].mulBase(4))
                .add(f[5].mulBase(8)).add(f[5].mul(f[6]).mulBase(16));
            fp = fingerprint(f[8].sub(ONE.sub(f[5]).mulBase(4)), f[1], f[2], domain, beta);
        }
    }

    function fractions(
        uint256 kind,
        uint256 height,
        uint256[] memory point,
        uint256[] memory f,
        Challenges memory c
    ) private pure returns (uint256[] memory nums, uint256[] memory dens) {
        uint256 count = kind < 2 ? 8 : (kind == 2 ? 5 : (kind == 3 ? 16 : 33));
        nums = new uint256[](count);
        dens = new uint256[](count);
        if (kind < 2) {
            uint256 busAddress = integerMle(point);
            for (uint256 i; i < 8; ++i) {
                uint256 indexedAddress = busAddress.add(EF.fromBase(i << height));
                uint256 fp = kind == 0
                    ? c.betaEq[0].mul(indexedAddress).add(c.betaEq[1].mul(f[2 * i]))
                        .add(c.betaEq[15])
                    : f[2 * i].add(c.betaEq[12].mul(indexedAddress)).add(c.betaEq[15].mulBase(2));
                nums[i] = EF.sub(0, f[2 * i + 1]);
                dens[i] = c.gamma.sub(fp);
            }
            return (nums, dens);
        }
        (uint256 numerator, uint256 fp) = virtualBus(kind, f, c.betaEq);
        nums[0] = numerator;
        dens[0] = c.gamma.sub(fp);
        for (uint256 i = 1; i < count; ++i) {
            nums[i] = ONE;
            if (kind == 2 && i == 1) {
                fp = c.betaEq[12].mul(f[0]).add(c.betaEq[15].mulBase(2));
                for (uint256 k; k < 12; ++k) {
                    fp = fp.add(c.betaEq[k].mul(f[8 + k]));
                }
            } else {
                uint256 busAddress;
                uint256 value;
                if (kind == 2) {
                    busAddress = f[i];
                    value = f[i + 3];
                } else if (kind == 3) {
                    uint256 section = (i - 1) / 5;
                    uint256 k = (i - 1) % 5;
                    busAddress = f[section == 0 ? 6 : (section == 1 ? 7 : 13)].add(EF.fromBase(k));
                    value = f[14 + section * 5 + k];
                } else if (i <= 4) {
                    busAddress = f[7].add(EF.fromBase(i - 1));
                    value = f[9 + i];
                } else if (i <= 8) {
                    busAddress = f[8].add(EF.fromBase(i - 5));
                    value = f[9 + i];
                } else if (i <= 16) {
                    busAddress = f[1].add(EF.fromBase(i - 9));
                    value = f[9 + i];
                } else {
                    busAddress = f[2].add(EF.fromBase(i - 17));
                    value = f[77 + i];
                }
                fp = c.betaEq[0].mul(busAddress).add(c.betaEq[1].mul(value)).add(c.betaEq[15]);
            }
            dens[i] = c.gamma.sub(fp);
        }
    }

    function section(
        uint256 kind,
        uint256 height,
        uint256[] memory point,
        uint256[] memory values,
        Challenges memory c,
        uint256 alphaPower
    ) internal pure returns (uint256 constraint, uint256 balance, uint256 nextAlpha) {
        nextAlpha = alphaPower;
        if (kind >= 2) {
            uint256 count = kind == 2 ? 14 : (kind == 3 ? 35 : 96);
            uint256[] memory alphas = new uint256[](count);
            for (uint256 i = 2; i < count; ++i) {
                alphas[i] = nextAlpha;
                nextAlpha = nextAlpha.mul(c.alpha);
            }
            uint256 n = columns(kind - 2);
            uint256[] memory flat = Poly.slice(values, 0, n);
            uint256[] memory shift = Poly.slice(values, n + 5 * groups(kind), shifts(kind - 2));
            constraint = kind == 2
                ? Air.evalExecutionTrusted(flat, shift, alphas, c.betaEq)
                : (kind == 3
                        ? Air.evalExtensionTrusted(flat, shift, alphas, c.betaEq)
                        : Air.evalPoseidonTrusted(flat, shift, alphas, c.betaEq));
        }
        (uint256[] memory nums, uint256[] memory dens) = fractions(kind, height, point, values, c);
        for (uint256 group; group < groups(kind); ++group) {
            uint256 numerator;
            uint256 denominator = ONE;
            uint256 limit = (group + 1) * 8;
            if (limit > nums.length) limit = nums.length;
            for (uint256 j = group * 8; j < limit; ++j) {
                numerator = numerator.mul(dens[j]).add(nums[j].mul(denominator));
                denominator = denominator.mul(dens[j]);
            }
            uint256 inverse = helper(values, helperStart(kind) + group * 5);
            constraint = constraint.add(nextAlpha.mul(inverse.mul(denominator).sub(ONE)));
            nextAlpha = nextAlpha.mul(c.alpha);
            balance = balance.add(inverse.mul(numerator));
        }
    }

    function evaluate(
        Layout memory l,
        Claims memory claims,
        Challenges memory c,
        uint256[] memory point
    ) internal pure returns (uint256 total) {
        uint256 alphaPower = ONE;
        for (uint256 i; i < 5; ++i) {
            uint256 kind = l.order[i];
            uint256 h = l.heights[kind];
            (uint256 constraint, uint256 balance, uint256 next) =
                section(kind, h, claims.points[kind], claims.values[kind], c, alphaPower);
            alphaPower = next;
            uint256 padding = ONE;
            for (uint256 j; j < point.length - h; ++j) {
                padding = padding.mul(point[j]);
            }
            uint256 equality = PackedPoly.eqPolynomial(
                Poly.slice(c.equality, c.equality.length - h, h), claims.points[kind]
            );
            total = total.add(padding.mul(equality.mul(constraint).add(c.balance.mul(balance))));
        }
    }
}
