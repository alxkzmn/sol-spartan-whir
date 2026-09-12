// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import { KoalaBearExt5 as EF } from "../field/KoalaBearExt5.sol";
import { KoalaBearPackedField as Packed } from "../field/KoalaBearPackedField.sol";
import { LeanVmTranscript as Transcript } from "./LeanVmTranscript.sol";

library LeanVmPolynomial {
    using Transcript for Transcript.State;
    uint256 internal constant ONE = uint256(1) << 224;

    function slice(uint256[] memory values, uint256 start, uint256 length)
        internal
        pure
        returns (uint256[] memory out)
    {
        require(start + length <= values.length, "SLICE");
        out = new uint256[](length);
        for (uint256 i; i < length; ++i) {
            out[i] = values[start + i];
        }
    }

    function reverse(uint256[] memory values) internal pure returns (uint256[] memory out) {
        out = new uint256[](values.length);
        for (uint256 i; i < values.length; ++i) {
            out[i] = values[values.length - 1 - i];
        }
    }

    function expand(uint256 value, uint256 count) internal pure returns (uint256[] memory point) {
        point = new uint256[](count);
        for (uint256 i; i < count; ++i) {
            point[i] = value;
            value = EF.square(value);
        }
    }

    function horner(uint256[] memory coefficients, uint256 value)
        internal
        pure
        returns (uint256 out)
    {
        if (coefficients.length == 0) return 0;
        out = coefficients[coefficients.length - 1];
        for (uint256 i = coefficients.length - 1; i != 0; --i) {
            out = EF.add(coefficients[i - 1], Packed.mul(out, value));
        }
    }

    function hornerBase(uint256[] memory coefficients, uint256 value)
        internal
        pure
        returns (uint256 out)
    {
        require(value < 2_130_706_433, "BASE_HORNER");
        if (coefficients.length == 0) return 0;
        out = coefficients[coefficients.length - 1];
        for (uint256 i = coefficients.length - 1; i != 0; --i) {
            out = EF.add(coefficients[i - 1], EF.mulBase(out, value));
        }
    }

    function sumcheck(
        Transcript.State memory state,
        bytes calldata transcript,
        uint256 target,
        uint256 rounds,
        uint256 degree,
        uint256 powBits
    ) internal pure returns (uint256[] memory point, uint256 finalValue) {
        point = new uint256[](rounds);
        for (uint256 i; i < rounds; ++i) {
            uint256[] memory coefficients = state.readExtension(transcript, degree + 1);
            uint256 sum = coefficients[0];
            for (uint256 j; j < coefficients.length; ++j) {
                sum = EF.add(sum, coefficients[j]);
            }
            require(sum == target, "SUMCHECK_IDENTITY");
            state.checkPow(transcript, powBits);
            point[i] = state.sample();
            target = horner(coefficients, point[i]);
        }
        finalValue = target;
    }

    function eqIndex(uint256[] memory point, uint256 index, uint256 count)
        internal
        pure
        returns (uint256 out)
    {
        require(count <= point.length && index < (uint256(1) << count), "SELECTOR");
        out = ONE;
        for (uint256 i; i < count; ++i) {
            out = Packed.mul(
                out, (index >> (count - 1 - i)) & 1 == 0 ? EF.sub(ONE, point[i]) : point[i]
            );
        }
    }

    function next(uint256[] memory x, uint256[] memory y) internal pure returns (uint256 out) {
        require(x.length == y.length, "NEXT_DIM");
        uint256 prefix = ONE;
        uint256 product = ONE;
        for (uint256 i; i < x.length; ++i) {
            uint256 xy = Packed.mul(x[i], y[i]);
            uint256 xOnly = EF.sub(x[i], xy);
            uint256 yOnly = EF.sub(y[i], xy);
            out = EF.add(Packed.mul(xOnly, out), Packed.mul(prefix, yOnly));
            prefix = Packed.mul(prefix, EF.sub(ONE, EF.add(xOnly, yOnly)));
            product = Packed.mul(product, xy);
        }
        out = EF.add(out, product);
    }

    function coefficients(uint256[] memory values, uint256[] memory point)
        internal
        pure
        returns (uint256 out)
    {
        require(values.length == (uint256(1) << point.length), "COEFF_DIM");
        // Coefficient-form multilinear evaluation has no (1-r) terms.
        uint256[] memory work = slice(values, 0, values.length);
        uint256 size = values.length;
        for (uint256 i; i < point.length; ++i) {
            size >>= 1;
            for (uint256 j; j < size; ++j) {
                work[j] = EF.add(work[j], Packed.mul(work[j + size], point[i]));
            }
        }
        out = work[0];
    }

    function log2(uint256 value) internal pure returns (uint256 out) {
        require(value != 0 && (value & (value - 1)) == 0, "POWER_OF_TWO");
        while (value > 1) {
            value >>= 1;
            out += 1;
        }
    }
}
