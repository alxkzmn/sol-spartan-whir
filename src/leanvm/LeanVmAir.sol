// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { KoalaBearExt5 as E } from "../field/KoalaBearExt5.sol";
import { KoalaBearPackedField as Packed } from "../field/KoalaBearPackedField.sol";
import { LeanVmAirLinear as Linear } from "./LeanVmAirLinear.sol";
import { LeanVmPoseidonAirConstants as C } from "./LeanVmPoseidonAirConstants.sol";

/// @notice Evaluates the three LeanVM AIRs at extension-field column evaluations.
/// @dev Every word uses KoalaBearExt5's packed encoding. Alpha powers are already
/// sliced for the table, in constraint emission order. The bus equality vector has 16 entries.
library LeanVmAir {
    using { E.add, E.sub, E.square, E.mulBase, Packed.mul } for uint256;

    uint256 internal constant ONE = uint256(1) << 224;

    struct Evaluator {
        uint256[] alphas;
        uint256 accumulator;
        uint256 index;
    }

    error AirInputLength();
    error AirConstraintCount();

    function evalExecution(
        uint256[] memory flat,
        uint256[] memory shift,
        uint256[] memory alphas,
        uint256[] memory betaEq
    ) internal pure returns (uint256) {
        _checkInputs(flat, shift, alphas, betaEq, 20, 2, 14);
        return evalExecutionTrusted(flat, shift, alphas, betaEq);
    }

    /// @dev Inputs must be canonical and have the fixed execution AIR dimensions.
    function evalExecutionTrusted(
        uint256[] memory flat,
        uint256[] memory shift,
        uint256[] memory alphas,
        uint256[] memory betaEq
    ) internal pure returns (uint256) {
        Evaluator memory e = _startTrusted(alphas);
        uint256[3] memory nf;
        uint256[3] memory nu;
        for (uint256 i; i < 3; ++i) {
            uint256 fpFlag = flat[i == 2 ? 14 : 15];
            nf[i] = ONE.sub(flat[11 + i]).sub(fpFlag);
            nu[i] = flat[11 + i].mul(flat[8 + i]).add(nf[i].mul(flat[5 + i]))
                .add(fpFlag.mul(flat[1].add(flat[8 + i])));
        }
        uint256 flagAdd = flat[18].mulBase(2).sub(flat[18].square());
        uint256 flagDeref = flat[18].mul(flat[18].sub(ONE)).mulBase(1_065_353_217);
        uint256 flagPrecompile = ONE.sub(flagAdd).sub(flat[16]).sub(flagDeref).sub(flat[17]);
        _bus(e, betaEq, flagPrecompile, flat[19], nu[0], nu[1], nu[2]);
        for (uint256 i; i < 3; ++i) {
            _zero(e, nf[i].mul(flat[2 + i].sub(flat[1].add(flat[8 + i]))));
        }
        _zero(e, flagAdd.mul(nu[1].sub(nu[0].add(nu[2]))));
        _zero(e, flat[16].mul(nu[1].sub(nu[0].mul(nu[2]))));
        _zero(e, flagDeref.mul(flat[3].sub(flat[5].add(flat[9]))));
        _zero(e, flagDeref.mul(flat[6].sub(nu[2])));
        uint256 jumping = flat[17].mul(nu[0]);
        _zero(e, jumping.mul(nu[0].sub(ONE)));
        _zero(e, jumping.mul(shift[0].sub(nu[1])));
        _zero(e, jumping.mul(shift[1].sub(nu[2])));
        _zero(e, ONE.sub(jumping).mul(shift[0].sub(flat[0].add(ONE))));
        _zero(e, ONE.sub(jumping).mul(shift[1].sub(flat[1])));
        return _finish(e);
    }

    function evalExtension(
        uint256[] memory flat,
        uint256[] memory shift,
        uint256[] memory alphas,
        uint256[] memory betaEq
    ) internal pure returns (uint256) {
        _checkInputs(flat, shift, alphas, betaEq, 29, 13, 35);
        return evalExtensionTrusted(flat, shift, alphas, betaEq);
    }

    /// @dev Inputs must be canonical and have the fixed extension AIR dimensions.
    function evalExtensionTrusted(
        uint256[] memory flat,
        uint256[] memory shift,
        uint256[] memory alphas,
        uint256[] memory betaEq
    ) internal pure returns (uint256) {
        Evaluator memory e = _startTrusted(alphas);
        uint256 domain = flat[0].mulBase(4).add(flat[3].mulBase(8)).add(flat[4].mulBase(16))
            .add(flat[5].mulBase(32)).add(flat[2].mulBase(64));
        _bus(
            e,
            betaEq,
            flat[1].mul(flat[3].add(flat[4]).add(flat[5])),
            domain,
            flat[6],
            flat[7],
            flat[13]
        );
        _bool(e, flat[0]);
        _bool(e, flat[1]);
        _bool(e, flat[3]);
        _bool(e, flat[4]);
        _bool(e, flat[5]);
        uint256 isEe = ONE.sub(flat[0]);
        uint256 notStart = ONE.sub(shift[1]);
        uint256[5] memory a;
        uint256[5] memory b;
        uint256[5] memory tail;
        for (uint256 k; k < 5; ++k) {
            a[k] = k == 0 ? flat[14] : flat[14 + k].mul(isEe);
            b[k] = flat[19 + k];
            tail[k] = shift[8 + k].mul(notStart);
        }
        uint256[5] memory product = _quinticProduct(a, b);
        for (uint256 k; k < 5; ++k) {
            _zero(e, flat[8 + k].sub(a[k].add(b[k]).add(tail[k])).mul(flat[3]));
        }
        for (uint256 k; k < 5; ++k) {
            _zero(e, flat[8 + k].sub(product[k].add(tail[k])).mul(flat[4]));
        }
        uint256[5] memory equality;
        for (uint256 k; k < 5; ++k) {
            equality[k] = product[k].mulBase(2).sub(a[k]).sub(b[k]);
        }
        equality[0] = equality[0].add(ONE);
        tail[0] = tail[0].add(shift[1]);
        uint256[5] memory eqProduct = _quinticProduct(equality, tail);
        for (uint256 k; k < 5; ++k) {
            _zero(e, flat[8 + k].sub(eqProduct[k]).mul(flat[5]));
        }
        for (uint256 k; k < 5; ++k) {
            _zero(e, flat[8 + k].sub(flat[24 + k]).mul(flat[1]));
        }
        _zero(e, notStart.mul(flat[2].sub(shift[2].add(ONE))));
        _zero(e, notStart.mul(flat[0].sub(shift[0])));
        _zero(e, notStart.mul(flat[3].sub(shift[3])));
        _zero(e, notStart.mul(flat[4].sub(shift[4])));
        _zero(e, notStart.mul(flat[5].sub(shift[5])));
        _zero(e, notStart.mul(shift[6].sub(flat[6]).sub(flat[0].add(isEe.mulBase(5)))));
        _zero(e, notStart.mul(shift[7].sub(flat[7]).sub(E.fromBase(5))));
        _zero(e, shift[1].mul(flat[2].sub(ONE)));
        return _finish(e);
    }

    function evalPoseidon(
        uint256[] memory flat,
        uint256[] memory shift,
        uint256[] memory alphas,
        uint256[] memory betaEq
    ) internal pure returns (uint256) {
        _checkInputs(flat, shift, alphas, betaEq, 110, 0, 96);
        return evalPoseidonTrusted(flat, shift, alphas, betaEq);
    }

    /// @dev Inputs must be canonical and have the fixed Poseidon AIR dimensions.
    function evalPoseidonTrusted(
        uint256[] memory flat,
        uint256[] memory,
        uint256[] memory alphas,
        uint256[] memory betaEq
    ) internal pure returns (uint256) {
        Evaluator memory e = _startTrusted(alphas);
        uint256 domain = E.fromBase(3).add(flat[9].mulBase(2)).add(flat[4].mulBase(4))
            .add(flat[5].mulBase(8)).add(flat[5].mul(flat[6]).mulBase(16));
        uint256 notLeft = ONE.sub(flat[5]);
        uint256 nuA = flat[8].sub(notLeft.mulBase(4));
        _bus(e, betaEq, flat[0], domain, nuA, flat[1], flat[2]);
        _bool(e, flat[0]);
        _bool(e, flat[3]);
        _bool(e, flat[4]);
        _bool(e, flat[5]);
        _bool(e, flat[9]);
        _zero(e, flat[9].mul(flat[3]));
        _zero(e, flat[4].mul(flat[3]));
        _zero(e, ONE.sub(flat[9]).mul(ONE.sub(flat[4])).mul(ONE.sub(flat[3])));
        _zero(e, flat[5].mul(flat[6].sub(flat[7])));
        _zero(e, notLeft.mul(nuA.sub(flat[7])));

        bytes memory constants = C.values();
        uint256[16] memory state;
        for (uint256 i; i < 16; ++i) {
            state[i] = flat[10 + i];
        }
        for (uint256 r; r < 2; ++r) {
            state = _fullRoundPair(state, constants, C.INITIAL + r * 32);
            for (uint256 i; i < 16; ++i) {
                uint256 post = flat[26 + r * 16 + i];
                _zero(e, state[i].sub(post));
                state[i] = post;
            }
        }
        for (uint256 i; i < 16; ++i) {
            state[i] = state[i].add(E.fromBase(_constant(constants, C.SPARSE_FIRST_RC + i)));
        }
        state = _matrix(state, constants, C.SPARSE_M_I);
        for (uint256 r; r < 20; ++r) {
            uint256 post = flat[58 + r];
            _zero(e, state[0].square().mul(state[0]).sub(post));
            state[0] = post;
            if (r < 19) {
                state[0] = state[0].add(E.fromBase(_constant(constants, C.SPARSE_SCALAR_RC + r)));
            }
            uint256 old0 = state[0];
            state[0] = Linear.dot16(state, constants, C.SPARSE_FIRST_ROW + r * 16);
            Linear.sparseTail(state, old0, constants, C.SPARSE_V + r * 16);
        }
        state = _fullRoundPair(state, constants, C.FINAL);
        for (uint256 i; i < 16; ++i) {
            uint256 post = flat[78 + i];
            _zero(e, state[i].sub(post));
            state[i] = post;
        }
        state = _fullRoundPair(state, constants, C.FINAL + 32);
        uint256 feedforward = ONE.sub(flat[9]);
        uint256 gateLo = ONE.sub(flat[3]);
        uint256 gateHi = ONE.sub(flat[4]).sub(flat[3]);
        for (uint256 i; i < 8; ++i) {
            uint256 difference = state[i].add(feedforward.mul(flat[10 + i])).sub(flat[94 + i]);
            _zero(e, i < 4 ? difference : gateLo.mul(difference));
            _zero(e, gateHi.mul(state[8 + i].sub(flat[102 + i])));
        }
        return _finish(e);
    }

    function _checkInputs(
        uint256[] memory flat,
        uint256[] memory shift,
        uint256[] memory alphas,
        uint256[] memory betaEq,
        uint256 columns,
        uint256 shifts,
        uint256 constraints
    ) private pure {
        if (
            flat.length != columns || shift.length != shifts || alphas.length != constraints
                || betaEq.length != 16
        ) {
            revert AirInputLength();
        }
        _validate(flat);
        _validate(shift);
        _validate(alphas);
        _validate(betaEq);
    }

    function _startTrusted(uint256[] memory alphas) private pure returns (Evaluator memory e) {
        e.alphas = alphas;
    }

    function _validate(uint256[] memory values) private pure {
        for (uint256 i; i < values.length; ++i) {
            E.validatePacked(values[i]);
        }
    }

    function _zero(Evaluator memory e, uint256 value) private pure {
        e.accumulator = e.accumulator.add(e.alphas[e.index].mul(value));
        ++e.index;
    }

    function _bool(Evaluator memory e, uint256 value) private pure {
        _zero(e, value.mul(ONE.sub(value)));
    }

    function _bus(
        Evaluator memory e,
        uint256[] memory betaEq,
        uint256 multiplicity,
        uint256 domain,
        uint256 a,
        uint256 b,
        uint256 c
    ) private pure {
        _zero(e, multiplicity);
        _zero(
            e,
            betaEq[0].mul(a).add(betaEq[1].mul(b)).add(betaEq[2].mul(c)).add(betaEq[15].mul(domain))
        );
    }

    function _finish(Evaluator memory e) private pure returns (uint256) {
        if (e.index != e.alphas.length) revert AirConstraintCount();
        return e.accumulator;
    }

    /// @dev The five coefficients are themselves extension-field values at the AIR point.
    function _quinticProduct(uint256[5] memory a, uint256[5] memory b)
        private
        pure
        returns (uint256[5] memory result)
    {
        uint256[9] memory product;
        for (uint256 i; i < 5; ++i) {
            for (uint256 j; j < 5; ++j) {
                product[i + j] = product[i + j].add(a[i].mul(b[j]));
            }
        }
        for (uint256 k = 8; k >= 5; --k) {
            product[k - 5] = product[k - 5].add(product[k]);
            product[k - 3] = product[k - 3].sub(product[k]);
        }
        for (uint256 i; i < 5; ++i) {
            result[i] = product[i];
        }
    }

    function _constant(bytes memory values, uint256 index) private pure returns (uint256 value) {
        assembly ("memory-safe") { value := shr(224, mload(add(add(values, 32), mul(index, 4)))) }
    }

    function _fullRoundPair(uint256[16] memory state, bytes memory constants, uint256 offset)
        private
        pure
        returns (uint256[16] memory)
    {
        for (uint256 r; r < 2; ++r) {
            uint256[16] memory sbox;
            for (uint256 i; i < 16; ++i) {
                uint256 shifted =
                    state[i].add(E.fromBase(_constant(constants, offset + r * 16 + i)));
                sbox[i] = shifted.square().mul(shifted);
            }
            Linear.mds16(sbox, state);
        }
        return state;
    }

    function _matrix(uint256[16] memory state, bytes memory constants, uint256 offset)
        private
        pure
        returns (uint256[16] memory result)
    {
        Linear.matrix16(state, constants, offset, result);
    }
}
