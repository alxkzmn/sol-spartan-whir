# Selecting an arithmetic technique

Use this menu to form a hypothesis from the profile. Read the relevant primary source far enough to verify its assumptions before implementing an adaptation.

| Measured work | Candidate | Cost or precondition to resolve |
| --- | --- | --- |
| Dense small-coefficient convolution | Kronecker substitution; split or reversed products | Lane carry bounds, discarded high bits, packing and extraction cost |
| Repeated polynomial or dot-product reductions | Delayed reduction; simultaneous modular reduction | Accumulation length, quotient precision, canonical output |
| General extension multiplication | Karatsuba or Toom-Cook decomposition | Addition/interpolation growth, invertible constants, signed intermediates, rematerialization |
| Repeated squares or structured operands | Symmetry, sparse convolution, fused scalar operations | Caller guarantees, reduction polynomial, specialization reachability |
| Many independent inversions | Batch inversion using prefix/suffix products | Zero treatment, storage and multiplication overhead, batch lifetime |
| Long sequences in one field representation | Montgomery or Barrett reduction as research candidates | Conversion and quotient cost versus EVM arithmetic; preserve transcript encoding |

Primary starting points:

- [Harvey, Faster polynomial multiplication via multipoint Kronecker substitution](https://arxiv.org/abs/0712.4046), section 3 for integer packing and carry reconstruction. Reciprocal variants motivate examining reversed coefficients; adapting them to truncated 256-bit products requires a separate derivation.
- [Dumas, Fousse, and Salvy, Simultaneous Modular Reduction and Kronecker Substitution for Small Finite Fields](https://arxiv.org/abs/0809.0063) for packed small-field arithmetic and simultaneous reduction. Check its machine-word and floating-point exactness assumptions against EVM integer operations.
- [GMP's Karatsuba discussion](https://gmplib.org/manual/Karatsuba-Multiplication) and [Toom-3 discussion](https://gmplib.org/manual/Toom-3_002dWay-Multiplication) explain multiplication counts and reconstruction overhead. Their CPU thresholds do not predict Solidity gas.

For another hotspot, search for its operation and constraints, then cite the primary algorithm used. Research plugins are optional; ordinary web and paper access suffice.

## Quintic carry-bound example

For five canonical coefficients, the unreduced convolution has term counts `1,2,3,4,5,4,3,2,1`. With `p = 0x7f000001`, four products fit in a 64-bit lane, while five maximal products do not. Check the strict bounds with arbitrary-precision integers:

```sh
python3 - <<'PY'
p = 0x7f000001
assert 4 * (p - 1)**2 < 2**64
assert 5 * (p - 1)**2 >= 2**64
print([min(k + 1, 9 - k, 5) * (p - 1)**2 for k in range(9)])
PY
```

Packing four consecutive coefficients in radix `2^64` permits exact recovery of their low four convolution coefficients from the low 256 bits. Reversing coefficient order permits recovery from the other end. The middle coefficient needs separate treatment: one 64-bit lane loses information on valid inputs. Adding a fifth term outside the packed multiplication needs a new bound for that sum.

Reduction uses `X^5 = 1 - X^2`. Derive degree-5 through degree-8 contributions before packing outputs. The project's [quintic experiment](../../../../docs/quintic-select-kronecker.md) contains a concrete derivation and independently checked tests. Recheck bounds when changing a field constant, input range, polynomial, lane width, or accumulation length.
