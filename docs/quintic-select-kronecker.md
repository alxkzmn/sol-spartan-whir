# Quintic select-term optimization experiment

The `k22_jb100_ext5_lir4_ff4_rsv3_pow28` native software verifier computes each select term as `a * (1 + s * b)` in `F_p[X] / (X^5 + X^2 - 1)`, where `p = 0x7f000001`. Its select-term kernel uses truncated Kronecker substitution to compute the polynomial product with four integer multiplications, followed by five scalar multiplications and five modular reductions.

## Measurement boundary

Measurements use the checked-in success fixture, Solidity 0.8.28, `via_ir = true`, and `optimizer_runs = 833`. Foundry test gas includes fixture-loading work. Anvil execution gas is the receipt gas minus 21,000 intrinsic gas and 856,336 calldata gas. The verification calldata has 54,436 bytes: 1,220 zero and 53,216 nonzero bytes.

The native verifier was already larger than EIP-170 before this experiment. Both measurements use the repository's local testing allowance for oversized contracts. This is an optimization experiment on that target, with single-contract deployability unresolved.

## Results

| Metric | Baseline | Candidate | Delta |
| --- | ---: | ---: | ---: |
| Foundry test gas | 5,454,992 | 5,426,216 | -28,776 |
| Anvil transaction gas | 5,574,139 | 5,545,363 | -28,776 |
| Anvil execution gas | 4,696,803 | 4,668,027 | -28,776 |
| Native phase sum | 4,696,506 | 4,667,730 | -28,776 |
| Constraint evaluation | 1,508,824 | 1,480,048 | -28,776 |
| Select-term flamegraph gas | 1,037,244 | 1,008,468 | -28,776 |
| Deployed runtime bytes | 31,856 | 31,963 | +107 |

The transaction saving is 0.516%; constraint evaluation saves 1.907%. Every other measured native phase is unchanged. The calldata bytes match exactly between the two transactions. The 31,963-byte candidate exceeds EIP-170 by 7,387 bytes.

The current compiler emits nine `mul` expressions for the kernel, compared with 32 in the baseline optimized IR. These are kernel-local static IR counts. Packing, extraction, addition, and reduction work accounts for much of the remaining kernel cost.

[Machine-readable measurements](../testdata/quintic_select_kronecker_measurement.json) include source hashes, transaction hashes, calldata hashes, compiler settings, and validation counts. The refreshed baseline transaction was measured before the edit; the README's earlier 5,646,080 figure came from an older transaction run.

## Arithmetic

Let `a_i` and `b_i` be canonical coefficients in `[0, p - 1]`, and let `c_k = sum(a_i * b_j)` over `i + j = k`. Set `B = 2^64` and define:

```text
A = a0 + a1*B + a2*B^2 + a3*B^3
B0 = b0 + b1*B + b2*B^2 + b3*B^3
Ar = a4 + a3*B + a2*B^2 + a1*B^3
Br = b4 + b3*B + b2*B^2 + b1*B^3

low  = A * B0 mod 2^256 = c0 + c1*B + c2*B^2 + c3*B^3
high = Ar * Br mod 2^256 = c8 + c7*B + c6*B^2 + c5*B^3
```

Every retained coefficient has at most four products. The bound `4 * (p - 1)^2 < 2^64` prevents carries between the four retained lanes. Higher coefficients are discarded by the EVM multiplication modulo `2^256`.

The middle coefficient has five terms and can exceed 64 bits. Compute its first four terms in the top lane of a third truncated product, then add the fifth separately:

```text
c4 = ((A * (b1 + b2*B + b3*B^2 + b4*B^3) mod 2^256) >> 192)
     + a4*b0
```

Reduction by `X^5 = 1 - X^2` gives:

```text
r0 = c0 + c5 - c8
r1 = c1 + c6
r2 = c2 - c5 + c7 + c8
r3 = c3 - c6 + c8
r4 = c4 - c7
out_i = (a_i + s*r_i) mod p
```

The implementation adds `p * 2^40` to expressions containing subtraction. This is a multiple of `p` larger than any subtracted coefficient. After multiplication by canonical `s`, all reduction intermediates are below `2^104`, so the unsigned additions, subtractions, and scalar multiplications are exact. Packed convolution multiplication deliberately uses the EVM's truncation.

The same field representation and canonical output encoding are used throughout. Only the native schedule's `WhirVerifierCore5._mulBySelectTermExt5` arithmetic changes; the helper has internal visibility to permit differential tests. Rust fixtures and generated fixed configuration require no regeneration.

## Technique references

[David Harvey, Faster polynomial multiplication via multipoint Kronecker substitution](https://arxiv.org/abs/0712.4046) explains coefficient packing and using several smaller integer multiplications, including reversed coefficient order. This kernel is a fixed-degree adaptation to EVM truncation and the KoalaBear coefficient bound.

[Dumas, Fousse, and Salvy, Simultaneous Modular Reduction and Kronecker Substitution for Small Finite Fields](https://arxiv.org/abs/0809.0063) discusses packing small-field polynomial arithmetic into machine words and controlling intermediate bounds. The gas results here are measured on this implementation.

## Validation

- Full Foundry suite: 308 passed, zero failed or skipped.
- Focused differential tests: 512 fuzz runs each for the arithmetic kernel and complete select chains.
- Deterministic cases cover zero, maximal coefficients, scalars 0/1/p-1, all 25 basis products, and boundary query variables.
- The arithmetic oracle uses `KoalaBearExt5.mulReference`; chain tests compare both fixed and pairwise evaluation with the generic helper at 10, 14, and 18 variables.
- The native success fixture, malformed-proof tests, and transcript parity tests pass in the full suite.
- The schedule calibration freshness check reports the edited core as stale. Calibration JSON and schedule scores require regeneration before using them to rank schedules for this implementation.

## Candidate record

| Construction | Foundry gas | Runtime bytes | Decision |
| --- | ---: | ---: | --- |
| Two packed products and evaluation at 1 for the middle coefficient | 8,840,096 | 33,355 | Reject: optimized IR repeatedly recomputes the packed products. |
| Scoped products with five direct middle-coefficient multiplies | 5,512,544 | 31,989 | Reject: packing overhead exceeds the arithmetic saving. |
| Scoped products with the four-term packed middle product | 5,426,216 | 31,963 | Retain as the local oversized-contract experiment. |

## Reproduce

Run from the repository root:

```sh
forge test --offline
forge test --match-path test/QuinticSelectKronecker.t.sol --fuzz-runs 512 -vv --offline
forge test --match-path test/WhirBlobVerifierNative5_k22_jb100_ext5_lir4_ff4_rsv3_pow28.t.sol --match-test testGasWhirVerifyBlobNativeFixed -vv --offline
forge test --match-path test/WhirGasProfile5_k22_jb100_ext5_lir4_ff4_rsv3_pow28.t.sol --match-test testProfileNativeBlobBreakdown5Pow28Rsv3 -vv --offline
forge test --match-path test/WhirBlobVerifierNative5_k22_jb100_ext5_lir4_ff4_rsv3_pow28.t.sol --match-test testGasWhirVerifyBlobNativeFixed --flamegraph --offline
python3 .agents/skills/forge-flamegraph-profiling/scripts/parse_flamegraphs.py cache/flamegraph_WhirBlobVerifierNative5K22Jb100Ext5Pow28Rsv3Test_testGasWhirVerifyBlobNativeFixed.svg
```

Start Anvil in a separate terminal and stop that instance after receipt parsing:

```sh
anvil --silent --code-size-limit 65536 --port 18549
```

```sh
RPC_URL=http://127.0.0.1:18549 bash .agents/skills/tx-gas-benchmarking/scripts/run_tx_gas_benchmark.sh script/WhirBlobNativeTxBenchmark_k22_jb100_ext5_lir4_ff4_rsv3_pow28.s.sol --offline
```

## Tool issues

The sandbox blocked Anvil's listening socket and aborted Forge's transaction run. The same local flow succeeded outside the sandbox. Foundry generated valid flamegraph SVGs but could not open them through the desktop association; the bundled SVG parser read both successfully. A cached artifact lacked optimized IR, so a targeted build wrote IR to a separate temporary artifact directory.
