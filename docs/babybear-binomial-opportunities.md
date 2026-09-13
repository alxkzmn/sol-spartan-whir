# BabyBear binomial extension opportunities

This report records the arithmetic experiment that selected the packed row algorithm for the [production BabyBear verifier](../README.md#verifiers). The complete verifier measurements and source fingerprints are in the [measurement manifest](../testdata/babybear_full_verifier_measurement.json).

The strongest measured opportunity is the 16-term extension dot product used by WHIR row evaluation. A packed `MULMOD` implementation costs **462,906 gas for BabyBear** and **521,586 for KoalaBear**, including weight setup, validation, and hashing for 31+19+14 rows. BabyBear is **58,680 gas (11.25%) cheaper** in this comparison.

These are isolated arithmetic and row-verification harnesses. The [fusion results](babybear-fusion-results.md) integrate this row algorithm and row/Horner fusion into a complete native KoalaBear experiment at **3,952,037 transaction gas**, and report the select and equality experiments. Production selects the packed-row part because it clears the strict 1% gate; the complete BabyBear verifier has its own proof, transcript, and full-caller measurements.

## Measured row implementations

Solidity 0.8.28, `via_ir`, 833 optimizer runs, Prague; 2026-09-05. Each field uses the same workload dimensions and its own canonical arithmetic. The cross-field benchmark inputs are identical and below both primes; derived weights differ because the fields differ.

| Measurement                                        |   KoalaBear |    BabyBear |
| -------------------------------------------------- | ----------: | ----------: |
| Prior selected complete row workload               |     672,014 |     625,835 |
| Three packed `MULMOD` accumulators                 | **521,586** | **462,906** |
| Reduction against the field's prior implementation |  **22.38%** |  **26.03%** |
| Prior arithmetic-only 16-term dot product          |       8,077 |       7,573 |
| New arithmetic-only 16-term dot product            |   **5,666** |   **4,802** |

The complete workload includes three weight preparations, 64 rows of 16 extension elements, coefficient validation, and prefixed leaf hashing. The dot measurement excludes row hashing and validation and uses maximal coefficients. These boundaries must remain separate.

Deployed harness runtime grows from 3,640 to 3,840 bytes for BabyBear and from 4,563 to 5,031 bytes for KoalaBear. These are isolated harness sizes, not complete verifier sizes.

The field difference in the complete row workload grows from 46,179 to 58,680 gas. Most of the algorithm's saving is available to both fields; the additional difference attributable to the matched field implementations is 12,501 gas. Full-caller compilation can change these results.

## Packed polynomial reduction with MULMOD

For BabyBear, choose `T = 2^16`, `B = 2^51`, and the integer modulus `m = B^5 - 2 = 2^255 - 2`. Split each canonical coefficient as `a_i = l_i + T*h_i`. Pack all five low limbs, high limbs, and their sums into separate radix-B words. The implementation first packs the five full coefficients, then obtains the two halves with shifts and masks; it caches the weight words once per batch.

An ordinary EVM `MULMOD` now performs the binomial polynomial reduction because `B^5 = 2 mod m`. Three products compute the low-low, high-high, and sum-sum convolutions:

```text
L += MULMOD(a_low, b_low, m)
H += MULMOD(a_high, b_high, m)
S += MULMOD(a_low + a_high, b_low + b_high, m)
```

After all 16 terms, recover each output coefficient as:

```text
(L_i + T*(S_i - L_i - H_i) + T^2*H_i) mod p
```

This keeps three packed accumulator words throughout the row. Coefficient extraction and reconstruction happen once at the end. It removes the per-element extraction of nine convolution coefficients in the prior implementation. `MULMOD` is an existing EVM opcode; this experiment uses no custom precompile or gas schedule.

For BabyBear, `l_i <= 65535`, `h_i <= 30720`, and `l_i+h_i <= 96255`. The largest coefficient after binomial reduction has at most nine product contributions, counting doubled terms. Thus each accumulated limb coefficient is bounded by `16*9*96255^2 = 1,334,163,603,600 < 2^41 < B`. Its packed word fits below bit 245. All coefficients of `S-L-H` are nonnegative, so subtraction introduces no lane borrows. Final reconstructed coefficients are below `16*9*(p-1)^2 < 2^69` before prime reduction.

KoalaBear uses the same construction with integer modulus `B^5+B^2-1`. Its polynomial reduction produces signed coefficients. The implementation uses three `ADDMOD` accumulators, adds a coefficient bias of `2^42` after the batch, and compensates for that bias during final reconstruction. The signed coefficient bound is `16*6*98047^2 < 2^40`; the biased coefficients fit in 51 bits. BabyBear's positive reduction permits plain `ADD` accumulators and simpler reconstruction.

The broader technique is Kronecker substitution with delayed reconstruction. [Harvey](https://arxiv.org/abs/0712.4046) describes packed polynomial multiplication and recovery, and [Dumas, Fousse, and Salvy, sections 2–3](https://arxiv.org/pdf/0809.0063) develop delayed and simultaneous reduction. The specific integer moduli, coefficient splitting, and three-accumulator EVM implementation above are this experiment's adaptation.

## Measured arithmetic surfaces

| Priority | Native computation                             | Work in the optimized control                                                                                                 | Opportunity                                                                                                                                   |
| -------- | ---------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| 1        | Extension row dot products                     | 1,024 product terms across 64 rows                                                                                            | Native integration saves 7.74% transaction gas in the fusion report.                                                                          |
| 2        | Row evaluation followed by claim Horner update | 50 extension rows in the two nonfinal extension STIR rounds                                                                   | Seventeen-term fusion saves 3.95% in the BabyBear component and another 0.72% in the native KoalaBear transaction.                            |
| 3        | Select polynomial product chains               | 566 dense products, plus nine cache products                                                                                  | Final-product/Horner fusion saves 4.93% in BabyBear. Persistent three-`MULMOD` products regress.                                              |
| 4        | Fixed equality preparation                     | 86 equality-term products, 81 accumulator products, and 64 squares                                                            | Persistent coefficient forms and selected fused helpers save 6.49% in BabyBear. KoalaBear integration regresses despite its component saving. |
| 5        | Other extension arithmetic                     | 44 sumcheck products; 26 weight products outside the row harness; approximately 94 Horner products outside the select harness | Outside the measured integration scope; no transaction saving is assigned.                                                                    |

The [row/Horner fusion experiment](babybear-fusion-results.md#row-and-horner-fusion) measures the second priority. Its identity is `nextClaim = claim*challenge + sum(row_i*weight_i)`. The same 51-bit lanes accommodate 17 terms; BabyBear's final unreduced coefficient bound becomes less than `2^70`. The arithmetic product `claim*challenge` remains necessary, while a separate canonicalization, transport packing, and addition boundary can be removed. Final STIR rows require their individual evaluations for comparison with the final polynomial and have a different consumer.

Counts follow the retained [native patch](../testdata/babybear/followup-native/native-optimized.patch) and fixed schedule. Separately compiled optimized IR established the operation shape but was not the deployed transaction artifact.

## Why the direct field difference is modest

Both prior packed multipliers compute their convolution with **three packed EVM multiplications and one scalar multiplication**, followed by **five prime reductions**. BabyBear's simpler polynomial changes the small linear reduction map after that convolution. It does not reduce those four multiplications or five prime reductions. On the EVM, `MUL` and `MOD` each cost five gas, while `ADD`, shifts, and stack operations commonly cost three; packing and stack handling are a material part of these kernels. [EVM opcode costs](https://ethereum.org/developers/docs/evm/opcodes/)

Several other costs dilute the arithmetic improvement:

- Transaction base and calldata account for **877,336 gas (20.33%)** of the measured native control. The fixed schedule retains five 32-bit slots per extension element.
- The exact native select profile costs 639,978 gas, including 275,988 in cubic factor evaluation. Those cubic evaluations use base scalars and coefficientwise arithmetic and obtain no direct benefit from the extension polynomial.
- Base rows, final univariate Horner evaluation at base-field points, domain exponentiation, transcript bytes, sorting, and Merkle hashing obtain no direct binomial benefit.
- The complete final-value phase costs only 61,609 gas; even a large local improvement there has a small transaction effect.
- Frobenius, inversion, and multiplication by a fixed extension monomial have attractive binomial formulas, but no reachable native caller uses them. The verifier's dense random challenges cannot be treated as sparse operands.

The final native flamegraph attributes 91,500 gas to ordinary multiplication leaf frames, 131,350 to packed general multiplication leaf frames, and 33,408 to specialized squares. These exclude inline row arithmetic and specialized select/equality kernels. Parent and child frame costs must not be summed.

## Validation and evidence

The matched isolated Solidity suites pass **16 tests**, including 256-case differential fuzzing per fuzz test, all basis-product pairs, maximal coefficients, complete multilinear row evaluation, canonical output checks, every malformed coefficient position, first-error ordering, and original prefixed row hashes. The independent Python oracle performs schoolbook convolution followed by generic descending polynomial reduction and passes **10,768 cases per field**, including 10,000 random complete dot products.

[Experiment sources, measurements, compiler metadata, and reproduction files](../testdata/babybear/binomial-mulmod/) preserve this comparison. The [fusion results](babybear-fusion-results.md) add the historical complete native KoalaBear integration and transaction receipts. The [production promotion](babybear-verifier-optimization-loop.md#koalabear-production-promotion) records the selected active integration and refreshed schedule scores.

From the repository root:

```sh
python3 testdata/babybear/binomial-mulmod/verify_bounds.py --random-cases 10000
benchmark_dir=$(mktemp -d)
python3 testdata/babybear/binomial-mulmod/reproduce.py --out-dir "$benchmark_dir/workspace"
(cd "$benchmark_dir/workspace" && forge test --offline --fuzz-runs 256 -vv)
```

The replay uses archived Solidity sources and compiler settings, checks their fingerprints, and links the repository's Foundry test library. The original source-construction script is retained separately as `generate_experiment.py`.
