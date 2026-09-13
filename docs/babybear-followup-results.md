# Further quintic and BabyBear optimization results

This report records the component benchmarks and KoalaBear control that selected kernels for the [production BabyBear verifier](../README.md#verifiers). The complete verifier measurements and source fingerprints are in the [measurement manifest](../testdata/babybear_full_verifier_measurement.json).

The [fusion results](babybear-fusion-results.md) record the subsequent experimental native control at **3,952,037 transaction gas**, plus measured BabyBear row, select, and equality fusion experiments. The [binomial extension investigation](babybear-binomial-opportunities.md) explains the packed `MULMOD` row algorithm. The measurements below retain their recorded implementation.

Measured on 2026-09-05 with Solidity 0.8.28, `via_ir`, 833 optimizer runs, and Prague. The complete native KoalaBear WHIR control costs **4,314,727 transaction gas**, saving **1,230,636 gas (22.19%)** against the verifier active during that experiment and **522,553 gas (10.80%)** against the control in the initial [BabyBear results](babybear-results.md). Both transactions use identical calldata.

The recorded experiment build measures BabyBear selects at **618,028 gas**, extension rows at **625,835**, and fixed equality preparation at **123,456**. These are arithmetic workload measurements; the complete verifier has its own proof and full-caller measurements.

The retained experiment implementations are test libraries and an independently replayable [complete native patch](../testdata/babybear/followup-native/native-optimized.patch). The measurements below identify the exact controls and compiler configuration.

## Measured improvements

| Boundary                                           | Starting value | Retained value |  Reduction |
| -------------------------------------------------- | -------------: | -------------: | ---------: |
| Complete native transaction                        |      5,545,363 |  **4,314,727** | **22.19%** |
| Transaction execution remainder                    |      4,668,027 |  **3,437,391** | **26.36%** |
| BabyBear select batch, including cache setup       |        812,885 |    **618,028** | **23.97%** |
| BabyBear rows, including three weight preparations |        704,649 |    **625,835** | **11.18%** |
| BabyBear fixed equality preparation                |        148,073 |    **123,456** | **16.62%** |

The three BabyBear workloads total **1,367,319 gas**, down from 1,665,607. Select workloads retain the 38×18, 31×14, and 19×10 steps and their Horner consumers. Rows retain 31+19+14 rows of 16 elements, validation, and prefixed leaf hashing. Equality retains the complete 22/18/14/10 preparation.

The final select library's isolated build measures 618,250 gas; the complete repository build measures 618,028. The matched baseline is 812,885 in both. The packed-Horner trial measures 618,918 in the repository build, a regression, and 615,109 in the isolated build, a 0.508% saving. Both results are excluded by the retention threshold.

## Select factors as cached cubics

For adjacent extension points `r,s`, the same select factors can be written as:

```text
(1-r+r*x) * (1-s+s*x²) = A + B*x + C*x² + D*x³
D = r*s
B = r-D
C = s-D
A = 1-r-s+D
```

The 18 shared points give nine reusable cubics. Their coefficients are prepared once, including the nine extension products. Four coefficient channels are evaluated together in 64-bit integer lanes; the fifth uses a packed dot product. The chain advances the base scalar to `x⁴` after each pair. This reduces general extension products from 1,220 to 566 while preserving the original polynomial, index order, and proof representation.

Canonical cubic coefficients and scalar powers give the lane bound `(p−1)+3(p−1)² < 2⁶⁴` for both fields. The independent [bounds checker](../script/babybear/select_followup_bounds.py) also validates the quintic products. The [implementation](../test/helpers/BabyBearSelectFollowup.sol) and [tests](../test/BabyBearSelectFollowup.t.sol) cover both full canonical fields, basis pairs, maximal elements, scalar boundaries, and complete chains.

## Factored row weights and combined validation

Weight construction uses `a*(1-r) = a-a*r`, reducing its extension products from 28 to 13. BabyBear setup falls from 23,273 to 14,948 gas per batch. During each row's existing loads, the verifier accumulates coefficient-range flags and checks once. A failure invokes the original checker in input order, preserving the exact first offending element and revert data.

BabyBear row gas falls first to 679,674, then to 625,835. The matched KoalaBear nine-accumulator harness falls from 791,529 to 672,014. The complete native control retains that nine-accumulator KoalaBear layout. A further BabyBear experiment packing five accumulated outputs into two 80-bit-lane words regresses to 683,243 gas.

[Row implementation](../test/helpers/BabyBearRowFollowup.sol), [independent tests](../test/BabyBearRowFollowup.t.sol), and [measurements](../testdata/babybear/followup-row-results.json).

## Shifted equality products

The selected equality preparation uses:

```text
eq(a,q) = 2*(a-1/2)*(q-1/2) + 1/2
```

It packs the shared shifted point once and carries two coefficient words through each accumulator product. Canonical reduction after every product maintains the convolution bounds; transport packing happens when returning the five complete equality products. Specialized squaring is retained.

BabyBear preparation falls through 143,107, 137,872, and 132,316 to **123,456 gas**. The corresponding KoalaBear result is **137,913**, compared with 170,823 initially. Skipping unused final squares saves only another 289 BabyBear gas, or 0.234%, so that trial is excluded.

[Equality implementation](../test/helpers/BabyBearEqFollowup.sol), [tests](../test/BabyBearEqFollowup.t.sol), and [bounds](../testdata/babybear/followup-eq/bounds.md).

## Complete native verifier restructuring

Three additional changes target costs identified in the full verifier:

- **Base rows:** prepack five weight coefficients into two words with 80-bit lanes, then accumulate all 16 scalar products before reduction. Each lane is bounded by `16*(p−1)² < 2⁶⁶`. This saves 66,797 test gas against the preceding complete control.
- **Final multilinear evaluation:** evaluate four contiguous 16-element blocks with shared weights for the last four coordinates, then perform the remaining three folds. This saves 75,829 test gas against that same control.
- **Final univariate evaluations:** prepack the 64 extension coefficients once for all 14 queries and keep Horner accumulators in 64-bit lanes. The pairwise version saves 105,531 test gas against the preceding control. The retained four-coefficient step uses `x,x²,x³,x⁴` and satisfies `4*(p−1)²+(p−1) < 2⁶⁴`.

These isolated changes interact in the complete caller, so their savings are not added to predict the final transaction. The original internal point-array select helpers remain available; the native control uses separate cubic-cache helpers. This preserves the existing arithmetic tests and other callers.

The final phase harness measures STIR phases totaling **2,247,750 gas**, constraint evaluation **908,019**, and final value checking **61,609**. Their baseline values are 2,828,712, 1,480,048, and 135,049.

## Transaction and compiler evidence

The baseline and final receipts contain the same 54,436-byte calldata: 1,220 zero bytes and 53,216 nonzero bytes. Its cost is 856,336 gas, plus 21,000 transaction base gas.

The deployed transaction contract has **33,639 runtime bytes** and **33,665 initcode bytes**. These sizes and hashes are derived from the recorded creation transaction, whose checked constructor copies the runtime from offset `0x1a`. Foundry's test artifact has 33,300 runtime bytes and measures 4,195,182 test gas; its verification frame costs 3,436,993 gas. Script deployment, test, and targeted IR builds produce different code layouts for the same source hashes. Receipt comparisons use the script deployment consistently.

The local target is **65,536 runtime bytes and 131,072 initcode bytes**, following [EIP-7954](https://eips.ethereum.org/EIPS/eip-7954). Foundry, the managed Anvil runner, and the project optimization instructions use that target. EIP-7954 is in Review as of 2026-09-05; network deployment requires activation there.

These isolated experiments predate the current production calibration; the direct transaction measurements above are independent of schedule estimates.

## Stopping decision

The final full-verifier round moves transaction gas from **4,358,127 to 4,314,727**, a **0.996%** saving. This experiment retained that positive change and stopped. The production promotion applies a strict greater-than-1% gate and therefore uses the 4,358,127-gas pairwise-Horner checkpoint before adding the qualifying packed-row implementation. A concurrently tested first-block initialization specialization saves only another 1,890 test gas and is excluded. BabyBear's remaining select and equality trials save less than 1% or regress; the next row packing trial regresses. Fused select helper and packed setup experiments fail `via_ir` compilation.

## Validation and reproduction

The recorded validation has **362 passing tests:** 322 in the main suite and 40 field tests separately, using 256 cases per fuzz test. Its combined invocation failed in `FieldArithmeticTest.setUp()` because that test contract's 65,717-byte runtime exceeded the configured 65,536-byte allowance. The current test splits the gas probes, deploys only the harness in setup, and parses one fixture section per vector test.

The additional native tests independently check maximal and random base dot products, scalar-Horner boundaries, nonzero blob offsets, and 64-element multilinear evaluation against schoolbook extension multiplication. Row tests exercise every coefficient position at the modulus, above it, with the high bit set, and at `0xffffffff`, plus exact first-error ordering. Select/equality Python checks supplement full-domain integer arguments. All generated files reproduce byte for byte.

```sh
python3 script/babybear/generate_all.py
python3 script/babybear/verify_bounds.py
python3 script/babybear/select_followup_bounds.py
python3 script/babybear/row_followup_bounds.py
python3 script/babybear/eq_followup_bounds.py
python3 script/babybear/native_followup/verify_bounds.py
forge test --match-path 'test/BabyBear*Followup.t.sol' --offline --fuzz-runs 256 -vv

benchmark_dir=$(mktemp -d)
python3 script/babybear/run_native_followup.py --out-dir "$benchmark_dir/native" --full-suite
(cd "$benchmark_dir/native/workspace" && bash .agents/skills/tx-gas-benchmarking/scripts/run_tx_gas_benchmark.sh \
  --start-anvil --port 18559 --snapshot-dir "$benchmark_dir/receipts" \
  script/WhirBlobNativeTxBenchmark_k22_jb100_ext5_lir4_ff4_rsv3_pow28.s.sol --offline)
```

The runner verifies baseline fingerprints, applies the patch only to its new workspace, includes the native differential tests, and splits full validation to reproduce the passing field/main runs.

## Tool issues

Foundry's combined field-suite setup failure required separate invocations. Desktop SVG opening failed after successful flamegraph generation; headless parsing validated the saved files. Targeted builds warned about the external signature cache while producing valid artifacts.
