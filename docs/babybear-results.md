# BabyBear quintic benchmark results

This report records the initial arithmetic benchmark. The selected kernels are integrated in the [production BabyBear verifier](../README.md#verifiers), whose complete measurements and source fingerprints are in the [measurement manifest](../testdata/babybear_full_verifier_measurement.json).

The [fusion results](babybear-fusion-results.md) record the subsequent experiment choices: **3,952,037 gas for the complete KoalaBear transaction**, **588,237 for BabyBear selects**, **491,008 for rows including claim updates**, and **115,450 for equality preparation**. The report defines the component workload boundaries. The sections below preserve the initial arithmetic experiment and its candidate comparisons.

The initial arithmetic benchmark completed on 2026-09-05. The selected BabyBear implementation saves **30.8% on select batches, 34.1% on extension rows, and 7.8% on fixed equality preparation** against the direct BabyBear ports. Matched KoalaBear controls capture much of the benefit. Production contracts and proof fixtures are unchanged by this experiment.

The best complete KoalaBear control saves **708,083 transaction gas**, with identical calldata. A complete BabyBear proof, transaction, prover measurement, schedule sweep, and leanVM migration are outside this arithmetic benchmark.

## Measurement boundary

All arithmetic measurements use Solidity 0.8.28, `via_ir`, 833 optimizer runs, and the Prague EVM target. `gasleft()` starts after ABI decoding and shape checks; input construction is excluded. Cache construction, basis conversion, weight preparation, and the fixed callers' consumers are included where applicable. Both fields receive identical deterministic inputs below the smaller modulus. Correctness tests separately cover each field's full canonical range.

The select workload has 38 × 18, 31 × 14, and 19 × 10 steps, including the production pair loops, odd tails, scalar squaring, and Horner consumers. Peeling removes 88 identity products, leaving 1,220 general calls. The row workload contains 31 + 19 + 14 rows of 16 elements, with three weight preparations, canonical validation, and the original prefixed leaf hash. Equality preparation evaluates 86 terms and 64 squares with the native 22/18/14/10 windows.

The recorded source fingerprints identify the exact artifacts. Gas is an execution count for these inputs, not a statistical timing estimate.

## Select experiments

| Variant | KoalaBear gas | BabyBear gas |
| --- | ---: | ---: |
| Direct baseline | 1,295,076 | 1,174,485 |
| Identity peeling | 1,235,388 | 1,129,686 |
| Branchless scalar | 1,267,818 | 1,147,227 |
| Raw point access | 1,259,886 | 1,140,993 |
| All three changes | 1,167,870 | 1,063,824 |
| Shared point prepacking and raw access | 1,102,917 | 1,026,067 |
| Prepacking with all three changes | 1,026,850 | 954,782 |
| Persistent accumulator forms and pointer loop: selected | **905,782** | **812,885** |
| Packed multiplication in Horner consumers | 900,126 | 811,416 |
| Load the three shared operand forms once per pair | 926,918 | 830,362 |

Prepacking converts the 18 distinct shared points into 54 words once per batch. The persistent representation keeps both four-lane accumulator words between steps and reconstructs the external packed element at the end of each chain. Its loop decrements a cache pointer, uses assembly `mulmod` with the fixed modulus, and avoids the unused final scalar square. This removes repeated accumulator packing while preserving canonical coefficients after every step.

The direct baseline profiles measure **771 gas per KoalaBear kernel and 681 per BabyBear kernel**. The 90-gas difference across 1,308 kernel calls accounts for 117,720 gas. Complete batch differences also include Horner arithmetic and compiler changes in the callers.

The selected BabyBear profile attributes 570,960 gas to 1,220 general calls, or **468 gas per call**. Its kernel is 143 machine instructions / 241 bytes, including 28 DUPs, 20 SWAPs, three cache MLOADs, nine MULs, five MODs, and zero MSTOREs. The body costs 460 gas plus the entering eight-gas jump. The byte sequence was matched uniquely inside the deployed runtime. The two caller loops also have zero MLOAD/MSTORE builtins in their own optimized-IR bodies; their callees perform the intentional cache accesses. No stack spills were found inside this kernel. The masks required for safe doubled-lane extraction survive compilation.

For comparison, the preceding prepacked kernel cost 585 gas, with 182 instructions, 27 DUPs, 21 SWAPs, and the same three loads / zero stores. Reducing packing and extraction work produced the gain even though the DUP count rose by one. The selected select harness grows from 3,231 to 3,691 runtime bytes relative to the direct BabyBear baseline.

The reciprocal KoalaBear basis costs 1,020,519 gas at the prepacked stage, including conversions, versus 1,026,850 in the original basis. Its 0.62% gain is below the stopping threshold. In the complete native select-plus-row control it saves only 1,932 gas while adding 825 runtime bytes. Keep the existing external basis.

The recorded profile, optimized IR, assembly, and first-round measurements establish this kernel shape.

## Extension rows

| Variant, including three weight preparations | KoalaBear gas | BabyBear gas |
| --- | ---: | ---: |
| Nine convolution accumulators | 1,084,224 | 1,068,573 |
| Five output accumulators with transformed weights | 988,479 | 884,364 |
| Prepacked Kronecker weights, nine accumulators | 791,529 | 775,881 |
| Prepacked Kronecker weights, five output accumulators | 810,537 | 737,865 |
| Load, validate, and accumulate each element in sequence: selected harness | **777,321** | **704,649** |
| Packed multiplication in weight preparation | 770,937 | 702,129 |
| Replace the unrolled element sequence with a loop | 851,920 | 779,056 |

The original row port reduces once per row. Its field difference is small: the fused row work saves 4,227 gas over 64 rows; the remaining 11,424-gas difference comes from setup and compiler behavior. It must not be charged once per each of the 1,024 elements.

Prepacked Kronecker weights remove repeated packing of the shared operand. Every element uses three packed integer products plus the scalar middle-coefficient product. Accumulators are unpacked between elements; the code does not accumulate multiple products in 64-bit lanes. Five output accumulators remove four live accumulator values but perform polynomial reduction per element. This helps BabyBear's positive binomial map and regresses for the biased KoalaBear map at this stage.

Staging each element's load and validation before accumulation removes the original 16 simultaneously live row values. The selected BabyBear fused row work costs **307,455 / 188,475 / 138,900 gas** for 31/19/14 rows, plus 23,273 setup gas for each batch. Hashing and rejection behavior match the independent reference. The selected harness is 3,628 bytes versus 4,063 for the nine-accumulator baseline.

The arithmetic-only dot harness stages array loads to compile without the original 16-argument stack pressure. Selection uses the fused calldata/hash caller. The row profile exposes the full batch frame; the inlined row helper has no separate flamegraph frame. The internal `gasleft()` boundary measures its complete repeated execution directly. The optimized IR retains three weight loads and zero stores in each accumulation helper.

The complete KoalaBear verifier reverses the harness preference for staged rows: with identical select and equality controls, staging increases native test gas from 4,718,133 to 4,749,651, while reducing runtime by 1,632 bytes. The complete KoalaBear control therefore retains the nine-accumulator Kronecker row. This benchmark does not assign the same result to a complete BabyBear caller.

## Squaring and fixed equality preparation

| Preparation variant | KoalaBear gas | BabyBear gas |
| --- | ---: | ---: |
| Direct specialized baseline | 225,314 | 160,526 |
| Peel five identity products | 219,286 | 157,177 |
| Remove five intermediate reductions per equality term | 220,584 | 155,796 |
| Both changes | 214,556 | 152,447 |
| Also use packed general multiplication: selected | **170,823** | **148,073** |
| Also use packed multiplication for squares | 180,563 | 155,893 |
| Also use a packed equality-term kernel | 185,323 | 165,823 |
| Selected implementation with unused final squares skipped | 170,234 | 147,748 |

Retain the specialized square and the schoolbook equality-term product with one final reduction per coefficient. Packed general multiplication helps the accumulator products, but packing overhead makes the square and equality-term replacements worse. Skipping four unused final squares saves only 325 gas (0.22%) in BabyBear after its extra conditionals.

In the selected BabyBear profile, equality terms consume 66,564 gas and squares 29,184 gas; these are children of the full preparation measurement. The standalone loop of 64 BabyBear squares costs 33,264 gas, including its loop overhead. The selected preparation harness is 2,069 bytes versus 1,909 for the direct baseline.

## Complete KoalaBear controls

These are temporary copies of the native verifier baseline used by the experiment, with its unchanged valid proof. The [selected patch](../testdata/babybear/native-optimized.patch) makes the exact experiment reviewable.

| Native control | Foundry test gas | Runtime bytes |
| --- | ---: | ---: |
| Experiment baseline | 5,426,216 | 31,963 |
| Shared point prepacking, peeling, branchless scalar, raw access | 5,140,531 | 32,377 |
| Also prepacked Kronecker rows | 4,862,485 | 32,428 |
| Reciprocal basis at that stage | 4,860,553 | 33,253 |
| Persistent select forms, packed Horner and equality multiplication, Kronecker rows: selected | **4,718,133** | **32,972** |
| Same selected control with staged row loads | 4,749,651 | 31,340 |

The native caller amplifies packed Horner multiplication: with the other controls held fixed it saves 18,500 gas, versus 5,656 in the focused KoalaBear select harness. Source-level savings are not additive, and the complete caller decides which representation to retain.

Anvil receipts confirm transaction gas **5,545,363 → 4,837,280**, and execution remainder **4,668,027 → 3,959,944**. Both transactions use the same 54,436-byte calldata, costing 856,336 gas plus 21,000 transaction base gas. The saving is 708,083 gas: 12.77% of transaction gas and 15.17% of the execution remainder.

This initial control adds 1,009 runtime bytes. The local allowance is now 65,536 runtime bytes under the experimental EIP-7954 target; network activation is separate. All 19 native success and malformed-proof tests pass for the selected control. The experiment predates the current production calibration and is not a production measurement.

## Security adjustment and interpretation

The two folding-PoW increases, round 0 from 22 to 23 bits and round 2 from 27 to 28, cost **1,795 gas for the two checks in both configurations**, across 16 transcript states. The independent test also compares sampled witness results with direct byte-level Keccak calculations. Retain the [adjusted configuration](../testdata/babybear/config.json) under the user's 5% rule. The exact-cardinality schedule expressions then have a 100.014549410-bit minimum. Expected grinding work doubles at each affected stage; total prover time was not measured.

The selected three harness workloads sum to **1,853,926 gas for KoalaBear and 1,665,607 for BabyBear**, a 188,319-gas difference. Transcript rejection, generated proof bytes, schedule choices, recursion, and full-caller compilation are outside this arithmetic measurement. The native row counterexample above quantifies why an arithmetic sum alone does not determine transaction gas.

## Stopping decision

Several optimization rounds followed the initial port. The last tested changes against the selected BabyBear components give:

| Remaining candidate | Change in affected workload | Decision |
| --- | ---: | --- |
| Packed Horner multiplication | −1,469 gas / −0.18% | Below 1% |
| Load shared packed operands once per select pair | +17,477 / +2.15% | Regression from the larger live argument set |
| Packed multiplication for row weight preparation | −2,520 / −0.36% | Below 1% |
| Loop over staged row elements | +74,407 / +10.56% | Regression |
| Skip final unused equality squares | −325 / −0.22% | Below 1% |
| Packed squaring in equality preparation | +7,820 / +5.28% | Regression |
| Packed equality-term kernel after packed squaring | +9,930 gas | Regression |
| Direct shifted accumulator masks; fused doubled extraction | Already emitted by the compiler | No remaining operation identified |

The inspected candidate set is exhausted at the requested 1% threshold. REDQ, frequency-domain representations, new proof formats, precompiles, and a different field or schedule are outside the measured candidate set. This stopping decision applies to the measured workloads and reviewed candidates.

## Validation and reproduction

The independent Solidity oracle uses unpacked schoolbook convolution and descending polynomial reduction. Tests cover all 25 basis products, maximal coefficients, scalar values through `2M−2`, zero and empty chains, odd tails, complete select batches, randomized complete equality preparation, row hashes, and malformed coefficients in every one of the 16 × 5 row positions. All outputs match canonical reference encodings.

The [integer bounds script](../script/babybear/verify_bounds.py) checks lane capacity, reconstructed middle terms, loose select scalars, delayed row sums, and doubled-lane contamination. BabyBear select intermediates remain below `2^97`, BabyBear row sums below `2^69`, and the biased five-output KoalaBear row experiment below `2^76`. Every memory-safe raw access is bounded by the harness shape check and fixed loop window. The preserved full native tests validate the retained KoalaBear integration.

```sh
python3 script/babybear/generate_all.py
python3 script/babybear/verify_bounds.py
forge test --match-path 'test/BabyBear*.t.sol' --offline --fuzz-runs 256 -vv
forge test --offline --isolate --threads 1
```

Generation is idempotent. The focused suite passes 29 tests with 256 cases per fuzz test. The recorded complete suite passes **337 tests** with call isolation. The recorded default combined invocation failed in `FieldArithmeticTest.setUp()` because the old test contract's 65,717-byte runtime exceeded the configured 65,536-byte allowance. The current test splits the gas probes into `FieldArithmeticGasTest`, deploys only the harness in setup, and parses the required JSON section in each vector test instead of decoding the complete fixture into storage.

Reproduce the selected complete control in a fresh temporary directory:

```sh
benchmark_dir=$(mktemp -d)
python3 script/babybear/run_native_control.py KoalaBearSelectFormsPackedHorner \
  --row-variant KoalaBearRowKronecker --eq-variant KoalaBearEqPackedMul \
  --out-dir "$benchmark_dir/native"
(cd "$benchmark_dir/native/workspace" && forge test \
  --match-path test/WhirBlobVerifierNative5_k22_jb100_ext5_lir4_ff4_rsv3_pow28.t.sol --offline)
```

The runner rejects a changed native-core fingerprint until the variants are regenerated and validated. For transaction reproduction, copy the matching `script/WhirBlobNativeTxBenchmark_k22_jb100_ext5_lir4_ff4_rsv3_pow28.s.sol` and `.agents/skills/tx-gas-benchmarking` directory into the isolated workspace, then follow the [managed-Anvil receipt workflow](../.agents/skills/tx-gas-benchmarking/SKILL.md) there. Compare against a separately generated `Baseline` control with identical inputs.

## Tool issues

The recorded combined-suite setup failure was caused by the old `FieldArithmeticTest` runtime exceeding the configured code-size allowance. The current split test runs in the combined serial suite without a retry. Flamegraph generation succeeded while desktop SVG opening failed; the headless parser validated the saved files. The sandbox blocked the initial Anvil socket; approved local runs completed and produced matching receipts. Targeted builds also warned about the external signature cache without affecting their artifacts.
