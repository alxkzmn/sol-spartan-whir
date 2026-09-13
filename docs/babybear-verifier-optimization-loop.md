# BabyBear verifier optimization loop

The strict optimization loop ended at **3,267,073 Foundry gas** and **3,390,891 transaction gas** for the checked-in success fixture, a reduction of **413,472 gas** in both measurements. A subsequent review cleanup removed dead helpers and an unused radix-64 calldata parameter. The active verifier now costs **3,240,976 Foundry gas** and **3,364,794 transaction gas** while preserving the proof, blob layout, transcript trace, schedule, and fixture bytes.

All measurements use Solidity 0.8.28, `via_ir`, 833 optimizer runs, the Prague EVM target, and the fixed `k22_jb100_ext5_lir4_ff4_rsv3_pow28` schedule. A candidate was retained only when it reduced the complete canonical Foundry gas test by strictly more than 1% of that round's starting value.

## BabyBear-loop measurements

The KoalaBear rows in this table record the shared changes retained by the BabyBear-only loop before the later KoalaBear production promotion.

| Boundary | Starting value | Final value | Reduction |
| --- | ---: | ---: | ---: |
| BabyBear canonical Foundry test | 3,680,545 | **3,267,073** | **413,472 / 11.234%** |
| BabyBear transaction | 3,804,363 | **3,390,891** | **413,472 / 10.868%** |
| BabyBear transaction execution | 2,928,915 | **2,515,443** | **413,472 / 14.117%** |
| BabyBear deployed runtime | 34,003 bytes | **34,397 bytes** | +394 bytes |
| BabyBear initcode | 34,029 bytes | **34,423 bytes** | +394 bytes |
| KoalaBear canonical Foundry test | 5,426,216 | **5,089,788** | **336,428 / 6.200%** |
| KoalaBear transaction | 5,545,363 | **5,208,935** | **336,428 / 6.067%** |
| KoalaBear transaction execution | 4,668,027 | **4,331,599** | **336,428 / 7.207%** |

The end-of-loop BabyBear runtime is 31,139 bytes below the 65,536-byte local target. Its initcode is 96,649 bytes below the 131,072-byte target. At this historical boundary, the KoalaBear runtime was 32,534 bytes and its initcode was 32,560 bytes.

The active reviewed BabyBear build is 26,097 gas below that loop boundary, a 0.799% reduction, and 617 runtime bytes smaller. This requested correctness and dead-code cleanup is separate from the rounds governed by the strict 1% retention rule. Across the original baseline and the active build, Foundry gas falls by 439,569 gas or 11.943%, transaction gas falls by 439,569 gas or 11.554%, and execution gas falls by 439,569 gas or 15.008%. The active runtime is 33,780 bytes and its initcode is 33,806 bytes.

## KoalaBear production promotion

The active KoalaBear verifier includes the qualifying verifier improvements from the archived arithmetic work alongside the fixed-base and Merkle changes above. It costs **3,518,733 Foundry gas** in a fresh full-project build and **3,637,880 transaction gas** for the checked-in success fixture.

| Boundary | End of BabyBear loop | Active KoalaBear | Reduction |
| --- | ---: | ---: | ---: |
| Canonical Foundry test | 5,089,788 | **3,518,733** | **1,571,055 / 30.867%** |
| Transaction | 5,208,935 | **3,637,880** | **1,571,055 / 30.161%** |
| Transaction execution | 4,331,599 | **2,760,544** | **1,571,055 / 36.270%** |
| Native phase sum | 4,331,108 | **2,846,923** | **1,484,185 / 34.268%** |

Production uses cached cubic select evaluation, factored equality accumulation, radix-80 base rows, the packed 16-term `MULMOD` extension-row kernel, the specialized 64-element multilinear evaluation, and radix-64 final-polynomial evaluation. The packed-row step measured **7.742%** in the isolated full verifier. The radix-64 path reduced the clean transaction from 3,813,088 to 3,641,381 gas, a **171,707-gas or 4.503%** reduction. The reviewed select-pointer and unused-code cleanup brings the current transaction measurement to 3,637,880 gas. The earlier 0.996% four-coefficient result remains a historical measurement from a different compiler composition. Row/Horner fusion remains excluded at **0.720%**.

The current targeted transaction-script compiler build is 34,898 runtime bytes and 34,924 initcode bytes. It remains above the current EIP-170 runtime limit and below the 65,536-byte runtime and 131,072-byte initcode limits proposed by EIP-7954.

The final serial suite passes **429 tests across 47 suites**, including 256 fuzz cases per fuzz test. The KoalaBear arithmetic regression suite covers packed multiplication, packed extension rows, radix-80 base rows, radix-64 Horner evaluation, the production cubic-select kernel, factored equality accumulation, and the final 64-element multilinear evaluation against independent implementations. The BabyBear production-kernel suite directly covers the three select ranges, a nonterminal range, equality-form multiplication, and the complete fixed equality accumulator against the independent schoolbook implementation. Transcript parity, malformed-proof rejection, fixed-base table reconstruction, packed-row bounds, the native phase profile, optimized IR, and the full receipt are also preserved.

## BabyBear-loop retained changes

| Round | Complete BabyBear gas | Reduction from round start | KoalaBear result |
| --- | ---: | ---: | ---: |
| Starting verifier | 3,680,545 | — | 5,426,216 |
| Fixed-base four-bit exponent tables | 3,580,867 | 99,678 / 2.708% | 5,327,093; 99,123 / 1.827% |
| Strict Merkle parent emission | 3,487,766 | 93,101 / 2.600% | 5,232,930; 94,163 / 1.768% |
| Final Merkle decommitment-length check | 3,441,505 | 46,261 / 1.326% | 46,855 / 0.895%; excluded |
| Merkle hashing split by node parity | 3,311,425 | 130,080 / 3.780% | 5,089,788; 143,142 / 2.735% |
| Packed extension endian conversion | **3,267,073** | **44,352 / 1.339%** | 44,352 / 0.871%; excluded |

### Fixed-base exponentiation

The four schedule-specific domain generators use packed four-bit window tables. Each table lookup returns a canonical field element, and `_fillSelVarsPow` retains the general exponentiation fallback for every other base.

[`script/verify_fixed_base_pow_tables.py`](../script/verify_fixed_base_pow_tables.py) independently reconstructs every table entry with modular exponentiation and checks all 336 entries per field, table order, generator mapping, and lookup byte order. Fixed-window exponentiation is the applicable method described in Daniel Gordon's [survey of fast exponentiation methods](https://www.dmgordon.org/papers/fast.pdf).

### Packed Merkle frontier

The packed frontier receives strictly increasing node indices. Adjacent siblings are consumed together, so every emitted parent index is also strictly increasing. The verifier therefore appends each parent directly instead of testing whether it should overwrite the preceding parent.

The hash loop has three cases: an even node with its sibling in the frontier, an even node with a decommitment, and an odd node with a decommitment. Each case writes the two hashes in their final order before `KECCAK256`. BabyBear validates decommitment consumption once after all levels because calldata reads have no side effects and exact pointer equality rejects both insufficient and trailing data. KoalaBear retains its per-read bounds checks because removing them saved less than 1% there.

The same packed-frontier code is used by the octic KoalaBear verifier. Its transaction measurement fell from 6,367,262 to **6,197,424 gas**, a 169,838-gas or 2.667% reduction.

### Packed endian conversion

BabyBear transcript reads and paired packed-element observations reverse five 32-bit lanes together with two mask-and-shift stages. The vector range predicate is equivalent to five scalar checks for the BabyBear modulus, and the observed transcript bytes remain the original 20-byte little-endian encoding.

The focused test executes the production challenger for boundary values, every invalid lane, invalid low padding, exact transcript bytes, and 256 fuzz cases. The complete transcript replay matches all Rust checkpoints.

## Excluded candidates

| Candidate | Measured result | Decision |
| --- | ---: | --- |
| Exponent-gap batching | −6,347 gas / 0.172% | Below 1% |
| Five-way exponent batching | −15,822 / 0.430% | Below 1% |
| One-pass row hashing and folding | +97,515 gas | Regression |
| Query insertion sort | +8,781 gas | Regression |
| In-place Merkle frontier | −609 gas / 0.017% | Below 1% |
| KoalaBear final decommitment check | −46,855 gas / 0.895% | Below 1% |
| KoalaBear packed endian conversion | −44,352 gas / 0.871% | Below 1% in the BabyBear-loop composition |

The final round starts at 3,267,073 gas, so its strict retention gate is 32,671 gas. Optimized-IR and flamegraph review gives these remaining credible ceilings:

| Surface | Measured work | Credible saving ceiling |
| --- | ---: | ---: |
| Remaining transcript observations | 22,354 gas | Below the gate even if eliminated |
| Merkle frontier compaction | 172,571 gas including 1,507 required Keccaks | Below 16,000 gas |
| `_evaluateSelectCubicPair` final-call specialization | 252,444 gas across 654 calls | 704 gas |
| Query sampling and sorting | 56,903 gas excluding child sampling | About 12,000 gas |
| Final polynomial Horner wrapper | 67,941 gas | 7,254 gas |
| Wider fixed-base windows | 69,281 gas | 816 gas before table overhead |
| Equality bookkeeping | 37,179 gas excluding required products | Low thousands |
| Scratch copy for repeated row reads | 1,024 packed values | At most 27,648 gas |

The row producer-consumer rewrite that could remove the repeated expressions is the measured one-pass candidate that regressed by 97,515 gas under `via_ir`. The final round therefore has no candidate that can clear the 32,671-gas gate, which ends the loop. The [Solidity optimizer documentation](https://docs.solidity.org/en/latest/internals/optimizer.html) describes the inlining, common-subexpression, and stack transformations checked in this review.

## Validation and evidence

- `forge test --offline --match-path 'test/BabyBear*.t.sol' --fuzz-runs 256 -vv`: **100 passed**.
- `forge test --offline --isolate --threads 1 --fuzz-runs 256 --force`: **429 passed across 47 suites**, zero failures and zero skips.
- BabyBear transcript parity: **3 passed** against the Rust trace.
- Packed endian tests: **6 passed**, including 256 fuzz runs.
- `python3 script/verify_fixed_base_pow_tables.py`: all BabyBear and KoalaBear tables passed.
- `python3 check_quintic_calibration_freshness.py --calibration testdata/quintic_calibration.json`: source fingerprints match.

The [active BabyBear measurement manifest](../testdata/babybear_review_fixes_measurement.json) records the current source hashes, gas, bytecode sizes, calldata hash, and evidence hashes. The historical [optimization-loop manifest](../testdata/babybear_full_verifier_measurement.json) preserves the strict loop boundary. Raw transaction receipts, compiler snapshots, flamegraphs, and suite logs named by these manifests are CI-regenerable artifacts and are not checked in.

The current KoalaBear build is recorded by the compact manifests and calibration evidence under `testdata/quintic_calibration_review_fixes/`. Its raw transaction receipt, compiler snapshot, and phase profile are CI-regenerable artifacts and are not checked in.

The quintic score calibration uses raw verifier score 6,766,857, measured transaction gas 3,637,880, and scale 0.5376026122614975. The ordinal calibration gate passes; the per-bucket diagnostics remain outside their target ranges for the octic Merkle and transcript buckets and the quartic transcript bucket.

## Tool issues

The sandboxed Anvil process could not open a local listening socket, so the approved managed runner created the final receipt through a loopback Anvil process. Targeted IR builds could not update Foundry's global signature cache, but compilation and artifact capture completed successfully.
