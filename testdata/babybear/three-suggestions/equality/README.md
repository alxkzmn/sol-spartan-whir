# Equality preparation experiments

Solidity 0.8.28 (`7893614a`), `viaIR`, 833 optimizer runs, Prague, Foundry 1.5.1 (`b0a9dd9ceda36f63e2326ce530c10e6916f4b8a2`). The measurement is the `gasleft()` difference inside the complete `prepare` harness. It includes 22 statement equality terms, OOD chains of 22/18/14/10 terms, 81 accumulator products, 64 point squares, shared-point cache preparation, and final output packing. Inputs are identical to the previously recorded benchmark.

| Variant | KoalaBear gas | BabyBear gas |
| --- | ---: | ---: |
| Existing shifted equality | 137,913 | 123,456 |
| Packed multiply used as square, retaining transport representation | 147,833 | 131,840 |
| Persistent point coefficients and packed squares | 132,679 | 117,676 |
| Persistent 51-bit coefficients with three MULMOD products | 233,576 | 174,767 |
| Persistent coefficients, square computed first | 132,679 | 117,676 |
| Persistent coefficients, specialized 15-product square | 135,239 | 121,580 |
| Specialized square computed first | 135,239 | 121,196 |
| Fused point equality, accumulator multiplication, and square | 129,393 | 118,632 |
| Selected point helper plus fused statement equality and multiplication | **128,104** | **115,450** |

The selected changes save **9,809 KoalaBear gas (7.11%)** and **8,006 BabyBear gas (6.49%)**. The field-specific best implementations differ by 12,654 gas, or **9.88%** of the KoalaBear workload. These are arithmetic harness measurements; complete-verifier integration and transaction receipts are separate measurements.

The selected libraries are `KoalaBearEqPersistentStatement` and `BabyBearEqPersistentStatement`. Both retain `_evaluateFixedEqTermsBlobRaw(bytes,uint256,uint256,uint256,uint256,uint256,uint256[])` and return the same five packed extension elements. `SelectedEquality.sol` contains the two libraries and their harnesses; the full generated source and independent tests are under `workspace/test`.

## Mechanism

The OOD points and equality accumulators retain two canonical coefficient words: coefficients 0–3 in ascending 64-bit lanes, and coefficients 4–1 in ascending 64-bit lanes. An OOD square consumes these words and returns the same representation. This removes the repeated transport packing and unpacking between each square and the next equality evaluation. The four OOD states occupy eight words alongside the ten accumulator words.

The KoalaBear point helper combines equality generation, accumulator multiplication, and the next square in one assembly body. This removes internal call and temporary-routing work that remains in the optimized IR. BabyBear retains separate point helpers because the corresponding fused implementation costs more gas. Both selected libraries fuse statement equality generation with its accumulator multiplication.

Every equality term and every multiplication still reduces all five coefficients to the base field before the next product. The equality identity remains `2*(a-1/2)*(q-1/2)+1/2`; coefficient ordering and proof encoding are unchanged. The fusion changes data flow and compiler routing, and does not remove the intermediate prime-field reduction.

## Bounds and validation

For both primes, four canonical coefficient products fit below `2^64`, while five do not. The packed convolution recovers the four low coefficients, four high coefficients in reverse order, and the middle coefficient with a fourth integer product and a separate scalar term. The middle coefficient is accumulated outside the 64-bit lane. KoalaBear subtraction uses a prime-multiple bias; all equality and multiplication intermediates fit below `2^73`. Each subsequent state is canonical. The 18-word state allocation is 576 bytes; the last write starts at byte 544.

`verify_bounds.py` independently checks both polynomials using schoolbook convolution and generic descending polynomial reduction. It passes 10,027 multiplication/square/equality cases per field and 100 full OOD chain cases per field. `bounds.json` records the integer bounds.

The Solidity suite passes **7 tests** across all 18 baseline/candidate harnesses. It includes 256 independent full-chain fuzz seeds using the full canonical range of each prime, 256 arithmetic fuzz cases, every maximal basis-product pair, and full chains containing maximal, zero, one, basis, and alternating coefficients. It preserves the original 22/18/14/10 schedule. `round4-tests.log` records the passing tests and gas measurements.

`compiler.json` records measured runtime/initcode sizes and compiler settings. The selected KoalaBear harness is 4,611 runtime bytes and 4,637 initcode bytes; BabyBear is 3,601/3,627. The fresh targeted IR build produces runtime bytes identical to the measured test artifacts, as recorded in `ir-metadata.json`. The selected `.ir` files show the retained persistent representation and fused helpers.

## Reproduction

Run from the Solidity repository, choosing an output directory that does not exist:

```sh
python3 path/to/reproduce.py --source-root . --out-dir /tmp/equality-replay --fuzz-runs 256
```

The replay uses a fresh temporary Foundry project with read-only source/library links, copies the benchmark helpers, generates all candidates, runs the independent arithmetic suite, and records bounds and generated-source hashes. Production source is unchanged. `generation-idempotence.json` confirms that the saved generator reproduces the measured Solidity source and tests byte for byte. `results.json` records source hashes, all variants, and measurement provenance.

## Tool issue

`forge inspect` reported missing cached IR. A fresh targeted `forge build ... --extra-output irOptimized` recovered the IR without changing the measured artifacts.
