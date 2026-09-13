# Verifier optimization audit

This audit covers the production native blob verifiers for the KoalaBear and BabyBear quintic schedules and the KoalaBear octic schedule. All acceptance measurements use the complete schedule-specific native verifier, Solidity 0.8.28, `via_ir`, 833 optimizer runs, and the Prague EVM target. A candidate is retained only when it reduces the current round's complete verifier gas by strictly more than 1%.

## Production measurements

| Verifier | Canonical Foundry gas | Transaction gas | Execution remainder | Calldata bytes | Runtime / initcode |
| --- | ---: | ---: | ---: | ---: | ---: |
| KoalaBear quintic `k22_jb100_ext5_lir4_ff4_rsv3_pow28` | 3,518,733 | 3,637,880 | 2,760,544 | 54,436 | 34,898 / 34,924 bytes |
| BabyBear quintic `k22_jb100_ext5_lir4_ff4_rsv3_pow28` | 3,240,976 | 3,364,794 | 2,489,346 | 54,084 | 33,780 / 33,806 bytes |
| KoalaBear octic `k22_jb100_lir6_ff4_rsv1` | 5,356,053 | 5,637,745 | 4,862,945 | 47,780 | 36,710 / 36,736 bytes |

The transaction receipts use the same calldata hashes as their comparison measurements. Runtime and initcode sizes come from current targeted optimized-IR builds and are below the project's 65,536-byte runtime and 131,072-byte initcode targets.

## Experimental LeanVM grouped terminal

The retained `GroupedLogupKeccakPow28T6` experiment replaces 221 quotient-GKR rounds with grouped inverse-product LogUp, adds a third helper commitment, shares polynomial weights, and opens all three roots with one Merkle frontier. A clean active-tree build and Cancun transaction reproduce 10,615,304 transaction gas, 9,089,188 execution gas, 98,596 bytes of calldata, and 62,156 / 62,182 bytes of runtime / initcode. This saves 2,280,852 transaction gas, or 17.69%, against the selected 12,896,156-gas C1 terminal.

The implementation, generated wrapper, adversarial tests, proof calldata, algebra vectors, and independent three-root Merkle fixtures are checked in so the result remains reproducible. The grouped verifier is experimental rather than production-selected because full protocol-composition security remains under review.

## KoalaBear and BabyBear quintic

Both production verifiers use the applicable shared mechanisms:

- schedule-specific four-bit fixed-base exponentiation tables;
- the packed Merkle frontier with strict parent emission and parity-specific hashing;
- cached cubic select evaluation and factored equality accumulation;
- radix-80 base-row accumulation and packed extension-row arithmetic;
- a specialized 64-value final multilinear evaluation;
- packed transcript encoding for the field-specific extension representation.

KoalaBear also uses a radix-64 final-polynomial evaluator for its five packed coefficients. On the production verifier, this changed the clean transaction measurement from 3,813,088 to 3,641,381 gas, a reduction of 171,707 gas or 4.503%. The reviewed select-pointer and unused-code cleanup brings the current transaction measurement to 3,637,880 gas. BabyBear already used its best field-specific final-polynomial implementation. Removing dead helpers and the unused radix-64 calldata parameter reduced its complete verifier by 26,097 gas or 0.799%; this requested cleanup is recorded separately from the strict optimization-loop rounds.

The remaining shared candidates did not clear the threshold. A general packed KoalaBear extension multiplication saved 6,726 Foundry gas or 0.182%. Hoisting the shared Merkle bound check and applying the BabyBear five-lane transcript construction to KoalaBear either regressed or stayed below 1%. Row and Horner fusion had already measured 0.720% on the complete verifier.

### Field specialization

The two quintic verifiers cannot be combined safely by passing only the modulus at runtime. BabyBear reduces with `X^5 = 2`, while KoalaBear reduces with `X^5 = 1 - X^2`; this changes the reduction signs, bias bounds, and packed arithmetic. The fields also have different canonical rejection bounds, domain generators, fixed-base tables, and measured kernel choices. Runtime parameters would add loads and live values to the inlined arithmetic and prevent `via_ir` from specializing those constants.

The production contracts remain field-specialized so the compiler can inline the modulus, extension polynomial, transcript rejection rule, generators, fixed-base tables, and field-specific kernels.

## KoalaBear octic

The octic verifier retains six measured rounds:

| Round | Complete Foundry gas | Reduction from round start |
| --- | ---: | ---: |
| Starting verifier | 5,915,732 | - |
| Factored dim-4 equality weights | 5,782,064 | 133,668 / 2.259% |
| Four-bit fixed-base exponentiation | 5,684,533 | 97,531 / 1.687% |
| Radix-80 base-row accumulation | 5,618,882 | 65,651 / 1.155% |
| Packed ext8 transcript validation and byte conversion | 5,514,794 | 104,088 / 1.852% |
| Packed ext8 row validation | 5,412,650 | 102,144 / 1.852% |
| Four-row final multilinear evaluation | **5,356,053** | **56,597 / 1.046%** |

The combined Foundry reduction is 559,679 gas or 9.461%. Transaction gas falls by the same 559,679 gas, from 6,197,424 to 5,637,745.

The packed ext8 range predicate uses eight repeated 32-bit masks. Each low-31-bit lane plus the bias is at most `0x80fffffe`, so the packed addition cannot carry into an adjacent lane. The radix-80 base-row kernel bounds its 16-term accumulators below 66 bits. The final multilinear evaluator bounds each 16-term tower accumulator by `352 * (p - 1)^2 < 2^71` before reducing its eight output coefficients.

Three measured octic candidates remained outside production: the shared Merkle bound hoist saved 28,062 gas or 0.499%; changing the shared statement-level ext8 validator saved 8,855 gas or 0.164%; and the first final-MLE formulation saved 50,305 gas or 0.929%. The arithmetic-only four-row formulation removes enough hashing and validation overhead to clear the gate.

## Validation and evidence

- The serial suite passes 429 tests across 47 suites with 256 fuzz runs, zero failures, and zero skips.
- The KoalaBear quintic, BabyBear quintic, and octic native verifier suites pass 19, 27, and 18 tests respectively.
- KoalaBear quintic and BabyBear quintic transcript replay pass three tests each; octic transcript replay passes four tests.
- The KoalaBear optimized arithmetic suite and octic tower arithmetic suite each pass ten tests with independent reference implementations and 256 fuzz runs.
- The BabyBear production-kernel suite passes four direct fuzz tests for select and equality accumulation against the independent schoolbook implementation.
- The ext8 packed transcript suite passes boundary, every-lane rejection, byte-order, and 256-run fuzz checks.
- The fixed-base reconstruction script verifies every retained BabyBear, KoalaBear quintic, and KoalaBear octic table.
- `FieldArithmeticTest` now deploys only its harness during setup and parses one fixture section per vector test. The gas probes are isolated in `FieldArithmeticGasTest`, keeping both test contracts below the configured runtime allowance; fixture structs follow `vm.parseJson`'s alphabetical object-member encoding.
- The quintic calibration source fingerprint is `0d13416cb1b41414fb41f25deb815763d7f098328bb20350b1c42e65580c5cfc`; the ordinal calibration gate passes.

Current KoalaBear evidence is recorded by the compact manifests and calibration records under `testdata/quintic_calibration_review_fixes/`. Current BabyBear evidence is recorded by `testdata/babybear_review_fixes_measurement.json`. Earlier optimization-loop and octic measurements retain compact manifests under `testdata/`; raw transaction receipts, compiler snapshots, profiles, plots, and logs are CI-regenerable artifacts and are not checked in.
