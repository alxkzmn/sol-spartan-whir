# BabyBear row, select, and equality fusion results

This report records the component benchmarks and KoalaBear control that selected kernels for the [production BabyBear verifier](../README.md#verifiers). The complete verifier measurements and source fingerprints are in the [measurement manifest](../testdata/babybear_full_verifier_measurement.json).

The 2026-09-05 experiment selected a complete KoalaBear native variant at **3,952,037 transaction gas**, down from **4,314,727**, a saving of **362,690 gas (8.41%)**. It uses the packed `MULMOD` row algorithm and fuses each nonfinal extension row evaluation with its claim update. The fusion step saves **0.72%**. Production uses the packed-row variant without fusion because the active promotion applies a strict greater-than-1% gate; its current measurements are in the [optimization report](babybear-verifier-optimization-loop.md#koalabear-production-promotion).

All three experiments were implemented and measured. BabyBear component improvements are **3.95%** for row/Horner fusion, **4.93%** for select/Horner fusion, and **6.49%** for equality preparation. Sources are retained in isolated, reproducible experiments and native patches; the component measurements remain separate from the complete verifier measurement.

## Component measurements

Solidity 0.8.28, `via_ir`, 833 optimizer runs, Prague; measured 2026-09-05. Each comparison uses the same compiler configuration and workload within its experiment.

| Computation                               | KoalaBear control | KoalaBear selected | BabyBear control | BabyBear selected |
| ----------------------------------------- | ----------------: | -----------------: | ---------------: | ----------------: |
| 50 extension rows and claim updates       |           452,084 |        **440,704** |          400,650 |       **384,842** |
| 88 select chains and their Horner updates |       **683,138** |        **683,138** |          618,753 |       **588,237** |
| Fixed equality preparation                |           137,913 |        **128,104** |          123,456 |       **115,450** |

The row measurement includes two weight/challenge preparations, prefixed leaf hashes, and two final OOD Horner updates. Adding the unchanged final 14 rows gives **560,314 KoalaBear gas** and **491,008 BabyBear gas**: BabyBear is **12.37% cheaper**. The select workload includes cubic cache setup, 38/31/19 selectors over 18/14/10 dimensions, and 91 Horner steps. The equality workload includes 86 equality terms, 81 accumulator products, and 64 squares. These boundaries differ from the earlier pure-row benchmark and must be compared separately.

### Row and Horner fusion

The identity is `nextClaim = sum(row_i*weight_i) + claim*challenge`. The implementation adds the final product to the packed row accumulator as a seventeenth term, then reconstructs and reduces the five output coefficients once. It prepares the challenge limbs once per batch and preserves the descending row order and final OOD fold. Final STIR still needs individual row evaluations for its polynomial comparison.

The 17-term integer bounds fit the existing 51-bit lanes. BabyBear's final unreduced coefficient is below `17*9*(p-1)^2 < 2^70`; KoalaBear's signed coefficients use the existing bias. The [row experiment](../testdata/babybear/three-suggestions/rows/) preserves sources, exact bounds, measured code, tests, and replay scripts.

The native integration also updates the final polynomial's four 16-element dot products to consume the new prepared-weight representation. Its independent 64-element multilinear oracle and the complete proof check cover this shared consumer.

### Select and Horner fusion

BabyBear retains the Horner accumulator in two words of canonical coefficients. It stores the unreduced `total*challenge` product in five scratch words, then adds those coefficients to the final select product before five prime reductions. This saves **30,516 gas (4.93%)** against ordinary Horner, or **26,995 (4.39%)** against the 615,232-gas packed-Horner control in the same build.

Intermediate chain products still require canonical coefficients. A persistent five-lane representation using three `MULMOD` operations per product costs 649,496 gas and is rejected. A direct final equality consumer costs 588,748, and packed final Horner costs 616,371; both regress against the selected BabyBear version.

KoalaBear's best new select fusion costs 737,569 gas against its 683,138-gas control, so the native integration retains the existing KoalaBear select implementation. The [select experiment](../testdata/babybear/three-suggestions/select/) includes all variants and their compiler artifacts. The selected BabyBear IR exactly matches its measured runtime; the separately compiled KoalaBear control has a different layout and is identified separately.

### Equality preparation

Keeping OOD points in canonical 64-bit coefficient lanes removes repeated transport packing between squares and equality evaluations. Both selected fields also fuse statement equality generation with accumulator multiplication. KoalaBear benefits from additionally combining the OOD equality, accumulator multiplication, and next square in one helper; BabyBear retains separate helpers because that fusion costs more.

The selected equality libraries save **9,809 KoalaBear gas (7.11%)** and **8,006 BabyBear gas (6.49%)** in their harnesses. Ordinary packed-square substitution, specialized 15-product squares, and the persistent three-`MULMOD` representation regress. Serial equality chains cannot amortize reconstruction over 16 products as row dot products do. The [equality experiment](../testdata/babybear/three-suggestions/equality/) contains all nine variants per field, independent bounds, and exact compiler evidence.

## Complete native integration

The full caller is the KoalaBear quintic native WHIR PCS verifier for `k22_jb100_ext5_lir4_ff4_rsv3_pow28`. Every transaction consumes the identical 54,436-byte calldata, with SHA-256 `73ced3d949b11d13f8bd81372abfc01deb4949d99456f50b99cba14770aaf8fd`. Transaction base plus calldata costs **877,336 gas** in each case.

| Variant                                                   | Foundry test gas | Transaction gas | Execution remainder | Runtime bytes |
| --------------------------------------------------------- | ---------------: | --------------: | ------------------: | ------------: |
| Starting control                                          |        4,195,182 |       4,314,727 |           3,437,391 |        33,639 |
| Packed `MULMOD` rows                                      |        3,944,426 |       3,980,692 |           3,103,356 |        34,454 |
| Rows plus row/Horner fusion — selected by this experiment |    **3,916,794** |   **3,952,037** |       **3,074,701** |    **34,735** |
| Rows plus equality change                                 |        3,934,859 |       4,053,227 |           3,175,891 |        35,883 |
| Rows plus both changes                                    |        3,906,712 |       4,028,209 |           3,150,873 |        36,501 |

The transaction comparison determines which complete implementation is retained. Equality improves its isolated harness and Foundry test result but increases deployed transaction gas by **76,172** when added to the retained version. It is excluded from the selected native patch. The test and deployment builds have different code layouts; the saved bytecode and source hashes identify both measurement contexts. The exact compiler transformation responsible for the equality integration regression is not isolated.

The experiment's selected runtime is **34,735 bytes** and its initcode is **34,761 bytes**, within the configured experimental targets of 65,536 and 131,072 bytes. Runtime sizes above come from the creation transactions; the checked constructor copies the runtime from offset `0x1a`. [Receipts, all native patches, measurements, and profiles](../testdata/babybear/three-suggestions/native/) are preserved together.

The native phase harness attributes the saving to extension STIR and final value evaluation:

| Phase                       | Starting control | Experiment-selected version |
| --------------------------- | ---------------: | --------------------------: |
| First extension STIR round  |          715,801 |                     596,335 |
| Second extension STIR round |          450,134 |                     376,717 |
| Final STIR                  |          457,614 |                     385,294 |
| Final value evaluation      |           61,609 |                      47,216 |
| Constraint evaluation       |          907,197 |                     907,220 |

The final flamegraph's verifier frame costs 3,158,605 gas. That frame and the phase harness use test compilation; transaction execution is measured separately above. Parent frame costs include their children. The targeted optimized IR is also archived with its distinct runtime hash.

The packed-row step saves **334,035 transaction gas (7.74%)**. Row/Horner fusion then saves another **28,655 (0.72%)**. The equality alternatives regress, and the additional BabyBear select and square variants regress. This historical experiment stopped at that point; the production promotion retains the packed-row step and excludes the fusion step.

## Validation and reproduction

- **362 native/repository tests pass:** 304 main tests, 40 field tests, 11 select benchmark tests, and 7 select followup tests. The runs retain 256 cases per fuzz test, transcript parity, malformed-proof rejection, and the independent native arithmetic oracles.
- **23 row experiment tests pass**, with full 31+19-row Horner recurrence checks, 256-case fuzzing, maximal coefficients, every malformed coefficient position, exact first-error behavior, and unchanged prefixed hashes. The Python oracle checks 10,770 cases per field, including 10,000 random 17-term dot products.
- **69 select experiment tests pass**, including 256 full-field full-batch fuzz cases and all 64 boundary combinations of zero/one/maximal/basis points and challenges. A separate schoolbook oracle checks 10,064 fused product cases.
- **7 equality experiment tests pass across 18 harnesses**, including 256 full-prime chain seeds per field and boundary chains. Python checks 10,027 kernels and 100 OOD chains per field.

Fresh replays of all three component experiments pass. The equality generator reproduces its frozen source and tests byte for byte. Native replay checks baseline source and fixture fingerprints, applies the selected patch only in a fresh workspace, and verifies the resulting source hashes. A fresh Anvil replay reproduces **3,952,037 transaction gas**, identical calldata, and identical executable deployment bytecode; only the compiler's 32-byte IPFS metadata digest differs.

From the repository root:

```sh
python3 testdata/babybear/three-suggestions/native/reproduce.py --out-dir /tmp/native-fusion-replay --full-suite
(cd /tmp/native-fusion-replay/workspace && bash .agents/skills/tx-gas-benchmarking/scripts/run_tx_gas_benchmark.sh \
  --start-anvil --port 0 --snapshot-dir ../tx \
  script/WhirBlobNativeTxBenchmark_k22_jb100_ext5_lir4_ff4_rsv3_pow28.s.sol --offline)
```

Use `--variant baseline`, `rows`, `rows-eq`, or `combined` to replay the other measured native candidates. Component reproduction commands are in their linked READMEs. These isolated experiments predate the current production calibration.

## Tool issues

The broad compiler invocation hits the same Yul stack error on the starting control and the candidate. Compiling the two select suites separately preserves every test and passes. The first combined select boundary test exceeded the harness memory limit; splitting its 64 cases into separate tests preserves complete coverage. Local Anvil required execution outside the tool sandbox because the sandbox disallows listening sockets; the approved local runs completed and preserved receipts. Foundry saved the passing final flamegraph but could not launch a desktop SVG viewer; the parser successfully read its gas entries.
