# sol-spartan-whir -- Agent Instructions

This is the Foundry project for the on-chain standalone WHIR verifiers over the KoalaBear and BabyBear fields and the LeanVM terminal verifier. The direct WHIR paths verify only the PCS portion used by Spartan-WHIR. The LeanVM path verifies a terminal proof whose guest execution covers the complete Spartan-WHIR verifier. External source repositories and cross-crate logic anchors are linked below in [Verifier Source Anchors](#verifier-source-anchors).

## Skills

Detailed workflow guides live under `.agents/skills/*/SKILL.md`:

- `.agents/skills/forge-flamegraph-profiling/SKILL.md` — execution gas profiling with Foundry flamegraphs and `gasleft()` harness tests
- `.agents/skills/tx-gas-benchmarking/SKILL.md` — total transaction gas measurement via Anvil broadcast runs
- `.agents/skills/solidity-compiler-analysis/SKILL.md` — optimized IR, repeated computation, stack spills, and gas versus deployed bytecode
- `.agents/skills/finite-field-arithmetic-optimization/SKILL.md` — algorithm research, arithmetic bounds, and independent correctness validation
- `.agents/skills/gas-calibration-maintenance/SKILL.md` — measurement provenance, calibration refresh, source fingerprints, and schedule reports

## Protocol Compatibility Rules

Transcript byte-level compatibility between Rust and Solidity is the highest correctness risk. If the Solidity challenger produces even one different byte during observe or sample operations, every subsequent challenge diverges and the proof is rejected.

Standalone-WHIR proof data is encoded with the Rust codec/exporter conventions. The standalone-WHIR Solidity verifier has three paths:

- Native blob verifier (`*WhirBlobVerifierNative*` schedule-specific variants): production-style path. Reads the fixed-shape blob directly from calldata.
- Typed ABI verifier (`*WhirVerifier*` schedule-specific variants): parity/test path. Uses `abi.encode`/`abi.decode` for debuggability.
- Blob decode-and-delegate wrapper (`*WhirBlobVerifier*` schedule-specific variants): decodes the blob into typed structs, then delegates to the typed verifier.

The blob layout mixes encoding conventions on purpose: transcript-native little-endian sections for data fed to the challenger, plus big-endian or packed sections for Merkle/proof data. Do not reorganize it for consistency. The layout is optimized for gas, and any change needs benchmarking plus Rust fixture regeneration.

Changes to transcript ordering, proof encoding, digest layout, Merkle hashing, or domain separator construction are protocol-surface changes. State explicitly which Solidity components are affected and what needs to be regenerated or updated.

The Solidity verifier assumes Keccak hashing with domain-separation prefix bytes (`0x00` for leaves, `0x01` for nodes). The `keccak_no_prefix` feature flag in the Rust implementation must stay disabled because enabling it silently breaks Merkle verification in Solidity.

EVM verifier compatibility takes priority over Rust-only cleanliness. Reject changes that make EVM verification harder, less efficient, or incompatible with the current plan, even if they improve Rust abstraction quality or prover performance.

## Verifier Source Anchors

Use these upstream locations as the logic sources when checking Solidity behavior:

| Surface                            | Source                                                                                                                                                                                                                                                                                                             |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| WHIR verification inside Spartan-WHIR | [spartan-whir/src/whir_pcs.rs](https://github.com/ethereum/spartan-whir/blob/main/src/whir_pcs.rs), [whir-p3/src/whir/verifier/mod.rs](https://github.com/alxkzmn/whir-p3/blob/csp/src/whir/verifier/mod.rs), and [whir-p3/src/whir/verifier/sumcheck.rs](https://github.com/alxkzmn/whir-p3/blob/csp/src/whir/verifier/sumcheck.rs) |
| Full Spartan IOP reference only     | [spartan-whir/src/protocol.rs](https://github.com/ethereum/spartan-whir/blob/main/src/protocol.rs) and [spartan-whir/src/sumcheck.rs](https://github.com/ethereum/spartan-whir/blob/main/src/sumcheck.rs). Use these for full-SNARK or Spartan IOP questions, not for standalone-WHIR Solidity gas work. |
| KoalaBear field arithmetic         | [Plonky3/koala-bear/src/koala_bear.rs](https://github.com/Plonky3/Plonky3/blob/main/koala-bear/src/koala_bear.rs)                                                                                                                                                                                                  |
| BabyBear field arithmetic          | [Plonky3/baby-bear/src/baby_bear.rs](https://github.com/Plonky3/Plonky3/blob/main/baby-bear/src/baby_bear.rs)                                                                                                                                                                                                  |
| Extension-field arithmetic         | [Plonky3/field/src/extension/binomial_extension.rs](https://github.com/Plonky3/Plonky3/blob/main/field/src/extension/binomial_extension.rs)                                                                                                                                                                        |
| Hashing                            | [spartan-whir/src/hashers.rs](https://github.com/ethereum/spartan-whir/blob/main/src/hashers.rs)                                                                                                                                                                                                                   |
| Merkle multiproof                  | [whir-p3/src/whir/merkle_multiproof.rs](https://github.com/alxkzmn/whir-p3/blob/csp/src/whir/merkle_multiproof.rs)                                                                                                                                                                                                 |
| Proof types                        | [whir-p3/src/whir/proof.rs](https://github.com/alxkzmn/whir-p3/blob/csp/src/whir/proof.rs)                                                                                                                                                                                                                         |
| Config derivation                  | [whir-p3/src/whir/parameters.rs](https://github.com/alxkzmn/whir-p3/blob/csp/src/whir/parameters.rs)                                                                                                                                                                                                               |
| Domain separator                   | [spartan-whir/src/domain_separator.rs](https://github.com/ethereum/spartan-whir/blob/main/src/domain_separator.rs) and [whir-p3/src/fiat_shamir/domain_separator.rs](https://github.com/alxkzmn/whir-p3/blob/csp/src/fiat_shamir/domain_separator.rs)                                                              |
| Structural Solidity reference only | [privacy-ethereum/sol-whir](https://github.com/privacy-ethereum/sol-whir) for project layout, gas harness, Merkle queue pattern, and test patterns. Do not use it as a logic source.                                                                                                                               |

## Extension Degree and Folding Schedule

The Solidity verifier architecture has extension-degree-specific verifier families. The current high-security target is quintic, with octic kept as a high-security reference point. Quartic is retained mainly as the 80-bit comparison baseline against `sol-whir`.

The Rust implementation currently hardcodes `FoldingFactor::Constant(...)` when building the WHIR config. Solidity schedule-specific verifiers must consume the exported per-round schedule instead of assuming a constant folding factor in verifier logic.

Changing Rust to `ConstantFromSecondRound` is a protocol-surface change: it changes the derived round schedule, WHIR Fiat-Shamir pattern, and fixed-config verifier constants. Do not change the folding-factor variant without schedule-tuning review and full fixture/generated-code regeneration.

## Basic Commands

The installed `forge fmt` can move statements out of compact one-line `while` and `if` bodies, changing semantics or producing invalid syntax. Write compound bodies with braces and one statement per line before formatting, then inspect the formatted control flow. Reproduced cases include `while (value != 0) { ++out; value >>= 1; }` and `if (i == 0) { low = bLow; rev = bRev; } else { ... }`. Keep a verified source snapshot for recovery. Remove this workaround after the formatter preserves both cases.

Use Foundry for the Solidity project:

```sh
forge build
forge test --offline --isolate --threads 1
```

Regenerate the generic fixture set from the companion exporter in release mode. Set `SPARTAN_WHIR_EXPORT_DIR` to a checkout of [spartan-whir-export](https://github.com/alxkzmn/spartan-whir-export):

```sh
cargo run --release --manifest-path "$SPARTAN_WHIR_EXPORT_DIR/Cargo.toml" --bin export-fixtures -- testdata
```

## LeanVM Terminal Workflow

The selected terminal is `LeanVmTwoCommitmentTerminal_KeccakPublicMemoryC1Pow28T6.verifyC1V1`. Keep its generated contract and the intentionally retained experimental `LeanVmGroupedTerminal_KeccakPow28T6` contract in `src/leanvm/generated/`; historical single-commitment and schedule variants belong in the workspace research archive, not in the active Foundry compilation tree.

Validate the native root fixture and its opening layout without changing generated outputs:

```sh
python3 script/generate_leanvm_two_commitment_terminal_fixture.py \
  ../leanVM/benchmark-results/terminal-c1-b-threshold6-pow28/native/root-fixture.json \
  KeccakPublicMemoryC1Pow28T6 \
  --validate-only
```

To regenerate, run the same command without `--validate-only` in a tree where the generated contract, test, benchmark script, and fixture directory do not exist. The generator deliberately refuses to overwrite them.

Focused validation:

```sh
forge test --offline --isolate --threads 1 \
  --match-contract LeanVmTwoCommitmentTerminal_KeccakPublicMemoryC1Pow28T6Test
forge test --offline --isolate --threads 1 \
  --match-contract LeanVmGroupedTerminal_KeccakPow28T6Test
```

Measure a fresh transaction into a new output directory after `forge build`:

```sh
python3 script/measure_leanvm_terminal_tx.py \
  KeccakPublicMemoryC1Pow28T6 \
  <new-output-directory>
python3 script/measure_leanvm_terminal_tx.py \
  GroupedLogupKeccakPow28T6 \
  <new-output-directory>
```

Run `forge build --offline --force` before a source-change measurement: the measurement script authenticates source hashes but reads the existing artifact and does not establish artifact freshness. It starts its own Cancun Anvil instance with the local 65,536-byte runtime allowance. The checked-in grouped LogUp terminal is an intentionally retained experimental verifier with runtime fixtures and focused tests; its full protocol-composition security remains under review. Superseded candidates, exact receipts, and other exploratory implementations belong in external research archives rather than this active Foundry project.

## Gas Profiling with Forge Flamegraphs

Use the flamegraph profiling skill above for the detailed profiling workflow.

Use that skill for:

- the `--flamegraph` vs `--flamechart` choice
- SVG parsing
- the `WhirGasProfile*.t.sol` harness family
- the current profiling command sequence

Foundry flamegraphs can crash on deep call trees because of trace-decoding issues. If that happens, switch to a smaller, more focused test instead of treating it as an out-of-memory condition.

For total transaction gas measurement, use the tx-gas benchmarking skill.

## Tx Benchmarking Caveat

Codex tool-side `forge script` failures are not enough evidence that Foundry is broken on the machine. If a tx benchmark fails from the agent in a way that looks environment-specific or tool-specific, retry the exact `anvil` + `forge script` flow in the direct local shell before claiming the benchmark path is broken.

For the native verifier tx benchmark:

- start Anvil with `--code-size-limit 65536`
- keep that Anvil process running until the benchmark and receipt parsing are complete
- remember that `--code-size-limit 65536` must be present on Anvil, not only on `forge script`
- inspect `broadcast/*/31337/run-latest.json` before concluding that the run failed in a meaningful verifier-specific way

If the direct shell run succeeds and the agent-run does not, treat the direct shell result as the source of truth and describe the agent failure as a tool-context issue instead of a machine-wide Foundry issue.

This caveat is temporary. If agent-side `forge script` runs stop showing tool-context-specific failures and behave the same as direct shell runs, remove or simplify this note.

## Fixture and Schedule Commands

Use release mode for exporter runs unless deliberately debugging the exporter. Set `SPARTAN_WHIR_EXPORT_DIR` to a checkout of [spartan-whir-export](https://github.com/alxkzmn/spartan-whir-export).

Current quintic fixture export:

```sh
cargo run --release --manifest-path "$SPARTAN_WHIR_EXPORT_DIR/Cargo.toml" \
  --bin export_fixtures_quintic_k22_jb100_ext5_lir4_ff4_rsv3_pow28 -- testdata
```

Octic schedule fixture family:

```sh
cargo run --release --manifest-path "$SPARTAN_WHIR_EXPORT_DIR/Cargo.toml" --bin export-fixtures-octic-k22-jb100-lir6-ff4-rsv1 -- testdata
```

Quintic schedule scoring inputs and reports:

```sh
cargo run --manifest-path "$SPARTAN_WHIR_EXPORT_DIR/Cargo.toml" --bin dump_quintic_schedule_microbench -- testdata/quintic_schedule_microbench_dump.json
cargo run --manifest-path "$SPARTAN_WHIR_EXPORT_DIR/Cargo.toml" --bin dump_calibration_references > testdata/calibration_reference_schedules.json
forge test --match-path test/QuinticMicroBenchmarks.t.sol -vv --offline > <forge-microbench-log>
RUSTFLAGS="-C target-cpu=native" cargo run --release --manifest-path "$SPARTAN_WHIR_EXPORT_DIR/Cargo.toml" --bin bench_quintic_pow_calibration -- --min-bits 20 --max-bits 22 --samples-per-bit 5 testdata/quintic_pow_calibration.json
RUSTFLAGS="-C target-cpu=native" cargo run --release --manifest-path "$SPARTAN_WHIR_EXPORT_DIR/Cargo.toml" --bin bench_quintic_prover_micro -- --max-candidates <N> --repetitions 3 testdata/quintic_prover_microbench.json
RUSTFLAGS="-C target-cpu=native" cargo run --release --manifest-path "$SPARTAN_WHIR_EXPORT_DIR/Cargo.toml" --bin profile_quintic_prover -- <candidate-label>
RUSTFLAGS="-C target-cpu=native" cargo run --release --manifest-path "$SPARTAN_WHIR_EXPORT_DIR/Cargo.toml" --bin profile_quintic_pow -- <candidate-label> --max-bits <N>
forge test --match-path test/GasCalibration_native_compare.t.sol -vv --offline > <forge-calibration-log>
python3 build_quintic_calibration.py --phase-log <forge-calibration-log> --gas-log <forge-microbench-log> --reference-schedule testdata/calibration_reference_schedules.json --quintic-schedule testdata/quintic_schedule_microbench_pow27_30_full.json --out testdata/quintic_calibration.json
python3 check_quintic_calibration_freshness.py --calibration testdata/quintic_calibration.json
python3 quintic_schedule_scorer.py \
  --schedule testdata/quintic_schedule_microbench_pow27_30_full.json \
  --prover-calibration-schedule testdata/quintic_schedule_microbench_pow24.json \
  --prover-calibration-schedule testdata/quintic_schedule_microbench_pow25.json \
  --prover-calibration-schedule testdata/quintic_schedule_microbench_pow26.json \
  --gas <forge-microbench-log> \
  --rust-timings testdata/quintic_prover_microbench.json \
  --pow-calibration testdata/quintic_pow_calibration.json \
  --calibration testdata/quintic_calibration.json \
  --require-calibration \
  --target-security-bits 100 \
  --report-plot-label constant_pow28_ff4_lir4_rsv3 \
  --out-dir testdata/quintic_scores
```

## Gas Measurement Commands

Phase breakdown rows:

```sh
forge test --match-path test/GasCalibration_native_compare.t.sol \
  --match-test testCompareNativePhaseBreakdown -vv

forge test --match-path test/WhirGasProfile5_k22_jb100_ext5_lir4_ff4_rsv3_pow28.t.sol \
  --match-test testProfileNativeBlobBreakdown5Pow28Rsv3 -vv
```

Quintic native blob flamegraph:

```sh
forge test \
  --match-test testGasWhirVerifyBlobNativeFixed \
  --match-path test/WhirBlobVerifierNative5_k22_jb100_ext5_lir4_ff4_rsv3_pow28.t.sol \
  --flamegraph
```

Native transaction benchmarks:

```sh
# 80-bit comparison baseline against sol-whir
bash .agents/skills/tx-gas-benchmarking/scripts/run_tx_gas_benchmark.sh script/WhirBlobNativeTxBenchmark_lir6_ff5_rsv1.s.sol

# high-security schedules
bash .agents/skills/tx-gas-benchmarking/scripts/run_tx_gas_benchmark.sh script/WhirBlobNativeTxBenchmark_k22_jb100_lir6_ff4_rsv1.s.sol
bash .agents/skills/tx-gas-benchmarking/scripts/run_tx_gas_benchmark.sh script/WhirBlobNativeTxBenchmark_k22_jb100_ext5_lir4_ff4_rsv4.s.sol
bash .agents/skills/tx-gas-benchmarking/scripts/run_tx_gas_benchmark.sh script/WhirBlobNativeTxBenchmark_k22_jb100_ext5_lir4_ff4_rsv3_pow28.s.sol
bash .agents/skills/tx-gas-benchmarking/scripts/run_tx_gas_benchmark.sh script/WhirBlobNativeTxBenchmark_k22_jb100_ext5_lir4_ff4_rsv3_pow28_precompile.s.sol
```

Precompile runner and RPC measurement commands live here because they depend on the custom [Foundry fork](https://github.com/alxkzmn/foundry/tree/codex/ext8-precompile-runner). Set `FOUNDRY_FORK_DIR` to that checkout and `SOL_SPARTAN_WHIR_DIR` to this repository checkout.

```sh
forge build
cargo check --manifest-path "$FOUNDRY_FORK_DIR/Cargo.toml" -p ext8-precompile-runner
cargo check --manifest-path "$FOUNDRY_FORK_DIR/Cargo.toml" -p ext5-precompile-runner
cargo run --release --manifest-path "$FOUNDRY_FORK_DIR/Cargo.toml" -p ext8-precompile-runner --bin calibrate-ext8-precompile-gas -- "$SOL_SPARTAN_WHIR_DIR/testdata/ext8_precompile_gas_schedule.json"
cargo run --release --manifest-path "$FOUNDRY_FORK_DIR/Cargo.toml" -p ext8-precompile-runner --bin export-ext8-precompile-vectors -- "$SOL_SPARTAN_WHIR_DIR/testdata"
cargo run --release --manifest-path "$FOUNDRY_FORK_DIR/Cargo.toml" -p ext5-precompile-runner --bin calibrate-ext5-precompile-gas -- "$SOL_SPARTAN_WHIR_DIR/testdata/ext5_precompile_gas_schedule.json"
cargo run --release --manifest-path "$FOUNDRY_FORK_DIR/Cargo.toml" -p ext5-precompile-runner --bin calibrate-extfield-mac-gas -- "$SOL_SPARTAN_WHIR_DIR/testdata/extfield_mac_gas_schedule.json"
cargo run --release --manifest-path "$FOUNDRY_FORK_DIR/Cargo.toml" -p ext5-precompile-runner --bin calibrate-extfield-lin-prod-gas -- "$SOL_SPARTAN_WHIR_DIR/testdata/extfield_lin_prod_gas_schedule.json"
cargo run --release --manifest-path "$FOUNDRY_FORK_DIR/Cargo.toml" -p ext5-precompile-runner --bin export-ext5-precompile-vectors -- "$SOL_SPARTAN_WHIR_DIR/testdata"
cargo run --release --manifest-path "$FOUNDRY_FORK_DIR/Cargo.toml" -p ext5-precompile-runner --bin export-extfield-mac-vectors -- "$SOL_SPARTAN_WHIR_DIR/testdata"
cargo run --release --manifest-path "$FOUNDRY_FORK_DIR/Cargo.toml" -p ext5-precompile-runner --bin export-extfield-lin-prod-vectors -- "$SOL_SPARTAN_WHIR_DIR/testdata"
```

Start one local runner at a time, then run the matching RPC scripts from this Foundry project:

```sh
cargo run --release --manifest-path "$FOUNDRY_FORK_DIR/Cargo.toml" -p ext8-precompile-runner --bin ext8-precompile-node -- "$SOL_SPARTAN_WHIR_DIR/testdata/ext8_precompile_gas_schedule.json" "$SOL_SPARTAN_WHIR_DIR/testdata/extfield_mac_gas_schedule.json" "$SOL_SPARTAN_WHIR_DIR/testdata/extfield_lin_prod_gas_schedule.json" 18547
python3 script/run_ext8_precompile_phase1_rpc.py --rpc-url http://127.0.0.1:18547 --skip-arithmetic
python3 script/run_ext8_precompile_phase1_rpc.py --rpc-url http://127.0.0.1:18547 --skip-benchmarks
python3 script/run_ext8_precompile_full_verifier_rpc.py --rpc-url http://127.0.0.1:18547
python3 script/run_ext8_precompile_eip_candidate_rpc.py --rpc-url http://127.0.0.1:18547
```

```sh
cargo run --release --manifest-path "$FOUNDRY_FORK_DIR/Cargo.toml" -p ext5-precompile-runner --bin ext5-precompile-node -- "$SOL_SPARTAN_WHIR_DIR/testdata/ext5_precompile_gas_schedule.json" "$SOL_SPARTAN_WHIR_DIR/testdata/extfield_mac_gas_schedule.json" "$SOL_SPARTAN_WHIR_DIR/testdata/extfield_lin_prod_gas_schedule.json" 18547
python3 script/run_ext5_precompile_rpc.py --rpc-url http://127.0.0.1:18547 --gas-limit 30000000
python3 script/run_ext5_precompile_full_verifier_rpc.py --rpc-url http://127.0.0.1:18547 --gas-limit 30000000
```

## Optimization Validation Workflow

1. Run `forge test` — the full Solidity suite must pass
2. Run `forge test --match-test testGasWhirVerifyFixed -vv` — get the single canonical gas number
3. Run `forge test --match-test testProfileFullBreakdown -vv` — verify phase-level breakdown
4. Compare against previous numbers to confirm the delta matches expectations

## Gas Optimization Workflow

Use this workflow to decide which verifier-only optimizations are worth attempting under `via_ir`, and how to reject weak candidates quickly.

### Steps

1. Measure canonical gas on the exact target path first.
2. If the available profiling harness exercises a different verifier path, treat its phase-level numbers as directional only.
3. Choose a hotspot from the real target path, not from source readability.
4. Map the hotspot data flow before editing:
   - which calldata regions are read
   - which memory buffers are written
   - which operation consumes each buffer next
5. Inspect `irOptimized` or `assemblyOptimized` for that exact target path.
6. Look specifically for:
   - the same calldata range read in multiple sequential code paths
   - repeated loops over the same coefficient window or row window
   - a buffer materialized only to be consumed by the very next operation
7. Only optimize work that is still duplicated or still structurally large in the optimized contract.
8. Keep the first rewrite narrow and path-specific.
9. Measure gas and deployed bytecode immediately after the change.
10. Check deployed runtime bytecode and initcode against their separate size targets.
    To get deployed bytes from `deployedBytecode`, strip the `0x` prefix and divide the remaining hex length by `2`.
    Use `deployedBytecodeSize` instead if the toolchain exposes it.

- Runtime target: at most `65,536` bytes (64 KiB), following [EIP-7954](https://eips.ethereum.org/EIPS/eip-7954).
- Initcode target: at most `131,072` bytes (128 KiB).
- Record both sizes. Prioritize gas improvements within these limits.
- Check the official EIP-7954 status before treating the configured local allowance as active on a deployment network.

11. Revert quickly if the result is not clearly positive.
12. Run the full suite only after the narrow benchmark is promising.
13. Write down why the change worked or failed before moving to the next candidate.

### Good Candidates

- A full second scan over the same calldata region.
- The same calldata range read by two sequential operations in the same call path.
- Repeated Horner or fold loops over the same coefficient window.
- Repeated row decoding, validation, or hashing that still survives in optimized IR.
- A buffer that is fully overwritten before any read and can be raw-allocated instead of zero-initialized with `new`.
- A native-only repeated pattern that can be collapsed without changing shared verifier structure.
- Algebraically redundant intermediate reductions inside heavily-inlined arithmetic (e.g., an intermediate `mod` on a difference when the final output already reduces). These are not duplicated work, but unnecessary work — and when the function is inlined dozens of times, the per-call saving compounds.

### Weak Candidates

- A seam that is obvious in Solidity source but mostly gone in optimized IR.
- A helper boundary that the compiler has already inlined.
- A rewrite that mainly changes representation shape without removing dynamic work.
- A large monolithic rewrite whose benefit depends on the compiler making better choices than it already does.
- Isolated compiler-generated overflow checks, Panic guards, and other tiny per-instance noise. (Exception: an `unchecked` block that propagates through inlined callees in a hot path can save more than expected — worth a quick try-and-measure.)
- Allocation cleanup when the buffer is small or not provably fully overwritten before any read.

### Practical Heuristics

Prefer:

- Removing duplicated calldata reads.
- Removing duplicated coefficient scans.
- Reusing existing buffers when the optimized path already materializes them.
- Replacing zero-initialized dynamic allocation with raw allocation when the buffer is provably overwritten before any read.
- Native-only specialization when the hotspot is native-only.
- Scalar accumulator state when batching avoids repeated packing and unpacking.

Avoid:

- Large rewrites before a narrow benchmark.
- Shared-path churn when only the native path is hot.
- Extra memory materialization unless it clearly replaces more expensive repeated work.
- Assuming that fewer source-level helpers means fewer runtime operations.

### Validation Gates

Use this order:

1. `forge test --match-test testGasWhirVerifyBlobNativeFixed -vv`
2. Inspect deployed bytecode for the exact native verifier contract under test.
   - strip the `0x` prefix and divide the remaining hex length by `2` before comparing against the 65,536-byte runtime target
3. native-path profiling if available; otherwise use typed/shared profiling only as directional evidence
4. targeted profiling tests if the change should move a known bucket
5. `forge test`

Reject a candidate when any of the following is true:

- gas regression
- runtime or initcode exceeding the configured target
- no clear explanation for the measured result
- the optimized IR does not actually reflect the intended structural change

### Stop Condition

Stop when no good candidates remain on the actual production path.

In practice, that means:

- the optimized native IR no longer shows duplicated scans, duplicated calldata reads, or obviously disposable temporary buffers
- the remaining ideas are mostly constant-factor cleanups or compiler-shape gambles
- further wins would likely require protocol or proof-format changes instead of verifier-only work

When that happens, move on to constant-factor candidates: algebraically redundant operations in hot arithmetic, unchecked blocks in inlined call chains, and opcode-level micro-optimizations (e.g., cascade byte-swap instead of 8-term combine). These are smaller individually, but when the hot functions are inlined many times they can compound to a meaningful total.

Stop entirely when constant-factor candidates are also exhausted or consistently measure below ~100 gas. Record the final gas and deployed-bytecode baseline.

### Working Rule

The best candidates are not "places where the source looks redundant." The best candidates are "places where the deployed native verifier still does the same expensive thing more than once."

## Warning: `via_ir` and Optimization Interactions

The Solidity compiler with `via_ir = true` (used in this project) is aggressive about inlining and eliminating dead code. Many "obvious" optimizations yield much less than estimated because the compiler was already doing something similar. Always benchmark before and after — never trust gas estimates alone. Previous examples of surprises:

- Low-level extension multiplication rewrite: expected a gas win, measured a regression because the compiler was already optimizing the high-level version better
- Batch sumcheck validation regressed because the extra memory allocation outweighed the saved checks.

## Known Gotchas

These are things that have wasted time before. Read before running the relevant tools.

### Schedule model (`whir_param_sweep.py`)

- The `Constant(5)` `lir11_ff5_rsv3`, `Constant(4)` `lir6_ff5_rsv1`, and octic `k22_jb100_lir6_ff4_rsv1` rows are exact anchors. Read their current values from `whir_param_sweep.py` and the measurement artifacts; other octic rows remain model estimates.
- `estimate_extfield_grinding_quartic.py` is a wrapper that monkey-patches the sweep's grinding cap above 30 bits to model a hypothetical extension-field PoW witness format the verifier does not implement. Its outputs are not deployable schedules. The PoW witness delta it adds is 16 bytes per witness instead of 4.
- Both scripts are estimation tools, not part of the deployable verifier path.

### Schedule scorer (`quintic_schedule_scorer.py`)

- The scorer's verifier axis is quintic-calibrated against the `constant_pow28_ff4_lir4_rsv3` anchor. If the anchor changes, regenerate `testdata/quintic_calibration.json` and the score reports so the raw score, measured transaction gas, and derived scale remain matched.
- `quartic_lir11_ff5_rsv3` phase breakdown **does not compile cleanly under `via_ir`**. It contributes total transaction gas only, and is excluded from per-bucket validation.
- The `lir6` transcript bucket includes setup and round commitment parsing, while the scorer charges transcript-observe work. The folding bucket is intentionally over-counted as a unit-cost sum; no per-round folding benchmark exists yet. Treat per-bucket ratios as diagnostic, not as ground truth.
- Real prover timings require release builds with `RUSTFLAGS="-C target-cpu=native"`. The Rust benchmark records `measurement_kind = "actual_whir_commit_prove"` and `target_cpu_native = true`; if either is missing in a timing JSON, the row is not comparable.
- The Rust schedule dump derives with `security_level_bits = 101` as a guard and filters rows against the actual 100-bit target through each row's `target_evaluation` block. Do not lower the guard.

### Precompile-backed verifier experiment

The local-only precompile experiment has its own operational pitfalls (stock `forge test` cannot execute the path, `forge script` simulation is unreliable, custom node on port `18547`, RPC scripts must use state-changing transactions, EIP-compatible boundary is `EXT8_MUL` and `EXT8_SQUARE` only). See [docs/precompile-experiment.md](./docs/precompile-experiment.md).
