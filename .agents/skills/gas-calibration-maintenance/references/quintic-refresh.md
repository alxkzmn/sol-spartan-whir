# Quintic calibration recipe

Run from the project root after capturing source/build context as described in `SKILL.md`. `calibration_run` is a fresh evidence directory. Keep command exit statuses and logs; failed Forge invocations cannot supply calibration inputs. This is a complete gas refresh recipe. Reuse only inputs justified by dependency and provenance review.

## Measurements

```sh
forge test --match-path test/QuinticMicroBenchmarks.t.sol -vv --offline > "$calibration_run/microbench.log" 2>&1
forge test --match-path test/GasCalibration_native_compare.t.sol \
  --match-test testCompareNativePhaseBreakdown -vv --offline > "$calibration_run/phases.log" 2>&1
```

The first log supplies `BENCH:` records; the second supplies `CALIBRATION:` records. Check compiler metadata against the actual build: the current scorer expects solc 0.8.28, `via_ir = true`, and optimizer runs 833. Keep EVM/fork settings comparable. For a deliberate compiler change, update the model's checks and remeasure references.

Capture four transaction references sequentially. Leave `RPC_URL` unset for managed mode; the helper stops only its own child. Each output directory must be new.

```sh
set -e
for entry in \
  quartic:WhirBlobNativeTxBenchmark_lir6_ff5_rsv1 \
  quartic-lir11:WhirBlobNativeTxBenchmark_lir11_ff5_rsv3 \
  octic:WhirBlobNativeTxBenchmark_k22_jb100_lir6_ff4_rsv1 \
  quintic:WhirBlobNativeTxBenchmark_k22_jb100_ext5_lir4_ff4_rsv3_pow28
do
  label=${entry%%:*}
  script_name=${entry#*:}
  bash .agents/skills/tx-gas-benchmarking/scripts/run_tx_gas_benchmark.sh \
    --start-anvil --port 0 --snapshot-dir "$calibration_run/$label" \
    "script/$script_name.s.sol" --offline
done
```

Also profile the exact quintic native phase affected by the optimization. The builder currently treats the quintic anchor as a total-score reference; it does not consume that phase profile. Keep the phase result as independent diagnostic evidence.

Validate each receipt via `parse_tx_gas.py --mode native --artifact PATH`. Confirm receipt index 1 corresponds by hash to transaction index 1, since the builder uses positional indexing. Preserve any reordered derived copy separately.

## Schedule and timing inputs

Use compatible Rust-emitted counts. An arithmetic-only Solidity change normally leaves schedule dumps and Rust timings reusable. Verify their hashes, Rust revision/dirty state, and full schedule parameters; a filename alone cannot establish compatibility.

If counts need regeneration, set `SPARTAN_WHIR_EXPORT_DIR` to the companion checkout and follow `AGENTS.md`'s exporter commands in release mode. Preserve the 101-bit derivation guard and actual 100-bit target filtering. Schedule variants or proof-layout changes also need fixture/generated-code regeneration and parity tests. Do not switch `Constant` to `ConstantFromSecondRound` as a calibration repair.

Native prover timings require release builds with `RUSTFLAGS="-C target-cpu=native"`, `measurement_kind = "actual_whir_commit_prove"`, and `target_cpu_native = true`. Retain timings when their source and measurement conditions remain applicable.

## Build calibration and scores

Check the before-measurement manifest, then capture actual inputs. Add all fixture blobs, schedule/timing JSON, compiler snapshots, and transaction run-info files used by the run to this abbreviated example:

```sh
python3 .agents/skills/gas-calibration-maintenance/scripts/measurement_manifest.py check "$calibration_run/sources-before.json"
python3 .agents/skills/gas-calibration-maintenance/scripts/measurement_manifest.py capture \
  --out "$calibration_run/inputs.json" \
  --input "$calibration_run/microbench.log" --input "$calibration_run/phases.log" \
  --input "$calibration_run/quartic/run.json" --input "$calibration_run/quartic-lir11/run.json" \
  --input "$calibration_run/octic/run.json" --input "$calibration_run/quintic/run.json"
python3 build_quintic_calibration.py \
  --phase-log "$calibration_run/phases.log" --gas-log "$calibration_run/microbench.log" \
  --reference-schedule testdata/calibration_reference_schedules.json \
  --quintic-schedule testdata/quintic_schedule_microbench_pow27_30_full.json \
  --quartic-tx-artifact "$calibration_run/quartic/run.json" \
  --quartic-lir11-tx-artifact "$calibration_run/quartic-lir11/run.json" \
  --octic-tx-artifact "$calibration_run/octic/run.json" \
  --quintic-tx-artifact "$calibration_run/quintic/run.json" \
  --out "$calibration_run/calibration.json"
python3 check_quintic_calibration_freshness.py --calibration "$calibration_run/calibration.json"
python3 quintic_schedule_scorer.py \
  --schedule testdata/quintic_schedule_microbench_pow27_30_full.json \
  --prover-calibration-schedule testdata/quintic_schedule_microbench_pow24.json \
  --prover-calibration-schedule testdata/quintic_schedule_microbench_pow25.json \
  --prover-calibration-schedule testdata/quintic_schedule_microbench_pow26.json \
  --gas "$calibration_run/microbench.log" \
  --rust-timings testdata/quintic_prover_microbench.json \
  --pow-calibration testdata/quintic_pow_calibration.json \
  --calibration "$calibration_run/calibration.json" --require-calibration \
  --target-security-bits 100 --report-plot-label constant_pow28_ff4_lir4_rsv3 \
  --out-dir "$calibration_run/scores"
python3 .agents/skills/gas-calibration-maintenance/scripts/measurement_manifest.py check "$calibration_run/inputs.json"
```

Inspect `scores/schedule_scores.json`: `calibration.accepted`, bucket diagnostics, `quintic_verifier_score_calibration`, kernel warnings, ranking eligibility, and implemented/report labels. Preserve requested report options when refreshing an existing report. Recompute the anchor triple from this run.

Known boundaries: quartic `lir11` contributes total transaction gas because its phase harness does not compile cleanly under `via_ir`; the quintic reference supplies total-score scaling; quartic transcript attribution includes setup/parse work; folding unit-cost sums overestimate and remain diagnostic. Do not change thresholds or discard references solely to make a gate pass.

Before publishing, copy selected evidence to stable repository-relative locations and rebuild derived JSON with those paths. The builder reduces external paths to basenames, which alone lose provenance and can collide across receipt directories. Keep receipts within uniquely named reference directories. Replace only affected generated reports, check source freshness again, and update baseline/anchor values and stale-calibration statements together.
