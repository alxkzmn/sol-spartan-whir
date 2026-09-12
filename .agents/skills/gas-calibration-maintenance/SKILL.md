---
name: gas-calibration-maintenance
description: Refresh verifier gas calibration and affected schedule scores after Solidity or cost-model changes. Preserve measurement provenance, verify source fingerprints and receipt inputs, and regenerate reports with the repository's calibration gates.
---

# Gas Calibration Maintenance

Maintain the chain from source and build settings through measured inputs, calibration JSON, and generated schedule scores. Run from the Foundry project root. Use [tx-gas-benchmarking](../tx-gas-benchmarking/SKILL.md) for validated receipt snapshots, [forge-flamegraph-profiling](../forge-flamegraph-profiling/SKILL.md) for phase measurements, and [solidity-compiler-analysis](../solidity-compiler-analysis/SKILL.md) for compiler artifacts.

When performing a refresh, finish measurements and generated outputs within the requested scope; report any remaining stale inputs explicitly.

## Determine what changed

Start with `python3 check_quintic_calibration_freshness.py --calibration testdata/quintic_calibration.json`. Inspect `CALIBRATION_SOURCE_PATTERNS` and the builder/scorer before deciding which measurements to reuse.

| Change | Refresh or establish |
| --- | --- |
| Schedule-specific verifier arithmetic | Exact native transaction and affected phase measurements; microbenchmarks if their implementation changed |
| Shared field, transcript, or Merkle code | Every affected reference transaction, phase log, and unit-cost measurement |
| Compiler, optimizer, EVM target, or harness | Every affected gas measurement, including references |
| Scorer or calibration builder only | Rebuild derived outputs from inputs whose source/build provenance remains valid |
| Rust schedule, security/config derivation, proof encoding | Compatible schedule dumps and fixtures, every affected verifier consumer and measurement |
| Rust prover implementation or timing environment | Affected prover/PoW timing calibration under comparable conditions |

The source fingerprint list is an explicit coverage set. Inspect dependencies for omissions; `foundry.toml`, fixtures, logs, schedule/timing JSON, tool versions, and environment overrides also affect validity. Add a missing source dependency to fingerprint coverage when warranted, then regenerate through the builder. Never edit recorded hashes just to satisfy the checker.

## Preserve measurement provenance

Create a fresh run directory; preserve existing calibration and score outputs before replacement. Save exact commands, Git revision and dirty patch, effective `forge config --json`, compiler metadata, Forge/Anvil versions, fork configuration, fixture hashes, and receipt snapshots. Keep local paths and signer material out of published reports.

The manifest helper hashes the scorer's source coverage plus `foundry.toml` and explicitly supplied inputs. Capture it before measuring, check it immediately afterward, then capture a second manifest including the new logs and receipts. It refuses to overwrite a manifest and fails on changed/missing files or changed source coverage. File integrity alone does not prove that an input was measured from those sources; the command log and preserved artifacts establish that association.

```sh
calibration_run=$(mktemp -d "${TMPDIR:-/tmp}/whir-calibration.XXXXXX")
forge config --json > "$calibration_run/forge-config.json"
python3 .agents/skills/gas-calibration-maintenance/scripts/measurement_manifest.py capture \
  --out "$calibration_run/sources-before.json" \
  --input "$calibration_run/forge-config.json"
# Run affected measurements using the recipe below, with fixed source and build settings.
python3 .agents/skills/gas-calibration-maintenance/scripts/measurement_manifest.py check \
  "$calibration_run/sources-before.json"
```

Record fixture/schedule inputs with additional `--input` arguments before measurement. If a source changes during the run, identify and repeat affected measurements. Reuse an older measurement only with source/build/fixture evidence supporting that choice. Unknown provenance requires remeasurement.

## Rebuild and verify

Follow [quintic-refresh.md](references/quintic-refresh.md) for script arguments, reference transactions, and score generation. Work in the fresh directory first and pass preserved receipt paths explicitly to the builder. Its default `run-latest.json` paths are mutable.

Validate receipts with the transaction skill before building. The current builder indexes the verification receipt at position 1. Confirm that receipt's hash matches the transaction at position 1, or create a separate derived copy reordered by hash after validation and retain the original. Check built gas/calldata values against validated parser output.

The builder records current source fingerprints even when supplied old logs. A passing freshness check therefore requires separate input provenance checks. Run the checker on the new calibration and the scorer with `--require-calibration`; inspect `calibration.accepted`, `bucket_validation_accepted`, and diagnostic failures. The current gate accepts ordinal calibration; bucket ratios are reported separately.

Record each quintic anchor's label, raw verifier score, measured total transaction gas, and `measured/raw` scale. With multiple anchors, the current scorer averages their scales. Confirm generated scales and reference rows match the inputs. Scaled scores estimate other schedules; native receipts establish actual gas.

Regenerate all affected score JSON and SVG reports from one consistent input set. Check freshness after final source edits and before publishing. Promote reviewed calibration, evidence, and reports together using repository-relative provenance paths. Update anchor values and stale-status statements only after successful refresh. Preserve unrelated artifacts and leave Git commits to the user.

Finish with the source fingerprint, measurement inputs, anchor/scale values, gate and diagnostic results, regenerated files, and remaining coverage or provenance limitations. A score refresh alone does not require new Rust timings when the prover and measurement conditions are unchanged.
