---
name: forge-flamegraph-profiling
description: Profile Solidity execution gas with Foundry harnesses, headless flamegraph parsing, and targeted optimized IR builds.
---

# Forge Flamegraph Profiling

Measure the exact verifier path and fixture family being optimized. Use the `gasleft()` harness to locate the expensive phase, the flamegraph to attribute calls inside it, and optimized IR to check which operations survive compilation. Use `tx-gas-benchmarking` for transaction receipts and calldata accounting.

## Profile the target

Run from the Foundry project directory. Qualify tests with `--match-path` or `--match-contract` when several schedules expose the same test name.

```sh
forge test --match-path test/WhirBlobVerifierNative5_k22_jb100_ext5_lir4_ff4_rsv3_pow28.t.sol --match-test testGasWhirVerifyBlobNativeFixed -vv --offline
forge test --match-path test/WhirGasProfile5_k22_jb100_ext5_lir4_ff4_rsv3_pow28.t.sol --match-test testProfileNativeBlobBreakdown5Pow28Rsv3 -vv --offline
```

For other schedules, locate the corresponding `test/WhirGasProfile*.t.sol` harness. Typed paths commonly use `testGasWhirVerifyFixed`, `testProfileFullBreakdown`, `testProfileStirBreakdown`, and `testProfileStirMicro`. Treat a different verifier path's phase measurements as directional evidence.

Prefer `--flamegraph` for aggregated call costs. Use `--flamechart` when call ordering matters. Exactly one test must match:

```sh
forge test --match-path test/WhirBlobVerifierNative5_k22_jb100_ext5_lir4_ff4_rsv3_pow28.t.sol --match-test testGasWhirVerifyBlobNativeFixed --flamegraph --offline
```

Foundry can fail while decoding deep traces. Inspect the error, and use a focused phase test when it identifies trace decoding as the failure. Fixture loading contributes to test gas; use the verifier's call frame for execution attribution.

## Read SVGs without opening a browser

Read the exact SVG path reported by the current run:

```sh
python3 .agents/skills/forge-flamegraph-profiling/scripts/parse_flamegraphs.py cache/flamegraph_WhirBlobVerifierNative5K22Jb100Ext5Pow28Rsv3Test_testGasWhirVerifyBlobNativeFixed.svg --limit 20
```

The parser reads XML titles, decodes escaped symbols, and exits nonzero for missing, malformed, or empty gas artifacts. An explicit SVG can live outside `cache/`; the parser only needs the project's `foundry.toml`. With no paths, it scans `cache/flamegraph_*.svg`.

Foundry may report a desktop `open` failure after successfully saving the SVG. Accept that artifact only when all three checks hold: the selected test passed, the log reports the saved SVG and its modification time confirms this run produced it, and the parser returns gas entries. Preserve the log and describe the viewer failure separately. Compilation failures, test failures, and trace failures require their own resolution; do not suppress all command errors.

Copy each accepted SVG and its log to a separate baseline or candidate directory before another run overwrites the cache filename. Do not use an image viewer to extract SVG gas data.

Gas in a parent frame includes its children. Repeated function names may belong to different stacks; the title list is a hotspot map, not a table whose rows can be summed. Treat `gasleft()` phase measurements, flamegraph frame costs, and total Foundry test gas as distinct boundaries.

## Inspect optimized IR without clearing project artifacts

For a known hotspot, inspect `irOptimized` or `assemblyOptimized` for the exact native contract. `forge inspect` can report that IR is missing from a cached artifact. Recover with a targeted build into fresh output and cache directories. This also preserves the original build artifacts for comparison.

```sh
profile_run=$(mktemp -d "${TMPDIR:-/tmp}/whir-ir.XXXXXX")
target_source=src/whir/k22_jb100_ext5_lir4_ff4_rsv3_pow28/WhirBlobVerifierNative5_k22_jb100_ext5_lir4_ff4_rsv3_pow28.sol
target_contract=WhirBlobVerifierNative5_k22_jb100_ext5_lir4_ff4_rsv3_pow28
forge build "$target_source" --extra-output irOptimized \
  --out "$profile_run/out" --cache-path "$profile_run/cache" --offline
python3 - "$profile_run" "$target_source" "$target_contract" <<'PY'
import json
from pathlib import Path
import sys

run, source, contract = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
artifact = run / "out" / source.name / f"{contract}.json"
data = json.loads(artifact.read_text())
ir = data.get("irOptimized")
if not ir:
    raise SystemExit(f"Optimized IR missing: {artifact}")
(run / f"{contract}.ir").write_text(ir)
runtime = data["deployedBytecode"]["object"].removeprefix("0x")
if len(runtime) % 2:
    raise SystemExit("Invalid deployed bytecode hex length")
print(f"Runtime bytes: {len(runtime) // 2}")
print(f"IR and build artifacts: {run}")
PY
```

Keep compiler version, `via_ir`, optimizer runs, and EVM target unchanged for a comparison. Use a fresh directory for each source version; retain its IR, deployed artifact, and measurement logs. Prefer this recovery to `forge clean`, which discards other builds and cached evidence.

Look for repeated scans, repeated packed expressions, memory spills, and disposable buffers. A mathematically cheaper expression can be recomputed several times by the optimizer. Static IR operation counts explain code shape; the same-fixture gas measurement establishes the runtime result.

## Validate an optimization

Measure the canonical target first, make a narrow change, then check gas and deployed runtime bytes immediately. Follow the project's size and acceptance rules. For a promising candidate, remeasure the affected phase, inspect the resulting IR, and run the required correctness suite. Preserve baseline and candidate evidence before updating documentation. Always measure the current source; do not bake gas baselines into this skill.
