---
name: forge-flamegraph-profiling
description: Profile Solidity gas with Foundry flamegraphs and harness tests.
---

# Forge Flamegraph Profiling

## Overview

Use this skill to profile **execution gas inside the EVM** with Foundry in a way that is fast, reproducible, and useful for optimization work. This is not total transaction gas — use the tx-gas benchmarking skill for that.

Start with the `gasleft()` harness tests to identify the expensive phase, then generate a focused flamegraph for that phase and parse the SVG titles programmatically.

## Workflow

1. Run the canonical gas number for the path you are profiling.

For the typed verifier path:

```bash
forge test --match-test testGasWhirVerifyFixed -vv
```

If the branch contains multiple suites with that test name, qualify it further with `--match-contract` or `--match-path`.

For the native blob verifier path:

```bash
forge test --match-test testGasWhirVerifyBlobNativeFixed -vv
```

2. Run the harness breakdown before generating a flamegraph.

```bash
forge test --match-test testProfileFullBreakdown -vv
forge test --match-test testProfileStirBreakdown -vv
forge test --match-test testProfileStirMicro -vv
```

3. Choose the visualization mode.

- Prefer `--flamegraph` first. It is aggregated by function and answers "where does total gas go?"
- Use `--flamechart` only after the hotspot is known and you need call ordering or sequencing.
- Foundry can crash on deep call trees when generating either artifact. Treat that as a Foundry trace-decoding bug, not as an OOM signal. If a test crashes, switch to a smaller or more focused test.

4. Generate the artifact from the Foundry project directory.

For this repo, run from `sol-spartan-whir/`. Prefer focused harness tests or synthetic tests over a full-path verifier test, because fixture loading adds noise.

Example:

```bash
forge test --match-test testFlameFinalStir --flamegraph
```

`--flamegraph` requires exactly one matching test. If the filter matches more than one suite, add `--match-contract` or `--match-path`.

5. Read the SVG programmatically.

- Do not use `view_image` on SVG flamegraphs.
- Foundry writes useful `<title>` tags into both flamegraphs and flamecharts.
- Use the script bundled with this skill.

To parse every `cache/flamegraph_*.svg` artifact:

```bash
python3 .agents/skills/forge-flamegraph-profiling/scripts/parse_flamegraphs.py
```

To parse a specific SVG:

```bash
python3 .agents/skills/forge-flamegraph-profiling/scripts/parse_flamegraphs.py \
  cache/flamegraph_WhirGasProfileTest_testProfileStirBreakdown.svg
```

Use `--limit N` to change the number of rows printed per SVG.

6. Interpret the results correctly.

- The `gasleft()` harness is the canonical phase-level breakdown.
- The flamegraph is for finding hidden internal costs inside that phase.
- The same function can appear multiple times in different call stacks in the SVG output. Treat the raw title list as a hotspot map, not as a de-duplicated accounting table.
- Compare changes only on the same verifier path and the same fixture family.

## Spartan-WHIR Profiling Surface

The main profiling surface lives in the `test/WhirGasProfile*.t.sol` harness family.

Use these tests as the standard entrypoints:

- `testGasWhirVerifyFixed`: single canonical gas number
- `testProfileFullBreakdown`: setup, sumchecks, STIR, constraints, final check
- `testProfileStirBreakdown`: per-round STIR internals
- `testProfileStirMicro`: micro-benchmarks for leaf hashing, node compression, `KoalaBear.pow`, and query sampling

Prefer focused flamegraphs for one phase at a time. Tests that call `_loadSuccessFixture()` include measurable harness noise.

## Validation Order

Use this order when profiling an optimization candidate:

1. Run `forge test`.
2. Measure the canonical gas number.
3. Measure the harness breakdown.
4. Flamegraph the hottest phase.
5. Re-measure after the code change on the same path.

Do not hardcode gas numbers into the skill. Always measure the current branch.
