---
name: tx-gas-benchmarking
description: Measure verifier transaction gas from Anvil broadcast artifacts.
---

# Tx Gas Benchmarking

## Overview

Use this skill to measure **total user-paid transaction gas** for the Solidity verifier paths in `sol-spartan-whir`. This includes intrinsic gas, calldata gas, byte counts, and execution remainder. It is not an execution-only or `gasleft()` profiling workflow — use the flamegraph profiling skill for that.

## Workflow

1. Run from `sol-spartan-whir/`.
2. Start Anvil in a separate terminal. Run this command in async mode so it stays running in the background:

```bash
anvil --silent --code-size-limit 50000
```

The `--code-size-limit` flag is required because the native verifier exceeds the default EIP-170 contract size limit (24576 bytes). Without it, the deployment transaction will fail.

3. Run the benchmark script for the desired mode or explicit script path, then parse the broadcast artifact with the parser bundled in this skill.

Use the bundled helper:

```bash
.agents/skills/tx-gas-benchmarking/scripts/run_tx_gas_benchmark.sh native
```

You can also pass an explicit benchmark script path:

```bash
.agents/skills/tx-gas-benchmarking/scripts/run_tx_gas_benchmark.sh \
  script/WhirBlobNativeTxBenchmark_lir6_ff5_rsv1.s.sol
```

Supported mode aliases:

- `native`: production path, `EOA -> WhirBlobVerifierNative4.verify(...)`
- `direct`: typed verifier, `EOA -> WhirVerifier4.verify(...)`
- `blob`: blob decode-and-delegate verifier
- `wrapper`: typed wrapper path

4. Stop Anvil when finished.

```bash
pkill -f "anvil"
```

If other Anvil instances might be running, do not use `pkill`. Stop the specific PID you started instead.

## Script Discovery

The helper accepts either:

- a mode alias: `native`, `direct`, `blob`, `wrapper`
- an explicit `script/*.s.sol` path

When given a mode alias, it searches `script/` for the matching benchmark family. If more than one script matches on the current branch, it fails and asks for an explicit path instead of guessing.

Wrapper benchmarks still add `--tc MeasureTxGas` automatically.

It then calls the bundled parser:

```bash
python3 .agents/skills/tx-gas-benchmarking/scripts/parse_tx_gas.py <mode-or-script-path>
```

## What The Bundled Parser Gives You

`scripts/parse_tx_gas.py` reads the Anvil broadcast `run-latest.json` artifacts and prints:

- total tx gas
- intrinsic gas
- calldata bytes
- zero bytes
- nonzero bytes
- calldata gas
- execution remainder after subtracting intrinsic plus calldata

Use it when you need user-paid transaction cost, not just execution inside the Foundry harness.

The parser accepts either a mode alias or a benchmark script path. It discovers the matching `broadcast/*/31337/run-latest.json` artifact by benchmark family and keeps the receipt-position assumptions in one internal mode table.

## Gotchas

- `--private-key` is required. Without it, Foundry can produce empty receipts and the parser will report a failed broadcast.
- Anvil must be started with `--code-size-limit 50000` (or similar). The native verifier exceeds the default 24576-byte EIP-170 limit, and Anvil will reject the deployment without this flag.
- The helper passes `--code-size-limit 50000` to `forge script` as well, so it does not prompt interactively about the oversized contract.
- `blob` and `wrapper` may not have checked-in `run-latest.json` artifacts on disk. If the parser prints `Not found: ...`, rerun the corresponding benchmark script first.
- If Foundry warns about artifacts built from source files that no longer exist, run `forge clean` before benchmarking. Stale artifacts can make mode-alias runs hit an old script family instead of the current one.
- The parser discovers the `sol-spartan-whir` root by walking upward until it finds `foundry.toml` and `broadcast/`.
- If the agent is running inside a sandbox and Anvil or `forge script` fails during tx simulation or broadcast in a way that looks environment-related, request running that command outside the sandbox and rerun it there.
- Invoke the helper directly with its shebang or with `bash`. Do not source it from `zsh`; it uses Bash features such as `mapfile`.
- Keep tx-gas comparisons on the same verifier family and fixture family.

## Validation Order

1. Ensure Anvil is running.
2. Run the benchmark for the desired mode.
3. Parse the result with the bundled parser.
4. Record total tx gas and execution remainder separately.
5. Compare against the same mode on the previous revision.
