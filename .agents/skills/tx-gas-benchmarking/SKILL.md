---
name: tx-gas-benchmarking
description: Measure verifier transaction gas with Anvil, preserve broadcast receipts, and compare baseline and candidate runs.
---

# Tx Gas Benchmarking

Measure verifier transaction gas from completed Anvil receipts. Keep total transaction gas, calldata cost, and execution remainder separate. Use `forge-flamegraph-profiling` for internal execution attribution.

## Run with a managed Anvil child

Run from `sol-spartan-whir/`. Put helper options before the target script and additional Forge options after it:

```sh
gas_run=$(mktemp -d "${TMPDIR:-/tmp}/whir-gas.XXXXXX")
bash .agents/skills/tx-gas-benchmarking/scripts/run_tx_gas_benchmark.sh \
  --start-anvil --port 18549 --snapshot-dir "$gas_run/baseline" \
  script/WhirBlobNativeTxBenchmark_k22_jb100_ext5_lir4_ff4_rsv3_pow28.s.sol --offline
```

`--start-anvil` binds a local child to the selected port with `--code-size-limit 65536`, checks readiness, and keeps it running through receipt parsing. The helper stops and reaps only that child on success, failure, or a handled interrupt. It refuses an occupied port; use another port or `--port 0` to choose a free one. Leave `RPC_URL` unset in managed mode.

The contract size allowance must be present on Anvil as well as Forge. The local allowance follows the 64 KiB runtime target in EIP-7954. Its 128 KiB initcode target and network activation are separate; record runtime and initcode sizes with the measurements.

## Use an existing server

Omit `--start-anvil` and set `RPC_URL` to the intended endpoint:

```sh
RPC_URL=http://127.0.0.1:18549 bash .agents/skills/tx-gas-benchmarking/scripts/run_tx_gas_benchmark.sh \
  --snapshot-dir "$gas_run/baseline" \
  script/WhirBlobNativeTxBenchmark_k22_jb100_ext5_lir4_ff4_rsv3_pow28.s.sol --offline
```

Without `RPC_URL`, existing-server mode uses `http://127.0.0.1:8545`. The helper leaves that server running. If you start Anvil yourself through an async terminal tool, retain the exact session handle or child PID, keep it alive until parsing finishes, and stop only that instance afterward. Do not use `pkill`, `killall`, or a process-name search to stop Anvil.

The shell entrypoint delegates to the bundled Python 3 runner, avoiding Bash-version-specific discovery commands. Explicit script paths are preferred when several schedules exist. The aliases `native`, `direct`, `blob`, and `wrapper` require exactly one matching script. Wrapper mode retains `--tc MeasureTxGas`. `PRIVATE_KEY` overrides the standard local Anvil development key; never copy signer/cache files into evidence directories.

## Preserve and compare receipts

Every invocation creates a fresh evidence directory. `--snapshot-dir` selects its location and refuses an existing directory; otherwise the helper prints a unique temporary directory. It preserves:

- `previous-run.json`, if the matching broadcast artifact existed before Forge ran.
- `run.json`, only when Forge writes a fresh artifact for this invocation.
- `forge.log`, `forge-version.txt`, and `run-info.json` with the target, chain ID, and run outcome.
- `metrics.json` after receipt validation; `anvil.log` when the helper started the node.

Only copy broadcast artifacts, not Foundry's adjacent cache files containing signer data. Preserve the baseline before editing the verifier. After the change, repeat the same command with `--snapshot-dir "$gas_run/candidate"`, keeping the script, fixture, compiler, optimizer settings, and Anvil fork configuration the same.

```sh
python3 .agents/skills/tx-gas-benchmarking/scripts/parse_tx_gas.py --mode native \
  --compare "$gas_run/baseline/run.json" "$gas_run/candidate/run.json"
```

The comparison requires matching chain ID, contract name, function, and exact calldata SHA-256. If those differ, inspect the inputs before presenting an optimization delta. The preserved source/build versions must also correspond to the intended comparison; identical calldata alone does not establish that.

Parse one saved artifact directly:

```sh
python3 .agents/skills/tx-gas-benchmarking/scripts/parse_tx_gas.py --mode native --artifact "$gas_run/baseline/run.json"
```

Positional script paths or unambiguous aliases remain supported for the default `broadcast/*/31337/run-latest.json` layout. Use `--artifact` with a different chain or a preserved copy. The runner reads the actual RPC chain ID when locating its output.

## Interpret results and recover failures

The parser selects the known verification transaction in the benchmark family and matches receipts by transaction hash. Missing, pending, reverted, or incomplete receipts produce a nonzero exit. The accounting model subtracts a 21,000 transaction base plus 4/16 gas per zero/nonzero calldata byte to report the execution remainder. Keep fork and transaction assumptions consistent between measurements.

The helper checks whether `run-latest.json` was rewritten. A stale successful file is not evidence that the current invocation succeeded. On failure, inspect the new evidence directory, Forge's log, and any fresh receipts before retrying. A retry needs a new snapshot directory so the failed attempt remains reviewable. Avoid concurrent benchmarks for the same script and chain because Foundry shares their `run-latest.json` filename.

If a sandbox blocks the listening socket or Forge aborts in the tool context, retry the same local Anvil and Forge flow through an authorized direct shell or an approved outside-sandbox execution. Preserve the original parameters and receipt boundaries. A successful direct-shell run is the measurement result; describe the agent failure as a tool-context issue. Do not infer a machine-wide Foundry failure from a sandboxed run or repeatedly retry an unexplained failure.

For missing IR or stale artifact diagnostics, first qualify the exact script/contract and use the profiling skill's targeted build recovery. Preserve receipt snapshots before any cache cleanup. Finish with the measured gas delta, deployed-bytecode boundary, and any unresolved validation issue.
