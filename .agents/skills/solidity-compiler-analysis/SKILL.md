---
name: solidity-compiler-analysis
description: Analyze optimized Solidity IR and assembly to explain gas regressions, repeated computation, stack spills, and inlining effects. Use when evaluating compiler-sensitive verifier optimizations and their deployed bytecode cost.
---

# Solidity Compiler Analysis

Connect a measured hotspot to the code emitted for the exact verifier contract. Work from the Foundry project root. Use [forge-flamegraph-profiling](../forge-flamegraph-profiling/SKILL.md) for profiling and targeted IR build recovery, and [tx-gas-benchmarking](../tx-gas-benchmarking/SKILL.md) for preserved transaction comparisons.

## Establish comparable builds

Identify the source, contract, entrypoint, schedule, fixture, and measurement boundary. Save a baseline before editing, including dirty source changes; a Git revision alone does not identify a dirty build. Keep the compiler version, optimizer settings, EVM version, linked libraries, and Foundry profile fixed unless the experiment specifically concerns one of them.

Use the profiling skill's targeted build into fresh output and cache directories, with `--extra-output irOptimized`. Read metadata from that build rather than assuming `foundry.toml` captures every environment override. Missing cached IR requires a fresh targeted build; avoid `forge clean` and broad rebuilds that replace other evidence.

Extract IR and deployed runtime bytes from that artifact:

```sh
python3 .agents/skills/solidity-compiler-analysis/scripts/snapshot_artifact.py \
  "$profile_run/out/$target_contract.sol/$target_contract.json" \
  --source "$target_source" --contract "$target_contract" \
  --out-dir "$profile_run/snapshot"
```

The variables are set by the profiling skill's build example. If the source filename differs from the contract name, use the actual artifact path. The helper verifies the compilation target and refuses existing output directories, missing IR, unresolved library placeholders, and empty runtime bytecode. It saves `optimized.yul`, `runtime.hex`, `artifact.json`, and `summary.json` with compiler settings and source hashes. Retain the corresponding source files or patch separately. Libraries and immutable substitutions need deployment-level verification when comparing actual deployed code.

## Trace the hotspot

Map calldata regions, coefficient or row indices, memory writes, and the next consumer before editing. Follow the native contract's runtime object, entrypoint selector, and reachable calls. Function names and `@src` annotations help locate code; a missing helper name can mean inlining. Exclude creation code and unreachable helpers from execution attribution.

| Observation | Evidence to establish | Narrow experiment |
| --- | --- | --- |
| Repeated loads or scans | The same address/index is evaluated on the same executed path with unchanged inputs | Decode once or fuse adjacent consumers |
| Recomputed packed products | Expensive expressions occur at multiple use sites after optimization; establish loop and call counts | Shorten value lifetimes or consume one product before constructing the next |
| Possible stack spills | Stores/reloads preserve live scalar temporaries in compiler-reserved memory; distinguish arrays, ABI encoding, and intentional scratch buffers | Reduce simultaneously live values or split scopes |
| Inlining and specialization | Call sites duplicate bodies or constants enable simplification; compare runtime size and caller code | Keep a helper boundary only if it survives and reduces measured work |
| Disposable buffer | Every write and next read is known, including branches and early exits | Fuse producer/consumer or reuse storage whose lifetime ended |

Repeated source expressions may share a compiled value. A single source variable can also be rematerialized at several uses. Static `mul`, `mod`, `mload`, and `mstore` counts are clues: account for control flow, loop bounds, and call frequency before attributing runtime cost. A memory operation by itself does not identify a spill.

If IR is inconclusive, inspect optimized assembly and source maps for the same build. Check `forge inspect --help` and `forge build --help` for the installed version; request `evm.assembly` through `--extra-output` when supported. Preserve it alongside the IR. Keep compiler settings unchanged while obtaining the dump.

The [Solidity optimizer documentation](https://docs.solidity.org/en/latest/internals/optimizer.html) explains common-subexpression elimination, rematerialization, inlining, and stack allocation. It is a living reference; check the matching compiler release before attributing a specific transformation. Assembly marked `memory-safe` must satisfy Solidity's memory contract before using that annotation to enable optimization.

## Decide from gas and deployed size

After one narrow edit, run the exact canonical native gas test and measure runtime bytes immediately. Compare snapshot settings and targets before accepting the delta. Report `candidate - baseline` for gas and bytes. Measure the complete deployed runtime including metadata by decoding `deployedBytecode.object`; creation bytecode has a different purpose.

Follow `AGENTS.md`'s experimental [EIP-7954](https://eips.ethereum.org/EIPS/eip-7954) targets: at most 65,536 runtime bytes and 131,072 initcode bytes. Prioritize gas improvements within these limits and record both sizes. EIP-7954 is in Review as of 2026-09-05; local size allowances do not establish network activation.

For a promising result, confirm the affected phase, preserved transaction receipts, and required correctness suite. Reject gas regressions, unexplained deltas, and code exceeding the configured size targets. Record measurements, the relevant IR excerpt, and the keep/reject reason. Fewer algebraic multiplications alone are insufficient evidence: packing, rematerialization, memory traffic, and inlining can reverse the expected saving.
