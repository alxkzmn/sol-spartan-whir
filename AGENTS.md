# sol-spartan-whir -- Agent Instructions

This is the Foundry project for the on-chain Solidity verifier of Spartan-WHIR proofs over the KoalaBear field. It contains the standalone WHIR verifier (typed ABI path, blob-native path, and blob decode-and-delegate wrapper), field and extension-field arithmetic libraries, Keccak-based Fiat-Shamir challenger, and Merkle multiproof verification — all targeting EVM execution. For workspace-level rules, layout, and cross-crate constraints, see the root `../AGENTS.md`.

## Skills

Detailed workflow guides live under `.agents/skills/*/SKILL.md`:

- `.agents/skills/forge-flamegraph-profiling/SKILL.md` — execution gas profiling with Foundry flamegraphs and `gasleft()` harness tests
- `.agents/skills/tx-gas-benchmarking/SKILL.md` — total transaction gas measurement via Anvil broadcast runs

## Gas Profiling with Forge Flamegraphs

The detailed profiling workflow lives in the flamegraph profiling skill above.

Use that skill for:

- the `--flamegraph` vs `--flamechart` choice
- SVG parsing
- the `WhirGasProfile*.t.sol` harness family
- the current profiling command sequence

Foundry flamegraphs can crash on deep call trees because of trace-decoding issues. If that happens, switch to a smaller, more focused test instead of treating it as an out-of-memory condition.

For total transaction gas measurement, use the tx-gas benchmarking skill.

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
10. Check deployed runtime bytecode, not creation bytecode, against warning bands.
    To get deployed bytes from `deployedBytecode`, strip the `0x` prefix and divide the remaining hex length by `2`.
    Use `deployedBytecodeSize` instead if the toolchain exposes it.

- below `22,000` bytes: normal
- `22,000` to `23,000`: warning
- `23,000` to `24,000`: require explicit justification
- `24,000` and above: reject unless it is a temporary experiment

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
2. `forge inspect src/whir/WhirBlobVerifierNative4.sol:WhirBlobVerifierNative4 deployedBytecode`
   - strip the `0x` prefix and divide the remaining hex length by `2` before comparing against the warning bands
3. native-path profiling if available; otherwise use typed/shared profiling only as directional evidence
4. targeted profiling tests if the change should move a known bucket
5. `forge test`

Reject a candidate when any of the following is true:

- gas regression
- marginal gas win with large bytecode growth
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

- Low-level ext4 mul rewrite: expected -50k, actual **+208k** (compiler was already optimizing the high-level version better)
- Batch sumcheck validation: expected -5k, actual **+4.7k** (extra memory allocation outweighed saved checks)
