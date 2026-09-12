---
name: finite-field-arithmetic-optimization
description: Optimize measured finite-field arithmetic bottlenecks in Solidity verifiers using relevant algorithms and papers, explicit coefficient and overflow bounds, independent arithmetic references, and complete verifier validation.
---

# Finite-Field Arithmetic Optimization

Start from an arithmetic hotspot measured on the exact verifier path. Use [forge-flamegraph-profiling](../forge-flamegraph-profiling/SKILL.md) to establish its cost and [solidity-compiler-analysis](../solidity-compiler-analysis/SKILL.md) to check whether the saving survives compilation. A research or derivation request alone does not authorize changing protocol parameters or proof encoding.

## Specify the arithmetic contract

Trace the caller and next consumer. Record the prime, extension degree, defining polynomial, coefficient order, packed representation, allowed input ranges, output canonicality, and rejection behavior. Identify general multiplication, squaring, base-scalar multiplication, structured linear terms, inversion, or repeated accumulation.

Read the actual degree-specific implementation and the pinned Rust dependency. This repository's quintic arithmetic uses `p = 0x7f000001` and `F_p[X]/(X^5 + X^2 - 1)`. `KoalaBearExt5.pack` places coefficients at bit offsets 224, 192, 160, 128, and 96, with the low 96 bits zero. These transport lanes differ from temporary integer-convolution lanes. Other extension degrees require their own polynomial and packing contract.

## Match research to the operation

Read [algorithm-selection.md](references/algorithm-selection.md) when selecting a technique. Search primary papers and official implementation sources after identifying the hotspot. For each candidate, name the operation it removes, cite the relevant algorithm or section, map its hypotheses to this field and word size, and account for EVM packing, extraction, reductions, and memory costs. Distinguish the paper's result from the proposed adaptation.

Use the smallest specialization justified by actual caller inputs. A long batch may amortize a representation conversion; a single multiply often cannot. Do not assume a CPU algorithm or asymptotic improvement saves gas on five coefficients.

## Derive bounds before an unchecked rewrite

Write the polynomial identity independently of its Solidity implementation. Derive integer intervals for every intermediate, including evaluation/interpolation, subtraction biases, accumulated products, and the final pack.

- For convolution coefficient `c_k`, count contributing terms and bound their sum using actual input ranges. For nonnegative canonical inputs, `c_k <= n_k*(p-1)^2`.
- For radix `2^w`, prove every retained lane is below `2^w`, including incoming carry from lower lanes. A lane straddling bit 256 is only partially observable. State exactly which coefficients EVM multiplication modulo `2^256` discards and how remaining coefficients are recovered.
- For signed algebra implemented with unsigned operations, choose a multiple of `p` large enough to prevent every intermediate underflow. Bound the biased value after later additions and multiplications below `2^256`. Wrapping modulo `2^256` before reduction modulo this prime generally changes the answer.
- Derive bounds from evaluation order, not just the simplified final identity. Removing a reduction changes the range of every later use.
- Prove output coefficients are canonical and unused packed bits remain zero. For inversion or batch inversion, preserve zero handling and denominator preconditions.

Use Python integers or a symbolic system to verify bounds and identities independently, retaining a written argument covering the full input domain. Random testing supplements that argument. Isolate and explain deliberate EVM truncation; `unchecked` and `memory-safe` each need their own justification.

## Validate and measure

Use an independent, straightforward oracle: unpacked schoolbook convolution followed by polynomial reduction, or the pinned Rust field implementation. `KoalaBearExt5.mulReference` is available here; inspect its transitive helpers before relying on independence from the edited code. If the candidate changes those helpers, use a separate oracle. Avoid expected values derived through the optimized kernel.

Test zero, one, `p-1`, maximum simultaneous coefficients, every basis-product pair, carry and bias boundaries, scalar extremes, and relevant zero denominators. Add differential fuzzing over canonical elements and complete repeated chains; one multiply does not validate the caller's range invariants. Test malformed packed inputs at the public boundary where rejection is required. Assert canonical outputs in differential tests.

For the quintic select kernel, `test/QuinticSelectKronecker.t.sol` demonstrates basis, maximum-coefficient, fuzz, and complete-chain tests. Extend tests for the changed surface rather than copying a test that shares its assumptions. After focused arithmetic checks, measure the canonical native gas test and runtime size. Reject regressions early. For a promising candidate, confirm the affected phase, compare preserved transaction receipts, and run the complete `forge test --offline` suite, including native/typed success fixtures, malformed proofs, and transcript parity.

Keep transcript ordering, canonical encoding, digest layout, Merkle hashing, and domain separation unchanged for a verifier-only arithmetic rewrite. If a proposal changes one of those surfaces, identify every affected Solidity/Rust consumer and required fixture/generated-code regeneration before expanding the implementation.

Record the identity and bounds, oracle independence, test results, gas and runtime deltas, and remaining limitations. Follow project bytecode acceptance rules. A retained verifier change requires [gas-calibration-maintenance](../gas-calibration-maintenance/SKILL.md) before schedule scores can describe that implementation; if refresh is outside the current request, report calibration as stale.
