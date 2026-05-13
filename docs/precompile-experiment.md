# Precompile-backed verifier experiment

Local-only A/B target for measuring generic KoalaBear ext5 / ext8 arithmetic precompiles against the baseline software verifier. This is **not** the production verifier path.

The experiment does not change WHIR protocol parameters, the verifier external ABI, the proof blob format, transcript ordering, Merkle tree layout, calldata encoding, or the baseline native verifier source. The precompile-backed variants live in parallel directories (`src/whir/k22_jb100_lir6_ff4_rsv1_precompile_phase1/`, `src/whir/k22_jb100_ext5_lir4_ff4_rsv3_pow28_precompile/`).

The custom node is an embedded Anvil launcher from the [Foundry fork](https://github.com/alxkzmn/foundry/tree/codex/ext8-precompile-runner), registering precompiles via `NodeConfig::with_precompile_factory(...)`.

## Operational gotchas

These are easy to rediscover the hard way. Read before running anything.

- **Stock `forge test` cannot execute the precompile-backed verifier path.** The custom precompiles only exist inside the embedded Anvil launcher.
- **`forge script` is not a reliable measurement driver** for precompile paths. Forge simulates the script body in its own local EVM before broadcasting, and that simulation does not know about the custom precompile addresses. Use the Python RPC scripts in `script/run_ext*_precompile_*_rpc.py` instead.
- **The custom node uses port `18547`** to avoid collision with a normal Anvil on `8545`.
- **The custom node sets `code_size_limit = 50,000` bytes** so over-EIP-170 measurement contracts deploy.
- **All RPC measurement scripts must use state-changing transactions** writing into a `lastResult` slot. Otherwise the compiler/EVM will elide output copying or arithmetic consumption and the gas number is meaningless.
- **There is intentionally no hand-written parallel Rust ext8/ext5 implementation.** The Rust precompiles call the same Plonky3 stack (`p3_koala_bear::KoalaBear`, `p3_field::extension::BinomialExtensionField`) that the prover/verifier uses; do not introduce a second arithmetic path.
- **Standalone vs in-harness no-op rows are not interchangeable.** The standalone no-op allocates and decodes fresh arrays; the select-harness no-op reuses the existing `fullPoint` calldata shape. Use the shape that matches what the integrated verifier would do when deciding gates.

## Input validation rules

- Scalar inputs are 32-byte `uint256`; the precompile rejects unless high 28 bytes are zero and the low `u32` value is `< 0x7f000001`.
- Batch inputs have no length prefix; `N` is derived from calldata length and malformed lengths are rejected.
- ext5 packed layout: five 32-bit limbs in the high 160 bits, zero low 96 bits. Non-zero low 96 bits are rejected.
- ext8 packed layout: eight 32-bit limbs filling the full 32-byte word (no low padding rule).
- All paths reject non-canonical limbs and non-canonical base scalars before arithmetic.
- `EXTFIELD_MAC` / `EXTFIELD_LIN_PROD` cap `N` at `1024`. `n = 0` returns the optional accumulator or extension one as appropriate.

## Gas calibration model

```text
assigned_base_gas(op) = ceil_50(8 * 25.86 * median_runtime_us(op))
```

- `25.86 gas / microsecond` is the EIP-1108-style fairness anchor.
- `8x` safety multiplier.
- Round up to the nearest 50 gas.
- The schedule metadata keeps `700` gas as an EIP-sanity floor; the local prototype charges the calibrated value with a 50-gas rounding floor instead.
- **Assigned base gas is not effective verifier gas.** Effective gas also covers Solidity-side input packing, memory writes, `STATICCALL`, returndata copy, and repacking. The no-op precompiles exist to measure that transport floor.

## EIP-compatible boundary conclusion

After the candidate sweep (`script/run_ext8_precompile_eip_candidate_rpc.py`), the only generic operations that beat the software loop including transport are `EXT8_MUL` and `EXT8_SQUARE`. Specifically:

- `EXT8_ADD`, `EXT8_SUB`, `EXT8_MUL_BASE`: too cheap in software; precompile does not beat local arithmetic once transport is included.
- Generic batch precompiles (`EXT8_SQUARE_BATCH`, `EXT8_MUL_BASE_BATCH`): not blanket replacements. The fixed-equality loop is the only place `EXT8_MUL_BATCH` integration paid off, because it has multiple independent multiplications per iteration and can reuse one scratch buffer.
- `EXTFIELD_MAC(n = 1)` is transport-bound; do not use it for singleton Horner-step multiplications.
- `EXTFIELD_LIN_PROD` validates and benchmarks cleanly but the transport floor is too high at the verifier's actual chain sizes (10, 14, 18). Not wired into the verifier.

Round 0 STIR base rows stay on software arithmetic because the first layer is a base-row fold, not a pure ext8/ext5 row fold.

Further precompile work should make `EXT8_MUL` / `EXT8_SQUARE` more EIP-ready (gas rationale, spec, cross-client benchmarks). WHIR-only fused kernels are a different design space (local accelerator), not an EIP-compatible candidate.

## Precompile interface tables

ext8 schedule (port-`0x08xx`):

| Address                              | Name                  | Status in verifier                |
| ------------------------------------ | --------------------- | --------------------------------- |
| `0x0801`                             | `EXT8_MUL`            | integrated                        |
| `0x0802`                             | `EXT8_SQUARE`         | integrated                        |
| `0x0803`                             | `EXT8_ADD`            | measured, rejected                |
| `0x0804`                             | `EXT8_SUB`            | measured, rejected                |
| `0x0805`                             | `EXT8_MUL_BASE`       | measured, rejected                |
| `0x0811`                             | `EXT8_MUL_BATCH`      | integrated for fixed equality     |
| `0x0812`                             | `EXT8_SQUARE_BATCH`   | measured, rejected                |
| `0x0813`                             | `EXT8_MUL_BASE_BATCH` | measured, rejected                |
| `0x0f01`                             | `EXTFIELD_MAC`        | integrated for extension-row dots |
| `0x0f02`                             | `EXTFIELD_LIN_PROD`   | measured, not integrated          |
| `0x08f1..0x08f4`, `0x0ff1`, `0x0ff2` | no-op controls        | transport calibration             |

ext5 schedule (port-`0x05xx`) mirrors ext8 with the same status decisions.

`EXTFIELD_MAC` input layout:

```text
header: 8 bytes big-endian {field_id u16, n u16, flags u32}
optional accumulator (if flags bit 0 set): 32 bytes
body: n pairs of (a, b) extension words
```

`EXTFIELD_LIN_PROD` modes:

- `flags = 0`: explicit `alpha_i, beta_i, x_i` extension words
- `flags = 1`: `beta_i, x_i` extension words; `alpha_i` is extension one
- `flags = 3`: `beta_i` is a 4-byte base-field scalar, `x_i` is an extension word; `alpha_i` is extension one (used by quintic select chains)

Implemented `field_id`: `0x0005` (KoalaBear ext5, `X^5 + X^2 - 1`), `0x0008` (KoalaBear ext8, `X^8 - 3`).

## Integration scope

The precompile-backed verifiers route only these paths through precompiles:

- Expanded equality products and equality-weight batches: `EXT8_MUL_BATCH` / `EXT5_MUL_BATCH`.
- Round 1+ STIR extension-row dot products: `EXTFIELD_MAC(n = 16)` with the equality-weight `b` operand templated once per round.
- Generic Horner-step extension multiplications, final-value folding, final closing multiplication: scalar `EXT8_MUL` / `EXT5_MUL`.
- Select accumulator products and constraint-select pairs: scalar precompile multiplications, evaluated two at a time to share `fullPoint` loads.

Everything else (ext add/sub, ext-by-base, base-row STIR, singleton Horner MAC calls) stays on existing software arithmetic.

## Files

| Path                                                                                       | Role                                                                 |
| ------------------------------------------------------------------------------------------ | -------------------------------------------------------------------- |
| `src/whir/k22_jb100_lir6_ff4_rsv1_precompile_phase1/`                                      | precompile-backed octic verifier variant                             |
| `src/whir/k22_jb100_ext5_lir4_ff4_rsv3_pow28_precompile/`                                  | precompile-backed quintic verifier variant                           |
| `src/field/KoalaBearExt8Precompile.sol`, `src/field/KoalaBearExt5Precompile.sol`           | Solidity wrappers for scalar, batch, MAC, and LIN_PROD calls         |
| `test/helpers/Ext8PrecompileHarness.sol`, `test/helpers/Ext5PrecompileHarness.sol`         | arithmetic, transport, row-layout, and candidate benchmark harnesses |
| `script/run_ext8_precompile_phase1_rpc.py`                                                 | ext8 arithmetic differential and equality/select A/B                 |
| `script/run_ext8_precompile_full_verifier_rpc.py`                                          | full octic baseline-vs-precompile A/B                                |
| `script/run_ext8_precompile_eip_candidate_rpc.py`                                          | standalone and batch EIP-compatible candidate sweep                  |
| `script/run_ext5_precompile_rpc.py`, `script/run_ext5_precompile_full_verifier_rpc.py`     | ext5 counterparts                                                    |
| `testdata/ext8_precompile_gas_schedule.json`, `testdata/ext5_precompile_gas_schedule.json` | locked scalar/batch gas schedules                                    |
| `testdata/extfield_mac_gas_schedule.json`, `testdata/extfield_lin_prod_gas_schedule.json`  | locked generic-primitive gas schedules                               |
| `testdata/extfield_mac_*_vectors.json`, `testdata/extfield_lin_prod_*_vectors.json`        | deterministic differential vectors                                   |

Foundry-fork sources for the precompile runners live under [alxkzmn/foundry](https://github.com/alxkzmn/foundry/tree/codex/ext8-precompile-runner):

- `crates/ext8-precompile-runner/`, `crates/ext5-precompile-runner/`
- `src/precompiles.rs` — dispatch, validation, arithmetic
- `src/gas_model.rs` — native runtime calibration, locked schedule generation
- `src/vectors.rs` — deterministic differential vector generation

## Commands

The command catalog (calibration binaries, vector exporters, runner launch, RPC scripts) lives in [../AGENTS.md](../AGENTS.md) under "Gas Measurement Commands".
