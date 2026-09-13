# sol-spartan-whir

Solidity verifiers for standalone WHIR polynomial openings over KoalaBear and BabyBear, plus a terminal LeanVM verifier for a complete Spartan-WHIR proof verified recursively inside the guest. The standalone WHIR contracts verify the PCS opening only; the LeanVM terminal verifies the recursive proof that covers the full Spartan-WHIR statement.

The Rust [`spartan-whir`](https://github.com/ethereum/spartan-whir) implementation is the protocol source of truth. [`spartan-whir-export`](https://github.com/alxkzmn/spartan-whir-export) generates Solidity-compatible standalone-WHIR fixtures.

## Build and test

```sh
forge build
forge test --offline --isolate --threads 1
```

Runtime fixtures are checked in under [`testdata/`](testdata/), so the test suite does not require the Rust exporter. Regenerate the default KoalaBear fixtures with:

```sh
cargo run --release \
  --manifest-path "$SPARTAN_WHIR_EXPORT_DIR/Cargo.toml" \
  --bin export-fixtures -- testdata
```

See [AGENTS.md](AGENTS.md) for schedule-specific export, gas measurement, compiler analysis, and precompile-runner commands.

## Verifiers

| Target | Contract | Public entrypoint |
| --- | --- | --- |
| KoalaBear quintic, `k22_jb100_ext5_lir4_ff4_rsv3_pow28` | [`WhirBlobVerifierNative5_k22_jb100_ext5_lir4_ff4_rsv3_pow28`](src/whir/k22_jb100_ext5_lir4_ff4_rsv3_pow28/WhirBlobVerifierNative5_k22_jb100_ext5_lir4_ff4_rsv3_pow28.sol) | `verify(bytes32,bytes)` |
| BabyBear quintic, `k22_jb100_ext5_lir4_ff4_rsv3_pow28` | [`BabyBearWhirBlobVerifierNative5_k22_jb100_ext5_lir4_ff4_rsv3_pow28`](src/whir/babybear_k22_jb100_ext5_lir4_ff4_rsv3_pow28/BabyBearWhirBlobVerifierNative5_k22_jb100_ext5_lir4_ff4_rsv3_pow28.sol) | `verify(bytes32,bytes)` |
| KoalaBear octic, `k22_jb100_lir6_ff4_rsv1` | [`WhirBlobVerifierNative8_k22_jb100_lir6_ff4_rsv1`](src/whir/k22_jb100_lir6_ff4_rsv1/WhirBlobVerifierNative8_k22_jb100_lir6_ff4_rsv1.sol) | `verify(bytes32,bytes)` |
| LeanVM terminal, `KeccakPublicMemoryC1Pow28T6` | [`LeanVmTwoCommitmentTerminal_KeccakPublicMemoryC1Pow28T6`](src/leanvm/generated/LeanVmTwoCommitmentTerminal_KeccakPublicMemoryC1Pow28T6.sol) | `verifyC1V1(Proof)` |
| Experimental LeanVM grouped terminal, `GroupedLogupKeccakPow28T6` | [`LeanVmGroupedTerminal_KeccakPow28T6`](src/leanvm/generated/LeanVmGroupedTerminal_KeccakPow28T6.sol) | `verifyGroupedLogupV1(Proof)` |

### Standalone WHIR API

The native blob contracts expose:

```solidity
function verify(bytes32 expectedCommitment, bytes calldata blob)
    external
    pure
    returns (bool);
```

`expectedCommitment` is the Merkle root bound by the opening claim. `blob` contains the statement and proof in the schedule-specific compact format. The blob header does not identify the field; callers must select the contract matching the proof source.

Each standalone target also provides:

- a typed verifier with `verify(bytes32, WhirStructs.WhirStatement, WhirStructs.WhirProof)`;
- a decode-and-delegate blob wrapper constructed with the typed verifier address;
- a native blob verifier that parses and verifies in one contract.

### LeanVM terminal API

The terminal contract exposes:

```solidity
function verifyC1V1(Proof calldata proof) external pure returns (bool);
```

`Proof` contains the packed transcript, Merkle openings, application root, carried SPARK and lift claims, and root evaluation. The selected generated contract pins the execution profile, fixed-program commitment, program layout, and WHIR configuration. Its checked-in ABI fixture and calldata are under [`testdata/leanvm_terminal/KeccakPublicMemoryC1Pow28T6/`](testdata/leanvm_terminal/KeccakPublicMemoryC1Pow28T6/).

The experimental grouped contract replaces the quotient-GKR rounds with grouped inverse-product LogUp, commits a third helper polynomial, shares polynomial weights, and authenticates the three commitments with one Merkle frontier. It exposes `verifyGroupedLogupV1(Proof)` and retains its fixture under [`testdata/leanvm_terminal/GroupedLogupKeccakPow28T6/`](testdata/leanvm_terminal/GroupedLogupKeccakPow28T6/). It is checked in to preserve and test the measured implementation; full protocol-composition security remains under review, so it is not the selected terminal verifier.

Validate that fixture against the native export with:

```sh
python3 script/generate_leanvm_two_commitment_terminal_fixture.py \
  ../leanVM/benchmark-results/terminal-c1-b-threshold6-pow28/native/root-fixture.json \
  KeccakPublicMemoryC1Pow28T6 \
  --validate-only
```

## Latest measurements

| Verifier | Foundry gas | Transaction gas | Execution gas | Calldata | Runtime / initcode |
| --- | ---: | ---: | ---: | ---: | ---: |
| KoalaBear quintic | `3,518,733` | `3,637,880` | `2,760,544` | `54,436` B | `34,898` / `34,924` B |
| BabyBear quintic | `3,240,976` | `3,364,794` | `2,489,346` | `54,084` B | `33,780` / `33,806` B |
| KoalaBear octic | `5,356,053` | `5,637,745` | `4,862,945` | `47,780` B | `36,710` / `36,736` B |
| LeanVM terminal | - | `12,896,156` | `11,276,316` | `106,628` B | `62,732` / `62,758` B |
| Experimental LeanVM grouped terminal | - | `10,615,304` | `9,089,188` | `98,596` B | `62,156` / `62,182` B |

Transaction gas is measured from Anvil receipts. Execution gas is `transaction gas - 21,000 - calldata gas`. The standalone measurements use `solc 0.8.28`, `via_ir`, 833 optimizer runs, and the Prague EVM target.

These monolithic contracts exceed the 24,576-byte EIP-170 runtime limit. The project measures them with a 65,536-byte runtime limit and 131,072-byte initcode limit. Deployment on a network enforcing EIP-170 requires a split verifier or another architecture.

Detailed measurement provenance and optimization records are in [the verifier optimization audit](docs/verifier-optimization-audit.md), [the BabyBear verifier results](docs/babybear-verifier-optimization-loop.md), and [the test-data retention guide](testdata/README.md).

## License

MIT
