# LeanVM AIR differential vectors

#### Evaluator interface

`LeanVmAir` evaluates the execution, extension-operation, and Poseidon16 AIRs at a quintic extension-field point. The inputs and result use `KoalaBearExt5` packed elements. Flat and shifted columns follow the names in `vectors.json`. Each table receives its already-sliced alpha powers and the 16-element bus equality vector. The table dimensions are execution 20/2/14, extension 29/13/35, and Poseidon 110/0/96, written as flat columns / shifted columns / constraints.

The Poseidon AIR uses eight full rounds and twenty partial rounds. Its sparse constants are generated from the Python verifier's primitive implementation. The extension-operation AIR multiplies five polynomial coefficients that are themselves quintic extension-field evaluations, reducing the coefficient polynomial modulo `X^5 + X^2 - 1`.

#### Regeneration and validation

From this Solidity checkout, regenerate the constants and 87 differential vectors, then run the Solidity checks:

```sh
python3 script/generate_leanvm_air_vectors.py --leanvm ../leanVM
forge test --offline --match-path test/LeanVmAir.t.sol --threads 1
```

The cases cover zero, one, minus one, every basis coordinate, deterministic random extension values, and individual constraint weights at group boundaries. The JSON records the exact Python source hashes and the Poseidon constant hash. The Solidity checks also reject invalid dimensions and noncanonical packed inputs.

From the sibling LeanVM checkout, compare the same vectors against the native AIR implementation. Cargo executes this integration test in its crate directory, so the relative vector path below is relative to `crates/spartan_whir_guest`:

```sh
LEANVM_AIR_VECTORS=../../../sol-spartan-whir/testdata/leanvm_air/vectors.json cargo test --release -p spartan_whir_guest --test terminal_air -- --ignored --test-threads=1
```

AIR evaluation returns the weighted constraint value. The terminal verifier separately authenticates the column evaluations, binds the transcript and program, and checks the sumcheck and lookup arguments.
