# LeanVM LogUp and quotient GKR vectors

#### Contents

`vectors.json` contains four small native Keccak240 proofs with complete expected claims and transcript continuation. They cover equal table heights, a taller extension table, a taller execution table, and a bytecode table taller than the execution tables. The lookup traces have balanced nonzero precompile multiplicities, nonzero memory and program values, and all table-bus column evaluations. These lookup traces exercise standalone LogUp; the separate AIR corpus tests the table constraint functions.

Extension values are arrays of five canonical KoalaBear coefficients. Transcript bytes encode little-endian base-field words; each raw block is padded to eight words. `provenance.json` records the LeanVM branch, upstream base, branch HEAD, and source hashes. The source hashes identify the working-tree implementation used to generate and validate the corpus.

#### Reproduce

From the sibling `leanVM` directory:

```sh
LEANVM_LOGUP_EXPORT_DIR=../../../sol-spartan-whir/testdata/leanvm_logup cargo test --release -p spartan_whir_guest --test terminal_logup -- --ignored --test-threads=1
```

Cargo runs the test from `crates/spartan_whir_guest`, which determines the relative export directory. From this Solidity repository, use a Python interpreter with NumPy and run:

```sh
python3 script/check_leanvm_logup_vectors.py
forge test --offline --match-path test/LeanVmLogUp.t.sol --threads 1 -vv
```

The Python checker uses the maintained LeanVM Python verifier through the workspace Keccak adapter. Solidity tests compare all claims and the next transcript sample, reject malformed proofs, and compare common-denominator accumulation with the original 32-inverse calculation. Call gas measurements exclude fixture parsing; the overall Foundry test gas includes it.
