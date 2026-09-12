# Select-chain fusion

The selected BabyBear implementation costs **588,237 gas**, versus 618,753 for the ordinary Horner control and 615,232 for the packed-Horner control in the same build. The respective savings are **4.93%** and **4.39%**. The workload includes cubic cache setup, 88 selectors across 18/14/10-dimensional chains, 91 Horner updates, and output packing.

`BabyBearChainFusedConsumer` retains each Horner accumulator in two words containing canonical coefficients in 64-bit lanes. It computes the unreduced `total*challenge` coefficients into five scratch words, then adds those coefficients to the last select product before the five prime reductions. The product chain still reduces between dependent products. The challenge is packed once per batch; the scratch allocation is seven words, including those two challenge words.

Four canonical coefficient products fit below `2^64`; five do not. The packed convolution recovers its middle coefficient separately. Each BabyBear output has at most nine product contributions, counting doubled terms; summing the select and Horner products is bounded by `18*(p-1)^2 < 2^67`. `verify_bounds.py` checks the two-product fusion independently against schoolbook multiplication for 10,064 cases. `bounds.json` records the bounds.

Keeping each chain product in five 51-bit lanes with three `MULMOD` operations regresses to 649,496 gas. A direct final equality consumer costs 588,748, and packed final Horner costs 616,371. These variants are rejected. KoalaBear's best control remains 683,138 gas; its best new fusion costs 737,569, a regression. Compiler context affects KoalaBear strongly: the separately compiled IR does not match its measured baseline runtime. Both artifacts are identified in `results.json`; the selected BabyBear IR matches its measured runtime exactly.

**69 tests pass**, including 256 independent full-batch fuzz cases with challenges and selectors sampled over the entire BabyBear field, 64 complete boundary combinations of zero/one/maximal/basis points and challenges, and chain/full-batch differential fuzzing for both fields. The boundary combinations are separate tests because accumulating all 64 schoolbook reference calculations in one call exceeded the test memory limit. All original cases are retained.

The selected BabyBear harness has 5,982 runtime bytes and 6,008 initcode bytes. Sources, compiler metadata, measured code, IR, and logs are archived here. These are component measurements; no complete BabyBear verifier or transaction has been produced.

From the repository root, use a fresh output directory:

```sh
python3 testdata/babybear/three-suggestions/select/verify_bounds.py
python3 testdata/babybear/three-suggestions/select/reproduce.py --out-dir /tmp/select-fusion-replay
```

The replay checks source/dependency hashes, copies the frozen test sources, and runs every case with 256 fuzz runs. Production source is linked read-only.
