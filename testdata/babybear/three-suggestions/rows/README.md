# Row and Horner fusion

The row dot product includes `claim*challenge` as a seventeenth term. Reconstruction and prime reduction happen once after all 17 terms. The 50 nonfinal extension rows cost **384,842 BabyBear gas**, down from 400,650, and **440,704 KoalaBear gas**, down from 452,084. Setup includes challenge packing once per batch, and both variants include two final OOD Horner updates. Final STIR's 14 individual row evaluations remain unchanged. Including those rows gives 491,008 BabyBear gas and 560,314 KoalaBear gas.

`bounds.md` and `verify_fusion_bounds.py` cover the 17-term bounds. `FusedRows.sol` contains the measured libraries and harnesses. `FusedRows.t.sol` independently checks full recurrence order, maximal inputs, malformed coefficients, exact error ordering, and prefixed hashes. The replay also runs the 16 tests in the underlying packed-row experiment: **23 tests pass** in total, with 256 fuzz runs.

From the repository root, choose a fresh output directory:

```sh
python3 testdata/babybear/three-suggestions/rows/reproduce_fusion.py --out-dir /tmp/row-fusion-replay
(cd /tmp/row-fusion-replay && forge test --offline --fuzz-runs 256 -vv)
python3 testdata/babybear/three-suggestions/rows/verify_fusion_bounds.py
```

The source construction script is preserved separately. The replay copies the frozen sources after checking their hashes.
