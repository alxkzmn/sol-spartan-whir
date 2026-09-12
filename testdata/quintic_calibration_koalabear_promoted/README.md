# KoalaBear promotion calibration evidence

This directory records the quintic calibration refresh for the measured `k22_jb100_ext5_lir4_ff4_rsv3_pow28` KoalaBear verifier.

The schedule-specific verifier, phase harness, and quintic transaction were remeasured. The quartic `lir6`, quartic `lir11`, and octic receipts were reused from `testdata/calibration_quartic_lir6_tx_snapshot`, `testdata/calibration_quartic_lir11_tx_snapshot`, and `testdata/calibration_octic_after_merkle_tx_snapshot`. The promoted source changes are confined to the quintic schedule directory and `KoalaBearPackedField.sol`; those files are not dependencies of the reused contracts. Their shared field, transcript, Merkle, compiler, optimizer, and EVM settings are unchanged from the receipt refresh that preceded this promotion. Each reused receipt was reparsed successfully before building the calibration.

`sources-final.json` records the source, build, schedule, timing, and fixture inputs at measurement time. `inputs.json` records the hashes of the measured logs, four receipts, compiler summary, and phase profile. Raw evidence and generated score reports are CI-regenerable and are not checked in. The octic Merkle and quartic transcript bucket diagnostics were outside their configured ranges in this snapshot.

The recorded promotion anchor is:

```text
raw verifier score: 6,766,857
measured transaction gas: 3,813,664
scale: 0.5635798126072414
```
