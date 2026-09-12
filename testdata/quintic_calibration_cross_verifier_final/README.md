# Final verifier calibration evidence

This directory contains the source and input manifests and refreshed calibration for the KoalaBear quintic and octic verifier optimization pass. Raw logs, receipts, compiler snapshots, profiles, and generated schedule reports are CI-regenerable and are not checked in.

The calibration uses these transaction receipts:

- `../koalabear_cross_field_final_tx_snapshot/run.json`: 3,641,381 total gas and 2,764,045 execution gas;
- `../octic_optimized_final_tx_snapshot/run.json`: 5,637,745 total gas and 4,862,945 execution gas;
- `../calibration_quartic_lir6_tx_snapshot/run.json` and `../calibration_quartic_lir11_tx_snapshot/run.json`: unchanged quartic references.

`calibration.json` has source fingerprint `825fad090dceb013e25d739a0970b0c36fdfe85c9144c7a013aecf6cdb614096`. The schedule scorer accepts the ordinal calibration gate. The octic Merkle and transcript bucket diagnostics and the quartic transcript bucket diagnostic remain outside their configured target ranges.

`inputs.json` records the hashes of the logs, receipts, schedules, timing inputs, success fixtures, compiler summaries, phase profiles, parsed flamegraphs, and serial suite log used by this refresh. The transaction runs predate the manifest capture; matching calldata hashes and the recorded compiler and source fingerprints bind the measurements to this historical snapshot.
