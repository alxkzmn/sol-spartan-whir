# Test data

This directory contains checked-in verifier inputs and the evidence needed to reproduce documented measurements. It is not a general output directory.

#### Runtime fixtures

Foundry tests read the field, Merkle, transcript, WHIR, BabyBear, and LeanVM fixtures directly. These files keep the offline test suite independent of the Rust exporter and LeanVM workspace.

#### Schedule inputs

Schedule microbenchmarks, prover timings, calibration references, and score reports are CI-regenerable outputs and are ignored. The commands in `AGENTS.md` reproduce them.

The quintic shortlist proof, statement, and blob fixtures remain checked in because active Foundry tests read them directly. Shortlist measurements and transaction receipts are ignored. The Rust schedule exporter can regenerate the proof and statement, but CI must gain a native-blob export step before all shortlist fixtures can be omitted safely.

#### Measurement evidence

Compact manifests and calibration records support measurements cited by the repository documentation. Compiler snapshots, transaction snapshots, profiles, plots, and raw logs are CI-regenerable and ignored. Historical exploration belongs in the workspace-level `research/` archive.

Generated score directories, temporary `*_tmp.json` files, build output, and operating-system metadata must not be committed.