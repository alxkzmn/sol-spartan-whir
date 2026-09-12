# Review-fix calibration evidence

This directory contains the Foundry configuration, source and input manifests, and refreshed quintic calibration for the reviewed KoalaBear verifier source. Raw logs, receipts, compiler snapshots, and generated score reports are CI-regenerable and are not checked in.

The KoalaBear quintic reference uses `../koalabear_review_fixes_tx_snapshot/run.json`: 3,637,880 total transaction gas and 2,760,544 execution gas for calldata SHA-256 `73ced3d949b11d13f8bd81372abfc01deb4949d99456f50b99cba14770aaf8fd`.

The quartic and octic calibration receipts are retained from the preceding final measurement. The Merkle change in this review is NatSpec only. Removing the unused private octic equality-weight argument also leaves the emitted executable runtime byte-for-byte identical: both targeted octic builds contain 36,657 executable bytes with SHA-256 `3b972620ba381ceba869ef885f5e42913b7aaa4975211a7bc8e1fab3e0308376` after stripping Solidity metadata.

The reviewed KoalaBear cleanup changes source metadata but leaves the executable portion of the deployed runtime byte-for-byte identical at 34,845 bytes with SHA-256 `292cbc0a4f690cfda04340dad7c95cccc95b8a56ed314ca49f52716371e6c076`; the targeted compiler snapshot recorded that result.

The calibration source fingerprint is `0d13416cb1b41414fb41f25deb815763d7f098328bb20350b1c42e65580c5cfc`. The schedule scorer accepts the ordinal calibration gate and uses quintic scale `0.5376026122614975`; the existing octic Merkle/transcript and quartic transcript bucket diagnostics remain outside their configured ranges.

`sources-final.json` and `inputs.json` record the hashes of the source and measurement inputs used for this historical snapshot. Generated reports under `../quintic_scores/` and calibration snapshot `scores/` directories are ignored.
