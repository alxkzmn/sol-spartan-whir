# Row, select, and equality fusion experiments

[Results and measurement boundaries](../../../docs/babybear-fusion-results.md) describe the three experiments and complete native integration. `rows`, `select`, and `equality` contain independent component harnesses, frozen sources, gas measurements, arithmetic checks, and replay scripts. `native` contains all five complete KoalaBear variants, transaction receipts, source fingerprints, full-suite logs, and the selected profile and optimized IR.

This experiment selected the `fusion` native variant: packed `MULMOD` rows plus row/Horner fusion, at **3,952,037 transaction gas**. The equality variants remain available for reproduction but regress in the deployed caller. The later production promotion retains the packed-row variant and excludes fusion under its strict greater-than-1% gate.

`validation.json` records the completion checks. Production source was unchanged when this archive was recorded; the qualifying packed-row variant was promoted later. Compiler metadata and IR source comments use repository-relative paths in this archive; executable code and source fingerprints are preserved.
