#!/usr/bin/env python3
"""Regenerate and format every test-only BabyBear arithmetic variant."""
import subprocess
from generate_select_variants import ROOT, generate as select
from generate_packed_fields import generate as fields
from generate_select_forms import generate as forms
from generate_row_variants import generate as rows
from generate_eq_variants import generate as equality
from row_followup import generate as row_followup
from eq_followup_generate import generate as eq_followup

for generate in [select, fields, forms, rows, equality]:
    generate()

files = ["BabyBearSelectVariants.sol", "BabyBearPackedFields.sol", "BabyBearSelectForms.sol",
         "BabyBearRowVariants.sol", "BabyBearEqVariants.sol"]
subprocess.run(["forge", "fmt", *[str(ROOT / "test/helpers" / p) for p in files]], check=True, cwd=ROOT)

row_followup()
eq_followup()
subprocess.run(["python3", str(ROOT / "script/babybear/select_followup_experiments.py")], check=True, cwd=ROOT)
