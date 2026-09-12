#!/usr/bin/env python3
"""Copy the measured sources into a fresh isolated Foundry workspace."""

import argparse
import hashlib
import json
import shutil
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--repo", type=Path, default=Path.cwd())
parser.add_argument("--out-dir", type=Path, required=True)
args = parser.parse_args()
bundle = Path(__file__).resolve().parent
repo = args.repo.resolve()
output = args.out_dir.resolve()
if output.exists():
    parser.error("--out-dir must not already exist")
if not (repo / "lib/forge-std/src/Test.sol").is_file():
    parser.error("--repo must contain lib/forge-std/src/Test.sol")
manifest = json.loads((bundle / "results.json").read_text())
for name, expected in manifest["bundle_source_sha256"].items():
    actual = hashlib.sha256((bundle / name).read_bytes()).hexdigest()
    if actual != expected:
        parser.error(f"archived source fingerprint differs: {name}")

(output / "src/field").mkdir(parents=True)
(output / "test/helpers").mkdir(parents=True)
(output / "lib").symlink_to(repo / "lib", target_is_directory=True)
shutil.copy2(bundle / "foundry.toml", output / "foundry.toml")
for name in ("KoalaBear.sol", "KoalaBearExt5.sol"):
    shutil.copy2(bundle / name, output / "src/field" / name)
for name in ("Rows.sol", "BabyBearReference.sol", "BabyBearPackedFields.sol", "BabyBearSelectVariants.sol"):
    shutil.copy2(bundle / name, output / "test/helpers" / name)
for name in ("BabyMulmodRows.t.sol", "KoalaMulmodRows.t.sol"):
    shutil.copy2(bundle / name, output / "test" / name)
print(output)
print("Run forge test --offline --fuzz-runs 256 -vv in this workspace.")
