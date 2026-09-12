#!/usr/bin/env python3
"""Replay the frozen select-chain comparison in an isolated Foundry project."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--repo', type=Path, default=Path.cwd())
parser.add_argument('--out-dir', type=Path, required=True)
parser.add_argument('--fuzz-runs', type=int, default=256)
args = parser.parse_args()
bundle = Path(__file__).resolve().parent
repo = args.repo.resolve()
manifest = json.loads((bundle / 'results.json').read_text())
for base, hashes in [(repo, manifest['dependency_sha256']), (bundle, manifest['source_sha256'])]:
    for relative, expected in hashes.items():
        if hashlib.sha256((base / relative).read_bytes()).hexdigest() != expected:
            raise SystemExit('Source fingerprint differs: ' + relative)
out = args.out_dir.resolve()
out.mkdir(parents=True, exist_ok=False)
shutil.copytree(bundle / 'test', out / 'test')
shutil.copy2(bundle / 'foundry.toml', out / 'foundry.toml')
for relative in manifest['dependency_sha256']:
    if relative.startswith('test/helpers/'):
        shutil.copy2(repo / relative, out / relative)
for name in ['src', 'lib']:
    (out / name).symlink_to(repo / name, target_is_directory=True)
with (out / 'tests.log').open('w') as log:
    subprocess.run(['forge', 'test', '--offline', '--fuzz-runs', str(args.fuzz_runs), '-vv'],
                   cwd=out, stdout=log, stderr=subprocess.STDOUT, check=True)
print(out / 'tests.log')
