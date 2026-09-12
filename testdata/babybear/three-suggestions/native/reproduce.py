#!/usr/bin/env python3
"""Reproduce a measured native variant without modifying production sources."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--repo', type=Path, default=Path.cwd())
parser.add_argument('--out-dir', type=Path, required=True)
parser.add_argument('--variant', choices=['baseline', 'rows', 'fusion', 'combined', 'rows-eq'], default='fusion')
parser.add_argument('--full-suite', action='store_true')
args = parser.parse_args()
repo = args.repo.resolve()
bundle = Path(__file__).resolve().parent
manifest = json.loads((bundle / 'results.json').read_text())
for relative, expected in {**manifest['baseline_source_sha256'], **manifest['fixture_sha256']}.items():
    if hashlib.sha256((repo / relative).read_bytes()).hexdigest() != expected:
        raise SystemExit('Baseline fingerprint differs: ' + relative)
variant = manifest['variants'][args.variant]
patch = bundle / args.variant / 'native.patch'
if hashlib.sha256(patch.read_bytes()).hexdigest() != variant['patch_sha256']:
    raise SystemExit('Patch fingerprint differs')
out = args.out_dir.resolve()
out.mkdir(parents=True, exist_ok=False)
work = out / 'workspace'
work.mkdir()
for name in ['src', 'test']:
    shutil.copytree(repo / name, work / name)
for name in ['lib', 'testdata']:
    (work / name).symlink_to(repo / name, target_is_directory=True)
shutil.copy2(repo / 'foundry.toml', work / 'foundry.toml')
subprocess.run(['git', 'apply', '--check', str(patch)], cwd=work, check=True)
subprocess.run(['git', 'apply', str(patch)], cwd=work, check=True)
for relative, expected in variant['source_sha256'].items():
    if hashlib.sha256((work / relative).read_bytes()).hexdigest() != expected:
        raise SystemExit('Candidate source differs: ' + relative)
shutil.copy2(repo / 'script/babybear/native_followup/NativeFollowup.t.sol.in', work / 'test/NativeFollowup.t.sol')
family = 'k22_jb100_ext5_lir4_ff4_rsv3_pow28'
(work / 'script').mkdir()
shutil.copy2(repo / 'script' / f'WhirBlobNativeTxBenchmark_{family}.s.sol', work / 'script')
shutil.copytree(repo / '.agents/skills/tx-gas-benchmarking', work / '.agents/skills/tx-gas-benchmarking')
commands = [['--match-path', f'test/WhirBlobVerifierNative5_{family}.t.sol', '--match-test', 'testGasWhirVerifyBlobNativeFixed', '-vv']]
if args.full_suite:
    commands.extend([
        ['--no-match-path', '{test/FieldArithmetic.t.sol,test/BabyBearSelectBenchmark.t.sol,test/BabyBearSelectFollowup.t.sol}'],
        ['--match-path', 'test/FieldArithmetic.t.sol'],
        ['--match-path', 'test/BabyBearSelectBenchmark.t.sol'],
        ['--match-path', 'test/BabyBearSelectFollowup.t.sol'],
    ])
for index, options in enumerate(commands):
    log_path = out / f'forge-{index}.log'
    with log_path.open('w') as log:
        subprocess.run(['forge', 'test', *options, '--offline', '--isolate', '--threads', '1', '--fuzz-runs', '256'],
                       cwd=work, stdout=log, stderr=subprocess.STDOUT, check=True)
    print(log_path)
print(work)
