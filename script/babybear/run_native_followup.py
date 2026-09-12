#!/usr/bin/env python3
"""Reproduce the complete quintic optimization control from its reviewed patch.

Production sources are copied into a new workspace; its patch keeps existing
internal point-array interfaces while the native verifier uses cached cubics.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[2]
EVIDENCE=ROOT/'testdata/babybear/followup-native'
FAMILY='k22_jb100_ext5_lir4_ff4_rsv3_pow28'
TEST=f'WhirBlobVerifierNative5_{FAMILY}.t.sol'

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out-dir',type=Path,required=True)
    parser.add_argument('--full-suite',action='store_true')
    args=parser.parse_args()
    out=args.out_dir.resolve();out.mkdir(parents=True,exist_ok=False)
    manifest=json.loads((EVIDENCE/'results.json').read_text())
    for rel,expected in {**manifest['baseline_source_sha256'], **manifest['fixture_sha256']}.items():
        actual=hashlib.sha256((ROOT/rel).read_bytes()).hexdigest()
        if actual!=expected:raise RuntimeError(f'Baseline source changed: {rel}; review and revalidate the patch first.')
    work=out/'workspace';work.mkdir()
    shutil.copytree(ROOT/'src',work/'src')
    shutil.copytree(ROOT/'test',work/'test')
    shutil.copytree(ROOT/'testdata',work/'testdata')
    os.symlink(ROOT/'lib',work/'lib',target_is_directory=True)
    shutil.copy2(ROOT/'foundry.toml',work/'foundry.toml')
    patch=EVIDENCE/'native-optimized.patch'
    subprocess.run(['git','apply','--check',str(patch)],cwd=work,check=True)
    subprocess.run(['git','apply',str(patch)],cwd=work,check=True)
    shutil.copy2(ROOT/'script/babybear/native_followup/NativeFollowup.t.sol.in',work/'test/NativeFollowup.t.sol')
    # Keep the transaction reproduction self-contained, including managed Anvil.
    (work/'script').mkdir()
    script=f'WhirBlobNativeTxBenchmark_{FAMILY}.s.sol'
    shutil.copy2(ROOT/'script'/script,work/'script'/script)
    shutil.copytree(ROOT/'.agents/skills/tx-gas-benchmarking',work/'.agents/skills/tx-gas-benchmarking')
    commands=[['forge','test','--match-path','test/'+TEST,'--match-test','testGasWhirVerifyBlobNativeFixed','-vv','--offline']]
    if args.full_suite:
        commands.extend([['forge','test','--match-path','test/FieldArithmetic.t.sol','--offline','--isolate','--threads','1','--fuzz-runs','256'], ['forge','test','--no-match-path','test/FieldArithmetic.t.sol','--offline','--isolate','--threads','1','--fuzz-runs','256']])
    for index,command in enumerate(commands):
        with (out/f'forge-{index}.log').open('w') as log:
            result=subprocess.run(command,cwd=work,stdout=log,stderr=subprocess.STDOUT)
        print((out/f'forge-{index}.log').read_text())
        if result.returncode:raise SystemExit(result.returncode)
    print(f'Control workspace: {work}')

if __name__=='__main__':main()
