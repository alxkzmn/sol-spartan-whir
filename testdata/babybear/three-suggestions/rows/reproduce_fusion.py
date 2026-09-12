#!/usr/bin/env python3
"""Reproduce the fused row experiment on top of the frozen MULMOD experiment."""
import argparse,hashlib,json,shutil,subprocess,sys
from pathlib import Path
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--repo',type=Path,default=Path.cwd())
parser.add_argument('--out-dir',type=Path,required=True)
args=parser.parse_args()
bundle=Path(__file__).resolve().parent
manifest=json.loads((bundle/'results.json').read_text())
for name,expected in manifest['source_sha256'].items():
    assert hashlib.sha256((bundle/name).read_bytes()).hexdigest()==expected,name
frozen=args.repo.resolve()/'testdata/babybear/binomial-mulmod'
subprocess.run([sys.executable,str(frozen/'reproduce.py'),'--repo',str(args.repo.resolve()),'--out-dir',str(args.out_dir.resolve())],check=True)
for src,dst in [('FusedRows.sol','test/helpers/FusedRows.sol'),('FusedRows.t.sol','test/FusedRows.t.sol'),('generate_fusion.py','generate_fusion.py'),('verify_fusion_bounds.py','verify_fusion_bounds.py')]:
    shutil.copy2(bundle/src,args.out_dir/dst)
print('Run forge test --offline --fuzz-runs 256 -vv in the output directory.')
