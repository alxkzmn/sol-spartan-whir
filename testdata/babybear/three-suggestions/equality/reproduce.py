#!/usr/bin/env python3
"""Replay all equality candidates in a fresh isolated Foundry workspace."""
from pathlib import Path
import argparse,os,shutil,subprocess,hashlib,json
ap=argparse.ArgumentParser();ap.add_argument('--source-root',type=Path,default=Path.cwd());ap.add_argument('--out-dir',type=Path,required=True);ap.add_argument('--fuzz-runs',type=int,default=256);args=ap.parse_args()
source=args.source_root.resolve();output=args.out_dir.resolve()
manifest=json.loads(Path(__file__).with_name('baseline-sources.json').read_text())
for relative,expected in manifest.items():
 actual=hashlib.sha256((source/relative).read_bytes()).hexdigest()
 if actual!=expected:raise SystemExit('Baseline source fingerprint differs: '+relative)
output.mkdir(parents=True,exist_ok=False)
workspace=output/'workspace';(workspace/'test/helpers').mkdir(parents=True)
shutil.copy2(source/'foundry.toml',workspace/'foundry.toml')
for p in (source/'test/helpers').glob('BabyBear*.sol'):shutil.copy2(p,workspace/'test/helpers'/p.name)
for p in ['src','lib']:(workspace/p).symlink_to(source/p,target_is_directory=True)
env=os.environ.copy();env['EQ_SOURCE_ROOT']=str(source);env['EQ_OUTPUT_ROOT']=str(workspace)
package=Path(__file__).resolve().parent
with (output/'generation.log').open('w') as log:subprocess.run(['python3',str(package/'round4.py')],env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
with (output/'tests.log').open('w') as log:subprocess.run(['forge','test','--root',str(workspace),'--match-path','test/BabyBearEqThird.t.sol','--offline','--fuzz-runs',str(args.fuzz_runs),'-vv'],stdout=log,stderr=subprocess.STDOUT,check=True)
with (output/'bounds.json').open('w') as log:subprocess.run(['python3',str(package/'verify_bounds.py')],stdout=log,check=True)
fingerprints={str(p.relative_to(workspace)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [workspace/'foundry.toml',workspace/'test/BabyBearEqThird.t.sol',workspace/'test/helpers/BabyBearEqThird.sol']}
(output/'generated-sources.json').write_text(json.dumps(fingerprints,indent=2)+'\n')
print(output)
