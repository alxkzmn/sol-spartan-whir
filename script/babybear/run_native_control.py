#!/usr/bin/env python3
"""Measure a select control inside an isolated copy of the native verifier.

Usage: python3 script/babybear/run_native_control.py VARIANT --out-dir NEW_DIRECTORY
VARIANT is Baseline or a generated KoalaBearSelect... library name.
The working production contracts, cache, and calibration are never overwritten.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from generate_select_variants import ROOT, CORE, function

FAMILY='k22_jb100_ext5_lir4_ff4_rsv3_pow28'
NATIVE=f'WhirBlobVerifierNative5_{FAMILY}'
SOURCE=Path(f'src/whir/{FAMILY}/{NATIVE}.sol')
TEST=f'WhirBlobVerifierNative5_{FAMILY}.t.sol'

def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('variant')
    ap.add_argument('--out-dir',type=Path,required=True)
    ap.add_argument('--row-variant',choices=['KoalaBearRowNine','KoalaBearRowFive','KoalaBearRowKronecker','KoalaBearRowKroneckerStream'])
    ap.add_argument('--eq-variant',choices=['KoalaBearEqCombined','KoalaBearEqPackedMul'])
    args=ap.parse_args()
    out=args.out_dir.resolve();out.mkdir(parents=True,exist_ok=False)
    work=out/'workspace';work.mkdir()
    shutil.copytree(ROOT/'src',work/'src')
    shutil.copytree(ROOT/'testdata',work/'testdata')
    (work/'test').mkdir()
    shutil.copy2(ROOT/'test'/TEST,work/'test'/TEST)
    os.symlink(ROOT/'lib',work/'lib',target_is_directory=True)
    shutil.copy2(ROOT/'foundry.toml',work/'foundry.toml')
    native=(work/SOURCE).read_text()
    core=CORE.read_text()
    if args.variant!='Baseline':
        generated=(ROOT/'test/helpers/BabyBearSelectVariants.sol').read_text()
        recorded=re.search(r'Native core SHA-256: ([0-9a-f]+)',generated)[1]
        if recorded!=digest(CORE):raise RuntimeError('Native source changed; regenerate and validate variants before measuring.')
        forms='SelectForms' in args.variant
        select_sources=generated
        if forms:generated=(ROOT/'test/helpers/BabyBearSelectForms.sol').read_text()
        start=generated.index('library '+args.variant+' {')
        end=generated.index('\nlibrary ',start+1) if '\nlibrary ' in generated[start+1:] else generated.index('\ncontract ',start+1)
        lib=generated[start:end]
        # Replace the two selector loops. Additional helpers are private/internal.
        for name in ['_selectPolyEvalFixed','_selectPolyEvalFixedPair']:
            core=core.replace(function(core,name),function(lib,name))
        if forms:
            cache_start=select_sources.index('library KoalaBearSelectPrepackedCombined {')
            lib+='\n'+function(select_sources[cache_start:],'prepare')
        if 'PackedHorner' in args.variant:
            core=core.replace(function(core,'_hornerStep'),function(lib,'_hornerStep'))
        extras=[]
        for name in ['_initialSelect','_loadPoint','_mulBySelectTermCached','_cachedAddress','prepare','_initialCached','_toReciprocal','_fromReciprocal','_prepareConverted','_multiply','_initial','_pack']:
            if 'function '+name+'(' in lib:extras.append(function(lib,name))
        core=core.rstrip()[:-1]+'\n'+'\n\n'.join(extras)+'\n}\n'
        if 'function prepare(' in lib:
            native=native.replace('        uint256 evaluationOfWeights =','        uint256[] memory packedPoint = WhirVerifierCore5.prepare(allRandomness);\n        uint256 evaluationOfWeights =',1)
            for n in [18,14,10]:
                pattern=r'(_evaluateConstraintSelectRaw'+str(n)+r'WithPrecomputedEq\([\s\S]*?\))'
                native,count=re.subn(pattern,lambda m:m[0].replace('allRandomness','packedPoint'),native)
                assert count==1
    if args.eq_variant:
        generated=(ROOT/'test/helpers/BabyBearEqVariants.sol').read_text()
        lib=generated[generated.index('library '+args.eq_variant+' {'):]
        for name in ['_evaluateFixedEqTermsBlobRaw','_eqTerm']:
            core=core.replace(function(core,name),function(lib,name))
    if 'KoalaBearPackedField.' in core:
        generated=(ROOT/'test/helpers/BabyBearPackedFields.sol').read_text()
        lib=generated[generated.index('library KoalaBearPackedField {'):generated.index('library BabyBearPackedField {')]
        packedpath=work/'src/field/KoalaBearPackedExperiment.sol'
        packedpath.write_text('// SPDX-License-Identifier: MIT\npragma solidity ^0.8.28;\nimport {KoalaBearExt5} from "./KoalaBearExt5.sol";\n'+lib)
        core=core.replace('pragma solidity ^0.8.28;','pragma solidity ^0.8.28;\nimport {KoalaBearPackedField} from "../../field/KoalaBearPackedExperiment.sol";')
    (work/CORE.relative_to(ROOT)).write_text(core)
    (work/SOURCE).write_text(native)
    utility=Path(f'src/whir/{FAMILY}/WhirVerifierUtils5.sol')
    if args.row_variant:
        generated=(ROOT/'test/helpers/BabyBearRowVariants.sol').read_text()
        start=generated.index('library '+args.row_variant+' {')
        end=generated.index('\nlibrary ',start+1) if '\nlibrary ' in generated[start+1:] else generated.index('\ncontract ',start+1)
        lib=generated[start:end]
        text=(work/utility).read_text()
        text=text.replace(function(text,'_dotExt5Weights16Unpacked'),function(lib,'_dotExt5Weights16Unpacked'))
        if args.row_variant.endswith('Stream'):
            text=text.replace(function(text,'_hashAndEvaluateExtension5RowDim4BlobUnpacked'),function(lib,'_hashAndEvaluateExtension5RowDim4BlobUnpacked'))
        before=function(text,'_computeDim4EqWeightsUnpacked')
        after='''    function _computeDim4EqWeightsUnpacked(uint256 p0,uint256 p1,uint256 p2,uint256 p3)
        internal pure returns (uint256) {
        return _prepareRowWeights(_computeDim4EqWeights(p0,p1,p2,p3));
    }'''
        text=text.replace(before,after)
        text=text.rstrip()[:-1]+'\n'+function(lib,'prepare').replace('function prepare(','function _prepareRowWeights(')+'\n}\n'
        (work/utility).write_text(text)
    command=['forge','test','--match-path','test/'+TEST,'--match-test','testGasWhirVerifyBlobNativeFixed','-vv','--offline']
    with (out/'forge.log').open('w') as log:
        result=subprocess.run(command,cwd=work,stdout=log,stderr=subprocess.STDOUT)
    log=(out/'forge.log').read_text()
    print(log)
    if result.returncode:raise SystemExit(result.returncode)
    match=re.search(r'\[PASS\] testGasWhirVerifyBlobNativeFixed\(\) \(gas: (\d+)\)',log)
    if not match:raise RuntimeError('Successful canonical measurement missing')
    artifact=work/'out'/SOURCE.name/(NATIVE+'.json')
    data=json.loads(artifact.read_text());metadata=json.loads(data['rawMetadata'])
    runtime=bytes.fromhex(data['deployedBytecode']['object'].removeprefix('0x'))
    evidence={'variant':args.variant,'command':command,'foundry_gas':int(match[1]),'runtime_bytes':len(runtime),'runtime_sha256':hashlib.sha256(runtime).hexdigest(),'compiler':metadata['compiler'],'settings':{k:metadata['settings'][k] for k in ['viaIR','optimizer','evmVersion']},'source_sha256':{str(CORE.relative_to(ROOT)):digest(work/CORE.relative_to(ROOT)),str(SOURCE):digest(work/SOURCE)},'fixture_sha256':{str(p.relative_to(work)):digest(p) for p in (work/'testdata').glob('quintic_whir_'+FAMILY+'_success*')}}
    evidence['row_variant']=args.row_variant
    evidence['eq_variant']=args.eq_variant
    if (work/'src/field/KoalaBearPackedExperiment.sol').exists():
        evidence['source_sha256']['src/field/KoalaBearPackedExperiment.sol']=digest(work/'src/field/KoalaBearPackedExperiment.sol')
    evidence['source_sha256'][str(utility)]=digest(work/utility)
    (out/'metrics.json').write_text(json.dumps(evidence,indent=2)+'\n')
    print(json.dumps(evidence,indent=2))

if __name__=='__main__':main()
