from pathlib import Path
import runpy,re
ns=runpy.run_path(str(Path(__file__).with_name('round3.py')));block,fn=ns['block'],ns['fn'];root,out=ns['root'],ns['out'];variants=ns['variants'];assemblybody=ns['assemblybody']
path=out/'test/helpers/BabyBearEqThird.sol';text=path.read_text()
for field in ['KoalaBear','BabyBear']:
 oldname=field+('EqPersistentFused' if field=='KoalaBear' else 'EqPersistent');name=field+'EqPersistentStatement'
 s=block(text,'library '+oldname+' {')+'\n'+block(text,'contract '+oldname+'Harness {');s=s.replace(oldname,name)
 eqbody=assemblybody(fn(s,'_eqForms'));mulbody=assemblybody(fn(s,'_mulForms'))
 unpack=assemblybody(fn(s,'_unpackForms'));unpack=re.sub(r'\blow\b','aLow',unpack);unpack=re.sub(r'\brev\b','aRev',unpack)
 fused='''    function _accEqAt(uint256 ptr,uint256 a,uint256[4] memory cache) private pure {
        assembly("memory-safe") {
            let termLow let termRev
            {
                let aLow let aRev
                { @UNPACK@ }
                let outLow let outRev
                @EQ@
                termLow:=outLow termRev:=outRev
            }
            {
                let aLow:=mload(ptr) let aRev:=mload(add(ptr,32)) let bLow:=termLow let bRev:=termRev let outLow let outRev
                @MUL@
                mstore(ptr,outLow) mstore(add(ptr,32),outRev)
            }
        }
    }'''.replace('@UNPACK@',unpack).replace('@EQ@',eqbody).replace('@MUL@',mulbody)
 s=s.replace(fn(s,'_accEqAt'),fused)
 variants.append(name);text+=s+'\n'
path.write_text(text)
# Extend existing generated test while preserving full-field independent oracle.
testpath=out/'test/BabyBearEqThird.t.sol';test=testpath.read_text();names=[]
for field in ['KoalaBear','BabyBear']:
 names.append(field+'EqShifted');names += [v for v in variants if v.startswith(field)]
N=len(names);half=N//2
start=test.index('    function setUp()');end=test.index('    function _canonical',start)
test=test[:start]+'    function setUp() external {\n'+''.join(f'h[{i}]=IEqHarness(address(new {v}Harness()));\n' for i,v in enumerate(names))+'}\n'+test[end:]
test=test.replace('IEqHarness[16] h',f'IEqHarness[{N}] h').replace('i < 16',f'i < {N}').replace('i < 8',f'i < {half}').replace('f == 0 ? 0 : 8',f'f == 0 ? 0 : {half}').replace('f == 0 ? 8 : 16',f'f == 0 ? {half} : {N}')
test=re.sub(r'string\[16\] memory names = \[.*?\];',f'string[{N}] memory names = ['+','.join('"'+v+'"' for v in names)+'];',test)
test=re.sub(r'import \{[^\n]+\} from "./helpers/BabyBearEqThird.sol";','import {'+','.join(v+'Harness' for v in variants)+'} from "./helpers/BabyBearEqThird.sol";',test)
testpath.write_text(test);print(names)
