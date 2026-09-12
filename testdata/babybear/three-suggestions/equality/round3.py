from pathlib import Path
import runpy,re
ns=runpy.run_path(str(Path(__file__).with_name('round2.py')));block,fn=ns['block'],ns['fn'];root,out=ns['root'],ns['out'];variants=ns['variants']
path=out/'test/helpers/BabyBearEqThird.sol';text=path.read_text()
for field in ['KoalaBear','BabyBear']:
 oldname=field+'EqPersistent';name=oldname+'Fused'
 s=block(text,'library '+oldname+' {')+'\n'+block(text,'contract '+oldname+'Harness {');s=s.replace(oldname,name)
 def assemblybody(f):
  b=f[f.index('assembly ("memory-safe")'):] if 'assembly ("memory-safe")' in f else f[f.index('assembly("memory-safe")'):]
  return b[b.index('{')+1:b.rfind('}')].rsplit('}',1)[0]
 eqbody=re.sub(r'\blow\b','convolutionLow',assemblybody(fn(s,'_eqForms')));mulbody=re.sub(r'\blow\b','convolutionLow',assemblybody(fn(s,'_mulForms')))
 fused='''    function _pointEq(uint256 ptr,uint256 pointPtr,uint256[4] memory cache,bool initial) private pure {
        assembly("memory-safe") {
            let al:=mload(pointPtr) let ar:=mload(add(pointPtr,32)) let low let rev
            { let aLow:=al let aRev:=ar let outLow let outRev
            @EQ@
            low:=outLow rev:=outRev }
            if iszero(initial) {
                let aLow:=mload(ptr) let aRev:=mload(add(ptr,32)) let bLow:=low let bRev:=rev let outLow let outRev
                @MUL@
                low:=outLow rev:=outRev
            }
            mstore(ptr,low) mstore(add(ptr,32),rev)
            { let aLow:=al let aRev:=ar let bLow:=al let bRev:=ar let outLow let outRev
                @MUL@
                mstore(pointPtr,outLow) mstore(add(pointPtr,32),outRev)
            }
        }
    }'''.replace('@EQ@',eqbody).replace('@MUL@',mulbody)
 s=s.replace(fn(s,'_pointEq'),fused)
 variants.append(name);text+=s+'\n'
path.write_text(text)
# General test generation from original, with independent full-prime chains.
names=[]
for field in ['KoalaBear','BabyBear']:
 names.append(field+'EqShifted');names += [v for v in variants if v.startswith(field)]
N=len(names);half=N//2
p=out/'test/BabyBearEqThird.t.sol';test=(root/'test/BabyBearEqFollowup.t.sol').read_text()
test=test.replace('IEqHarness[6] h',f'IEqHarness[{N}] h').replace('BabyBearEqFollowupTest','BabyBearEqThirdTest')
start=test.index('    function setUp()');end=test.index('    function _canonical',start)
test=test[:start]+'    function setUp() external {\n'+''.join(f'h[{i}]=IEqHarness(address(new {v}Harness()));\n' for i,v in enumerate(names))+'}\n'+test[end:]
test=test.replace('i < 6',f'i < {N}').replace('i < 3',f'i < {half}').replace('f == 0 ? 0 : 3',f'f == 0 ? 0 : {half}').replace('f == 0 ? 3 : 6',f'f == 0 ? {half} : {N}')
test=re.sub(r'string\[6\] memory names = \[.*?\];',f'string[{N}] memory names = ['+','.join('"'+v+'"' for v in names)+'];',test)
test=test.replace('import { Test }','import {'+','.join(v+'Harness' for v in variants)+'} from "./helpers/BabyBearEqThird.sol";\nimport { Test }')
packed=fn(test,'_packed').replace('_packed(uint256 seed, uint256 i)','_packedFor(uint256 seed, uint256 i,uint256 p)').replace(' % 0x78000001',' % p')
packed=packed.replace('        uint256[5] memory a;','''        uint256[5] memory a;
        if(seed==0) return Ref.pack([p-1,p-1,p-1,p-1,p-1]);
        if(seed==1) return (p-1) << (224-32*(i%5));
        if(seed==2) return 0;
        if(seed==3) return uint256(1)<<224;
        if(seed==4) return Ref.pack([p-1,0,p-1,0,p-1]);''')
inputs=fn(test,'_inputs').replace('_inputs(uint256 seed)','_inputsFor(uint256 seed,uint256 p)').replace('_packed(seed, i)','_packedFor(seed, i,p)').replace('_packed(seed, i + 22)','_packedFor(seed, i + 22,p)').replace('_packed(seed, j + 44)','_packedFor(seed, j + 44,p)')
test=test.replace('    function _checkPreparation(',packed+'\n'+inputs+'\n    function testBoundaryPreparation() external view {for(uint256 seed;seed<5;++seed) _checkPreparation(seed);}\n    function _checkPreparation(',1)
test=test.replace('        (bytes memory statement, uint256[4] memory ood, uint256[] memory point) = _inputs(seed);\n        for (uint256 f;', '        for (uint256 f;')
test=test.replace('            uint256 p = f == 0 ? 0x7f000001 : 0x78000001;','            uint256 p = f == 0 ? 0x7f000001 : 0x78000001;\n            (bytes memory statement,uint256[4] memory ood,uint256[] memory point)=_inputsFor(seed,p);')
p.write_text(test)
print(names)
