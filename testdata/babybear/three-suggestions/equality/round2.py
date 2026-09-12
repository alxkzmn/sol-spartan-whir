from pathlib import Path
import runpy,re
ns=runpy.run_path(str(Path(__file__).with_name('generate.py')))
block,fn=ns['block'],ns['fn'];root=ns['root'];out=ns['out'];variants=ns['variants']
path=out/'test/helpers/BabyBearEqThird.sol';text=path.read_text()
for field in ['KoalaBear','BabyBear']:
 oldname=field+'EqPersistent'
 orig=block(text,'library '+oldname+' {')+'\n'+block(text,'contract '+oldname+'Harness {')
 for specialized,first in [(False,True),(True,False),(True,True)]:
  name=oldname+('Specialized' if specialized else '')+('First' if first else '')
  s=orig.replace(oldname,name)
  if specialized:
   source=(root/('src/field/KoalaBearExt5.sol' if field=='KoalaBear' else 'test/helpers/BabyBearSelectVariants.sol')).read_text()
   square=fn(source,'_squarePacked' if field=='KoalaBear' else 'square')
   start=square.index('            let a0 :=');end=square.index('            let a0a0',start)
   square=square[:start]+'''            let a0 := and(aLow,0xffffffff)
            let a1 := and(shr(64,aLow),0xffffffff)
            let a2 := and(shr(128,aLow),0xffffffff)
            let a3 := shr(192,aLow)
            let a4 := and(aRev,0xffffffff)

'''+square[end:]
   square=square[:square.index('            out :=')]+'''            @OUTPUT@
        }
    }
'''
   reduced=['add(add(c0,c5),sub(bias,c8))','add(c1,c6)','add(add(add(c2,sub(bias,c5)),c7),c8)','add(add(c3,sub(bias,c6)),c8)','add(c4,sub(bias,c7))'] if field=='KoalaBear' else ['add(c0,shl(1,c5))','add(c1,shl(1,c6))','add(c2,shl(1,c7))','add(c3,shl(1,c8))','c4']
   output='\n'.join(f'let o{i}:=mod({v},M)' for i,v in enumerate(reduced))+'\n'+'''outLow:=or(or(o0,shl(64,o1)),or(shl(128,o2),shl(192,o3)))
            outRev:=or(or(o4,shl(64,o3)),or(shl(128,o2),shl(192,o1)))'''
   square=square.replace('@OUTPUT@',output)
   square=re.sub(r'function (_squarePacked|square)\(uint256 a\) (private|internal) pure returns \(uint256 out\)',r'function _squareForms(uint256 aLow,uint256 aRev) private pure returns(uint256 outLow,uint256 outRev)',square)
   s=s.replace('    function _unpackForms(',square+'\n    function _unpackForms(',1)
   s=s.replace('(low,rev)=_mulForms(al,ar,al,ar);','(low,rev)=_squareForms(al,ar);')
  if first:
   f=fn(s,'_pointEq');lines=f.splitlines()
   sq=[i for i,l in enumerate(lines) if '(low,rev)=' in l and ('_squareForms' in l or '_mulForms(al,ar,al,ar)' in l)][0]
   sqline=lines[sq].replace('(low,rev)=','(uint256 sl,uint256 sr)=')
   storeline=lines[sq+1].replace('mstore(pointPtr,low)','mstore(pointPtr,sl)').replace('mstore(add(pointPtr,32),rev)','mstore(add(pointPtr,32),sr)')
   lines=lines[:sq]+lines[sq+2:]
   lines.insert(2,storeline);lines.insert(2,sqline)
   s=s.replace(f,'\n'.join(lines))
  variants.append(name);text+=s+'\n'
path.write_text(text)
# regenerate test ordering for all variants
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
p.write_text(test)
print(names)
