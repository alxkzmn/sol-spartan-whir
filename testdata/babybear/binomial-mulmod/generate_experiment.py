#!/usr/bin/env python3
"""Create an isolated Foundry workspace; no production writes or builds."""
from pathlib import Path
import sys,re,shutil
import argparse
ap=argparse.ArgumentParser(description='Reproduce isolated BabyBear and KoalaBear three-MULMOD row experiments.')
ap.add_argument('--repo',type=Path,default=Path.cwd())
ap.add_argument('--out-dir',type=Path,required=True)
args=ap.parse_args()
ROOT=args.repo.resolve();sys.path.insert(0,str(ROOT/'script/babybear'))
from generate_select_variants import function
from row_followup import item
W=args.out_dir.resolve();(W/'src/field').mkdir(parents=True,exist_ok=True);(W/'test/helpers').mkdir(parents=True,exist_ok=True)
if not (W/'lib').exists():(W/'lib').symlink_to(ROOT/'lib')
shutil.copy2(ROOT/'foundry.toml',W/'foundry.toml')
for n in ['KoalaBear.sol','KoalaBearExt5.sol']:shutil.copy2(ROOT/'src/field'/n,W/'src/field'/n)
for n in ['BabyBearReference.sol','BabyBearPackedFields.sol']:shutil.copy2(ROOT/'test/helpers'/n,W/'test/helpers'/n)
s=(ROOT/'test/helpers/BabyBearSelectVariants.sol').read_text();s=s[:s.index('library KoalaBearSelectBaseline')];(W/'test/helpers/BabyBearSelectVariants.sol').write_text(s)
s=(ROOT/'test/helpers/BabyBearRowFollowup.sol').read_text();base=item(s,'library','BabyBearRowStreamCombinedFollowup');h=item(s,'contract','BabyBearRowStreamCombinedFollowupHarness');header=s[:s.index('library ')]
new=base.replace('BabyBearRowStreamCombinedFollowup','BabyBearRowMulmod')
N=hex((1<<255)-2);mask=hex((1<<51)-1)
def ors(v):return v[0] if len(v)==1 else f'or({v[0]},{ors(v[1:])})'
def split(a,hi):
 terms=[]
 for i in range(5):
  val=f'and(shr({224-32*i+(16 if hi else 0)},{a}),0xffff)'
  terms.append(val if not i else f'shl({51*i},{val})')
 return ors(terms)
low=split('a',False);high=split('a',True)
old=function(new,'prepare')
new=new.replace(old,f'''    function prepare(uint256 packedPtr) internal pure returns(uint256 ptr){{assembly("memory-safe"){{ptr:=mload(0x40) mstore(0x40,add(ptr,1536)) for{{let i:=0}} lt(i,16){{i:=add(i,1)}}{{let a:=mload(add(packedPtr,shl(5,i))) let dst:=add(ptr,mul(i,96)) let low:={low} let high:={high} mstore(dst,low) mstore(add(dst,32),high) mstore(add(dst,64),add(low,high))}}}}}}''')
acc=f'''function accumulate(a,w,d0,d1,d2)->e0,e1,e2{{let low:={low} let high:={high} e0:=add(d0,mulmod(low,mload(w),{N})) e1:=add(d1,mulmod(high,mload(add(w,32)),{N})) e2:=add(d2,mulmod(add(low,high),mload(add(w,64)),{N}))}}'''
def replace_yul_function(s):
 a=s.index('function accumulate(');b=s.index('{',a)+1;depth=1
 while depth:depth+=(s[b]=='{')-(s[b]=='}');b+=1
 return s[:a]+acc+s[b:]
for fn in ['_hashAndEvaluateExtension5RowDim4BlobUnpacked','_dotExt5Weights16Unpacked','dotArray']:
 old=function(new,fn);changed=replace_yul_function(old)
 changed=re.sub(r'\s*let c3 := 0\s*let c4 := 0','',changed)
 changed=re.sub(r'c0,\s*c1,\s*c2,\s*c3,\s*c4','c0,c1,c2',changed)
 dest='evalValue' if fn.startswith('_hash') else 'out';marker=changed.index(dest+' :=')
 reconstruction='let cross:=sub(sub(c2,c0),c1)\n'
 for i in range(5):
  L=f'and(shr({51*i},c0),{mask})';H=f'and(shr({51*i},c1),{mask})';C=f'and(shr({51*i},cross),{mask})'
  reconstruction+=f'let r{i}:=mod(add(add({L},shl(16,{C})),shl(32,{H})),M)\n'
 changed=changed[:marker]+reconstruction+changed[marker:]
 for i in range(5):changed=re.sub(r'mod\(c'+str(i)+r',\s*M\)',f'r{i}',changed)
 new=new.replace(old,changed)
(W/'test/helpers/Rows.sol').write_text(header+base+'\n'+h+'\n'+new+'\n'+h.replace('BabyBearRowStreamCombinedFollowup','BabyBearRowMulmod'))
t=(ROOT/'test/BabyBearRowFollowup.t.sol').read_text()
# Reuse its independent full-row oracle, deterministic batch inputs and malformed-boundary tests.
start=t.index('contract BabyBearRowFollowupTest')
t=t[start:].replace('BabyBearRowFollowupTest','BabyBearMulmodRowsTest')
t=t.replace('IRowFollowupHarness[8] h;','IRowFollowupHarness[2] h;')
a=t.index('    function setUp()');b=t.index('    function _packed',a)
t=t[:a]+'''    function setUp() external {h[0]=IRowFollowupHarness(address(new BabyBearRowStreamCombinedFollowupHarness()));h[1]=IRowFollowupHarness(address(new BabyBearRowMulmodHarness()));}\n'''+t[b:]
t=t.replace('for (uint256 f; f < 2; ++f)', 'for (uint256 f=1; f < 2; ++f)').replace('for (uint256 i = f == 0 ? 0 : 5; i < (f == 0 ? 5 : 8); ++i)', 'for(uint256 i;i<2;++i)').replace('for (uint256 i; i < 8; ++i)','for(uint256 i;i<2;++i)').replace('h[7].batch','h[1].batch')
a=t.index('        string[8] memory names = [');b=t.index('        uint256[4] memory point;',a)
t=t[:a]+'        string[2] memory names=["BabyCombined","BabyMulmod"];\n'+t[b:]
header='''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import {Test} from "forge-std/Test.sol";
import {BabyBearReference as Ref} from "./helpers/BabyBearReference.sol";
import {BabyBearRowStreamCombinedFollowupHarness,BabyBearRowMulmodHarness} from "./helpers/Rows.sol";
interface IRowFollowupHarness {function batch(bytes calldata,uint256[4] memory,uint256) external view returns(uint256,uint256,uint256,bytes32);function dot(uint256[16] memory,uint256[16] memory) external view returns(uint256,uint256);}
'''
pos=t.rfind('}')
t=t[:pos]+'''function testFuzzIndependentDot(bytes32 seed) external view {uint256[16] memory a;uint256[16] memory b;uint256 expected;for(uint256 i;i<16;++i){a[i]=_packed(seed,i,0x78000001);b[i]=_packed(seed,i+16,0x78000001);expected=Ref.add(expected,Ref.mul(a[i],b[i],0x78000001,1),0x78000001);}for(uint256 j;j<2;++j){(,uint256 actual)=h[j].dot(a,b);assertEq(actual,expected);}}
function testMaximalDotAndBasis() external{uint256 Q=0x78000001;uint256[16] memory a;uint256[16] memory b;uint256 max=Ref.pack([Q-1,Q-1,Q-1,Q-1,Q-1]);for(uint256 i;i<16;++i){a[i]=max;b[i]=max;}uint256 expected=Ref.scale(Ref.mul(max,max,Q,1),16,Q);for(uint256 j;j<2;++j){(uint256 used,uint256 actual)=h[j].dot(a,b);assertEq(actual,expected);emit log_named_uint(j==0?"BabyCombined.dot":"BabyMulmod.dot",used);}for(uint256 i;i<5;++i)for(uint256 j;j<5;++j){for(uint256 z;z<16;++z){a[z]=(Q-1)<<(224-32*i);b[z]=(Q-1)<<(224-32*j);}expected=Ref.scale(Ref.mul(a[0],b[0],Q,1),16,Q);(,uint256 actual)=h[1].dot(a,b);assertEq(actual,expected);}}
'''+t[pos:]
(W/'test/BabyMulmodRows.t.sol').write_text(header+t)
print(W)

U=ors([f'and(shr({224-32*i},a),0xffffffff)' if i==0 else f'shl({51*i},and(shr({224-32*i},a),0xffffffff))' for i in range(5)])
mask16=hex(sum(0xffff<<(51*i) for i in range(5)))
old=f'let low:={low} let high:={high}'
assert new.count(old)==4
u=new.replace('BabyBearRowMulmod','BabyBearRowMulmodUMask').replace(old,f'let u:={U} let low:=and(u,{mask16}) let high:=and(shr(16,u),{mask16})')
p=W/'test/helpers/Rows.sol';p.write_text(p.read_text()+'\n'+u+'\n'+h.replace('BabyBearRowStreamCombinedFollowup','BabyBearRowMulmodUMask'))
p=W/'test/BabyMulmodRows.t.sol';t=p.read_text().replace('BabyBearRowMulmodHarness}', 'BabyBearRowMulmodHarness,BabyBearRowMulmodUMaskHarness}').replace('IRowFollowupHarness[2] h;','IRowFollowupHarness[3] h;').replace('function setUp() external {','function setUp() external {h[2]=IRowFollowupHarness(address(new BabyBearRowMulmodUMaskHarness()));').replace('i<2;++i','i<3;++i').replace('j<2;++j','j<3;++j').replace('string[2] memory names=["BabyCombined","BabyMulmod"]','string[3] memory names=["BabyCombined","BabyMulmod","BabyMulmodUMask"]').replace('h[1].dot(a,b);assertEq(actual,expected);}}','h[2].dot(a,b);assertEq(actual,expected);}}')
p.write_text(t)

source=(ROOT/'test/helpers/BabyBearRowFollowup.sol').read_text()
kbase=item(source,'library','KoalaBearRowCombinedFollowup');kh=item(source,'contract','KoalaBearRowCombinedFollowupHarness');k=kbase.replace('KoalaBearRowCombinedFollowup','KoalaBearRowMulmod')
k=k.replace(function(k,'prepare'),function(u,'prepare'))
NK=hex((1<<255)+(1<<102)-1);K=1<<42;T=1<<16;P=0x7f000001;bias=hex(sum(K<<(51*i) for i in range(5)));C=hex((P<<64)+K*(T-1-T*T))
kacc=f'''function accumulate(a,w,d0,d1,d2)->e0,e1,e2{{let u:={U} let low:=and(u,{mask16}) let high:=and(shr(16,u),{mask16}) e0:=addmod(d0,mulmod(low,mload(w),{NK}),{NK}) e1:=addmod(d1,mulmod(high,mload(add(w,32)),{NK}),{NK}) e2:=addmod(d2,mulmod(add(low,high),mload(add(w,64)),{NK}),{NK})}}'''
for fn in ['_dotExt5Weights16Unpacked','dotArray']:
 old=function(k,fn);a=old.index('function accumulate(');b=old.index('{',a)+1;depth=1
 while depth:depth+=(old[b]=='{')-(old[b]=='}');b+=1
 changed=old[:a]+kacc+old[b:]
 changed=re.sub(r'\s*let c[3-8] := 0','',changed)
 changed=re.sub(r'c0\s*,\s*c1\s*,\s*c2\s*,\s*c3\s*,\s*c4\s*,\s*c5\s*,\s*c6\s*,\s*c7\s*,\s*c8','c0,c1,c2',changed)
 marker=changed.index('            out :=')
 reconstruction='\n'.join(f'c{i}:=addmod(c{i},{bias},{NK})' for i in range(3))+'\n'
 vals=[]
 for i in range(5):
  L=f'and(shr({51*i},c0),{mask})';H=f'and(shr({51*i},c1),{mask})';S=f'and(shr({51*i},c2),{mask})'
  reconstruction+=f'let l{i}:={L} let h{i}:={H} let s{i}:={S}\nlet r{i}:=mod(sub(add(add(add(l{i},shl(16,s{i})),shl(32,h{i})),{C}),shl(16,add(l{i},h{i}))),M)\n'
  vals.append(f'shl({224-32*i},r{i})')
 changed=changed[:marker]+reconstruction+'out:='+ors(vals)+'\n}\n}'
 k=k.replace(old,changed)
p=W/'test/helpers/Rows.sol';p.write_text(p.read_text()+'\n'+kbase+'\n'+kh+'\n'+k+'\n'+kh.replace('KoalaBearRowCombinedFollowup','KoalaBearRowMulmod'))
t=(W/'test/BabyMulmodRows.t.sol').read_text()
a=t.index('import {BabyBearRowStreamCombinedFollowupHarness');b=t.index('\ninterface ',a)
t=t[:a]+'import {KoalaBearRowCombinedFollowupHarness,KoalaBearRowMulmodHarness} from "./helpers/Rows.sol";'+t[b:]
t=t.replace('BabyBearMulmodRowsTest','KoalaMulmodRowsTest').replace('IRowFollowupHarness[3] h;','IRowFollowupHarness[2] h;')
a=t.index('    function setUp()');b=t.index('    function _packed',a)
t=t[:a]+'''    function setUp() external {h[0]=IRowFollowupHarness(address(new KoalaBearRowCombinedFollowupHarness()));h[1]=IRowFollowupHarness(address(new KoalaBearRowMulmodHarness()));}\n'''+t[b:]
t=t.replace('for (uint256 f=1; f < 2; ++f)','for (uint256 f=0; f < 1; ++f)').replace('i<3;++i','i<2;++i').replace('j<3;++j','j<2;++j').replace('h[2].dot','h[1].dot').replace('string[3] memory names=["BabyCombined","BabyMulmod","BabyMulmodUMask"]','string[2] memory names=["KoalaCombined","KoalaMulmod"]')
# Independent direct-dot tests use full Koala canonical range; benchmark retains common Q-bounded inputs.
a=t.index('function testFuzzIndependentDot');pre=t[:a];tail=t[a:].replace('0x78000001','0x7f000001').replace('0x7f000001,1','0x7f000001,0').replace('Q,1','Q,0').replace('BabyCombined.dot','KoalaCombined.dot').replace('BabyMulmod.dot','KoalaMulmod.dot')
t=pre+tail
(W/'test/KoalaMulmodRows.t.sol').write_text(t)
