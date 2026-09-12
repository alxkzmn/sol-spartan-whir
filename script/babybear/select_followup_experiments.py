#!/usr/bin/env python3
"""Reproduce the paired-cubic select experiment without editing production code.

Default output is two test-only Solidity files. With --out-dir NEW_DIRECTORY,
create a standalone Foundry workspace using symlinks to the repository src/lib.
The 64-bit packed cubic evaluations use canonical inputs and coefficients.
See select_followup_bounds.py for the whole-domain integer argument.
"""
from pathlib import Path
import sys,re,shutil,json,subprocess,hashlib
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'script/babybear'))
from generate_select_variants import function
import argparse,tempfile
ap=argparse.ArgumentParser(description="Generate select factoring experiments and independent tests; --out-dir creates an isolated Foundry workspace.")
ap.add_argument('--out-dir',type=Path)
args=ap.parse_args()
W=args.out_dir.resolve() if args.out_dir else Path(tempfile.mkdtemp(prefix='babybear-select-generation-'))
W.mkdir(parents=True,exist_ok=True)
for d in ['src','lib']:
 if not (W/d).exists():(W/d).symlink_to(ROOT/d,target_is_directory=True)
(W/'test/helpers').mkdir(parents=True,exist_ok=True)
shutil.copy2(ROOT/'foundry.toml',W/'foundry.toml')
for p in (ROOT/'test/helpers').glob('BabyBear*.sol'):shutil.copy2(p,W/'test/helpers'/p.name)
s=(W/'test/helpers/BabyBearSelectForms.sol').read_text()
start=s.index('library BabyBearSelectForms {');end=s.index('library KoalaBearSelectFormsPackedHorner {')
base=s[start:end]
def yulbody(fn):return fn[fn.index('assembly ("memory-safe") {')+len('assembly ("memory-safe") {'):fn.rindex('}')].rstrip().removesuffix('}').rstrip()
body=re.sub(r'\blow\b','convLow',yulbody(function(base,'_multiply')))
variants=[]
for suffix in ['Inline','Singles','AssemblyLoop']:
 c=base.replace('BabyBearSelectForms','BabyBearSelect'+suffix)
 if suffix=='Singles':
  old=function(c,'_selectPolyEvalFixedPair')
  new=old[:old.index('{')+1]+ '\n return (_selectPolyEvalFixed(current0,cache,offset,n),_selectPolyEvalFixed(current1,cache,offset,n));\n }'
  c=c.replace(old,new)
 elif suffix=='Inline':
  for low,rev,cur in [('low','rev','current'),('low0','rev0','current0'),('low1','rev1','current1')]:
   b=body
   for a,v in [('aLow',low),('aRev',rev),('scalar',f'add({cur},0x78000000)'),('lowOut',low),('revOut',rev)]: b=re.sub(r'\b'+a+r'\b',v,b)
   c=re.sub(r'\('+low+r',\s*'+rev+r'\)\s*=\s*_multiply\('+low+r',\s*'+rev+r',\s*ptr,\s*'+cur+r'\s*\+\s*\(0x78000001\s*-\s*1\)\);',lambda m:'assembly ("memory-safe") {\n'+b+'\n}',c)
 elif suffix=='AssemblyLoop':
  for name in ['_selectPolyEvalFixed','_selectPolyEvalFixedPair']:
   old=function(c,name); new=old
   loopstart=new.index('            for (uint256 i = n - 1; i > 0; --i) {')
   loopend=new.index('\n            }',loopstart)+len('\n            }')
   pairs=[('low','rev','current')] if name.endswith('Fixed') else [('low0','rev0','current0'),('low1','rev1','current1')]
   loop='            assembly ("memory-safe") { for { let i := sub(n,1) } i {i:=sub(i,1)} { ptr:=sub(ptr,96)\n'
   for low,rev,cur in pairs:
    b=body
    for a,v in [('aLow',low),('aRev',rev),('scalar',f'add({cur},0x78000000)'),('lowOut',low),('revOut',rev)]:b=re.sub(r'\b'+a+r'\b',v,b)
    loop+=f'{cur}:=mulmod({cur},{cur},0x78000001)\n{{\n'+b+'\n}\n'
   loop+='}}'
   new=new[:loopstart]+loop+new[loopend:];c=c.replace(old,new)
 variants.append(c)
header=s[:s.index('library KoalaBearSelectForms {')]
(W/'test/helpers/BabyBearSelectFollowup.sol').write_text(header+base+'\n'.join(variants))
names=['Forms','Inline','Singles','AssemblyLoop']
test='''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import {Test} from "forge-std/Test.sol";
import {BabyBearReference as Ref} from "./helpers/BabyBearReference.sol";
import {'''+','.join('BabyBearSelect'+n+'Harness' for n in names)+'''} from "./helpers/BabyBearSelectFollowup.sol";
interface H {function batch(uint256[] memory,uint256[][3] memory,uint256[3] memory,uint256[3] memory) external view returns(uint256,uint256[3] memory);function chains(uint256[] memory,uint256,uint256,uint256,uint256) external view returns(uint256,uint256,uint256);function single(uint256[] memory,uint256,uint256,uint256) external pure returns(uint256);}
contract SelectFollowupTest is Test {
 uint256 constant Q=0x78000001;
 H['''+str(len(names))+'''] h;
 function setUp() external {'''+''.join(f'h[{i}]=H(address(new BabyBearSelect{n}Harness()));' for i,n in enumerate(names))+'''}
 function point(bytes32 seed) private pure returns(uint256[] memory p){p=new uint256[](22);for(uint256 i;i<22;++i){uint256[5] memory a;for(uint256 j;j<5;++j)a[j]=uint256(keccak256(abi.encode(seed,i,j)))%Q;p[i]=Ref.pack(a);}}
 function inputs() private pure returns(uint256[] memory p,uint256[][3] memory s,uint256[3] memory c,uint256[3] memory eq){p=point(bytes32(uint256(20260905)));uint256[3] memory counts=[uint256(38),31,19];for(uint256 r;r<3;++r){s[r]=new uint256[](counts[r]);for(uint256 i;i<counts[r];++i)s[r][i]=uint256(keccak256(abi.encode(r,i)))%Q;c[r]=p[r];eq[r]=p[r+3];}}
 function testBenchmark() external{(uint256[] memory p,uint256[][3] memory s,uint256[3] memory c,uint256[3] memory eq)=inputs();(,uint256[3] memory expected)=h[0].batch(p,s,c,eq);'''
for i,n in enumerate(names): test+=f'{{(uint256 gasUsed,uint256[3] memory result)=h[{i}].batch(p,s,c,eq);emit log_named_uint("{n}",gasUsed);assertEq(abi.encode(result),abi.encode(expected));}}'
test+='''}
function testFuzzChains(bytes32 seed,uint256 a,uint256 b) external view{uint256[] memory p=point(seed);a%=Q;b%=Q;for(uint256 n=10;n<=18;n+=4){uint256 expected=Ref.chain(a,p,22-n,n,Q,1);uint256 expectedB=Ref.chain(b,p,22-n,n,Q,1);for(uint256 i;i<h.length;++i){(,uint256 x,uint256 y)=h[i].chains(p,a,b,22-n,n);assertEq(x,expected);assertEq(y,expectedB);assertEq(h[i].single(p,a,22-n,n),expected);}}}
function testBoundaryChains() external view {uint256[] memory p=new uint256[](22);for(uint256 j;j<22;++j)p[j]=Ref.pack([Q-1,Q-1,Q-1,Q-1,Q-1]);for(uint256 n;n<=18;n+=9){uint256 ex=Ref.chain(0,p,22-n,n,Q,1);uint256 ey=Ref.chain(Q-1,p,22-n,n,Q,1);for(uint256 i;i<h.length;++i){(,uint256 x,uint256 y)=h[i].chains(p,0,Q-1,22-n,n);assertEq(x,ex);assertEq(y,ey);}}}
}'''
(W/'test/SelectFollowup.t.sol').write_text(test)
print(W)

c=base.replace('BabyBearSelectForms','BabyBearSelectCubics')
product=function(c,'_multiply').replace('uint256 ptr, uint256 scalar','uint256 bLow, uint256 bRev')
product=product.replace('            let bLow := mload(ptr)\n','').replace('mload(add(ptr, 32))','or(shr(64,bLow),shl(192,and(bRev,0xffffffff)))').replace('mload(add(ptr, 64))','bRev')
for i,a in enumerate(['and(aLow, 0xffffffff)','and(shr(64, aLow), 0xffffffff)','and(shr(128, aLow), 0xffffffff)','shr(192, aLow)','and(aRev, 0xffffffff)']):
 reduction=['add(c0, shl(1, c5))','add(c1, shl(1, c6))','add(c2, shl(1, c7))','add(c3, shl(1, c8))','c4'][i]
 product=re.sub(r'let o'+str(i)+r' :=[\s\S]*?(?=\n            let |\n            lowOut)',f'let o{i} := mod({reduction},M)',product,count=1)
c=c.replace(function(c,'_multiply'),product)
old=function(c,'_selectPolyEvalFixed')
c=c.replace(old,'''    function _selectPolyEvalFixed(uint256 current,uint256[] memory cache,uint256,uint256 n) internal pure returns(uint256){
 if(n==0)return uint256(1)<<224;
 uint256 ptr;assembly("memory-safe"){ptr:=add(cache,1312)}
 (uint256 low,uint256 rev,uint256 next)=_factor(ptr,current);
 unchecked {for(uint256 i=n/2-1;i>0;--i){ptr-=160;uint256 bLow;uint256 bRev;(bLow,bRev,next)=_factor(ptr,next);(low,rev)=_multiply(low,rev,bLow,bRev);}}
 return _pack(low,rev);
 }''')
old=function(c,'_selectPolyEvalFixedPair')
c=c.replace(old,'''    function _selectPolyEvalFixedPair(uint256 a,uint256 b,uint256[] memory cache,uint256 offset,uint256 n) internal pure returns(uint256,uint256){return (_selectPolyEvalFixed(a,cache,offset,n),_selectPolyEvalFixed(b,cache,offset,n));}''')
new='''    function _factor(uint256 ptr,uint256 x) private pure returns(uint256 lowOut,uint256 revOut,uint256 next) {
 assembly("memory-safe") {
 let M:=0x78000001
 let x2:=mulmod(x,x,M)
 let x3:=mulmod(x2,x,M)
 next:=mulmod(x2,x2,M)
 let low:=add(add(mload(ptr),mul(mload(add(ptr,32)),x)),add(mul(mload(add(ptr,64)),x2),mul(mload(add(ptr,96)),x3)))
 let last:=shr(192,mul(mload(add(ptr,128)),or(or(x3,shl(64,x2)),or(shl(128,x),shl(192,1)))))
 let o0:=mod(and(low,0xffffffffffffffff),M)
 let o1:=mod(and(shr(64,low),0xffffffffffffffff),M)
 let o2:=mod(and(shr(128,low),0xffffffffffffffff),M)
 let o3:=mod(shr(192,low),M)
 let o4:=mod(last,M)
 lowOut:=or(or(o0,shl(64,o1)),or(shl(128,o2),shl(192,o3)))
 revOut:=or(or(o4,shl(64,o3)),or(shl(128,o2),shl(192,o1)))
 }
 }
 function prepare(uint256[] memory point) internal pure returns(uint256[] memory cache) {
 cache=new uint256[](45);
 for(uint256 i;i<9;++i){uint256 r=point[2*i+5];uint256 s=point[2*i+4];uint256 d=BabyBearBenchField.mul(r,s);uint256 b=BabyBearBenchField.sub(r,d);uint256 cc=BabyBearBenchField.sub(s,d);uint256 a=BabyBearBenchField.add(BabyBearBenchField.sub(BabyBearBenchField.sub(uint256(1)<<224,r),s),d);
 uint256 ptr;assembly("memory-safe"){ptr:=add(add(cache,32),mul(i,160))}
 _storeLow(ptr,a);_storeLow(ptr+32,b);_storeLow(ptr+64,cc);_storeLow(ptr+96,d);
 assembly("memory-safe"){mstore(add(ptr,128),or(or(and(shr(96,a),0xffffffff),shl(64,and(shr(96,b),0xffffffff))),or(shl(128,and(shr(96,cc),0xffffffff)),shl(192,and(shr(96,d),0xffffffff)))))}
 }
 }
 function _storeLow(uint256 ptr,uint256 b) private pure {assembly("memory-safe"){mstore(ptr,or(or(shr(224,b),shl(64,and(shr(192,b),0xffffffff))),or(shl(128,and(shr(160,b),0xffffffff)),shl(192,and(shr(128,b),0xffffffff)))))}}
'''
idx=c.index('contract BabyBearSelectCubicsHarness')
c=c[:idx].rstrip().removesuffix('}')+new+'}\n'+c[idx:]
# Wrappers fall back for non-paired generic windows; fixed batch uses every cubic.
c=c.replace('BabyBearSelectPrepackedCombined.prepare(point)','BabyBearSelectCubics.prepare(point)')
fn=function(c,'chains');sfn=fn.replace('uint256 start = gasleft();','''if(n%2!=0 || offset+n!=22){uint256 t=gasleft();(x,y)=BabyBearSelectForms._selectPolyEvalFixedPair(a,b,BabyBearSelectPrepackedCombined.prepare(point),offset,n);return(t-gasleft(),x,y);}
        uint256 start = gasleft();''');c=c.replace(fn,sfn)
fn=function(c,'single');sfn=fn.replace('        return BabyBearSelectCubics.', '''        if(n%2!=0 || offset+n!=22)return BabyBearSelectForms._selectPolyEvalFixed(a,BabyBearSelectPrepackedCombined.prepare(point),offset,n);
        return BabyBearSelectCubics.''');c=c.replace(fn,sfn)
p=W/'test/helpers/BabyBearSelectFollowup.sol';p.write_text(p.read_text()+c)
p=W/'test/SelectFollowup.t.sol';t=p.read_text().replace('BabyBearSelectAssemblyLoopHarness}', 'BabyBearSelectAssemblyLoopHarness,BabyBearSelectCubicsHarness}').replace('H[4] h;','H[5] h;').replace('function setUp() external {','function setUp() external {h[4]=H(address(new BabyBearSelectCubicsHarness()));')
marker='function testFuzzChains';pos=t.index(marker);prev=t.rfind('}',0,pos)
t=t[:prev]+'''{(uint256 gasUsed,uint256[3] memory result)=h[4].batch(p,s,c,eq);emit log_named_uint("Cubics",gasUsed);assertEq(abi.encode(result),abi.encode(expected));}'''+t[prev:]
p.write_text(t)

# Koala control of the same cubic factoring.
k=c.replace('BabyBear','KoalaBear').replace('KoalaBearBenchField','KoalaBearExt5').replace('0x78000001','0x7f000001')
f=function(k,'_multiply').replace('let c8 := and(high, 0xffffffffffffffff)','let c8 := and(high, 0xffffffffffffffff)\n let bias:=shl(40,M)')
rs=['add(add(c0,c5),sub(bias,c8))','add(c1,c6)','add(add(add(c2,sub(bias,c5)),c7),c8)','add(add(c3,sub(bias,c6)),c8)','add(c4,sub(bias,c7))']
for i,r in enumerate(rs):f=re.sub(r'let o'+str(i)+r' :=[\s\S]*?(?=\n            let |\n            lowOut)',f'let o{i} := mod({r},M)',f,count=1)
k=k.replace(function(k,'_multiply'),f)
p=W/'test/helpers/BabyBearSelectFollowup.sol';p.write_text(p.read_text().replace('import { BabyBearBenchField,','import { KoalaBearSelectPrepackedCombined, BabyBearBenchField,')+'\nimport {KoalaBearSelectForms} from "./BabyBearSelectForms.sol";\n'+k)
t=(W/'test/SelectFollowup.t.sol').read_text().replace('BabyBearSelectCubicsHarness}','BabyBearSelectCubicsHarness,KoalaBearSelectCubicsHarness}')
t=t.replace('H[5] h;','H[5] h; H kh;').replace('function setUp() external {','function setUp() external {kh=H(address(new KoalaBearSelectCubicsHarness()));')
pos=t.index('function testFuzzChains');prev=t.rfind('}',0,pos)
t=t[:prev]+'''{(uint256 gasUsed,)=kh.batch(p,s,c,eq);emit log_named_uint("KoalaCubics",gasUsed);}'''+t[prev:]
pos=t.rfind('}')
t=t[:pos]+'''function testFuzzKoala(bytes32 seed,uint256 a,uint256 b) external view {uint256 P=0x7f000001;uint256[] memory p=new uint256[](22);for(uint256 i;i<22;++i){uint256[5] memory v;for(uint256 j;j<5;++j)v[j]=uint256(keccak256(abi.encode(seed,i,j)))%P;p[i]=Ref.pack(v);}a%=P;b%=P;for(uint256 n=10;n<=18;n+=4){uint256 ex=Ref.chain(a,p,22-n,n,P,0);uint256 ey=Ref.chain(b,p,22-n,n,P,0);(,uint256 x,uint256 y)=kh.chains(p,a,b,22-n,n);assertEq(x,ex);assertEq(y,ey);}}
'''+t[pos:]
(W/'test/SelectFollowup.t.sol').write_text(t)

extras=[]
for suffix in ['PackedHorner']:
 cc=c.replace('BabyBearSelectCubics','BabyBearSelectCubics'+suffix)
 if 'PackedHorner' in suffix:
  old=function(cc,'_hornerStep');cc=cc.replace(old,old.replace('BabyBearBenchField.mul','BabyBearPackedField.mul'))
 if 'Fused' in suffix:
  factorbody=yulbody(function(cc,'_factor').replace('assembly("memory-safe")','assembly ("memory-safe")'))
  factorbody=re.sub(r'\blowOut\b','bLow',factorbody);factorbody=re.sub(r'\brevOut\b','bRev',factorbody)
  productbody=yulbody(function(cc,'_multiply'))
  step='''    function _step(uint256 aLow,uint256 aRev,uint256 ptr,uint256 x) private pure returns(uint256 lowOut,uint256 revOut,uint256 next) {assembly("memory-safe"){let bLow let bRev\n{\n'''+factorbody+'\n}\n{\n'+productbody+'\n}\n}}\n'
  idx=cc.index('contract BabyBearSelectCubics'+suffix+'Harness')
  cc=cc[:idx].rstrip().removesuffix('}')+step+'}\n'+cc[idx:]
  cc=cc.replace('uint256 bLow;uint256 bRev;(bLow,bRev,next)=_factor(ptr,next);(low,rev)=_multiply(low,rev,bLow,bRev);','(low,rev,next)=_step(low,rev,ptr,next);')
 extras.append(cc)
p=W/'test/helpers/BabyBearSelectFollowup.sol';p.write_text(p.read_text()+'\n'.join(extras))
p=W/'test/SelectFollowup.t.sol';t=p.read_text().replace('KoalaBearSelectCubicsHarness}',','.join(['KoalaBearSelectCubicsHarness']+['BabyBearSelectCubics'+n+'Harness' for n in ['PackedHorner']])+'}').replace('H[5] h;','H[6] h;')
t=t.replace('function setUp() external {','function setUp() external {'+''.join(f'h[{i+5}]=H(address(new BabyBearSelectCubics{n}Harness()));' for i,n in enumerate(['PackedHorner'])))
pos=t.index('function testFuzzChains');prev=t.rfind('}',0,pos)
for i,n in enumerate(['PackedHorner']):
 chunk=f'{{(uint256 gasUsed,uint256[3] memory result)=h[{i+5}].batch(p,s,c,eq);emit log_named_uint("{n}",gasUsed);assertEq(abi.encode(result),abi.encode(expected));}}'
 t=t[:prev]+chunk+t[prev:];prev+=len(chunk)
p.write_text(t)

# Additional independent boundary and profiling checks for the retained factoring.
p=W/'test/SelectFollowup.t.sol'
t=p.read_text()
t=t.replace('contract SelectFollowupTest is Test', 'contract BabyBearSelectFollowupTest is Test')
pos=t.rfind('}')
t=t[:pos]+"""
function testCubicBasisAndMaxima() external view {
 for(uint256 f;f<2;++f){uint256 m=f==0?Q:0x7f000001;H target=f==0?h[4]:kh;
 uint256[] memory p=new uint256[](22);
 for(uint256 a;a<5;++a)for(uint256 b;b<5;++b){for(uint256 j;j<22;++j)p[j]=(m-1)<<(224-32*(j%2==0?a:b));
 (,uint256 x,uint256 y)=target.chains(p,0,m-1,4,18);
 assertEq(x,Ref.chain(0,p,4,18,m,f==0?1:0));assertEq(y,Ref.chain(m-1,p,4,18,m,f==0?1:0));}
 for(uint256 j;j<22;++j)p[j]=Ref.pack([m-1,m-1,m-1,m-1,m-1]);
 for(uint256 n;n<=18;n+=2){(,uint256 x,uint256 y)=target.chains(p,1,m-1,22-n,n);
 assertEq(x,Ref.chain(1,p,22-n,n,m,f==0?1:0));assertEq(y,Ref.chain(m-1,p,22-n,n,m,f==0?1:0));}
 }
}
function testProfileCubicBabyBear() external view {(uint256[] memory p,uint256[][3] memory s,uint256[3] memory c,uint256[3] memory eq)=inputs();(,uint256[3] memory r)=h[4].batch(p,s,c,eq);assertTrue(r[0]!=0);}
function testProfileBaselineBabyBear() external view {(uint256[] memory p,uint256[][3] memory s,uint256[3] memory c,uint256[3] memory eq)=inputs();(,uint256[3] memory r)=h[0].batch(p,s,c,eq);assertTrue(r[0]!=0);}
"""+t[pos:]
p.write_text(t)
helper=W/'test/helpers/BabyBearSelectFollowup.sol'
helper.write_text(helper.read_text().replace('// Generated by script/babybear/generate_select_forms.py.','// Generated by script/babybear/select_followup_experiments.py.\n// Adjacent select factors are expanded as A+B*x+C*x^2+D*x^3.'))
subprocess.run(['forge','fmt',str(helper),str(p)],cwd=W,check=True,stdout=subprocess.DEVNULL)
if args.out_dir is None:
 shutil.copy2(helper,ROOT/'test/helpers/BabyBearSelectFollowup.sol')
 shutil.copy2(p,ROOT/'test/BabyBearSelectFollowup.t.sol')
 shutil.rmtree(W)
else:
 p.rename(W/'test/BabyBearSelectFollowup.t.sol')
