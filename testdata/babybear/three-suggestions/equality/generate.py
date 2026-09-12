from pathlib import Path
import re,os
root=Path(os.environ['EQ_SOURCE_ROOT']).resolve()
out=Path(os.environ.get('EQ_OUTPUT_ROOT',str(Path(__file__).with_name('workspace')))).resolve()
src=(root/'test/helpers/BabyBearEqFollowup.sol').read_text()

def block(text, marker):
 start=text.index(marker); brace=text.index('{',start); depth=1; i=brace+1
 while depth:
  depth+=(text[i]=='{')-(text[i]=='}');i+=1
 return text[start:i]

def fn(text,name): return block(text,'    function '+name+'(')
header=src[:src.index('library KoalaBearEqShifted')]
variants=[]; alltext=header
for field,base,packed,p in [('KoalaBear','KoalaBearExt5','KoalaBearPackedField',0x7f000001),('BabyBear','BabyBearBenchField','BabyBearPackedField',0x78000001)]:
 orig=block(src,'library '+field+'EqShifted {')+'\n'+block(src,'contract '+field+'EqShiftedHarness {')
 name=field+'EqPackedSquare'
 s=orig.replace(field+'EqShifted',name).replace(base+'.square',packed+'.square')
 variants.append(name);alltext+=s+'\n'
 # Persistent low/reverse forms for the OOD points. Store one point alongside
 # the matching accumulator so no transport encoding is needed per iteration.
 name=field+'EqPersistent'
 s=orig.replace(field+'EqShifted',name)
 old=fn(s,'_eqForms')
 eq=old.replace('uint256 acc, uint256[4]','uint256 aLow, uint256 aRev, uint256[4]')
 begin=eq.index('                let a0 :=')
 end=eq.index('                c4 :=',begin)
 eq=eq[:begin]+'''                let a0 := mod(add(and(aLow,0xffffffff),shr(1,M)),M)
                aLow := or(and(aLow,not(0xffffffff)),a0)
                let a4 := and(aRev,0xffffffff)
                let bLow := mload(cache)
'''+eq[end:]
 eq=eq.replace('or(or(a4,shl(64,a3)),or(shl(128,a2),shl(192,a1)))','aRev')
 s=s.replace(old,eq)
 # Standalone eq wrapper still accepts transport values.
 s=s.replace('(uint256 low,uint256 rev)=_eqForms(a,cache);','(uint256 al,uint256 ar)=_unpackForms(a); (uint256 low,uint256 rev)=_eqForms(al,ar,cache);')
 s=s.replace('uint256[10] memory state','uint256[18] memory state')
 # Helpers for OOD states at indexes 5..8.
 helpers='''
    function _unpackForms(uint256 a) private pure returns(uint256 low,uint256 rev) {
        assembly("memory-safe") {
            let a0:=shr(224,a) let a1:=and(shr(192,a),0xffffffff) let a2:=and(shr(160,a),0xffffffff) let a3:=and(shr(128,a),0xffffffff) let a4:=and(shr(96,a),0xffffffff)
            low:=or(or(a0,shl(64,a1)),or(shl(128,a2),shl(192,a3)))
            rev:=or(or(a4,shl(64,a3)),or(shl(128,a2),shl(192,a1)))
        }
    }
    function _setPoint(uint256 ptr,uint256 a) private pure { (uint256 low,uint256 rev)=_unpackForms(a); assembly("memory-safe"){mstore(ptr,low) mstore(add(ptr,32),rev)} }
    function _pointEq(uint256 ptr,uint256 pointPtr,uint256[4] memory cache,bool initial) private pure {
        uint256 al;uint256 ar;assembly("memory-safe"){al:=mload(pointPtr) ar:=mload(add(pointPtr,32))}
        (uint256 low,uint256 rev)=_eqForms(al,ar,cache);
        if(!initial){uint256 sl;uint256 sr;assembly("memory-safe"){sl:=mload(ptr) sr:=mload(add(ptr,32))} (low,rev)=_mulForms(sl,sr,low,rev);}
        assembly("memory-safe"){mstore(ptr,low) mstore(add(ptr,32),rev)}
        (low,rev)=_mulForms(al,ar,al,ar);
        assembly("memory-safe"){mstore(pointPtr,low) mstore(add(pointPtr,32),rev)}
    }
'''
 s=s.replace('    function _eqForms(',helpers+'    function _eqForms(',1)
 for index,current in enumerate(['initialCurrent','round0Current','round1Current','round2Current']):
  source=['initialOodPoint','round0OodPoint','round1OodPoint','round2OodPoint'][index]
  s=s.replace('        uint256 '+current+' = '+source+';','')
  s=s.replace('        uint256[4] memory cache;','        uint256[4] memory cache;\n        _setPoint(_stateAt(state,'+str(5+index)+'),'+source+');',1)
  s=s.replace('_initialEqAt(_stateAt(state,'+str(index+1)+'),'+current+',cache);','_pointEq(_stateAt(state,'+str(index+1)+'),_stateAt(state,'+str(index+5)+'),cache,true);')
  s=s.replace('_accEqAt(_stateAt(state,'+str(index+1)+'),'+current+',cache);','_pointEq(_stateAt(state,'+str(index+1)+'),_stateAt(state,'+str(index+5)+'),cache,false);')
  s=re.sub(r'\s*'+current+' = '+base+r'\.square\('+current+r'\);','',s)
 variants.append(name);alltext+=s+'\n'
 # U=5 canonical coefficients at51-bit offsets. A single word persists per
 # point/accumulator, with3MULMOD images for multiplication and square.
 name=field+'EqMulmod'
 s=orig.replace(field+'EqShifted',name)
 B=1<<51; K=1<<42; T=1<<16; modulus=B**5-2 if field=='BabyBear' else B**5+B**2-1
 lowmask=sum(65535*B**i for i in range(5));himask=sum(32767*B**i for i in range(5));bias=K*sum(B**i for i in range(5))
 def reconstruction(eq=False):
  z=''
  if field=='KoalaBear': z+=f'lo:=addmod(lo,{bias},{modulus}) hi:=addmod(hi,{bias},{modulus}) ss:=addmod(ss,{bias},{modulus})\n'
  for i in range(5):
   ex=lambda x:f'and(shr({51*i},{x}),{B-1})'
   if field=='BabyBear': expr=f'add(add(l,shl(16,sub(sub(t,l),h))),shl(32,h))'
   else: expr=f'sub(add(add(add(l,shl(16,t)),shl(32,h)),{(p<<64)+K*(T-1-T*T)}),shl(16,add(l,h)))'
   if eq: expr=f'add(shl(1,{expr}),{(p+1)//2 if i==0 else 0})'
   z+=f'{{ let l:={ex("lo")} let h:={ex("hi")} let t:={ex("ss")} out:=or(out,shl({51*i},mod({expr},M))) }}\n'
  return z
 mul='''    function _mulU(uint256 a,uint256 b) private pure returns(uint256 out) { assembly("memory-safe") {
 let M:=@P@ let lm:=@LM@ let hm:=@HM@ let mm:=@MM@
 let al:=and(a,lm) let ah:=and(shr(16,a),hm) let bl:=and(b,lm) let bh:=and(shr(16,b),hm)
 let lo:=mulmod(al,bl,mm) let hi:=mulmod(ah,bh,mm) let ss:=mulmod(add(al,ah),add(bl,bh),mm)
 @RECON@
 } }
'''.replace('@RECON@',reconstruction())
 equ='''    function _eqU(uint256 a,uint256[4] memory cache) private pure returns(uint256 out) { assembly("memory-safe") {
 let M:=@P@ let lm:=@LM@ let hm:=@HM@ let mm:=@MM@
 a:=or(and(a,not(0xffffffff)),mod(add(and(a,0xffffffff),shr(1,M)),M))
 let al:=and(a,lm) let ah:=and(shr(16,a),hm)
 let lo:=mulmod(al,mload(cache),mm) let hi:=mulmod(ah,mload(add(cache,32)),mm) let ss:=mulmod(add(al,ah),mload(add(cache,64)),mm)
 @RECON@
 } }
'''.replace('@RECON@',reconstruction(True))
 extra=mul+equ+'''    function _toU(uint256 a) private pure returns(uint256 u) { assembly("memory-safe") { @TOU@ } }
    function _fromU(uint256 a) private pure returns(uint256 u) { assembly("memory-safe") { @FROMU@ } }
'''.replace('@TOU@',' '.join(f'u:=or(u,shl({51*i},and(shr({224-32*i},a),0xffffffff)))' for i in range(5))).replace('@FROMU@',' '.join(f'u:=or(u,shl({224-32*i},and(shr({51*i},a),0xffffffff)))' for i in range(5)))
 extra=extra.replace('@P@',str(p)).replace('@LM@',str(lowmask)).replace('@HM@',str(himask)).replace('@MM@',str(modulus))
 for f in ['_eqForms','_mulForms','_eqCached','_initialEqAt','_accEqAt','_packAt','_prepare','_packForms']:
  s=s.replace(fn(s,f),'')
 helpers='''
    function _initialEqAt(uint256 ptr,uint256 a,uint256[4] memory cache) private pure {uint256 r=_eqU(_toU(a),cache);assembly("memory-safe"){mstore(ptr,r)}}
    function _accEqAt(uint256 ptr,uint256 a,uint256[4] memory cache) private pure {uint256 r=_eqU(_toU(a),cache);uint256 prev;assembly("memory-safe"){prev:=mload(ptr)}r=_mulU(prev,r);assembly("memory-safe"){mstore(ptr,r)}}
    function _pointEq(uint256 ptr,uint256 pointPtr,uint256[4] memory cache,bool initial) private pure {
     uint256 a;assembly("memory-safe"){a:=mload(pointPtr)} uint256 r=_eqU(a,cache);
     if(!initial){uint256 prev;assembly("memory-safe"){prev:=mload(ptr)}r=_mulU(prev,r);}
     assembly("memory-safe"){mstore(ptr,r)} r=_mulU(a,a); assembly("memory-safe"){mstore(pointPtr,r)}
    }
    function _setPoint(uint256 ptr,uint256 a) private pure {uint256 u=_toU(a);assembly("memory-safe"){mstore(ptr,u)}}
    function _packAt(uint256 ptr) private pure returns(uint256){uint256 r;assembly("memory-safe"){r:=mload(ptr)}return _fromU(r);}
    function _prepare(uint256 q,uint256[4] memory cache) internal pure {q=_toU(q);assembly("memory-safe"){
      q:=or(and(q,not(0xffffffff)),mod(add(and(q,0xffffffff),@HALF@),@P@))
      let lo:=and(q,@LM@) let hi:=and(shr(16,q),@HM@) mstore(cache,lo) mstore(add(cache,32),hi) mstore(add(cache,64),add(lo,hi))
    }}
'''.replace('@HALF@',str(p//2)).replace('@P@',str(p)).replace('@LM@',str(lowmask)).replace('@HM@',str(himask))
 s=s.replace(fn(s,'_eqTerm'),'    function _eqTerm(uint256 a,uint256 b) internal pure returns(uint256){uint256[4] memory cache;_prepare(b,cache);return _fromU(_eqU(_toU(a),cache));}')
 s=s.replace('    function _stateAt(',extra+helpers+'    function _stateAt(',1)
 s=s.replace('uint256[10] memory state','uint256[18] memory state')
 for index,current in enumerate(['initialCurrent','round0Current','round1Current','round2Current']):
  source=['initialOodPoint','round0OodPoint','round1OodPoint','round2OodPoint'][index]
  s=s.replace('        uint256 '+current+' = '+source+';','')
  s=s.replace('        uint256[4] memory cache;','        uint256[4] memory cache;\n        _setPoint(_stateAt(state,'+str(5+index)+'),'+source+');',1)
  s=s.replace('_initialEqAt(_stateAt(state,'+str(index+1)+'),'+current+',cache);','_pointEq(_stateAt(state,'+str(index+1)+'),_stateAt(state,'+str(index+5)+'),cache,true);')
  s=s.replace('_accEqAt(_stateAt(state,'+str(index+1)+'),'+current+',cache);','_pointEq(_stateAt(state,'+str(index+1)+'),_stateAt(state,'+str(index+5)+'),cache,false);')
  s=re.sub(r'\s*'+current+' = '+base+r'\.square\('+current+r'\);','',s)
 variants.append(name);alltext+=s+'\n'
(out/'test/helpers/BabyBearEqThird.sol').write_text(alltext)
# Derive an independent test fixture harness from the existing oracle test.
test=(root/'test/BabyBearEqFollowup.t.sol').read_text()
names=[]
for field in ['KoalaBear','BabyBear']:
 names.append(field+'EqShifted');names += [v for v in variants if v.startswith(field)]
test=test.replace('IEqHarness[6] h','IEqHarness[8] h').replace('BabyBearEqFollowupTest','BabyBearEqThirdTest')
start=test.index('    function setUp()');end=test.index('    function _canonical',start)
test=test[:start]+'    function setUp() external {\n'+''.join(f'h[{i}]=IEqHarness(address(new {v}Harness()));\n' for i,v in enumerate(names))+'}\n'+test[end:]
test=test.replace('i < 6','i < 8').replace('i < 3','i < 4').replace('f == 0 ? 0 : 3','f == 0 ? 0 : 4').replace('f == 0 ? 3 : 6','f == 0 ? 4 : 8')
test=re.sub(r'string\[6\] memory names = \[.*?\];','string[8] memory names = ['+','.join('"'+v+'"' for v in names)+'];',test)
test=test.replace('import { Test }','import {'+','.join(v+'Harness' for v in variants)+'} from "./helpers/BabyBearEqThird.sol";\nimport { Test }')
(out/'test/BabyBearEqThird.t.sol').write_text(test)
print(names)
