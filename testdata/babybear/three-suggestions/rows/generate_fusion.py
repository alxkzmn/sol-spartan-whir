from pathlib import Path
import re
root=Path(__file__).resolve().parent
source=(root/'test/helpers/Rows.sol').read_text()

def block(s, key):
    start=s.index(key); op=s.index('{',start); depth=1; j=op+1
    while depth:
        depth+=(s[j]=='{')-(s[j]=='}');j+=1
    return s[start:j]

out='''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import {KoalaBearExt5} from "../../src/field/KoalaBearExt5.sol";
import {BabyBearBenchField} from "./BabyBearSelectVariants.sol";
import {BabyBearPackedField, KoalaBearPackedField} from "./BabyBearPackedFields.sol";
import {BabyBearRowMulmodUMask, KoalaBearRowMulmod} from "./Rows.sol";
'''
for field,old in [('Baby','BabyBearRowMulmodUMask'),('Koala','KoalaBearRowMulmod')]:
    lib=block(source,'library '+old+' {')
    funcs=[]
    for name in ['_computeDim4EqWeights','_storeDim4EqWeightPair','prepare','_hashAndEvaluateExtension5RowDim4BlobUnpacked','_dotExt5Weights16Unpacked','dotArray']:
        fn=block(lib,'function '+name+'(')
        if name=='_hashAndEvaluateExtension5RowDim4BlobUnpacked':
            fn=re.sub(r'function _hashAndEvaluateExtension5RowDim4BlobUnpacked\(.*?\) internal pure', 'function hashAndFold(bytes calldata blob,uint256 offset,uint256 weightsPtr,uint256 claim,uint256 challengePtr) internal pure',fn,count=1,flags=re.S)
            fn=re.sub(r'\n        r\d\d;', '', fn)
            fn=fn.replace('weightsPtr, v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15','weightsPtr, v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, claim, challengePtr')
        elif name=='_dotExt5Weights16Unpacked':
            fn=fn.replace('uint256 v15\n','uint256 v15, uint256 claim, uint256 challengePtr\n')
        elif name=='dotArray':
            fn=fn.replace('uint256[16] memory values)','uint256[16] memory values,uint256 claim,uint256 challengePtr)')
        if 'function accumulate(' in fn:
            acc=block(fn,'function accumulate(')
            fn=fn.replace(acc,acc+'\n            c0,c1,c2 := accumulate(claim,challengePtr,c0,c1,c2)',1)
        funcs.append(fn)
    challenge='''function prepareChallenge(uint256 a) internal pure returns(uint256 ptr) {assembly("memory-safe") {ptr:=mload(0x40) mstore(0x40,add(ptr,96)) let u:=or(and(shr(224,a),0xffffffff),or(shl(51,and(shr(192,a),0xffffffff)),or(shl(102,and(shr(160,a),0xffffffff)),or(shl(153,and(shr(128,a),0xffffffff)),shl(204,and(shr(96,a),0xffffffff)))))) let low:=and(u,0xffff000000001fffe000000003fffc000000007fff800000000ffff) let high:=and(shr(16,u),0xffff000000001fffe000000003fffc000000007fff800000000ffff) mstore(ptr,low) mstore(add(ptr,32),high) mstore(add(ptr,64),add(low,high))}}'''
    out+='\nlibrary '+field+'FusedRow {\n'+'\n'.join(funcs)+'\n'+challenge+'\n}\n'
    for fused in [False,True]:
        name=field+('Fused' if fused else 'Unfused')+'RowHarness'
        candidate=field+'FusedRow'; packed=field+'BearPackedField'
        extra=f'uint256 chPtr={candidate}.prepareChallenge(challenge);' if fused else ''
        zeroargs=','.join(['0']*20)
        regular=f'{old}._hashAndEvaluateExtension5RowDim4BlobUnpacked(blob,(i-1)*320,ptr,{zeroargs})'
        folding=f'(bytes32 h,uint256 next)={candidate}.hashAndFold(blob,(i-1)*320,ptr,result,chPtr); result=next; digest^=h;' if fused else f'(bytes32 h,uint256 row)={regular}; result={packed}.add({packed}.mul(result,challenge),row); digest^=h;'
        dot=f'{candidate}.dotArray(ptr,values,claim,chPtr)' if fused else f'{packed}.add({old}.dotArray(ptr,values),{packed}.mul(claim,challenge))'
        out+=f'''
contract {name} {{
function batch(bytes calldata blob,uint256[4] memory point,uint256 count,uint256 claim,uint256 challenge,uint256 ood) external view returns(uint256 setupGas,uint256 rowGas,uint256 result,bytes32 digest) {{
require(blob.length==count*320&&count>0,"SHAPE"); uint256 start=gasleft(); uint256 packedPtr={old}._computeDim4EqWeights(point[0],point[1],point[2],point[3]); uint256 ptr={old}.prepare(packedPtr);
{extra}
setupGas=start-gasleft();start=gasleft();result=claim;
unchecked{{for(uint256 i=count;i>0;--i){{{folding}}}}} result={packed}.add({packed}.mul(result,challenge),ood);
rowGas=start-gasleft();
}}
function dot(uint256[16] memory values,uint256[16] memory weights,uint256 claim,uint256 challenge) external view returns(uint256 used,uint256 result) {{uint256 start=gasleft();uint256 packedPtr;assembly("memory-safe"){{packedPtr:=weights}}uint256 ptr={old}.prepare(packedPtr);{extra}result={dot};used=start-gasleft();}}
}}
'''
(root/'test/helpers/FusedRows.sol').write_text(out)
