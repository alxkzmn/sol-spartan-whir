#!/usr/bin/env python3
"""Generate fixed Poseidon1 Solidity primitives and parity vectors."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--primitives", type=Path, required=True)
parser.add_argument("--vectors", type=Path, required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
p = args.primitives
spec=importlib.util.spec_from_file_location('terminal_primitives',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
rc=''.join(x.to_bytes(4,'big').hex() for x in m.P1_ROUND_CONSTANTS_16)
mds=[]
for i in range(16):
 terms=[]
 for j in range(16):
  c=m.MDS_FIRST_ROW_16[(j-i)%16]
  v=f'mload(add(state, {j*32}))'
  terms.append(v if c==1 else f'mul({v}, {c})')
 expr=terms[0]
 for term in terms[1:]:expr=f'add({expr}, {term})'
 mds.append(f'                mstore(add(scratch, {i*32}), mod({expr}, p))')
out=f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// Poseidon1 over KoalaBear: width 16, cubic S-box, 8 full and 20 partial rounds.
library LeanVmPoseidon1 {{
    uint256 internal constant MODULUS = 2130706433;
    bytes private constant ROUND_CONSTANTS = hex"{rc}";
    error NonCanonicalField();
    error InvalidLeafLength();

    function permute(uint256[16] memory state) internal pure {{
        bytes memory constants = ROUND_CONSTANTS;
        assembly ("memory-safe") {{
            let p := 2130706433
            let scratch := mload(0x40)
            mstore(0x40, add(scratch, 512))
            for {{ let round := 0 }} lt(round, 28) {{ round := add(round, 1) }} {{
                for {{ let i := 0 }} lt(i, 16) {{ i := add(i, 1) }} {{
                    let slot := add(state, shl(5, i))
                    let constant := shr(224, mload(add(add(constants, 32), add(mul(round, 64), shl(2, i)))))
                    let x := addmod(mload(slot), constant, p)
                    if or(or(lt(round, 4), gt(round, 23)), iszero(i)) {{ x := mulmod(mulmod(x, x, p), x, p) }}
                    mstore(slot, x)
                }}
{chr(10).join(mds)}
                for {{ let i := 0 }} lt(i, 512) {{ i := add(i, 32) }} {{
                    mstore(add(state, i), mload(add(scratch, i)))
                }}
            }}
        }}
    }}

    function compress(uint256[8] memory left, uint256[8] memory right) internal pure returns (uint256[8] memory result) {{
        uint256[16] memory state;
        for (uint256 i = 0; i < 8; ++i) {{ state[i] = left[i]; state[i + 8] = right[i]; }}
        permute(state);
        for (uint256 i = 0; i < 8; ++i) result[i] = state[i];
    }}

    function hashWords(uint256[] memory values) internal pure returns (uint256[8] memory result) {{
        if (values.length == 0 || values.length % 8 != 0) revert InvalidLeafLength();
        uint256[16] memory state;
        state[0] = values.length;
        for (uint256 offset = 0; offset < values.length; offset += 8) {{
            for (uint256 i = 0; i < 8; ++i) {{
                uint256 value = values[offset + i];
                if (value >= MODULUS) revert NonCanonicalField();
                state[i + 8] = value;
            }}
            permute(state);
        }}
        for (uint256 i = 0; i < 8; ++i) result[i] = state[i + 8];
    }}

    function hashLeaf(uint256[] memory values) internal pure returns (uint256[8] memory result) {{
        if (values.length == 0 || values.length % 8 != 0) revert InvalidLeafLength();
        uint256[16] memory state;
        state[0] = values.length;
        for (uint256 offset = values.length; offset != 0; offset -= 8) {{
            for (uint256 i = 0; i < 8; ++i) {{
                uint256 value = values[offset - 8 + i];
                if (value >= MODULUS) revert NonCanonicalField();
                state[i + 8] = value;
            }}
            permute(state);
        }}
        for (uint256 i = 0; i < 8; ++i) result[i] = state[i + 8];
    }}
}}
'''
(root/'src/leanvm').mkdir(exist_ok=True)
(root/'src/leanvm/LeanVmPoseidon1.sol').write_text(out)
perm=m.Poseidon1(m.PARAMS_16)
inputs=[[0]*16,list(range(16)),[m.P-1]*16]
vectors=[]
for inp in inputs:vectors.append([x.value for x in perm.permute([m.Fp(x) for x in inp])])
# Independent raw reference iterates canonical Python fields.
leaf=[m.Fp(i) for i in range(512)];state=[m.Fp(0)]*16;state[0]=m.Fp(len(leaf))
for off in range(len(leaf),0,-8):state=perm.permute(state[:8]+leaf[off-8:off])
leafout=[x.value for x in state[8:]]
arr=lambda xs:'[uint256('+str(xs[0])+'), '+', '.join(map(str,xs[1:]))+']'
tests=[]
for i,(inp,exp) in enumerate(zip(inputs,vectors)):
 tests.append(f'''    function testPermutation{i}() external pure {{
        uint256[16] memory state = {arr(inp)};
        uint256[16] memory expected = {arr(exp)};
        LeanVmPoseidon1.permute(state);
        for (uint256 i=0; i<16; ++i) assertEq(state[i], expected[i]);
    }}''')
test=f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import {{Test, console2}} from "forge-std/Test.sol";
import {{LeanVmPoseidon1}} from "../src/leanvm/LeanVmPoseidon1.sol";
contract LeanVmPoseidon1Test is Test {{
{chr(10).join(tests)}
    function testLeaf512() external view {{
        uint256[] memory leaf = new uint256[](512);
        for (uint256 i=0;i<512;++i) leaf[i]=i;
        uint256 beforeGas = gasleft();
        uint256[8] memory result = LeanVmPoseidon1.hashLeaf(leaf);
        uint256 used = beforeGas-gasleft();
        uint256[8] memory expected = {arr(leafout)};
        for(uint256 i=0;i<8;++i) assertEq(result[i],expected[i]);
        console2.log("poseidon1 leaf512 execution gas",used);
    }}
    function testPermutationGas() external view {{
        uint256[16] memory state;
        uint256 beforeGas = gasleft();
        LeanVmPoseidon1.permute(state);
        uint256 used=beforeGas-gasleft();
        assertEq(state[0], {vectors[0][0]});
        console2.log("poseidon1 permutation execution gas",used);
    }}
}}
'''
(root/'test/LeanVmPoseidon1.t.sol').write_text(test)
args.vectors.write_text(json.dumps({'source_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'inputs':inputs,'permutations':vectors,'leaf512':leafout},indent=2)+'\n')
