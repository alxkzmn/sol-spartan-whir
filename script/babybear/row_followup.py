#!/usr/bin/env python3
"""Generate factored row weights and one-check row canonicality experiments.

Writes only BabyBearRowFollowup.sol. Existing source variants supply arithmetic
and the caller shapes, including the original independent error checker.
"""
import argparse
from pathlib import Path
import re
import subprocess
from generate_select_variants import ROOT, function


def item(source, kind, name):
    start = source.index(f'{kind} {name} {{')
    pos = source.index('{', start)
    depth = 1
    while depth:
        pos += 1
        depth += (source[pos] == '{') - (source[pos] == '}')
    return source[start:pos + 1]


def factor_weights(lib, field):
    old = function(lib, '_computeDim4EqWeights')
    start = old.index('        uint256 q0')
    end = old.index('        assembly', start)
    lines = [f'        uint256 a11 = {field}.mul(p0, p1);',
             f'        uint256 a10 = {field}.sub(p0, a11);',
             f'        uint256 a01 = {field}.sub(p1, a11);',
             f'        uint256 a00 = {field}.sub({field}.sub({field}.ONE, p0), a01);']
    for a, even, odd in [('a00','b000','b001'), ('a01','b010','b011'),
                         ('a10','b100','b101'), ('a11','b110','b111')]:
        lines += [f'        uint256 {odd} = {field}.mul({a}, p2);',
                  f'        uint256 {even} = {field}.sub({a}, {odd});']
    new = old[:start] + '\n'.join(lines) + '\n\n' + old[end:]
    new = new.replace(', q3, p3)', ', 0, p3)')
    lib = lib.replace(old, new)
    old_pair = f'uint256 w0 = {field}.mul(prefix, q3);\n        uint256 w1 = {field}.mul(prefix, p3);'
    new_pair = f'uint256 w1 = {field}.mul(prefix, p3);\n        uint256 w0 = {field}.sub(prefix, w1);'
    assert old_pair in lib
    return lib.replace(old_pair, new_pair)


def combined_validation(lib, baby, stream):
    """OR each word and its biased form; inspect only the five lane sign bits.

    A preexisting high bit makes the final OR nonzero. If all high bits are
    clear, adding (2^31 - p) per lane cannot carry between the 32-bit lanes,
    and sets a lane high bit precisely for coefficients >= p. The original
    checker then determines the first malformed element and exact error data.
    """
    old = function(lib, '_hashAndEvaluateExtension5RowDim4BlobUnpacked')
    bias = ('07ffffff' if baby else '00ffffff') * 5 + '0' * 24
    high = '80000000' * 5 + '0' * 24
    if stream:
        new = old.replace('            let M :=', '            let invalidBits := 0\n            let M :=', 1)
        new, count = re.subn(r'                validateExt5\(v\)', f'                invalidBits := or(invalidBits, or(v, add(v, 0x{bias})))', new)
        assert count == 16
        pos = new.index('            evalValue :=')
        fallback = f'''            if and(invalidBits, 0x{high}) {{
                for {{ let i := 0 }} lt(i, 16) {{ i := add(i, 1) }} {{
                    validateExt5(and(calldataload(add(src, mul(i, 20))), lowMask))
                }}
            }}
'''
        new = new[:pos] + fallback + new[pos:]
    else:
        start = old.index('            validateExt5(v0)')
        end = old.index('            mstore8(ptr', start)
        checks = old[start:end]
        new_checks = '            let invalidBits := 0\n'
        for i in range(16):
            new_checks += f'            invalidBits := or(invalidBits, or(v{i}, add(v{i}, 0x{bias})))\n'
        new_checks += f'            if and(invalidBits, 0x{high}) {{\n' + checks + '            }\n\n'
        new = old[:start] + new_checks + old[end:]
    return lib.replace(old, new)


def generate(out_root=ROOT):
    source = (ROOT / 'test/helpers/BabyBearRowVariants.sol').read_text()
    header = source[:source.index('library ')]
    header = header.replace('generate_row_variants.py', 'row_followup.py')
    header += '''// Weights use 13 extension products: one for the first two dimensions,
// four for dimension three, and eight for dimension four. Complement weights
// use prefix - prefix*point, preserving canonical outputs through field.sub.
// Combined checks preserve the original first-malformed-element error data.
'''
    outputs = []
    for baby in [False, True]:
        field = 'BabyBear' if baby else 'KoalaBear'
        arithmetic = 'BabyBearBenchField' if baby else 'KoalaBearExt5'
        shapes = [('KroneckerStream', 'Stream')] if baby else [('Kronecker', ''), ('KroneckerStream', 'Stream')]
        for shape, label in shapes:
            original = field + 'Row' + shape
            for combined in [False, True]:
                name = field + 'Row' + label + ('CombinedFollowup' if combined else 'FactoredFollowup')
                lib = factor_weights(item(source, 'library', original), arithmetic)
                if combined:
                    lib = combined_validation(lib, baby, shape.endswith('Stream'))
                lib = lib.replace(original, name)
                harness = item(source, 'contract', original + 'Harness').replace(original, name)
                outputs += [lib, harness]
    path = out_root / 'test/helpers/BabyBearRowFollowup.sol'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(header + '\n\n'.join(outputs) + '\n')
    subprocess.run(['forge', 'fmt', str(path)], cwd=ROOT, check=True, capture_output=True, text=True)
    return path


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out-root', type=Path, default=ROOT)
    print(generate(parser.parse_args().out_root))
