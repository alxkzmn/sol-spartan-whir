#!/usr/bin/env python3
"""Check the new row canonicality predicate and the rejected packed-sum bounds."""
import json
from pathlib import Path
import random

ROOT = Path(__file__).resolve().parents[2]
WORD_MASK = (1 << 256) - 1
HIGH_BITS = sum(1 << (224 - 32*j + 31) for j in range(5))


def packed(xs):
    return sum(x << (224 - 32*j) for j, x in enumerate(xs))


def main():
    rng = random.Random(0xBABEBEA5)
    results = []
    for p in [0x7f000001,0x78000001]:
        bias = packed([(1 << 31) - p] * 5)
        cases = 0
        edge = [0,1,p-1,p,p+1,(1<<31)-1,1<<31,(1<<32)-1]
        for j in range(5):
            for x in edge:
                for fill in [0,p-1,(1<<32)-1]:
                    xs = [fill]*5
                    xs[j] = x
                    v = packed(xs)
                    assert bool((v | ((v+bias)&WORD_MASK)) & HIGH_BITS) == any(x >= p for x in xs)
                    cases += 1
        for _ in range(10000):
            xs = [rng.randrange(1<<32) for _ in range(5)]
            v = packed(xs)
            assert bool((v | ((v+bias)&WORD_MASK)) & HIGH_BITS) == any(x >= p for x in xs)
            cases += 1
        # BabyBear's five binomial output sums contain 9,8,7,6,5 products
        # per element. Sixteen elements fit below 2^70 and each proposed
        # 80-bit accumulation lane is therefore independent.
        bounds = [16*n*(p-1)**2 for n in [9,8,7,6,5]]
        assert max(bounds) < 1 << 70
        assert max(bounds) < 1 << 80
        assert bounds[0]+(bounds[1]<<80)+(bounds[2]<<160) < 1 << 256
        results.append({'prime':hex(p),'predicate_cases':cases,
                        'baby_binomial_row_sum_bounds':[str(x) for x in bounds],
                        'max_bound_bits':max(bounds).bit_length()})
    result = {
        'canonicality_proof': 'A set input lane high bit remains set in the OR. If no input lane high bit is set, adding 2^31-p per lane creates no inter-lane carry and sets that high bit exactly when the coefficient is at least p. OR over all sixteen elements therefore rejects exactly the original noncanonical rows. The original checker runs in input order only after a failure and preserves the exact first-element error data.',
        'weight_identity': 'For each prefix A and next coordinate r, the two weights are A-Ar and Ar. For dimensions 0 and 1, compute t=p0*p1 once and obtain p0-t, p1-t, and 1-p0-p1+t by field subtraction. This gives 1+4+8=13 extension multiplications, versus 4+8+16=28. Every intermediate uses canonical field operations.',
        'memory_and_rejection': 'Valid-row arithmetic retains the original canonical inputs and bounds. Malformed-row arithmetic may wrap before the deferred check, but accesses only fixed bounded calldata and the same prepared weights; the result is discarded by the original error path. No external calls, output writes, or hash result escapes before the check.',
        'packed_sum_trial': 'Rejected on gas. The five BabyBear output sums fit in two 80-bit-lane words (3 plus 2), but extra per-element shifts and packing outweighed the reduced live accumulator state.',
        'checks': results,
    }
    path = ROOT/'testdata/babybear/followup-row-bounds.json'
    path.write_text(json.dumps(result,indent=2)+'\n')
    print(path)


if __name__ == '__main__':
    main()
