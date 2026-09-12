#!/usr/bin/env python3
"""Independent BabyBear schoolbook oracle for the fused final product and Horner product."""
import json
import random

P = 0x78000001
MASK = (1 << 64) - 1
WORD = (1 << 256) - 1

def schoolbook(a, b):
    c = [0] * 9
    for i in range(5):
        for j in range(5):
            c[i+j] += a[i] * b[j]
    for i in range(8, 4, -1):
        c[i-5] += 2 * c[i]
    return c[:5]

def packed(a, b):
    low_a = sum(a[i] << (64*i) for i in range(4))
    low_b = sum(b[i] << (64*i) for i in range(4))
    rev_a = sum(a[4-i] << (64*i) for i in range(4))
    rev_b = sum(b[4-i] << (64*i) for i in range(4))
    low = low_a * low_b & WORD
    high = rev_a * rev_b & WORD
    middle = ((low_a * ((low_b >> 64) | (b[4] << 192)) & WORD) >> 192) + a[4]*b[0]
    return [((low >> (64*i)) & MASK) + 2*((high >> (64*(3-i))) & MASK) for i in range(4)] + [middle]

assert 4*(P-1)**2 < 2**64
assert 5*(P-1)**2 >= 2**64
assert 18*(P-1)**2 < 2**67
rng = random.Random(20260905)
boundary = [[0]*5, [P-1]*5, [1, 0, 0, 0, 0]]
boundary += [[(P-1) if i == j else 0 for i in range(5)] for j in range(5)]
cases = [(a, b, b, a) for a in boundary for b in boundary]
cases += [tuple([rng.randrange(P) for _ in range(5)] for _ in range(4)) for _ in range(10000)]
for a, b, c, d in cases:
    expected = [(x+y) % P for x, y in zip(schoolbook(a,b), schoolbook(c,d))]
    actual = [(x+y) % P for x, y in zip(packed(a,b), packed(c,d))]
    assert actual == expected
print(json.dumps({'status': 'PASS', 'cases': len(cases), 'four_product_lane_max': 4*(P-1)**2,
                  'fused_output_max': 18*(P-1)**2, 'scratch_bytes': 224}, indent=2))
