#!/usr/bin/env python3
"""Check the integer bounds and an independent paired-factor identity.

For canonical r,s in F_m[X]/f and canonical base x, define D=r*s,
B=r-D, C=s-D and A=1-r-s+D, reducing all five coefficients modulo m.
Then (1+r*(x-1))*(1+s*(x*x-1)) = A+B*x+C*x^2+D*x^3.
Only the base powers are reduced before evaluation. Each integer output lane
is at most (m-1)+3*(m-1)^2 < 2^64. Therefore four 64-bit coefficient lanes
can be evaluated together without carries between lanes. The fifth coefficient
is the top retained lane of one packed four-term dot product; higher lanes are
intentionally discarded by multiplication modulo 2^256. Canonical reduction
of all five outputs precedes the extension multiplication and repacking.

Every cached read is one of 45 words: pair i occupies words 5*i..5*i+4 for
0<=i<9. Fixed native suffixes have n in {10,14,18}; traversal begins at pair8
and visits n/2 pairs. Generic test wrappers use the original implementation
for odd lengths or windows not ending at point[22].
"""
import json
import random

MASK = (1 << 256) - 1
LANE = (1 << 64) - 1


def add(a, b, p):
    return [(x+y) % p for x, y in zip(a, b)]


def scale(a, x, p):
    return [(v*x) % p for v in a]


def mul(a, b, p, baby):
    c = [0] * 9
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            c[i+j] += x*y
    for k in range(8, 4, -1):
        if baby:
            c[k-5] += 2*c[k]
        else:
            c[k-5] += c[k]
            c[k-3] -= c[k]
    return [v % p for v in c[:5]]


def packed(a):
    return sum(v << (64*i) for i, v in enumerate(a))


def factor(r, s, x, p, baby):
    one = [1, 0, 0, 0, 0]
    d = mul(r, s, p, baby)
    b = [(ri-di) % p for ri, di in zip(r, d)]
    c = [(si-di) % p for si, di in zip(s, d)]
    a = [(oi-ri-si+di) % p for oi, ri, si, di in zip(one, r, s, d)]
    x2, x3 = x*x % p, x*x*x % p
    low = (packed(a[:4])+packed(b[:4])*x+packed(c[:4])*x2+packed(d[:4])*x3) & MASK
    last = ((packed([a[4], b[4], c[4], d[4]])*packed([x3, x2, x, 1])) & MASK) >> 192
    actual = [((low >> (64*i)) & LANE) % p for i in range(4)]+[last % p]
    expected = mul(add(one, scale(r, x-1, p), p), add(one, scale(s, x2-1, p), p), p, baby)
    assert actual == expected
    assert all(0 <= v < p for v in actual)


def main():
    rng = random.Random(20260905)
    result = {}
    for name, p, baby in [('BabyBear', 0x78000001, True), ('KoalaBear', 0x7f000001, False)]:
        factor_bound = (p-1)+3*(p-1)**2
        product_bound = 4*(p-1)**2
        assert factor_bound < 1 << 64
        assert product_bound < 1 << 64
        count = 0
        for i in range(5):
            for j in range(5):
                r, s = [0]*5, [0]*5
                r[i] = s[j] = p-1
                for x in [0, 1, p-1]:
                    factor(r, s, x, p, baby)
                    count += 1
        for x in [0, 1, p-1]:
            factor([p-1]*5, [p-1]*5, x, p, baby)
            count += 1
        for _ in range(10000):
            factor([rng.randrange(p) for _ in range(5)], [rng.randrange(p) for _ in range(5)], rng.randrange(p), p, baby)
            count += 1
        result[name] = {'factor_lane_max': factor_bound, 'four_term_convolution_max': product_bound,
                        'lane_bits': 64, 'independent_cases': count}
    for n in [10, 14, 18]:
        assert all(0 <= 5*i+j < 45 for i in range(9-n//2, 9) for j in range(5))
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
