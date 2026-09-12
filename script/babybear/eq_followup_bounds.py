#!/usr/bin/env python3
"""Independent integer checks for shifted equality and persistent forms."""
from random import Random


def mul(a,b,p,baby):
    c=[0]*9
    for i,x in enumerate(a):
        for j,y in enumerate(b):c[i+j]+=x*y
    for k in range(8,4,-1):
        if baby:c[k-5]+=2*c[k]
        else:
            c[k-5]+=c[k]
            c[k-3]-=c[k]
    return [x%p for x in c[:5]]


def check(p,baby):
    h=(p+1)//2
    assert 0 <= (p-1)//2 <= 3*(p-1)//2 < 2**32
    assert 4*(p-1)**2 < 2**64
    assert 5*(p-1)**2 < 2**65
    if baby:
        # Maximum reduced coefficient has nine base products before doubling.
        assert 18*(p-1)**2+h < 2**67
    else:
        bias=(1<<40)*p
        assert bias > 4*(p-1)**2
        assert 2*bias+22*(p-1)**2+h < 2**73
    rng=Random(p)
    vectors=[[0]*5,[1,0,0,0,0],[p-1]*5]
    vectors += [[(p-1 if i==j else 0) for i in range(5)] for j in range(5)]
    pairs=[(a,b) for a in vectors for b in vectors]
    pairs += [([rng.randrange(p) for _ in range(5)],[rng.randrange(p) for _ in range(5)]) for _ in range(1000)]
    for a,b in pairs:
        aa=a.copy();bb=b.copy()
        aa[0]=(aa[0]+(p-1)//2)%p;bb[0]=(bb[0]+(p-1)//2)%p
        product=mul(a,b,p,baby);shifted=mul(aa,bb,p,baby)
        expected=[(2*product[i]-a[i]-b[i]+(i==0))%p for i in range(5)]
        actual=[(2*shifted[i]+(h if i==0 else 0))%p for i in range(5)]
        assert actual==expected
        low=sum(actual[i]<<(64*i) for i in range(4))
        rev=sum(actual[4-i]<<(64*i) for i in range(4))
        restored=[(low>>(64*i))&0xffffffff for i in range(4)]+[rev&0xffffffff]
        assert restored==actual and all(0<=x<p for x in restored)
    print(('BabyBear' if baby else 'KoalaBear')+f': {len(pairs)} identities and coefficient bounds pass')


if __name__=='__main__':
    check(0x7f000001,False)
    check(0x78000001,True)
