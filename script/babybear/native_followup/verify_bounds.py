#!/usr/bin/env python3
"""Whole-domain bounds for packed base rows and final Horner evaluation."""
for name,p in [('KoalaBear',0x7f000001),('BabyBear',0x78000001)]:
    row=16*(p-1)**2
    pair=2*(p-1)**2+(p-1)
    four=4*(p-1)**2+(p-1)
    assert row < 2**66 < 2**80
    assert row*(1+2**80+2**160) < 2**256
    assert pair < 2**64 and four < 2**64
    assert pair*sum(2**(64*i) for i in range(4)) < 2**256
    assert four*sum(2**(64*i) for i in range(4)) < 2**256
    print(name,dict(base_row_lane_max=row,horner_pair_lane_max=pair,horner_four_lane_max=four))
