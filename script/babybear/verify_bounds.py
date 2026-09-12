#!/usr/bin/env python3
"""Integer range checks for the canonical quintic benchmark inputs."""
P, Q = 0x7F000001, 0x78000001
for modulus in [P, Q]:
    # The packed products retain at most four terms in any 64-bit lane.
    assert 4 * (modulus - 1) ** 2 < 2**64
    assert 5 * (modulus - 1) ** 2 >= 2**64
    # The five-term middle coefficient is reconstructed outside the lanes.
    assert 5 * (modulus - 1) ** 2 < 2**65
assert 9 * (Q - 1) ** 2 * (2 * Q - 2) + Q - 1 < 2**97
assert 11 * (P - 1) ** 2 * (2 * P - 2) + P - 1 < 2**98
# In the original biased KoalaBear map, the largest sum of positive terms is
# c2+c7+c8: six base products. Every subtracted coefficient is below the bias.
assert ((P << 40) + 6 * (P - 1) ** 2) * (2 * P - 2) + P - 1 < 2**103
assert 16 * 9 * (Q - 1) ** 2 < 2**69
assert 16 * ((P << 40) + 6 * (P - 1) ** 2) < 2**76
assert 2 * ((P << 40) + 9 * (P - 1) ** 2) + 4 * P + 1 < 2**73
# Four-term c5 fits its lane, but c6 can set bit 63.
coefficients = [min(i + 1, 9 - i, 5) * (Q - 1) ** 2 for i in range(9)]
high = sum(coefficients[8 - i] << (64 * i) for i in range(4))
assert high >> 191 == 2 * coefficients[5] + 1
assert (high >> 191) & 0x1FFFFFFFFFFFFFFFE == 2 * coefficients[5]
print("All packing, loose-scalar, row, equality, and doubled-lane bounds pass.")
