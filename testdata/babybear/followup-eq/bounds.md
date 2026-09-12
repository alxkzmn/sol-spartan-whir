# Shifted equality and persistent coefficient forms

For either odd prime M, set h = (M+1)/2. The equality factor is

`1-a-q+2*a*q = 2*(a-h)*(q-h)+h`.

Only coefficient zero changes when subtracting h. The implementation adds `(M-1)/2` and reduces once, so the integer entering this reduction is between `(M-1)/2` and `3*(M-1)/2`, strictly below 2^32. Every multiplicand coefficient is canonical before convolution. The point q is shared by up to five equality factors; its transformed low, middle, and reverse forms are prepared once for each of the 22 points.

The low and reverse four-coefficient products use radix 2^64. Each retained lane contains at most four base products, and `4*(M-1)^2 < 2^64` for both primes. EVM multiplication discards coefficients at bit 256 and above. The middle coefficient is reconstructed from four terms in the top lane of a separate product plus one scalar product; its bound is `5*(M-1)^2 < 2^65`.

BabyBear reduces with X^5=2. Its largest positive output contains nine base products, so the doubled equality output plus h is below `18*(M-1)^2+h < 2^67`. KoalaBear reduces with X^5=1-X^2. The bias `2^40*M` exceeds every subtracted convolution coefficient. The biased, doubled result plus h is below `2*(2^40*M)+22*(M-1)^2+h < 2^73`. Every final coefficient is reduced modulo M before storing its persistent form or reconstructing transport packing. Unsigned wrapping therefore occurs only in the deliberately truncated packed products.

A low word stores coefficients 0,1,2,3 in lanes 0,64,128,192; a reverse word stores 4,3,2,1. These words retain canonical coefficients. General accumulation consumes and returns these forms, avoiding transport packing between the equality factor and the product or between consecutive accumulator products.

The selected implementation allocates a four-word point cache and a ten-word state array. Only the first three cache words are read. All three are initialized before any equality factor. State indices are fixed at 0 through 4, each occupying two words; all five pairs are initialized by the first peeled iteration before any read. Final pack operations read the same five in-bounds pairs. The 22/18/14/10 loop windows and statement offsets are unchanged and remain covered by the external shape check.

`python3 script/babybear/eq_followup_bounds.py` independently checks the identity with schoolbook multiplication and descending polynomial reduction for all pairs of zero, one, maximum, and maximum basis vectors plus 1,000 random pairs per field. The Solidity test independently checks full preparation chains, individual products and squares, equality factors, all basis products, maximum coefficients, and zero. Each of its two fuzz tests uses 256 cases.

The retained result is BabyBear 148,073 to 123,456 gas and KoalaBear 170,823 to 137,913 gas. Four successful rounds reduce the shared factor arithmetic, retain coefficient forms between the factor and accumulator multiplication, retain them across each chain, and then apply the shifted identity. The final unused-square trial saves only 0.234% in BabyBear and 0.401% in KoalaBear and is retained only as a reproducible stopping trial.

Reproduce the selected and terminal trial with:

```sh
python3 script/babybear/eq_followup_generate.py
python3 script/babybear/eq_followup_bounds.py
forge test --match-path test/BabyBearEqFollowup.t.sol --offline --fuzz-runs 256 -vv
```

`selected-profile.svg` was parsed headlessly. Equality factor formation costs 46,784 inclusive gas over 86 calls (544 each), specialized squares cost 29,184, point preparation costs 5,434, and `_accEqAt` costs 77,355 including its factor formation. These inclusive buckets must not be summed. The `gasleft()` full preparation boundary is 123,456 gas.
