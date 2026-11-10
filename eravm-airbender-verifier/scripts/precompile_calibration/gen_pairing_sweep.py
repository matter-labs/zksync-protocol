#!/usr/bin/env python3
"""ec_pairing input vectors: k copies of (G1, G2) for k = 1,2,4,8, plus a
degenerate pair whose G1 term is the point at infinity.

Encoding is EIP-197: 192 bytes per pair, G1 = (x, y) then G2 = (x_c1, x_c0,
y_c1, y_c0) -- imaginary part first. `EcPairing.yul` requires
calldatasize % 192 == 0 (otherwise burnGas) and charges 80,000 gas per pair
with a zero base cost.
"""
import os
OUT = os.path.dirname(os.path.abspath(__file__))
u = lambda x: int(x).to_bytes(32, "big")

G1 = (1, 2)
G2 = (0x198E9393920D483A7260BFB731FB5D25F1AA493335A9E71297E485B7AEF312C2,
      0x1800DEEF121F1E76426A00665E5C4479674322D4F75EDADD46DEBD5CD992F6ED,
      0x090689D0585FF075EC9E99AD690C3395BC4B313370B38EF355ACDADCD122975B,
      0x12C85EA5DB8C6DEB4AAB71808DCB408FE3D1E7690C43D37B4CE6CC0166FA7DAA)

def pair(g1):  # one 192-byte (G1, G2) chunk
    return u(g1[0]) + u(g1[1]) + u(G2[0]) + u(G2[1]) + u(G2[2]) + u(G2[3])

for k in (1, 2, 4, 8):
    d = pair(G1) * k
    open(os.path.join(OUT, f"ecpair_{k}.hex"), "w").write(d.hex())
    print(f"ecpair_{k}.hex        {len(d):>5} B  pairs={k}  expect result 0 "
          f"(e(G1,G2)^{k} != 1), call must still SUCCEED")
# degenerate: G1 term is the point at infinity -> e(O, G2) = 1, product == 1
d = pair((0, 0))
open(os.path.join(OUT, "ecpair_inf.hex"), "w").write(d.hex())
print(f"ecpair_inf.hex       {len(d):>5} B  pairs=1  G1 = O  expect result 1")
