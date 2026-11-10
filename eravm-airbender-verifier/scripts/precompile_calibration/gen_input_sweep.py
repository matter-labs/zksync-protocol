#!/usr/bin/env python3
"""Generate precompile input vectors that sweep the INPUT dimension.

Unlike gen_inputs.py (one fixed input per family, driver sweeps call count),
this emits several inputs per family so a fixed-count sweep isolates the
per-call cost's dependence on the input itself.

Pure python (no `cryptography` dep) so the ECDSA vectors are reproducible and
we can *shape* them (leading-zero r, chosen v).
"""
import hashlib, os, json

OUT = os.path.dirname(os.path.abspath(__file__))

def u256(x): return int(x).to_bytes(32, "big")

# ---------------- generic short-weierstrass ECDSA (y^2 = x^3 + ax + b) -------
class Curve:
    def __init__(self, p, a, b, gx, gy, n):
        self.p, self.a, self.b, self.g, self.n = p, a, b, (gx, gy), n
    def add(self, P, Q):
        p = self.p
        if P is None: return Q
        if Q is None: return P
        if P[0] == Q[0] and (P[1] + Q[1]) % p == 0: return None
        if P == Q:
            l = (3 * P[0] * P[0] + self.a) * pow(2 * P[1], -1, p) % p
        else:
            l = (Q[1] - P[1]) * pow(Q[0] - P[0], -1, p) % p
        x = (l * l - P[0] - Q[0]) % p
        return (x, (l * (P[0] - x) - P[1]) % p)
    def mul(self, k, P=None):
        P = P or self.g
        R, k = None, k % self.n
        while k:
            if k & 1: R = self.add(R, P)
            P = self.add(P, P); k >>= 1
        return R
    def on_curve(self, P):
        if P is None: return True
        x, y = P
        return (y * y - x * x * x - self.a * x - self.b) % self.p == 0

SECP256K1 = Curve(
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F, 0, 7,
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
SECP256R1 = Curve(
    0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
    0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551)

def sign(curve, d, z, k):
    n = curve.n
    R = curve.mul(k)
    r = R[0] % n
    s = pow(k, -1, n) * (z + r * d) % n
    return r, s, R[1] & 1

def verify(curve, pub, z, r, s):
    n = curve.n
    if not (0 < r < n and 0 < s < n): return False
    w = pow(s, -1, n)
    P = curve.add(curve.mul(z * w % n), curve.mul(r * w % n, pub))
    return P is not None and P[0] % n == r


def find_sig(curve, want_r_leading_zero, low_s=True, seed=b"sweep"):
    """Deterministic search for a signature with the requested r shape."""
    i = 0
    while True:
        i += 1
        h = hashlib.sha256(seed + i.to_bytes(4, "big")).digest()
        d = int.from_bytes(hashlib.sha256(b"d" + h).digest(), "big") % (curve.n - 1) + 1
        k = int.from_bytes(hashlib.sha256(b"k" + h).digest(), "big") % (curve.n - 1) + 1
        z = int.from_bytes(h, "big")
        r, s, ybit = sign(curve, d, z, k)
        if r == 0 or s == 0: continue
        if low_s and s > curve.n // 2:
            s = curve.n - s; ybit ^= 1
        rz = r < (1 << 248)
        if rz != want_r_leading_zero: continue
        pub = curve.mul(d)
        assert curve.on_curve(pub), "generated pubkey off curve"
        assert verify(curve, pub, z, r, s), "generated signature does not verify"
        return dict(z=z, d=d, r=r, s=s, v=27 + ybit, pub=pub, tries=i)

# ---------------- bn254 (for on-curve ecadd points) --------------------------
BN254 = Curve(
    0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD47, 0, 3,
    1, 2,
    0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001)

# ---------------- emitters ---------------------------------------------------
VEC = {}
def emit(name, data, meta):
    VEC[name] = dict(hex=data.hex(), bytes=len(data), **meta)

# modexp: fixed 32B base/modulus, dense 0xff exponent of varying length
MODEXP_BASE = b"\x02" * 32
MODEXP_MOD = b"\xff" * 31 + b"\xfd"
for L in (1, 4, 8, 16, 32):
    exp = b"\xff" * L
    emit(f"modexp_exp{L}b",
         u256(32) + u256(L) + u256(32) + MODEXP_BASE + exp + MODEXP_MOD,
         dict(family="modexp", addr="0x05", input_param=f"exp_bytes={L}",
              bits=8 * L, note="dense 0xff exponent, all 8L bits set"))
# control: the OLD campaign's vector, 0x03 repeated -> 26 significant bits
emit("modexp_old_0x03x4",
     u256(32) + u256(4) + u256(32) + MODEXP_BASE + b"\x03" * 4 + MODEXP_MOD,
     dict(family="modexp", addr="0x05", input_param="exp_bytes=4(0x03)",
          bits=26, note="the shipped-coefficient vector: 0x03030303, 26 sig bits"))

# ecmul: fixed generator, scalar sweeps the bit range
R_BN254 = BN254.n
for label, k in (("s3", 7), ("s32", (1 << 32) - 1), ("s64", (1 << 64) - 1),
                 ("s128", (1 << 128) - 1), ("smax", R_BN254 - 1)):
    emit(f"ecmul_{label}", u256(1) + u256(2) + u256(k),
         dict(family="ecmul", addr="0x07", input_param=f"scalar_bits={k.bit_length()}",
              bits=k.bit_length(),
              note=f"scalar={hex(k)} popcount={bin(k).count('1')}"))

# ecadd: three input classes
P2 = BN254.mul(2); P3 = BN254.mul(3)
assert BN254.on_curve(P2) and BN254.on_curve(P3)
emit("ecadd_gg", u256(1) + u256(2) + u256(1) + u256(2),
     dict(family="ecadd", addr="0x06", input_param="class=G+G(double)", bits=0,
          note="the shipped-coefficient vector; equal points -> doubling path"))
emit("ecadd_distinct", u256(P2[0]) + u256(P2[1]) + u256(P3[0]) + u256(P3[1]),
     dict(family="ecadd", addr="0x06", input_param="class=2G+3G(distinct)", bits=0,
          note="two distinct on-curve points -> generic addition path"))
emit("ecadd_identity", u256(P2[0]) + u256(P2[1]) + u256(0) + u256(0),
     dict(family="ecadd", addr="0x06", input_param="class=2G+O(identity)", bits=0,
          note="point + point-at-infinity; may short-circuit"))

# ecrecover: two valid secp256k1 sigs with different shapes
for label, want_zero in (("a", False), ("b", True)):
    sg = find_sig(SECP256K1, want_zero, seed=b"ecrec")
    data = u256(sg["z"]) + u256(sg["v"]) + u256(sg["r"]) + u256(sg["s"])
    emit(f"ecrecover_{label}", data,
         dict(family="ecrecover", addr="0x01",
              input_param=f"class=v{sg['v']}_r{'zeroLead' if want_zero else 'full'}",
              bits=sg["r"].bit_length(),
              note=f"r={hex(sg['r'])} s={hex(sg['s'])} v={sg['v']} "
                   f"r_bits={sg['r'].bit_length()} s_bits={sg['s'].bit_length()}"))

# secp256r1 (RIP-7212): two valid P-256 sigs with different shapes
for label, want_zero in (("a", False), ("b", True)):
    sg = find_sig(SECP256R1, want_zero, seed=b"p256")
    x, y = sg["pub"]
    data = u256(sg["z"]) + u256(sg["r"]) + u256(sg["s"]) + u256(x) + u256(y)
    emit(f"secp256r1_{label}", data,
         dict(family="secp256r1", addr="0x100",
              input_param=f"class=r{'zeroLead' if want_zero else 'full'}",
              bits=sg["r"].bit_length(),
              note=f"r={hex(sg['r'])} s={hex(sg['s'])} "
                   f"r_bits={sg['r'].bit_length()} s_bits={sg['s'].bit_length()}"))

for name, v in VEC.items():
    with open(os.path.join(OUT, name + ".hex"), "w") as f:
        f.write(v["hex"])
    print(f"{name:22s} {v['bytes']:>5} B  {v['family']:10s} {v['input_param']:28s} bits={v['bits']:<4} {v['note']}")
with open(os.path.join(OUT, "vectors.json"), "w") as f:
    json.dump(VEC, f, indent=1)
