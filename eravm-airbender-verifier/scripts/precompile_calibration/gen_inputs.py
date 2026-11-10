#!/usr/bin/env python3
"""Generate precompile input vectors (hex, no 0x) for the PrecompileHammer.

Emits one <precompile>_<tier>.hex file per (precompile, tier); the driver
(`run_calibration.sh`) reads these and sweeps the per-tx call count itself.

Design:
- sha256/ecpairing tier by INPUT SIZE (light/medium/heavy or pair count).
  modexp gets only a light (<=32B-operand) input: the circuit rejects larger
  operands (burnGas -> 0 cycles), so bigger vectors would calibrate nothing —
  the driver ranges the feature via call count instead. Fixed-cost precompiles
  (ecadd, ecmul, secp256r1) share one input and the driver sweeps `count`.
- Curve inputs use the canonical bn254 generators (G1 = (1,2); EIP-197 G2
  generator). They are VALID by construction but MUST be confirmed against the
  live node (`cast call <precompile> <input>`) before mass-generation — a bad
  point makes the precompile fail and cost nothing. secp256r1 needs a real P-256
  signature; generated here if `cryptography` is available, else left as a TODO.
"""
import os

OUT = os.path.dirname(os.path.abspath(__file__))


def w(name, hexstr):
    path = os.path.join(OUT, f"{name}.hex")
    with open(path, "w") as f:
        f.write(hexstr)
    return os.path.relpath(path, OUT), len(hexstr) // 2


def u256(x):
    return x.to_bytes(32, "big")


# --- modexp (0x05): [baseLen|expLen|modLen|base|exp|mod], any bytes valid ------
def modexp(base_len, exp_len, mod_len):
    base = (b"\x02" * base_len)
    exp = (b"\x03" * exp_len)  # nonzero exponent so it does real work
    mod = (b"\xff" * (mod_len - 1) + b"\xfd")  # large odd modulus
    return (u256(base_len) + u256(exp_len) + u256(mod_len) + base + exp + mod).hex()


# --- sha256 (0x02): arbitrary bytes -------------------------------------------
def sha256_in(n):
    return (bytes((i * 31 + 7) & 0xFF for i in range(n))).hex()


# --- bn254 constants ----------------------------------------------------------
G1 = (1, 2)  # generator; on curve (y^2 = x^3 + 3): 4 == 1 + 3
# EIP-197 G2 generator, encoded (x_c1, x_c0, y_c1, y_c0) — imaginary part first.
G2 = (
    0x198E9393920D483A7260BFB731FB5D25F1AA493335A9E71297E485B7AEF312C2,
    0x1800DEEF121F1E76426A00665E5C4479674322D4F75EDADD46DEBD5CD992F6ED,
    0x090689D0585FF075EC9E99AD690C3395BC4B313370B38EF355ACDADCD122975B,
    0x12C85EA5DB8C6DEB4AAB71808DCB408FE3D1E7690C43D37B4CE6CC0166FA7DAA,
)


def ec_add():  # 128 bytes: G1 + G1
    return (u256(G1[0]) + u256(G1[1]) + u256(G1[0]) + u256(G1[1])).hex()


def ec_mul(scalar):  # 96 bytes: scalar * G1
    return (u256(G1[0]) + u256(G1[1]) + u256(scalar)).hex()


def ec_pairing(k):  # k * 192 bytes: k copies of (G1, G2); valid points, result != 1
    pair = u256(G1[0]) + u256(G1[1]) + u256(G2[0]) + u256(G2[1]) + u256(G2[2]) + u256(G2[3])
    return (pair * k).hex()


# --- ecrecover (0x01): 128 bytes hash|v|r|s -----------------------------------
# secp256k1 order, for the low-s normalization below.
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def ec_recover_vector():
    """A VALID secp256k1 signature over a fixed hash, as ecrecover input.

    ecrecover does not have to recover any particular address — it just has to do
    the work — but the signature must be well-formed or the precompile fails and
    costs nothing (which would calibrate a coefficient of ~0). So: sign a real
    hash, normalize `s` into the lower half of the order (accepted by both strict
    and lax implementations), and use v = 27; for a genuine (r, s) both parities
    recover a point on the curve, so the recovery id does not need to be known.
    """
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import (
            Prehashed,
            decode_dss_signature,
        )
    except Exception:
        return None
    key = ec.generate_private_key(ec.SECP256K1())
    msg_hash = bytes((i * 7 + 3) & 0xFF for i in range(32))
    sig = key.sign(msg_hash, ec.ECDSA(Prehashed(hashes.SHA256())))
    r, s = decode_dss_signature(sig)
    if s > SECP256K1_N // 2:
        s = SECP256K1_N - s
    return (u256(int.from_bytes(msg_hash, "big")) + u256(27) + u256(r) + u256(s)).hex()


# --- secp256r1 (RIP-7212, addr 0x100): 160 bytes hash|r|s|x|y ------------------
def secp256r1_vector():
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import (
            Prehashed,
            decode_dss_signature,
        )
    except Exception:
        return None
    key = ec.generate_private_key(ec.SECP256R1())
    msg_hash = bytes((i * 13 + 1) & 0xFF for i in range(32))
    # Sign the raw hash via Prehashed
    sig = key.sign(msg_hash, ec.ECDSA(Prehashed(hashes.SHA256())))
    r, s = decode_dss_signature(sig)
    nums = key.public_key().public_numbers()
    return (u256(int.from_bytes(msg_hash, "big")) + u256(r) + u256(s) + u256(nums.x) + u256(nums.y)).hex()


def main():
    def add(name, hexstr, note=""):
        rel, nbytes = w(name, hexstr)
        print(f"{rel:22s} {nbytes:>7} B  {note}")

    # modexp: light (<=32B operands) only — the circuit rejects larger operands
    # (burnGas -> 0 cycles); the driver ranges the feature via call count.
    add("modexp_light", modexp(32, 4, 32))

    # sha256: tier by input size
    add("sha256_light", sha256_in(64))
    add("sha256_medium", sha256_in(4096))
    add("sha256_heavy", sha256_in(32768))

    # ecpairing: tier by number of pairs (input size)
    add("ecpairing_light", ec_pairing(1), "verify on-curve on live node")
    add("ecpairing_medium", ec_pairing(4), "verify on-curve on live node")
    add("ecpairing_heavy", ec_pairing(10), "verify on-curve on live node")

    # ecadd / ecmul: fixed cost/call — one input, driver sweeps count
    add("ecadd_fixed", ec_add(), "verify on-curve on live node")
    add("ecmul_fixed", ec_mul(7), "verify on-curve on live node")

    # ecrecover: fixed cost/call — one input, driver sweeps count. Required to
    # identify `ec_recover_cycles`, which the organic corpus cannot (near-constant
    # column; see PrecompileHammer.ecRecover).
    recover = ec_recover_vector()
    if recover:
        add("ecrecover_fixed", recover, "cast call 0x01 -> must return a nonzero address")
    else:
        print("ecrecover_fixed: SKIPPED — python `cryptography` unavailable; generate a "
              "valid secp256k1 hash|v|r|s (128B) vector before use")

    # secp256r1: fixed cost/call — needs a valid P-256 signature
    p256 = secp256r1_vector()
    if p256:
        add("secp256r1_fixed", p256, "verify returns 1 on live node")
    else:
        print("secp256r1_fixed: SKIPPED — python `cryptography` unavailable; "
              "generate a valid RIP-7212 hash|r|s|x|y (160B) vector before use")


if __name__ == "__main__":
    main()
