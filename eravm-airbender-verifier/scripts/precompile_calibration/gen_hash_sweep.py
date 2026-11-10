#!/usr/bin/env python3
"""Input vectors for the keccak256 / sha256 volume + input-size families.

Both precompiles price and trace per ROUND, so the swept quantity is the round
count implied by the input length:
  keccak256: numRounds = len // 136 + 1                 (Keccak256.yul)
  sha256   : numRounds = pad64(len + 8) // 64           (SHA256.yul)
Deterministic byte pattern so the vectors are reproducible; the expected digest
is emitted alongside so `cast call` can be checked against ground truth.
"""
import hashlib, json, os

OUT = os.path.dirname(os.path.abspath(__file__))
SIZES = [32, 1024, 8192, 65536]

def data(n):
    return bytes((i * 31 + 7) & 0xFF for i in range(n))

def keccak_rounds(n):
    return n // 136 + 1

def sha256_rounds(n):
    ext = n + 8
    return (ext + (64 - ext % 64)) // 64

meta = {}
for n in SIZES:
    d = data(n)
    name = f"hashin_{n}"
    open(os.path.join(OUT, name + ".hex"), "w").write(d.hex())
    meta[name] = dict(bytes=n, keccak_rounds=keccak_rounds(n),
                      sha256_rounds=sha256_rounds(n),
                      sha256_digest="0x" + hashlib.sha256(d).hexdigest())
    print(f"{name:14s} {n:>6} B  keccak_rounds={keccak_rounds(n):>5} "
          f"sha256_rounds={sha256_rounds(n):>5}  sha256={meta[name]['sha256_digest']}")
json.dump(meta, open(os.path.join(OUT, "hash_vectors.json"), "w"), indent=1)
