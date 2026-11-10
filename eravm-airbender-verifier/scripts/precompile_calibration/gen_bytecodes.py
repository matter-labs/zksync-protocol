#!/usr/bin/env python3
"""Generate N DISTINCT pre-deployable bytecodes of a target size.

Distinctness is the whole point: EraVM keys decommits by code hash, so the same
code at N addresses is ONE bytecode and the axis would not move. Each contract
therefore gets a payload whose period-256 pattern is PHASE-SHIFTED by its id
(byte j = (j + 7*id) & 0xFF) and an `id()` returning that id, so no two runtime
images can coincide. The deployed hashes are verified distinct on-chain before
any fixture is generated.

Payload pattern follows the decommit campaign's Blob*.sol: period-256
incrementing bytes are not compile-shrunk by zksolc (no run to collapse, no
repeated 32-byte word for the constant pool to dedupe) yet compress ~4:1 in
era's bytecode publication, which keeps the DEPLOY batches inside
max_pubdata_per_batch.
"""
import os, sys

OUT = sys.argv[1]
def contract(name, cid, nbytes):
    pad = bytes((j + 7 * cid) & 0xFF for j in range(nbytes)).hex()
    return f'''
contract {name} {{
    bytes constant BLOB = hex"{pad}";
    function id() external pure returns (uint256) {{ return {cid}; }}
    function ping() external pure returns (uint256) {{ return {cid} * 3 + 7; }}
    function at(uint256 i) external pure returns (bytes1) {{ return BLOB[i]; }}
    function size() external pure returns (uint256) {{ return BLOB.length; }}
}}
'''

def emit(path, prefix, ids, nbytes):
    src = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.28;\n"
    for i in ids:
        src += contract(f"{prefix}{i}", i, nbytes)
    open(path, "w").write(src)
    print(f"{os.path.basename(path)}: {len(ids)} contracts x {nbytes} B payload, "
          f"source {len(src)/1024:.0f} KiB")

# count sweep: 150 small distinct bytecodes (ids 0..149)
emit(os.path.join(OUT, "SmallCode.sol"), "S", range(150), 2048)
# size sweep: 8 distinct bytecodes at each of three larger sizes (ids offset so
# they cannot collide with the small set or each other)
emit(os.path.join(OUT, "Mid8K.sol"),  "M", range(1000, 1008), 8192)
emit(os.path.join(OUT, "Mid24K.sol"), "N", range(2000, 2008), 24576)
emit(os.path.join(OUT, "Big48K.sol"), "B", range(3000, 3008), 49152)
