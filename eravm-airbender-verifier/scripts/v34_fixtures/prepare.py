#!/usr/bin/env python3
"""Build Merkle witnesses from the upstream VM's prestate and storage logs."""
import argparse
import hashlib
import json
from pathlib import Path

ZERO = bytes(32)


def digest(data):
    return hashlib.blake2s(data).digest()


def unhex(value):
    return bytes.fromhex(value.removeprefix("0x"))


def word(value):
    return hex(value)


class Tree:
    def __init__(self, state):
        self.empty = [digest(bytes(40))]
        for _ in range(256):
            self.empty.append(digest(self.empty[-1] * 2))
        self.nodes = [{} for _ in range(257)]
        for key, (value, index) in state.items():
            self.update(key, value, index)

    def update(self, key, value, index):
        self.nodes[0][key] = digest(index.to_bytes(8, "big") + value)
        for height in range(256):
            left = key & ~1
            siblings = self.nodes[height]
            self.nodes[height + 1][key >> 1] = digest(
                siblings.get(left, self.empty[height])
                + siblings.get(left + 1, self.empty[height])
            )
            key >>= 1

    def root(self):
        return self.nodes[256].get(0, self.empty[256])

    def proof(self, key):
        proof = []
        for height in range(256):
            proof.append(self.nodes[height].get(key ^ 1, self.empty[height]))
            key >>= 1
        start = 0
        while start < 256 and proof[start] == self.empty[start]:
            start += 1
        return [list(node) for node in proof[start:]]


def prepare(raw):
    initial = raw["initial_storage"]
    state = {int.from_bytes(unhex(k), "little"): (unhex(v), i)
             for k, (v, i) in initial["state"].items()}
    tree = Tree(state)
    old_root = tree.root()
    assert raw["l1_batch_env"]["previous_batch_hash"] == "0x" + old_root.hex()
    next_index = initial["last_enum_index_set"] + 1
    expected = raw["expected"]
    log_keys = {int(log["key"], 16) for log in expected["storage_logs"]}
    read_keys = set(state) | {int(k, 16) for k in raw["accessed_keys"]}
    reads = []
    for key in sorted(read_keys - log_keys):
        value, index = state.get(key, (ZERO, 0))
        reads.append({"leaf_hashed_key": word(key), "leaf_enumeration_index": index,
                      "value": list(value), "merkle_path": tree.proof(key)})
    paths = []
    for log in expected["storage_logs"]:
        key = int(log["key"], 16)
        value, index = state.get(key, (ZERO, 0))
        proof = tree.proof(key)
        first_write = log["is_write"] and index == 0
        if first_write:
            index = next_index
            next_index += 1
        if log["is_write"]:
            tree.update(key, unhex(log["value"]), index)
        else:
            assert value == unhex(log["value"])
        paths.append({
            "root_hash": list(tree.root()), "is_write": log["is_write"],
            "first_write": first_write, "merkle_paths": proof,
            "leaf_hashed_key": word(key), "leaf_enumeration_index": index,
            "value_written": list(unhex(log["value"])), "value_read": list(value),
        })
    expected["state_root"] = "0x" + tree.root().hex()
    expected["new_enumeration_index"] = next_index
    base = raw["system_env"]["base_system_smart_contracts"]
    code_words = lambda code: [list(int(w, 16).to_bytes(32, "big")) for w in code]
    used = {k: [code[i:i+32] for i in range(0, len(code), 32)]
            for k, code in initial["factory_deps"].items()}
    return {"input": {
        "vm_run_data": {
            "l1_batch_number": raw["l1_batch_env"]["number"],
            "protocol_version": "Version34", "used_bytecodes": used,
            "initial_heap_content": expected["bootloader_memory"],
            "bootloader_code": code_words(base["bootloader"]["code"]),
            "default_account_code_hash": base["default_aa"]["hash"],
            "evm_emulator_code_hash": base["evm_emulator"]["hash"],
            "storage_refunds": expected["storage_refunds"],
            "pubdata_costs": expected["pubdata_costs"],
            "witness_block_state": {"read_storage_key": [], "is_write_initial": []},
        },
        "merkle_paths": {"merkle_paths": paths, "next_enumeration_index": initial["last_enum_index_set"] + 1},
        "prestate_read_proofs": reads,
        "l2_blocks_execution_data": raw["l2_blocks_execution_data"],
        "system_env": raw["system_env"], "l1_batch_env": raw["l1_batch_env"],
        "pubdata_params": raw["pubdata_params"], "commitment_input": None,
    }, "expected": expected}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    for name in ("normal", "mixed"):
        data = prepare(json.loads((args.directory / f"{name}.json").read_text()))
        (args.directory / f"{name}.prepared.json").write_text(json.dumps(data, sort_keys=True))
