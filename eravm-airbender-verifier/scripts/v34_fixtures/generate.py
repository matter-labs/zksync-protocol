#!/usr/bin/env python3
"""Generate v34 fixtures using a pinned, local Era checkout and compiled contracts."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
from prepare import prepare

ERA_REVISION = "dd9f819a46b807aa93884126f4a5ae3d0568283a"
CONTRACTS_REVISION = "4ab4a0ef3366e5fea80345d4fd91d7b996099020"
HERE = Path(__file__).resolve().parent


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--era-repo", type=Path, required=True)
    parser.add_argument("--contracts", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=HERE.parents[1] / "testdata/v34")
    args = parser.parse_args()
    contracts = args.contracts.resolve()
    work = args.work_dir.resolve()
    output = args.output.resolve()
    if git(contracts, "rev-parse", "HEAD") != CONTRACTS_REVISION:
        parser.error(f"contracts must be checked out at {CONTRACTS_REVISION}")
    if git(contracts, "status", "--porcelain", "--untracked-files=no"):
        parser.error("contracts has tracked source changes")
    artifacts = sorted(p for directory in ("system-contracts/zkout", "l1-contracts/zkout")
                       for p in (contracts / directory).rglob("*.json"))
    if not artifacts or not (contracts / "system-contracts/zkout/proved_batch.yul/Bootloader.json").is_file():
        parser.error("build the system contracts and bootloader first")
    marker = work / ".v34-fixture-generator"
    if work.exists():
        if not marker.exists() or marker.read_text().strip() != ERA_REVISION:
            parser.error("work-dir already exists and is not owned by this generator")
        if git(work, "rev-parse", "HEAD") != ERA_REVISION:
            parser.error("generator checkout is on a different revision")
    else:
        subprocess.run(["git", "-C", str(args.era_repo.resolve()), "worktree", "add", "--detach", str(work), ERA_REVISION], check=True)
        marker.write_text(ERA_REVISION + "\n")
    link = work / "contracts"
    if link.is_symlink():
        if link.resolve() != contracts:
            parser.error("generator checkout points at different contracts")
    else:
        link.rmdir()
        link.symlink_to(contracts, target_is_directory=True)
    patches = {
        "core/lib/vm_interface/src/storage/in_memory.rs": (
            "#[derive(Debug, Default, Clone, PartialEq)]",
            "#[derive(Debug, Default, Clone, PartialEq, serde::Serialize)]",
        ),
    }
    for relative, (old, new) in patches.items():
        original = git(work, "show", f"{ERA_REVISION}:{relative}")
        if original.count(old) != 1:
            raise RuntimeError(f"unexpected source layout: {relative}")
        (work / relative).write_text(original.replace(old, new) + "\n")
    module = "core/lib/multivm/src/versions/testonly/mod.rs"
    (work / module).write_text(git(work, "show", f"{ERA_REVISION}:{module}") + "\nmod v34_fixture_export;\n")
    (work / Path(module).parent / "v34_fixture_export.rs").write_bytes((HERE / "era_export.rs").read_bytes())
    manifest = "core/lib/multivm/Cargo.toml"
    (work / manifest).write_text(git(work, "show", f"{ERA_REVISION}:{manifest}")
        + "\nzksync_l1_contract_interface.workspace = true\nzksync_crypto_primitives.workspace = true\n")
    raw = work / ".v34-fixtures"
    raw.mkdir(exist_ok=True)
    env = dict(os.environ, V34_FIXTURE_OUTPUT=str(raw), ZKSYNC_HOME=str(work))

    def run_test(name):
        subprocess.run(["cargo", "test", "-p", "zksync_multivm", "--lib", name,
                        "--", "--ignored", "--nocapture"], cwd=work / "core", env=env, check=True)

    run_test("export_v34_fixtures")
    for name in ("normal", "mixed"):
        fixture = prepare(json.loads((raw / f"{name}.json").read_text()))
        (raw / f"{name}.prepared.json").write_text(json.dumps(fixture, sort_keys=True))
    run_test("finalize_v34_fixture_commitments")
    artifact_hashes = {str(p.relative_to(contracts)): sha256(p) for p in artifacts}
    provenance = {
        "era_revision": ERA_REVISION,
        "contracts_revision": CONTRACTS_REVISION,
        "protocol_version": 34,
        "generator_sha256": {name: sha256(HERE / name) for name in ("generate.py", "prepare.py", "era_export.rs")},
        "contracts_artifacts_sha256": hashlib.sha256(json.dumps(artifact_hashes, sort_keys=True).encode()).hexdigest(),
        "era_cargo_lock_sha256": sha256(work / "core/Cargo.lock"),
    }
    output.mkdir(parents=True, exist_ok=True)
    cases = {}
    for name in ("normal", "mixed"):
        fixture = json.loads((raw / f"{name}.prepared.json").read_text())
        fixture["provenance"] = provenance
        for field in ("bootloader_memory", "storage_logs", "storage_refunds", "pubdata_costs"):
            fixture["expected"].pop(field)
        encoded = json.dumps(fixture, sort_keys=True, separators=(",", ":")).encode()
        path = output / f"{name}.json.gz"
        path.write_bytes(gzip.compress(encoded, mtime=0))
        cases[name] = {
            "sha256": sha256(path),
            "bootloader_hash": fixture["input"]["system_env"]["base_system_smart_contracts"]["bootloader"]["hash"],
            "state_root": fixture["expected"]["state_root"],
            "commitment": fixture["expected"]["commitment"],
        }
        print(f"Wrote {path} ({path.stat().st_size} bytes)", flush=True)
    (output / "manifest.json").write_text(json.dumps({"provenance": provenance, "cases": cases}, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
