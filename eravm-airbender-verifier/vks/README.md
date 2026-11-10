# Verification keys

The prover server only loads verification keys from disk; it never derives
them on the fly. The canonical VKs are **published as GitHub release assets**,
not committed to this repo — they are built from the exact released commit by
[`.github/workflows/release-artifacts.yaml`](../../.github/workflows/release-artifacts.yaml),
so they can never drift from the source they were generated against:

- `fri_vk.bin` — bincode-encoded `airbender_host::VerificationKey` for the
  FRI proof. Deterministically derived from the guest binary (`app.bin`), whose
  sha256 it embeds.
- `snark_vk.json` — JSON-encoded `zkos_wrapper::SnarkWrapperVK` for the
  phase-3 SNARK wrapper. Derived from the trusted setup chain.

Download them from a release (alongside `app.bin` / `app.text` and a
`checksums.txt`), or point the server / host at a local copy via `--fri-vk`
(`FRI_VK`) and the guest dist env var. Local files placed in this directory are
git-ignored.

## Regenerating for development

```bash
# Needs a GPU runner with the trusted setup (CRS) on disk.
cargo run -p eravm-prover-host --features gpu_snark -- gen-vks \
    --output-dir vks \
    --trusted-setup /path/to/setup.key
```

You normally don't need to do this locally. VK generation is costly, so it runs
in CI only for the proving test (`verifier-host-integration-run`, on
guest/VK-relevant changes) and at release time. Regenerate locally only when you actually need to
prove against a locally-changed guest.
