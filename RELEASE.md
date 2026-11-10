# Release process

> [!CAUTION]
> Creating new releases for the old versions of code is covered separately below on this page.
> If you intend to release a fix for the old version of the code, make sure to read the relevant
> section first.

## What this repository releases

Each cargo workspace here is a root of its own, with its own version line, its own lockfile and
its own changelog:

| workspace | crates | version line | tag | changelog |
|---|---|---|---|---|
| `protocol/` | `zk_evm`, `zkevm_circuits`, `zkevm_test_harness`, … | `0.153.x` | `v0.153.16` | `protocol/CHANGELOG.md` |
| `crypto/` | `boojum`, `zksync_bellman`, `zksync_pairing`, … | `0.32.x` | `crypto-v0.32.13` | `crypto/CHANGELOG.md` |
| `crypto-gpu/` | `shivini`, `boojum-cuda`, `era_cudart`, … | `0.156.x` | `crypto-gpu-v0.156.6` | `crypto-gpu/CHANGELOG.md` |
| `vm2/` | `zksync_vm2`, `zksync_vm2_interface` | `0.7.x` | `vm2-v0.7.0` | `vm2/CHANGELOG.md` |
| `eravm-airbender-verifier/` | `zksync_airbender_verifier`, `eravm-prover-host`, `eravm-prover-guest`, … | `31.x` | `eravm-airbender-verifier-v31.1.1` | `eravm-airbender-verifier/CHANGELOG.md` |
| `zkos-wrapper/` | `zkos-wrapper`, `wrapper_generator`, `circuit_mersenne_field` | `0.1.x` | `zkos-wrapper-v0.1.0` | `zkos-wrapper/CHANGELOG.md` |

There is no manifest at the repository root, and no workspace knows the layout of the others
beyond the relative paths it depends on.

They release **independently**: a release pull request, a tag and a changelog each, on their own
cadences. Nothing forces a vm2 change to move the protocol version, or a protocol change to move
the crypto version.

The version lines are deliberately different numbers, and none of them is "the repository
version". They came from separate repositories and they keep the numbering their consumers
already pin.

One of them releases more than a tag. `eravm-airbender-verifier/` publishes the Airbender guest
binary (`app.bin`, `app.text`) and both verification keys (`fri_vk.bin`, `snark_vk.json`) as
**release assets**, built from the tagged commit by
[`release-artifacts.yaml`](.github/workflows/release-artifacts.yaml) — see
[Release assets](#release-assets-eravm-airbender-verifier) below. Nothing else here ships binaries.

## How a version gets bumped

[release-please](https://github.com/googleapis/release-please) watches `dev`, this repository's
trunk. On every push it re-computes, per workspace, what the next version would be from the
[conventional commits](https://www.conventionalcommits.org/en/v1.0.0/) merged since that
workspace's last tag, and opens (or updates) one release pull request per workspace. Merging that
pull request cuts the tag and the GitHub release.

> [!IMPORTANT]
> `dev` must remain the repository's **default** branch. release-please takes the branch it
> targets from its `target-branch` input, which the reusable workflow does not expose, so it falls
> back to the default branch. If the default is ever moved back to `main`, the release workflow
> will still fire on pushes to `dev` but will look for its config on `main` and quietly do
> nothing. `main` here is the two-commit skeleton left over from repository creation.

**The directory a commit touches decides which workspace it releases — not the scope in its
title.**

- a commit touching `protocol/**` → releases `zksync-protocol`
- a commit touching `crypto/**` → releases `crypto`
- a commit touching `crypto-gpu/**` → releases `crypto-gpu`
- a commit touching `vm2/**` → releases `vm2`
- a commit touching `eravm-airbender-verifier/**` → releases `eravm-airbender-verifier`
- a commit touching `zkos-wrapper/**` → releases `zkos-wrapper`
- a commit touching several of those → releases each of them
- a commit touching only shared repository files (`.github/**`, `rust-toolchain`, `deny.toml`, the
  root `README.md`) → releases **nothing**, because those belong to no workspace

That falls straight out of the layout: each package in
[`.github/release-please/config.json`](.github/release-please/config.json) is a real directory, so
release-please's path split does the scoping with nothing configured on top of it.

The match is against the files a commit *itself* touched, not against where those files live
today. Commits from before the protocol crates moved into `protocol/` touch `crates/…` and so
belong to no workspace — which is why `0.153.16` was cut by hand as a baseline (see
[`protocol/CHANGELOG.md`](protocol/CHANGELOG.md)) rather than by release-please. Nothing before
`v0.153.16`, `crypto-v0.32.13`, `crypto-gpu-v0.156.6`, `vm2-v0.7.0`,
`eravm-airbender-verifier-v31.1.1` or `zkos-wrapper-v0.1.0` will ever appear in a generated
changelog; those tags are where the automation starts.

> [!IMPORTANT]
> **Do not delete those tags.** A version in the manifest is not an anchor: release-please
> finds a workspace's last release from the tags and GitHub releases, and reads the manifest for
> the number only once it has a commit to stop at. With nothing to stop at it walks back past the
> split into the root-level commits, several of which carry a `Release-As:` footer from 2024 that
> pins every workspace to `0.150.8` at once. [`config.json`](.github/release-please/config.json)
> sets `last-release-sha` to the vendoring commit as a second floor against exactly that.

> [!IMPORTANT]
> **A crypto fix does not move the protocol version, even though the protocol crates build against
> it.** `protocol/crates/*` depends on `crypto/crates/*` by path, so a crypto change does change
> what the protocol crates compile to — but release-please attributes the commit to `crypto/` only,
> and anyone pinning `v0.153.16` keeps getting the old crypto until some later commit under
> `protocol/**` cuts a new protocol tag.
>
> When a crypto fix has to reach protocol consumers now, do one of:
>
> - point them at the `crypto-v0.32.x` tag — it names the whole tree, protocol crates included
>   (see [Consuming a release](#consuming-a-release)); or
> - land a `fix(protocol): …` commit that touches `protocol/**` so a protocol tag is cut on top of
>   it. Bumping `protocol/Cargo.lock` alone counts.
>
> The same applies to `vm2/`, which builds against `protocol/crates/*`, to `crypto-gpu/`, which
> builds against both `protocol/crates/*` and `crypto/crates/*`, and to
> `eravm-airbender-verifier/`, which builds against `protocol/crates/*`, `vm2/crates/vm2` and
> `zkos-wrapper/wrapper` — with one extra consequence there: a change in any of those moves the
> guest binary or the SNARK verification key, so the keys the *next* verifier release publishes will
> differ from the ones the last one did, even though no file under `eravm-airbender-verifier/`
> changed.

Scopes in PR titles (`feat(vm2): …`, `fix(boojum): …`) are for humans reading the changelog. They
have no effect on which workspace is released. Put the change in the right directory instead.

Every pull request title must follow conventional commits — [`pr-title.yaml`](.github/workflows/pr-title.yaml)
enforces it — because the squashed title is the commit message release-please parses.

Only `feat` and `fix` open a release pull request. `chore`, `ci`, `docs`, `perf` and friends are
*included* in a release pull request that already exists, but never create one. If you need a
release for a change that is genuinely a chore, mark the PR `fix` or `feat`.

On a `0.x` version line — all of them except the verifier's `31.x` — a breaking change (`feat!`, `fix!`, or a
`BREAKING CHANGE:` footer) bumps the **minor**, and everything else bumps the **patch**. There is
no automatic path to `1.0.0`; getting there is a deliberate `Release-As:` (see below).

### What lands in the release pull request

For the released workspace, release-please writes the version into `<workspace>/Cargo.toml`
(the `# x-release-please-version` line), prepends the changelog and updates
[`.github/release-please/manifest.json`](.github/release-please/manifest.json). CI then runs
`cargo workspaces version` inside that workspace to rewrite the `=<version>` pins in its
`[workspace.dependencies]`, and refreshes every lockfile — the cross-workspace path
dependencies mean a crypto bump moves entries in `protocol/Cargo.lock`, `crypto-gpu/Cargo.lock`,
`vm2/Cargo.lock`, `eravm-airbender-verifier/Cargo.lock` and `zkos-wrapper/Cargo.lock` too. Review that all of it is there before merging; a release PR that only
touched one lockfile is a bug, not a shortcut.

### What CI runs on a release pull request

Not the per-workspace jobs. The diff is manifests, lockfiles and changelogs, so no test, lint or
proving run can come out differently than it did on the commit being released; only *resolution*
can break, through an `=<version>` pin `cargo workspaces version` missed or a lockfile left stale.
So [`ci.yaml`](.github/workflows/ci.yaml) hands the PR to
[`ci-release-check.yaml`](.github/workflows/ci-release-check.yaml) — `cargo check --locked` per
affected workspace, which is step 3 of [Manual releases](#manual-releases) done for you — and the
GPU jobs and the VK divergence check stand down. `cargo deny` still runs: it reads the lockfiles
the PR rewrites.

Push anything outside the manifests, lockfiles and changelogs onto a release branch and the full
CI comes back: the filter checks the paths in the diff, not just the branch name. A hand fix
confined to those files — which is what most bad release PRs need — still gets the release check
alone, and `cargo check --locked` is what has to catch it.

### Forcing a release

Two escape hatches, in order of preference:

1. **Land a real change under that workspace's directory** with a `feat`/`fix` title. This is the
   normal answer when a workspace needs a tag that carries a change made elsewhere in the repo —
   vm2 or protocol needing a tag cut after a `crypto/` fix, say. Touching that workspace's
   `Cargo.lock` is enough to make the commit count.
2. **`Release-As: <version>`** in the pull request body, to pin the next version of a workspace
   explicitly (a `1.0.0`, a version-line jump). Note that release-please still needs at least one
   commit attributed to that workspace to act on.

An empty commit (`git commit --allow-empty`) is attributed to **every** workspace, so a
`feat: …` with no files releases every workspace at once. That is occasionally what you want and almost
never what you meant — prefer changing a file under the one directory.

## Consuming a release

Nothing here is published to crates.io. `zk_evm_abstractions` depends on `airbender-crypto` from
`matter-labs/airbender-platform` by git, which is not on crates.io, so `cargo publish` cannot
succeed for the protocol workspace; the others are held to the same rule so that all are
consumed the same way. `publish-to-crates-io` is `false` in
[`release.yaml`](.github/workflows/release.yaml). A release here means **a tag and a GitHub
release**, and consumers pin the git tag:

```toml
zk_evm       = { git = "https://github.com/matter-labs/zksync-protocol", tag = "v0.153.16" }
boojum       = { git = "https://github.com/matter-labs/zksync-protocol", tag = "crypto-v0.32.13" }
shivini      = { git = "https://github.com/matter-labs/zksync-protocol", tag = "crypto-gpu-v0.156.6" }
zksync_vm2   = { git = "https://github.com/matter-labs/zksync-protocol", tag = "vm2-v0.7.0" }
eravm-prover-host = { git = "https://github.com/matter-labs/zksync-protocol", tag = "eravm-airbender-verifier-v31.1.1" }
zkos-wrapper = { git = "https://github.com/matter-labs/zksync-protocol", tag = "zkos-wrapper-v0.1.0" }
```

Because the workspaces share one repository, **any** of these tags names a whole tree.
`tag = "v0.153.16"` resolves `boojum`, `shivini` and `zksync_vm2` just as well as it resolves
`zk_evm` — cargo finds the packages under `crypto/crates/`, `crypto-gpu/crates/` and
`vm2/crates/`. A consumer that wants them in lockstep should pin one tag for all of them — the
most recently cut, whichever workspace it belongs to.

### Release assets (`eravm-airbender-verifier`)

A verifier release also carries files, because its consumers need the *built* guest rather than
its sources: the prover service in `zksync-era` loads the verification keys from disk and never
derives them. [`release-artifacts.yaml`](.github/workflows/release-artifacts.yaml) fires on
`release: published`, rebuilds the guest in the pinned `cargo-airbender` image, regenerates both
keys from it on a GPU runner and attaches `app.bin`, `app.text`, `fri_vk.bin`, `snark_vk.json` and
`checksums.txt` to the release. It is guarded on the `eravm-airbender-verifier-v` tag prefix, so
the other four workspaces' releases skip it.

Two things follow. A verifier tag without those five assets means that workflow failed — re-run it
(`workflow_dispatch` builds the same bundle without touching a release) rather than re-cutting the
tag. And since the keys are derived from the guest, they are a function of the whole tree the tag
names: `protocol/` and `vm2/` compile into the guest, so a release cut after a change there
publishes different keys.

Pin per-workspace tags only when you want that workspace's semver to mean something to you, and
read the note above about a crypto fix not moving the protocol version: `v0.153.16` is a promise
about the protocol *sources*, not about the crypto they were last built against.

Do **not** reach for `[patch.crates-io]` to redirect the published crypto crates at this tree. It
replaces the crates.io source globally for every consumer, which breaks consumers such as
zksync-era that also build historical protocol crates from crates.io against the published crypto
crates. A registry source and a git source can
coexist; two semver-compatible registry versions cannot. See the long comment above the crypto
dependencies in [`protocol/Cargo.toml`](protocol/Cargo.toml).

## Adding a seventh workspace

The pattern generalises. For a workspace vendored at `foo/`:

1. Add `"foo"` to `packages` in `config.json` with `"component": "foo"`,
   `"include-component-in-tag": true` and the `Cargo.toml` extra-file entry.
2. Add `"foo": "<current version>"` to `manifest.json`, matching
   `foo/Cargo.toml`'s `# x-release-please-version` line exactly.
3. Create the anchor GitHub release `foo-v<current version>` on the vendoring commit, so
   release-please has a starting point and does not walk the whole history looking for one.
4. Add `foo` to `workspace-dirs` in `release.yaml`, to the `deny.yaml` matrix, and to
   [`changed-workspaces`](.github/actions/changed-workspaces/action.yaml) — its `known` paths, its
   dependency edges, its `dirs` output and the release-only path set.
5. Add it to the workspace choice list in `publish-crates.yaml`.

Nothing else, as far as *releasing* goes. There is no root package to teach about `foo/`, and no
`exclude-paths` to maintain — a new workspace is scoped by being a directory. `crypto-gpu/`, `eravm-airbender-verifier/` and `zkos-wrapper/` were all added this way.

What a vendored workspace can additionally need — everything `eravm-airbender-verifier/` needed
beyond the five steps above — is: exceptions folded into the root [`deny.toml`](deny.toml) if its
graph pulls licences or advisories the others do not; a `rust-toolchain.toml` of its own if it
cannot move to the repository nightly (it must justify that in its `Cargo.toml` header, as the
verifier does); a tag-prefix guard on any release workflow of its own, since `release: published`
fires for every workspace's releases; and, if it carries Git LFS content, a line in the root
[`.lfsconfig`](.lfsconfig).

Only `protocol/` keeps `"include-component-in-tag": false`, so that its tags stay bare `v0.153.x`
and every existing consumer pin keeps resolving. Every other workspace gets a component-prefixed
tag.

## Manual releases

> [!WARNING]
> Manual releases are discouraged, and should only be used as a last resort measure.
> Discuss the manual release with the team beforehand and prepare a plan.

> [!CAUTION]
> Never release code that does not correspond to any tag.

If release-please cut the tag but a follow-up step failed, fix that step — do not re-cut the tag.
The [`Publish crates`](.github/workflows/publish-crates.yaml) workflow is the manual escape hatch;
it takes the workspace to publish (`protocol`, `crypto`, `crypto-gpu`, `vm2`,
`eravm-airbender-verifier` or `zkos-wrapper`) as an input. It is
only useful if crates.io publishing is ever re-enabled.

To create a release entirely by hand:

1. Install `cargo workspaces`: `cargo install cargo-workspaces`.
2. Create a branch, and in the workspace you are releasing, set the version:
   `cargo workspaces version custom <version> --all --exact --force '*' --no-git-commit`.
   Run it from that workspace's directory — `protocol/`, `crypto/`, `crypto-gpu/`, `vm2/`,
   `eravm-airbender-verifier/` or `zkos-wrapper/`. There is no manifest at the repository root, so
   running it there does nothing.
3. `cargo build` in every workspace (`crypto-gpu/` needs a CUDA toolkit, or
   `ZKSYNC_USE_CUDA_STUBS=1 cargo check`; `eravm-airbender-verifier/` builds with
   `ZKSYNC_USE_CUDA_STUBS=1` and excludes its guest, which `cargo airbender build` builds). It must succeed, and it is the point of the exercise:
   the path dependencies mean the others see the new version.
4. Update the workspace's `CHANGELOG.md` and its entry in
   `.github/release-please/manifest.json` by hand. If you skip the manifest, release-please will
   propose the same version again on the next push.
5. Get the PR reviewed and merged.
6. Tag the merge commit — `v<version>` for `protocol/`, `crypto-v<version>`,
   `crypto-gpu-v<version>`, `vm2-v<version>`, `eravm-airbender-verifier-v<version>` or
   `zkos-wrapper-v<version>` for the
   others — and push the tag.
7. Create a GitHub release from that tag. release-please reads GitHub releases to find where a
   workspace last released, so a tag without a release will make it walk the history instead. For
   `eravm-airbender-verifier/` this is also what builds and attaches the guest binary and the
   verification keys, so publish the release rather than leaving it a draft.

## Updating old releases

The `dev` branch of this repository corresponds to the actively supported version of ZKsync protocol.
The old released versions are marked via [tags](https://github.com/matter-labs/zksync-protocol/tags)
and [GitHub Releases](https://github.com/matter-labs/zksync-protocol/releases).

We **DO NOT** use long-living branches for the old versions of the code.

So, if you want to release a fix, you need to:

1. Check out to a _tag_ corresponding to the _latest_ patch version of the protocol. For example,
  at the time of writing it's `v0.140.3` for the protocol version `1.4.0`, and `v0.142.2` for `1.4.2`.
  Make sure that you checkout to the latest tag available.
2. Checkout to a new branch. Do the changes. Release them manually.
3. If you introduced multiple changes, squash them into a single commit. This way, it will be easier to
  see the changes later.
4. Tag the commit with a new version, e.g. `v0.142.3`. Push the branch and tag.
5. Create a new release from this tag. Describe changes you have made. If you backported some fix from
  `dev` branch, ideally insert a link to the corresponding PR.
6. Remove the branch you pushed. The change will live as a tag only.

Then, in the core monorepo you need to update `circuit_sequencer_api` package. It's not pinned for old
versions, so you have to do it as follows:

```
cargo update circuit_sequencer_api@0.133
```

where `0.133` stands for `major.minor` versions of the package you just released. It will update all the
necessary references in the `Cargo.lock` file.

A few caveats:

- Old versions may only contain code required for MultiVM, so some crates can be missing.
- Versions before `0.150` did not have a formal process for releases, so they do not share a single
  version. Do your research and make sure that the version you want to release wasn't already published.
- Tags predating the vm2 and crypto vendoring contain only the protocol workspace. `vm2-v*`,
  `crypto-v*`, `crypto-gpu-v*`, `eravm-airbender-verifier-v*` and `zkos-wrapper-v*` tags start at
  their respective vendoring commits; there is nothing to back-port to before them.
