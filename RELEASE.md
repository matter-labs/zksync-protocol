# Release process

> [!CAUTION]
> Creating new releases for the old versions of code is covered separately below on this page.
> If you intend to release a fix for the old version of the code, make sure to read the relevant
> section first.

## Automatic releases

We use [release-plz](https://release-plz.dev/) to manage and publish releases to [crates.io](https://crates.io/).

Any pull request name must follow [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/)
specification, and then, based on the PR titles, a release pull request will be created, which
will take care of changelog generation.

Important: only `fix` and `feat` labels will trigger a release PR creation. So, if a `chore` or `ci`
PR will be merged right after release, the PR will not be created (they _will_ be included into a release,
if a release PR exists, but they won't trigger PR creation or appear in the changelog). If you want to make
sure that the change will trigger a release PR, mark the PR as `fix` or `feat`.

By default, a patch version will be bumped. If you want to bump a minor version, mark the PR as breaking with
an exclamation point, e.g. `feat!` or `fix!`.

It is recommended that each PR has a component mentioned, e.g. `feat(component): change added`.

Once release PR is merged, it will be published to `crates.io`, and a notification will be sent to Slack.

If you did just chore changes, create empty PR (with this doc change for example) with feat in PR.

## Manual releases

> [!WARNING]  
> Manual releases are discouraged, and should only be used as a last resort measure.
> Discuss the manual release with the team beforehand and prepare a plan.
>
> Additionally, if the release was created, but wasn't published, you will only need a subset
> of the actions listed below (e.g. if the it failed due to a transient error, you just need to
> publish code without creating any tags; but if the release can't be published, it's better to
> remove it, fix the issue, and try releasing again via automation).

> [!CAUTION]
> Never release code that does not correspond to any tag.

If you want to release the packages on crates.io, follow this process:

1. Install `cargo workspaces`: `cargo install cargo-workspaces`
2. Create a new branch to prepare a release.
3. Change versions in the `Cargo.toml`:
  - `version` in `[workspace.package]`
  - `version` in `[workspace.dependencies]` for all the relevant crates.
4. Run `cargo build`. It must succeed.
5. Commit changes.
6. Run `cargo ws publish --dry-run`. Check the output. It might fail, but it might be OK.
  - `error: config value 'http.cainfo' is not set` can be ignored.
  - There might be warnings, this is OK.
  - There might be errors related to the version resolution, e.g. `failed to select a version`
    (in particular, for `zkevm_test_harness`). It's due to a bug in cargo workspaces.
    Check that the packages it complains about actually have the specified version, and if so,
    it's safe to proceed.
7. Create a PR named `crates.io: Release <version>`. Get a review and merge it.
8. From the main branch _after_ you merge it, run `cargo ws publish --publish-as-is --allow-dirty`.
  - The `--publish-as-is` argument skips the versioning step, which you already did before.
  - The `--allow-dirty` argument is required, because `cargo ws` temporarily removes dev-dependencies
    during publishing.
  - Important: if something fails and you have to do changes to the code, it's safe to run the same
    command again. `cargo ws` will skip already published packages.
9. If something goes wrong, see recommendations below.
10. If everything is OK, create a tag: `git tag v<version>`, e.g. `git tag v0.150.4`
11. `git push --tags`
12. Go to the Releases in the GitHUb, and create a release for published version.

## Updating old releases

The main branch of this repository corresponds to the actively supported version of ZKsync protocol.
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
  `main` branch, ideally insert a link to the corresponding PR.
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
