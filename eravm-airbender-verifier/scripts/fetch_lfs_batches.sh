#!/usr/bin/env bash
set -euo pipefail

# This workspace is one of five sibling cargo workspaces in the repository, so
# the corpus sits at `<workspace>/testdata/...` while `git lfs pull --include`
# matches patterns against paths from the *repository* root. Derive the prefix
# rather than hard-coding it, so renaming or moving the workspace does not
# silently turn every include into a no-match (which fetches nothing and fails
# nothing).
workspace_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Usage:
  ./scripts/fetch_lfs_batches.sh --all
  ./scripts/fetch_lfs_batches.sh <batch-file> [<batch-file>...]
  ./scripts/fetch_lfs_batches.sh <batch-file[,batch-file...]>

This pulls only the requested Git LFS batch objects. The repository default is
to leave the mainnet corpus as small pointer files until you opt in.
EOF
}

if ! git -C "$workspace_root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "error: $workspace_root is not a git repository" >&2
  exit 1
fi

repo_root="$(git -C "$workspace_root" rev-parse --show-toplevel)"
workspace_prefix="${workspace_root#"$repo_root"}"
workspace_prefix="${workspace_prefix#/}"
batch_glob_root="${workspace_prefix:+$workspace_prefix/}testdata/era_mainnet_batches/binary"

if ! git -C "$repo_root" lfs version >/dev/null 2>&1; then
  echo "error: git-lfs is required to fetch batch data; install it first" >&2
  exit 1
fi

# The objects live in the upstream repository's LFS store, not in this one (see
# the repository-root `.lfsconfig`), so the pull has to be pointed at it. A named
# remote rather than an `lfs.url`: git-lfs derives an LFS endpoint from a remote
# URL identically across the versions in use, but disagrees with itself about how
# to interpret a literal `lfs.url` -- 3.0.x posts to a path GitHub rejects, 3.7.x
# rewrites it -- so no single spelling of that setting works everywhere. The
# remote is added on first use and carries no refs anybody wants, hence
# `skipFetchAll`.
lfs_remote="eravm-airbender-verifier-upstream"
lfs_remote_url="https://github.com/matter-labs/eravm-airbender-verifier.git"
if ! git -C "$repo_root" remote get-url "$lfs_remote" >/dev/null 2>&1; then
  git -C "$repo_root" remote add "$lfs_remote" "$lfs_remote_url"
  git -C "$repo_root" config "remote.${lfs_remote}.skipFetchAll" true
fi

if [ "$#" -eq 0 ]; then
  usage
  exit 1
fi

includes=()

# We keep the CLI deliberately small so CI and local docs can share the same
# fetch primitive without carrying a separate manifest parser.
if [ "$1" = "--all" ]; then
  if [ "$#" -ne 1 ]; then
    echo "error: --all cannot be combined with explicit batch files" >&2
    exit 1
  fi
  includes+=("${batch_glob_root}/**")
else
  # CI stores its curated batch list as one comma-separated env var, while local
  # callers often pass files as separate shell arguments. We accept both forms so
  # the fetch helper stays aligned with the Rust CLIs.
  for batch_file_arg in "$@"; do
    IFS=',' read -r -a batch_file_parts <<< "$batch_file_arg"
    for batch_file in "${batch_file_parts[@]}"; do
      case "$batch_file" in
        *.bin.gz)
          includes+=("${batch_glob_root}/${batch_file}")
          ;;
        *.bin)
          includes+=("${batch_glob_root}/${batch_file}.gz")
          ;;
        *)
          echo "error: batch file '$batch_file' must end with .bin or .bin.gz" >&2
          exit 1
          ;;
      esac
    done
  done
fi

include_arg="$(
  IFS=,
  echo "${includes[*]}"
)"

git -C "$repo_root" lfs pull "$lfs_remote" --include="$include_arg" --exclude=""
