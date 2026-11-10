#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target_dir="$repo_root/testdata/era_mainnet_batches/binary"
source_dir=""
all_batches=false
declare -a requested_batches=()

usage() {
  cat <<'EOF'
Usage:
  ./scripts/import_mainnet_batches.sh --source-dir <dir> --all
  ./scripts/import_mainnet_batches.sh --source-dir <dir> <batch-number> [<batch-number>...]

The script compresses raw `<number>.bin` inputs into `<number>.bin.gz`, validates
the round-trip, and stages the result so Git LFS stores the payload outside the
main Git history.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --source-dir)
      if [ "$#" -lt 2 ]; then
        echo "error: --source-dir requires a path" >&2
        exit 1
      fi
      source_dir="$2"
      shift 2
      ;;
    --all)
      all_batches=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      requested_batches+=("$1")
      shift
      ;;
  esac
done

if [ -z "$source_dir" ]; then
  echo "error: --source-dir is required" >&2
  usage
  exit 1
fi

if ! git -C "$repo_root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "error: $repo_root is not a git repository" >&2
  exit 1
fi

if ! git -C "$repo_root" lfs version >/dev/null 2>&1; then
  echo "error: git-lfs is required to stage compressed batch data" >&2
  exit 1
fi

mkdir -p "$target_dir"

if [ "$all_batches" = true ]; then
  if [ "${#requested_batches[@]}" -ne 0 ]; then
    echo "error: --all cannot be combined with explicit batch numbers" >&2
    exit 1
  fi

  shopt -s nullglob
  while IFS= read -r batch_number; do
    requested_batches+=("$batch_number")
  done < <(
    for source_path in "$source_dir"/*.bin; do
      basename "$source_path" .bin
    done | sort -n
  )
  shopt -u nullglob
fi

if [ "${#requested_batches[@]}" -eq 0 ]; then
  echo "error: choose --all or pass at least one batch number" >&2
  exit 1
fi

# TODO: Add resumable parallel compression if the corpus grows substantially.
for batch_number in "${requested_batches[@]}"; do
  if [[ ! "$batch_number" =~ ^[0-9]+$ ]]; then
    echo "error: batch number '$batch_number' must be numeric" >&2
    exit 1
  fi

  source_path="$source_dir/${batch_number}.bin"
  target_path="$target_dir/${batch_number}.bin.gz"

  if [ ! -f "$source_path" ]; then
    echo "error: missing source batch $source_path" >&2
    exit 1
  fi

  gzip -9 -c "$source_path" > "$target_path"

  if ! cmp -s "$source_path" <(gzip -dc "$target_path"); then
    echo "error: gzip round-trip verification failed for batch $batch_number" >&2
    exit 1
  fi

  git -C "$repo_root" add -- "$target_path"
  echo "imported batch $batch_number -> ${target_path#$repo_root/}"
done
