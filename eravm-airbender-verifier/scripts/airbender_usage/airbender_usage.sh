#!/usr/bin/env bash
# airbender_usage.sh
#
# Collect the set of airbender-platform items that are monomorphized (i.e.
# reachable) from this workspace's binaries, using rustc's
# `-Zprint-mono-items=y`. Optionally diff that against the set of public
# items *defined* in a local airbender-platform checkout to produce a list of
# unused items.
#
# Usage:
#   scripts/airbender_usage/airbender_usage.sh [--target host|guest|both]
#                                              [--compare PATH_TO_AIRBENDER_PLATFORM]
#                                              [--keep-target]
#
# Defaults: --target both.
#
# Caveats:
#   - `-Zprint-mono-items=y` is emitted per-crate. For the binary crate,
#     mono items correspond to reachable generic instantiations + locally
#     defined items; for dep crates compiled as rlibs, rustc conservatively
#     lists their public items (it doesn't know who the downstream callers
#     are). The union is therefore an *upper bound* on what ends up in the
#     final binary — things listed may still be stripped by the linker. It is
#     however a tight *lower bound* on the API surface your workspace touches
#     transitively, which is what you asked for.
#   - The "--compare" side is an approximate, heuristic parse of
#     `pub fn|struct|enum|trait|type|const|static|union` from the airbender
#     crates' source. Inherent- and trait-`impl` methods ARE handled: the
#     enclosing `impl <Type>` block is tracked with a best-effort brace-depth
#     scan so a method is emitted as `mod::Type::method` (the path MONO_ITEM
#     actually carries) rather than `mod::method` — otherwise the majority of
#     the API (associated methods) would be spuriously reported as unused.
#     This is still a heuristic, NOT a Rust parser: items declared inside
#     macros, behind `#[cfg]`, re-exported under a different name, or in impl
#     blocks whose opening `{` is not on the `impl ...` header line will not
#     match perfectly. Treat the "unused" list as a starting point to eyeball,
#     not a proof.

set -euo pipefail
export LC_ALL=C

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SELF_DIR="${ROOT}/scripts/airbender_usage"
WRAPPER="${SELF_DIR}/rustc_wrapper.sh"
OUT_DIR="${ROOT}/target/airbender-usage"

mode_target="both"
compare_path=""
keep_target=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)  [[ $# -ge 2 && -n "${2:-}" ]] || { echo "--target requires a value" >&2; exit 2; }; mode_target="$2"; shift 2 ;;
        --compare) [[ $# -ge 2 && -n "${2:-}" ]] || { echo "--compare requires a value" >&2; exit 2; }; compare_path="$2"; shift 2 ;;
        --keep-target)  keep_target=true; shift ;;
        -h|--help)
            sed -n '2,30p' "$0"
            exit 0
            ;;
        *) echo "unknown flag: $1" >&2; exit 2 ;;
    esac
done

case "${mode_target}" in
    host|guest|both) ;;
    *) echo "--target must be host|guest|both, got ${mode_target}" >&2; exit 2 ;;
esac

chmod +x "${WRAPPER}"
mkdir -p "${OUT_DIR}"
# Only this run's targets should contribute to the combined reachable set;
# drop any per-target lists left over from a previous invocation.
rm -f "${OUT_DIR}"/reachable-*.txt

AIRBENDER_CRATE_PREFIX='airbender[a-zA-Z0-9_]*'
AIRBENDER_PATH_RE="${AIRBENDER_CRATE_PREFIX}(::[A-Za-z_][A-Za-z0-9_]*)+"

build_one() {
    local name="$1"      # host | guest
    local subdir="${ROOT}/${name}"
    local target_dir="${OUT_DIR}/target-${name}"
    local log="${OUT_DIR}/mono-${name}.log"
    local list="${OUT_DIR}/reachable-${name}.txt"

    echo "==> [${name}] clean build under ${target_dir}"
    rm -rf "${target_dir}"

    echo "==> [${name}] cargo build --release (capturing MONO_ITEM lines)"
    (
        cd "${subdir}"
        # RUSTC_WRAPPER wraps every rustc invocation (workspace AND deps),
        # appending -Zprint-mono-items=y without touching the flags cargo
        # already computed from .cargo/config.toml.
        CARGO_TARGET_DIR="${target_dir}" \
        RUSTC_WRAPPER="${WRAPPER}" \
        cargo build --release > "${log}"
    )

    echo "==> [${name}] extracting airbender_* items"
    # MONO_ITEM lines look like:
    #   MONO_ITEM fn airbender_host::program::Program::load @@ cgu[kind]
    #   MONO_ITEM fn std::ptr::drop_in_place::<airbender_host::runner::ExecutionResult> @@ ...
    # We grab every identifier chain starting with airbender*.
    grep -E '^MONO_ITEM ' "${log}" \
        | grep -oE "\b${AIRBENDER_PATH_RE}" \
        | sort -u > "${list}" || true

    echo "    reachable items: $(wc -l < "${list}" | tr -d ' ')  (see ${list})"
}

enumerate_defined() {
    local airbender_path="$1"
    local out="$2"

    python3 - "${airbender_path}" "${out}" <<'PY'
import os, re, sys

root, out = sys.argv[1], sys.argv[2]

# Crates to scan. Keep in sync with airbender-platform/Cargo.toml.
crates = [
    "airbender-core", "airbender-codec", "airbender-crypto",
    "airbender-guest", "airbender-host", "airbender-macros",
    "airbender-rt",   "airbender-sdk",
]

# Match a public item declaration. Deliberately conservative: captures the
# item kind and its identifier, ignores generics/lifetimes/visibility qualifiers
# beyond `pub` and `pub(crate)`. We skip `pub use` because it just re-exports.
decl = re.compile(
    r'^\s*pub(?:\(crate\))?\s+'
    r'(?:unsafe\s+|async\s+|default\s+|const\s+)*'
    r'(fn|struct|enum|trait|type|const|static|union)\s+'
    r'([A-Za-z_][A-Za-z0-9_]*)'
)
mod_decl = re.compile(r'^\s*pub(?:\(crate\))?\s+mod\s+([A-Za-z_][A-Za-z0-9_]*)')

# Match an `impl` header and capture the SELF type (the token after `for` for a
# trait impl, otherwise the only type). Best-effort: nested generics that
# contain `>` and impl headers whose `{` is on a later line are not handled.
impl_decl = re.compile(
    r'^\s*(?:default\s+|unsafe\s+)*impl(?:\s*<[^>]*>)?\s+'
    r'(?:.+\s+for\s+)?([A-Za-z_][A-Za-z0-9_]*)'
)

def module_prefix(crate_name_snake: str, src_root: str, file_path: str) -> str:
    rel = os.path.relpath(file_path, src_root)
    parts = rel[:-3].split(os.sep)  # strip ".rs"
    if parts == ["lib"]:
        return crate_name_snake
    if parts[-1] == "mod":
        parts = parts[:-1]
    return "::".join([crate_name_snake, *parts])

items = set()
scanned = 0
for crate in crates:
    src_root = os.path.join(root, "crates", crate, "src")
    if not os.path.isdir(src_root):
        sys.stderr.write(f"    warning: crate source dir not found, skipping: {src_root}\n")
        continue
    scanned += 1
    crate_name = crate.replace("-", "_")
    # airbender-sdk re-exports as `airbender` (see its [lib] name).
    lib_name = "airbender" if crate == "airbender-sdk" else crate_name
    for dirpath, _, files in os.walk(src_root):
        for fname in files:
            if not fname.endswith(".rs"):
                continue
            mod_prefix = module_prefix(lib_name, src_root, os.path.join(dirpath, fname))
            # Best-effort tracking of the enclosing `impl <Type>` block so that
            # inherent/trait methods are emitted as `mod::Type::method` (the
            # path MONO_ITEM actually carries) instead of a bare `mod::method`.
            # This is a heuristic brace-depth scan, not a real Rust parser.
            depth = 0
            impl_stack = []  # list of (open_depth, type_name)
            with open(os.path.join(dirpath, fname), encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    m = decl.match(line)
                    if m:
                        if impl_stack:
                            items.add(f"{mod_prefix}::{impl_stack[-1][1]}::{m.group(2)}")
                        else:
                            items.add(f"{mod_prefix}::{m.group(2)}")
                    else:
                        m = mod_decl.match(line)
                        if m:
                            # `pub mod` is always at module level.
                            items.add(f"{mod_prefix}::{m.group(1)}")
                        else:
                            im = impl_decl.match(line)
                            if im and "{" in line:
                                impl_stack.append((depth, im.group(1)))
                    depth += line.count("{") - line.count("}")
                    while impl_stack and depth <= impl_stack[-1][0]:
                        impl_stack.pop()

with open(out, "w") as fh:
    for it in sorted(items):
        fh.write(it + "\n")

print(f"    defined items: {len(items)} (from {scanned}/{len(crates)} crates)")
PY
}

# ---------------- main ----------------

case "${mode_target}" in
    host)  build_one host ;;
    guest) build_one guest ;;
    both)  build_one host; build_one guest ;;
esac

REACHABLE_ALL="${OUT_DIR}/reachable-all.txt"
cat "${OUT_DIR}"/reachable-*.txt 2>/dev/null | sort -u > "${REACHABLE_ALL}"
echo "==> combined reachable set: $(wc -l < "${REACHABLE_ALL}" | tr -d ' ')  (${REACHABLE_ALL})"

if [[ -n "${compare_path}" ]]; then
    echo "==> enumerating pub items in ${compare_path}"
    DEFINED="${OUT_DIR}/defined.txt"
    UNUSED="${OUT_DIR}/unused.txt"
    enumerate_defined "${compare_path}" "${DEFINED}"
    [[ -s "${DEFINED}" ]] || { echo "no defined items parsed from ${compare_path} — not an airbender-platform checkout? refusing to emit an 'unused' verdict" >&2; exit 2; }
    comm -23 "${DEFINED}" "${REACHABLE_ALL}" > "${UNUSED}"
    echo "==> unused (defined & not reachable): $(wc -l < "${UNUSED}" | tr -d ' ')  (${UNUSED})"
    echo
    echo "--- unused by crate ---"
    awk -F'::' '{print $1}' "${UNUSED}" | sort | uniq -c | sort -rn
fi

if ! ${keep_target}; then
    echo "==> cleaning per-target build dirs (pass --keep-target to preserve)"
    rm -rf "${OUT_DIR}"/target-host "${OUT_DIR}"/target-guest
fi
