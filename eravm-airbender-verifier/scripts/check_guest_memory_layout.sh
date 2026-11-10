#!/usr/bin/env bash
# check_guest_memory_layout.sh — verify the built guest's RAM layout is the one
# we intend to prove.
#
# The guest's heap arena is a LINK-TIME constant: `riscv_common`'s link.x
# `PROVIDE(_heap_size = 768M)`, overridden in guest/.cargo/config.toml with
# `-C link-arg=--defsym=_heap_size=<bytes>`. The arena is baked into app.bin and
# therefore into both verification keys, so a guest built with an unintended one
# is a guest no registered VK accepts. Drift paths this catches:
#
#   * a rustflags list RE-AUTHORED without the `--defsym` — a Dockerfile, a CI
#     matrix, a downstream build, or a re-scaffold. This is the concrete one:
#     `cargo airbender new` emits a guest .cargo/config.toml carrying
#     `-Tmemory.x`/`-Tlink.x` but NO `--defsym`, so a config reconciled against
#     that template links fine and silently falls back to 768 MiB;
#   * an upstream `PROVIDE(_heap_size = ...)` change at the next airbender bump
#     (a plain script assignment would beat the `--defsym` outright);
#   * a change in `--defsym`-vs-`PROVIDE` precedence in a new toolchain.
#
# NOT caught, by design: `.rodata`/`.bss` growth moving `_sheap` up one 2 MiB slot.
# The arena size is unchanged and the link still succeeds, so there is nothing to
# reject; pinning `_sheap` would turn that benign growth into a build failure, and
# past the cushion the linker fails on its own.
#
# (A whole-array RUSTFLAGS override is NOT one of them: it drops `-Tmemory.x`
# / `-Tlink.x` and the getrandom cfg with the `--defsym`, so the build fails
# loudly rather than silently reverting. The reachable shape is always a list
# that KEEPS the linker scripts and loses only the `--defsym`.)
#
# The guest links against its own guest/eravm_memory.x (ROM 4 MiB + RAM 4090 MiB,
# ending 2 MiB below 2^32) and the host runs it with a 4 GiB RAM image
# (`RamSize::FourGb`). An `_eheap` above the region top means the memory map and
# the arena have drifted apart, so the ceiling is asserted here as well.
#
# Usage:
#   check_guest_memory_layout.sh <app.elf> [--expect-heap-mib N]
#                               [--expect-stack-mib N] [--ram-top-mib N] [--nm PATH]
#
#   --expect-heap-mib N   require `_eheap - _sheap` to be exactly N MiB.
#                         Omit to report the layout without pinning a size.
#   --expect-stack-mib N  require `_sstack - _estack` to be exactly N MiB
#                         (default 64 = link.x's `PROVIDE(_hart_stack_size = 64M)`).
#                         Checked by default because that PROVIDE can change at an
#                         airbender bump exactly like the heap one, and the stack
#                         sits below `.heap`: moving it moves `_sheap`, changing
#                         app.bin and both VKs while the arena stays the same.
#   --ram-top-mib N       top of the RAM region in MiB (default 4094 =
#                         guest/eravm_memory.x ROM 4M + RAM 4090M). Only change
#                         this alongside that file.
#   --nm PATH             llvm-nm to use (default: the guest toolchain's).
#
# Exit codes: 0 = layout as expected, 1 = violation, 2 = usage or environment error.

set -euo pipefail

usage() {
  sed -n '/^# Usage:/,/^# Exit codes/p' "$0" | sed 's/^# \{0,1\}//'
}

die() {
  echo "error: $*" >&2
  exit 2
}

MIB=$((1024 * 1024))

# --- Argument parsing ---------------------------------------------------------
ELF=""
EXPECT_HEAP_MIB=""
EXPECT_STACK_MIB=64
RAM_TOP_MIB=4094
NM="${NM:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --expect-heap-mib)
      [[ $# -ge 2 && -n "$2" ]] || die "--expect-heap-mib requires a number"
      EXPECT_HEAP_MIB="$2"; shift 2 ;;
    --expect-stack-mib)
      [[ $# -ge 2 && -n "$2" ]] || die "--expect-stack-mib requires a number"
      EXPECT_STACK_MIB="$2"; shift 2 ;;
    --ram-top-mib)
      [[ $# -ge 2 && -n "$2" ]] || die "--ram-top-mib requires a number"
      RAM_TOP_MIB="$2"; shift 2 ;;
    --nm)
      [[ $# -ge 2 && -n "$2" ]] || die "--nm requires a path"
      NM="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    -*) die "unknown option: $1 (see --help)" ;;
    *)
      [[ -z "$ELF" ]] || die "unexpected extra argument: $1"
      ELF="$1"; shift ;;
  esac
done

[[ -n "$ELF" ]] || { usage >&2; die "missing <app.elf> argument"; }
[[ -f "$ELF" ]] || die "no such file: $ELF"
[[ -z "$EXPECT_HEAP_MIB" || "$EXPECT_HEAP_MIB" =~ ^[0-9]+$ ]] \
  || die "--expect-heap-mib must be a non-negative integer"
[[ "$EXPECT_STACK_MIB" =~ ^[0-9]+$ ]] || die "--expect-stack-mib must be a non-negative integer"
[[ "$RAM_TOP_MIB" =~ ^[0-9]+$ ]] || die "--ram-top-mib must be a non-negative integer"

# Normalize to base 10 once: the regexes above accept a leading zero, which bash
# arithmetic would read as octal — silently for `02000`, and as a hard expansion
# error for `0952`.
[[ -z "$EXPECT_HEAP_MIB" ]] || EXPECT_HEAP_MIB=$((10#$EXPECT_HEAP_MIB))
EXPECT_STACK_MIB=$((10#$EXPECT_STACK_MIB))
RAM_TOP_MIB=$((10#$RAM_TOP_MIB))

# --- Sanity: must be a 32-bit RISC-V ELF --------------------------------------
# The sibling check_guest_riscv_code.sh gates on llvm-objdump --file-headers; the
# same guard from the ELF header itself avoids resolving a second llvm tool. Without
# it, a wrong artifact reaches the symbol read and is reported as a stripping
# problem, which is not what went wrong.
elf_bytes() { od -An -tu1 -j "$1" -N "$2" -- "$ELF" | tr -s ' \n' ' '; }
read -r e0 e1 e2 e3 eclass <<<"$(elf_bytes 0 5)"
[[ "$e0 $e1 $e2 $e3" == "127 69 76 70" ]] || die "$ELF is not an ELF file"
(( eclass == 1 )) || die "$ELF is not a 32-bit ELF (EI_CLASS=$eclass) — expected the riscv32 guest, not the host binary"
read -r m0 m1 <<<"$(elf_bytes 18 2)"           # e_machine, little-endian
(( m0 + (m1 << 8) == 243 )) \
  || die "$ELF is not a RISC-V ELF (e_machine=$((m0 + (m1 << 8))), expected 243) — wrong artifact"

# --- Tool discovery -----------------------------------------------------------
# Same anchoring as check_guest_riscv_code.sh: resolve llvm-nm from the toolchain
# that BUILT the guest (guest/rust-toolchain.toml declares llvm-tools-preview),
# independent of the invoker's cwd.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

find_llvm_tool() {
  local tool="$1"
  local guest_dir="$SCRIPT_DIR/../guest" anchor
  if [[ -f "$guest_dir/rust-toolchain.toml" ]]; then
    anchor="$guest_dir"
  else
    anchor="$SCRIPT_DIR"
  fi
  if command -v rustc >/dev/null 2>&1; then
    local sysroot host candidate
    sysroot="$(cd "$anchor" && rustc --print sysroot)"
    host="$(cd "$anchor" && rustc -vV | sed -n 's/^host: //p')"
    candidate="$sysroot/lib/rustlib/$host/bin/$tool"
    if [[ -x "$candidate" ]]; then
      echo "$candidate"
      return 0
    fi
  fi
  command -v "$tool" || return 1
}

[[ -n "$NM" ]] || NM="$(find_llvm_tool llvm-nm)" \
  || die "llvm-nm not found; install the llvm-tools-preview rustup component or pass --nm"
echo "using llvm-nm: $NM" >&2

# --- Read the layout symbols --------------------------------------------------
SYMBOLS="$("$NM" --defined-only "$ELF" 2>/dev/null)" || die "llvm-nm failed on $ELF"
[[ -n "$SYMBOLS" ]] \
  || die "$ELF has no defined symbols — this check needs an unstripped ELF (the build ELF and dist app.elf both keep their symtab)"

sym_addr() { # $1 = symbol name -> decimal address on stdout, empty if absent
  local hex
  hex="$(awk -v want="$1" 'NF >= 3 && $3 == want { print $1; exit }' <<<"$SYMBOLS")"
  [[ -n "$hex" ]] || return 1
  echo "$((16#$hex))"
}

for s in _estack _sstack _sheap _eheap; do
  sym_addr "$s" >/dev/null 2>&1 \
    || die "$ELF defines no '$s' — not an Airbender guest linked with riscv_common's link.x?"
done

ESTACK="$(sym_addr _estack)"
SSTACK="$(sym_addr _sstack)"
SHEAP="$(sym_addr _sheap)"
EHEAP="$(sym_addr _eheap)"

HEAP_SIZE=$((EHEAP - SHEAP))
STACK_SIZE=$((SSTACK - ESTACK))
RAM_TOP=$((RAM_TOP_MIB * MIB))

hex() { printf '0x%08x' "$1"; }
mib() { printf '%s MiB' "$(( $1 / MIB ))"; }

cat <<EOF
guest RAM layout ($ELF):
  .stack   $(hex "$ESTACK") .. $(hex "$SSTACK")   $(mib "$STACK_SIZE") (grows down from _sstack)
  .heap    $(hex "$SHEAP") .. $(hex "$EHEAP")   $(mib "$HEAP_SIZE") ($HEAP_SIZE bytes)
  RAM top  $(hex "$RAM_TOP")                 $(mib "$RAM_TOP") — end of eravm_memory.x RAM
  unused   $(mib $(( EHEAP <= RAM_TOP ? RAM_TOP - EHEAP : 0 ))) above _eheap
EOF

# --- Assertions ---------------------------------------------------------------
FAILURES=0
CHECKED=0
fail() {
  echo "FAIL: $*" >&2
  FAILURES=$((FAILURES + 1))
}

(( EHEAP <= RAM_TOP )) \
  || fail "_eheap $(hex "$EHEAP") is above the RAM top $(hex "$RAM_TOP") — the arena and guest/eravm_memory.x disagree"

# link.x aligns .heap to 2 MiB; a violation means the layout is not what we think.
(( SHEAP % (2 * MIB) == 0 )) \
  || fail "_sheap $(hex "$SHEAP") is not 2 MiB-aligned (link.x aligns .heap to 2 MiB)"

# boot_sequence::init() asserts this at runtime (_estack must equal
# common_constants::rom::ROM_BYTE_SIZE = 4 MiB); catching it at build time is strictly better.
(( ESTACK == 4 * MIB )) \
  || fail "_estack $(hex "$ESTACK") != 4 MiB — boot_sequence::init() asserts _estack == ROM_BYTE_SIZE and will abort the guest"

(( SHEAP >= SSTACK )) \
  || fail "_sheap $(hex "$SHEAP") overlaps the stack region (ends $(hex "$SSTACK"))"

# The stack is sized by link.x's PROVIDE(_hart_stack_size = 64M), so it drifts by
# the same routes as the heap PROVIDE — and because .heap follows it, a change
# moves _sheap and rewrites app.bin (and both VKs) with the arena still exact.
(( STACK_SIZE == EXPECT_STACK_MIB * MIB )) \
  || fail "stack is $(mib "$STACK_SIZE"), expected ${EXPECT_STACK_MIB} MiB — _hart_stack_size changed, which moves _sheap and both VKs"

if [[ -n "$EXPECT_HEAP_MIB" ]]; then
  expect_bytes=$((EXPECT_HEAP_MIB * MIB))
  if (( HEAP_SIZE != expect_bytes )); then
    fail "heap is $(mib "$HEAP_SIZE") ($HEAP_SIZE bytes), expected ${EXPECT_HEAP_MIB} MiB ($expect_bytes bytes)"
    if (( HEAP_SIZE == 768 * MIB )); then
      echo "hint: 768 MiB is riscv_common link.x's PROVIDE default — the" >&2
      echo "      '--defsym=_heap_size=...' link-arg did not reach the linker. Either the flag" >&2
      echo "      was edited out of guest/.cargo/config.toml, or this build used a rustflags" >&2
      echo "      list re-authored without it (note: the 'cargo airbender new' scaffold ships" >&2
      echo "      -Tmemory.x/-Tlink.x but no --defsym). This guest matches no registered VK." >&2
    else
      # Not the PROVIDE default, so the arena was set deliberately and one of the
      # sites that state it was left behind. They are independent on purpose — the
      # config is the cause, the workflows are a separate assertion of intent — so
      # the fix is to move them together, never to derive one from the other.
      echo "hint: the linked arena is neither the expected value nor link.x's 768 MiB default," >&2
      echo "      so it was changed deliberately somewhere. If that change is intended, update" >&2
      echo "      ALL of these together (paths relative to eravm-airbender-verifier/;" >&2
      echo "      the workflows sit outside it, at the repository root):" >&2
      echo "        - guest/.cargo/config.toml                     --defsym=_heap_size=<bytes>  (the cause)" >&2
      echo "        - guest/eravm_memory.x                         RAM LENGTH, if the arena outgrows it" >&2
      echo "        - ../.github/workflows/ci-verifier.yaml         --expect-heap-mib" >&2
      echo "        - ../.github/workflows/release-artifacts.yaml   --expect-heap-mib" >&2
      echo "        - README.md 'Guest memory (heap arena)'         (prose only; nothing checks it)" >&2
      echo "      and remember it changes app.bin, so both VKs must be regenerated." >&2
    fi
  fi
  CHECKED=1
fi

if (( FAILURES > 0 )); then
  echo "error: $FAILURES memory-layout violation(s)" >&2
  exit 1
fi

if [[ -n "$EXPECT_HEAP_MIB" ]]; then
  # The success message must never outlive the comparison that earns it.
  (( CHECKED )) || die "internal: the heap size was never compared — refusing to report success"
  echo "OK: heap is exactly ${EXPECT_HEAP_MIB} MiB and the layout is within $(mib "$RAM_TOP") of RAM"
else
  echo "OK: layout is within $(mib "$RAM_TOP") of RAM (no --expect-heap-mib given, size not pinned)"
fi
