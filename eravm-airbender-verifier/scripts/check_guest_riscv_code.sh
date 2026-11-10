#!/usr/bin/env bash
# check_guest_riscv_code.sh — verify the built guest contains only provable RV32IM code.
#
# The Airbender circuit proves RV32IM. Any instruction outside that set in the
# guest binary (floating-point, atomic, compressed, another extension, or an
# undecodable word in an executable section) makes the guest unprovable, so
# this script fails on anything not in an explicit RV32IM mnemonic allowlist.
#
# Two layers:
#
#   1. Instruction allowlist (always on). Disassembles the executable sections
#      of the ELF with the pinned toolchain's llvm-objdump and checks every
#      decoded instruction against the allowlist below. --mattr is UNIONED
#      with the ELF's own arch attributes, so a forbidden instruction decodes
#      by name (e.g. `fadd.s`); bytes the assembler marked as data render as
#      raw `.word` lines and undecodable code as `<unknown>` — both fail the
#      allowlist just the same.
#
#      Scope: this scans sections marked executable in our own reproducibly
#      built guest — a drift tripwire against toolchain/codegen/dependency
#      changes, not a defense against an adversarially crafted ELF.
#
#   2. Soft-float growth check (with --baseline). On a soft-float target,
#      f32/f64 *arithmetic* compiles to ordinary integer code behind
#      compiler-builtins intrinsics (__addsf3, __divdf3, ...), which layer 1
#      cannot see. This layer extracts the defined soft-float intrinsic symbols
#      and fails if any symbol appears that is not in the checked-in baseline —
#      so new float arithmetic entering the guest is a conscious, reviewed act.
#
# Usage:
#   check_guest_riscv_code.sh <app.elf> [--baseline FILE] [--update-baseline]
#                             [--min-insns N] [--objdump PATH] [--nm PATH]
#
# Exit codes: 0 = clean, 1 = violations found, 2 = usage or environment error.

set -euo pipefail

# --- Instruction allowlist ----------------------------------------------------
# Canonical (no-alias) mnemonics of RV32I + M as emitted for
# riscv32im-risc0-zkvm-elf. Additions must be checked against what the
# Airbender circuit actually proves before being added here.
ALLOWED_MNEMONICS=(
  # RV32I: arithmetic / logic
  lui auipc addi slti sltiu xori ori andi slli srli srai
  add sub sll slt sltu xor srl sra or and
  # RV32I: control flow
  jal jalr beq bne blt bge bltu bgeu
  # RV32I: loads / stores
  lb lh lw lbu lhu sb sh sw
  # `fence` appears only as dead spin-loop-hint fences (crossbeam PAUSE; never
  # reached, and the zkVM traps if one ever executes). `unimp` is the canonical
  # trap filler emitted for aborts. `ecall`/`ebreak` are deliberately NOT
  # allowed: the Airbender machine does not prove them and the guest contains
  # none today.
  fence unimp
  # RV32M
  mul mulh mulhsu mulhu div divu rem remu
)

# `csrrw` is allowed only against these CSRs — Airbender's CSR-mapped guest
# I/O transport (0x7c0, airbender_core::wire::CsrTransport) and the delegated
# precompile circuits: 0x7c7 blake2s, 0x7ca bigint-ops-with-control (the BN254
# and secp field arithmetic behind the delegated ecrecover/ecadd/ecmul/
# ecpairing/secp256r1 precompiles), 0x7cb keccak. These CSR offsets are
# NON_DETERMINISM_CSR (0x7c0) + {7, 10, 11} per common_constants::delegation_types.
# Any other CSR (or any other csr* mnemonic) is not something the circuit proves
# and fails the check.
ALLOWED_CSRS=(0x7c0 0x7c7 0x7ca 0x7cb)

# Defined-symbol names that indicate soft-float arithmetic was linked in.
# Covers the compiler-builtins float intrinsics families: arithmetic
# (__addsf3), comparison (__eqsf2, __unordsf2), float<->int conversion
# (__fixsfsi, __floatunsidf), float<->float conversion (__extendsfdf2,
# __truncdfhf2), and __powisf2. s/d/h/t/x cover f32/f64/f16/f128/x87 widths.
SOFT_FLOAT_SYMBOL_RE='^__(add|sub|mul|div|neg|eq|ne|lt|le|gt|ge|unord|cmp|powi)[sdhtx]f[23]?$|^__fix(uns)?[sdhtx]f[dst]i$|^__float(un)?[dst]i[sdhtx]f$|^__(extend|trunc)[sdhtx]f[sdhtx]f2?$|^__gnu_[fh]2[hf]_ieee$|^__(mul|div)[sdx]c3$'

usage() {
  sed -n '/^# Usage:/,/^# Exit codes/p' "$0" | sed 's/^# \{0,1\}//'
}

die() {
  echo "error: $*" >&2
  exit 2
}

# --- Argument parsing ---------------------------------------------------------
ELF=""
BASELINE=""
UPDATE_BASELINE=0
MIN_INSNS=1
OBJDUMP="${OBJDUMP:-}"
NM="${NM:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --baseline)
      [[ $# -ge 2 && -n "$2" ]] || die "--baseline requires a non-empty file argument"
      BASELINE="$2"; shift 2 ;;
    --update-baseline) UPDATE_BASELINE=1; shift ;;
    --min-insns)
      [[ $# -ge 2 && -n "$2" ]] || die "--min-insns requires a number"
      MIN_INSNS="$2"; shift 2 ;;
    --objdump)
      [[ $# -ge 2 && -n "$2" ]] || die "--objdump requires a path"
      OBJDUMP="$2"; shift 2 ;;
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
[[ "$UPDATE_BASELINE" -eq 0 || -n "$BASELINE" ]] \
  || die "--update-baseline requires --baseline"
[[ "$MIN_INSNS" =~ ^[0-9]+$ ]] || die "--min-insns must be a non-negative integer"

# --- Tool discovery -----------------------------------------------------------
# Prefer the llvm-tools of the toolchain that BUILT the guest ELF
# (guest/rust-toolchain.toml, present in the cargo-airbender image) so the
# disassembler version is as reproducible as the build itself. That file — not
# the repo-root rust-toolchain.toml — declares the llvm-tools-preview component,
# and rustup auto-installs a toolchain's declared components on invocation, so
# anchoring resolution there both avoids version skew and, on a fresh machine,
# actively installs the tool. rustup resolves the toolchain from the working
# directory, so we cd to a fixed anchor (the guest dir, else this script's dir) —
# the invoker's cwd must not change which toolchain answers.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

find_llvm_tool() {
  local tool="$1"
  # Anchor to the guest toolchain (the one that built the ELF, and the only file
  # declaring llvm-tools-preview); fall back to this script's dir for a
  # standalone run without a sibling guest/rust-toolchain.toml.
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
  # PATH fallback for environments without llvm-tools-preview; the resolved
  # path is logged below so version drift stays visible in CI logs.
  command -v "$tool" || return 1
}

[[ -n "$OBJDUMP" ]] || OBJDUMP="$(find_llvm_tool llvm-objdump)" \
  || die "llvm-objdump not found; install the llvm-tools-preview rustup component or pass --objdump"
[[ -n "$NM" ]] || NM="$(find_llvm_tool llvm-nm)" \
  || die "llvm-nm not found; install the llvm-tools-preview rustup component or pass --nm"
echo "using llvm-objdump: $OBJDUMP" >&2
echo "using llvm-nm: $NM" >&2

# --- Sanity: the input must be a 32-bit RISC-V ELF ----------------------------
read -r elf_class elf_machine < <(
  "$OBJDUMP" --file-headers "$ELF" 2>/dev/null | awk '
    /^architecture:/ { arch = $2 }
    END {
      if (arch == "") print "NOARCH", "unknown"
      else print (arch ~ /^riscv32/) ? "ELF32" : "OTHER", arch
    }
' )
case "$elf_class" in
  ELF32) ;;
  NOARCH) die "llvm-objdump could not read $ELF — not an object file, or the tool failed (try: $OBJDUMP --file-headers $ELF)" ;;
  *) die "$ELF is not a riscv32 ELF (architecture: $elf_machine); refusing to scan the wrong artifact" ;;
esac

FAILURES=0

# --- Layer 1: instruction allowlist -------------------------------------------
# --mattr enables decoding of the extensions we FORBID, so violations are
# named. -M no-aliases keeps mnemonics canonical, so the allowlist is small.
allowed_re="$(IFS='|'; echo "${ALLOWED_MNEMONICS[*]}")"
allowed_csr_re="$(IFS='|'; echo "${ALLOWED_CSRS[*]}")"

# Cap on individually-listed violation lines (awk print cap + bash tail math).
MAX_SHOWN=50

# The awk program prints at most MAX_SHOWN violation lines itself (avoiding a
# SIGPIPE-prone `| head` under pipefail) plus TOTAL/BAD counters at the end.
disasm_report="$(
  "$OBJDUMP" -d -M no-aliases --no-show-raw-insn \
    --mattr=+m,+a,+f,+d,+c,+zicsr,+zifencei \
    "$ELF" \
  | awk -v allowed_re="^(${allowed_re})\$" \
        -v allowed_csr_re="^(${allowed_csr_re}),?\$" \
        -v max_shown="$MAX_SHOWN" '
      function report(section, addr, symbol,    i, rest) {
        bad++
        if (bad > max_shown) return
        rest = ""
        for (i = 3; i <= NF; i++) rest = rest " " $i
        printf "VIOLATION section %s @ 0x%s in <%s>: %s%s\n", \
               section, addr, symbol, $2, rest
      }
      /^Disassembly of section / { section = $4; sub(/:$/, "", section); next }
      /^[0-9a-f]+ <.*>:$/ { symbol = $2; gsub(/[<>:]/, "", symbol); next }
      # Instruction lines: "    <addr>: <mnemonic> [operands...]". Addresses
      # are right-aligned to 8 hex digits, so VMAs >= 0x10000000 start at
      # column 0 — leading whitespace must be optional. The section gate
      # excludes the "<file>: file format ..." preamble, which precedes any
      # "Disassembly of section" header.
      /^[[:space:]]*[0-9a-f]+:[[:space:]]/ && section != "" {
        addr = $1; sub(/:$/, "", addr)
        mnemonic = $2
        # Zero-padding runs print as an unaddressed "..." on LLVM 22 (skipped
        # by the address regex); this guard covers formats that address it.
        if (mnemonic == "...") next
        total++
        if (mnemonic == "csrrw") {
          # "csrrw rd, 0xNNN, rs" — only the Airbender transport/precompile
          # CSRs are provable.
          if ($4 !~ allowed_csr_re) report(section, addr, symbol)
        } else if (mnemonic !~ allowed_re) {
          report(section, addr, symbol)
        }
        next
      }
      END { printf "TOTAL %d\nBAD %d\n", total, bad }
    '
)" || die "llvm-objdump failed on $ELF"

total_insns="$(sed -n 's/^TOTAL //p' <<<"$disasm_report")"
bad_insns="$(sed -n 's/^BAD //p' <<<"$disasm_report")"
[[ -n "$total_insns" && -n "$bad_insns" ]] \
  || die "failed to parse disassembly summary — llvm-objdump output format changed?"

if (( total_insns < 10#$MIN_INSNS )); then
  echo "error: decoded only $total_insns instruction(s) (< --min-insns $MIN_INSNS);" \
       "the disassembly is empty or the output format changed — refusing to pass vacuously" >&2
  exit 2
fi

if (( bad_insns > 0 )); then
  echo "FAIL: $bad_insns instruction(s) outside the RV32IM allowlist (of $total_insns decoded):"
  sed -n 's/^VIOLATION /  /p' <<<"$disasm_report"
  (( bad_insns > MAX_SHOWN )) && echo "  ... and $((bad_insns - MAX_SHOWN)) more"
  FAILURES=1
else
  echo "OK: all $total_insns decoded instructions are within the RV32IM allowlist"
fi

# --- Layer 2: soft-float intrinsic growth check --------------------------------
if [[ -n "$BASELINE" ]]; then
  symbols="$("$NM" --defined-only "$ELF" 2>/dev/null | awk 'NF >= 3 { print $3 }')" \
    || die "llvm-nm failed on $ELF"
  if [[ -z "$symbols" ]]; then
    die "$ELF has no defined symbols — the soft-float check needs an unstripped ELF (dist app.elf keeps symbols)"
  fi

  current="$(grep -E "$SOFT_FLOAT_SYMBOL_RE" <<<"$symbols" | sort -u || true)"

  if (( UPDATE_BASELINE )); then
    if (( FAILURES > 0 )); then die "refusing to regenerate the baseline: the instruction-allowlist check failed above — fix the guest first"; fi
    {
      echo "# Soft-float intrinsics linked into the guest (see check_guest_riscv_code.sh)."
      echo "# Regenerate with: scripts/check_guest_riscv_code.sh <app.elf> --baseline <this file> --update-baseline"
      [[ -n "$current" ]] && echo "$current"
    } > "$BASELINE"
    echo "OK: wrote $(grep -vc '^#' "$BASELINE" || true) soft-float symbol(s) to $BASELINE"
  else
    [[ -f "$BASELINE" ]] \
      || die "baseline file $BASELINE not found; bootstrap it with --update-baseline"
    known="$(grep -v '^#' "$BASELINE" | sed '/^[[:space:]]*$/d' | sort -u || true)"
    new_symbols="$(comm -13 <(echo "$known") <(echo "$current") | sed '/^$/d')"
    gone_symbols="$(comm -23 <(echo "$known") <(echo "$current") | sed '/^$/d')"

    if [[ -n "$new_symbols" ]]; then
      echo "FAIL: new soft-float intrinsic(s) linked into the guest (not in $BASELINE):"
      sed 's/^/  /' <<<"$new_symbols"
      echo "  New float arithmetic reached the guest. If intentional, regenerate the baseline with --update-baseline."
      FAILURES=1
    else
      echo "OK: no soft-float intrinsics beyond the baseline ($(sed '/^$/d' <<<"$current" | grep -c . || true) present)"
    fi
    if [[ -n "$gone_symbols" ]]; then
      echo "FAIL: $BASELINE lists soft-float intrinsic(s) no longer present in the guest:"
      sed 's/^/  /' <<<"$gone_symbols"
      echo "  A stale baseline superset silently pre-authorizes these intrinsics; regenerate it with --update-baseline."
      FAILURES=1
    fi
  fi
fi

exit "$FAILURES"
