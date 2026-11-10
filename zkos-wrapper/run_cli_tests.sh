#!/usr/bin/env bash
#
# Run CLI tests for the zkos-wrapper binary.
#
# Usage:
#   ./run_cli_tests.sh                        # CPU, security_80 (default)
#   ./run_cli_tests.sh --security 100         # CPU, security_100
#   ./run_cli_tests.sh --gpu                  # GPU, security_80
#   ./run_cli_tests.sh --gpu --security 100   # GPU, security_100
#
set -euo pipefail

cd "$(dirname "$0")"

ulimit -s unlimited

export RUSTFLAGS="-Awarnings"
export RUST_MIN_STACK=100485760

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
USE_GPU=false
SECURITY=80

while [[ $# -gt 0 ]]; do
    case "$1" in
        --gpu)
            USE_GPU=true
            shift
            ;;
        --security)
            SECURITY="$2"
            shift 2
            ;;
        *)
            echo "Usage: $0 [--gpu] [--security <80|100>]"
            exit 1
            ;;
    esac
done

if [[ "$SECURITY" != "80" && "$SECURITY" != "100" ]]; then
    echo "Error: --security must be 80 or 100 (got '$SECURITY')"
    exit 1
fi

# ---------------------------------------------------------------------------
# Derived variables
# ---------------------------------------------------------------------------
SB="${SECURITY}sb"
DATA="wrapper/testing_data"

FEATURES="security_${SECURITY}"
DEVICE="cpu"
LABEL="CPU, security_${SECURITY}"
TRUSTED_SETUP_FLAG=""
if [ "$USE_GPU" = true ]; then
    FEATURES="${FEATURES},gpu"
    DEVICE="gpu"
    LABEL="GPU, security_${SECURITY}"
    TRUSTED_SETUP_FLAG="--trusted-setup crs/setup_gpu.key"
fi

TARGET_DIR="target-${DEVICE}-${SECURITY}"
export CARGO_TARGET_DIR="$TARGET_DIR"

BUILD_CMD="cargo +nightly build --package zkos-wrapper --release --no-default-features --features ${FEATURES}"

# Test data paths (parameterized by security level)
RISC_PROOF="$DATA/risc_proof_${SB}"
RISC_APP_BIN="$DATA/risc_app.bin"
RISC_APP_TEXT="$DATA/risc_app.text"
RISC_WRAPPER_PROOF="$DATA/risc_wrapper_proof_${SB}"
RISC_WRAPPER_VK="$DATA/risc_wrapper_vk_${SB}"
COMPRESSION_PROOF="$DATA/compression_proof_${SB}"
COMPRESSION_VK="$DATA/compression_vk_${SB}"
SNARK_PROOF="$DATA/snark_wrapper_proof_${SB}"
SNARK_VK="$DATA/snark_wrapper_vk_${SB}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
FAILED=0
pass() { echo "  ✓ $1"; }
fail() { echo "  ✗ $1 FAILED"; FAILED=1; }

BIN="./${TARGET_DIR}/release/wrapper"

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
echo "=== Building wrapper binary ($LABEL) ==="
echo "  $BUILD_CMD"
$BUILD_CMD 2>&1

# ---------------------------------------------------------------------------
# Lightweight tests
# ---------------------------------------------------------------------------
echo ""
echo "=== Lightweight tests ($LABEL) ==="

echo "--- verify risc-wrapper ---"
if $BIN verify --stage risc-wrapper \
    --proof "$RISC_WRAPPER_PROOF" --vk "$RISC_WRAPPER_VK" | grep -q "VALID"; then
    pass "verify risc-wrapper"
else
    fail "verify risc-wrapper"
fi

echo "--- verify compression ---"
if $BIN verify --stage compression \
    --proof "$COMPRESSION_PROOF" --vk "$COMPRESSION_VK" | grep -q "VALID"; then
    pass "verify compression"
else
    fail "verify compression"
fi

echo "--- verify snark ---"
if $BIN verify --stage snark \
    --proof "$SNARK_PROOF" --vk "$SNARK_VK" | grep -q "VALID"; then
    pass "verify snark"
else
    fail "verify snark"
fi

echo "--- vk-hash ---"
if $BIN vk-hash --vk "$SNARK_VK" | grep -q "VK hash"; then
    pass "vk-hash"
else
    fail "vk-hash"
fi

echo "--- verify mismatched proof/vk (expect failure) ---"
if ! $BIN verify --stage snark \
    --proof "$SNARK_PROOF" --vk "$COMPRESSION_VK" 2>/dev/null; then
    pass "verify mismatched proof/vk"
else
    fail "verify mismatched proof/vk"
fi

echo "--- verify missing file (expect failure) ---"
if ! $BIN verify --stage snark \
    --proof "/nonexistent/proof.json" --vk "$SNARK_VK" 2>/dev/null; then
    pass "verify missing file"
else
    fail "verify missing file"
fi

echo "--- no subcommand (expect failure) ---"
if ! $BIN 2>/dev/null; then
    pass "no subcommand"
else
    fail "no subcommand"
fi

if [ "$FAILED" -ne 0 ]; then
    echo ""
    echo "!! Lightweight tests FAILED ($LABEL)"
    # exit 1
fi

# ---------------------------------------------------------------------------
# Heavy tests (sequential)
# ---------------------------------------------------------------------------
echo ""
echo "=== Heavy tests ($LABEL, sequential) ==="

TMP=$(mktemp -d)
BENCH_DIR=$(mktemp -d)
trap 'rm -rf "$TMP" "$BENCH_DIR"' EXIT

bench() {
    local name="$1"; shift
    /usr/bin/time -v "$@" 2>"$BENCH_DIR/${name}.time"
}

echo "--- prove-risc-wrapper ---"
RISC_APP_FLAGS=()
if [ "$SECURITY" == "80" ]; then
    RISC_APP_FLAGS=(--bin "$RISC_APP_BIN" --text "$RISC_APP_TEXT")
fi
if bench prove-risc-wrapper $BIN prove-risc-wrapper \
    --proof "$RISC_PROOF" \
    "${RISC_APP_FLAGS[@]}" \
    -o "$TMP/risc" \
  && [ -f "$TMP/risc/risc_wrapper_proof.json" ] \
  && [ -f "$TMP/risc/risc_wrapper_vk.json" ]; then
    pass "prove-risc-wrapper"
else
    fail "prove-risc-wrapper"
fi

echo "--- prove-compression ---"
if bench prove-compression $BIN prove-compression \
    --risc-wrapper-proof "$RISC_WRAPPER_PROOF" \
    --risc-wrapper-vk "$RISC_WRAPPER_VK" \
    -o "$TMP/comp" \
  && [ -f "$TMP/comp/compression_proof.json" ] \
  && [ -f "$TMP/comp/compression_vk.json" ]; then
    pass "prove-compression"
else
    fail "prove-compression"
fi

echo "--- generate-vk ---"
if bench generate-vk $BIN generate-vk $TRUSTED_SETUP_FLAG -o "$TMP/vk" \
  && [ -f "$TMP/vk/risc_wrapper_vk.json" ] \
  && [ -f "$TMP/vk/compression_vk.json" ] \
  && [ -f "$TMP/vk/snark_vk.json" ]; then
    pass "generate-vk"
else
    fail "generate-vk"
fi

echo "--- prove-snark ---"
if bench prove-snark $BIN prove-snark \
    $TRUSTED_SETUP_FLAG \
    --compression-proof "$COMPRESSION_PROOF" \
    --compression-vk "$COMPRESSION_VK" \
    -o "$TMP/snark" \
  && [ -f "$TMP/snark/snark_proof.json" ] \
  && [ -f "$TMP/snark/snark_vk.json" ]; then
    pass "prove-snark"
else
    fail "prove-snark"
fi

echo "--- prove-all --save-intermediates ---"
if bench prove-all $BIN prove-all \
    $TRUSTED_SETUP_FLAG \
    --proof "$RISC_PROOF" \
    "${RISC_APP_FLAGS[@]}" \
    --save-intermediates \
    -o "$TMP/all" \
  && [ -f "$TMP/all/snark_proof.json" ] \
  && [ -f "$TMP/all/snark_vk.json" ] \
  && [ -f "$TMP/all/risc_wrapper_proof.json" ] \
  && [ -f "$TMP/all/risc_wrapper_vk.json" ] \
  && [ -f "$TMP/all/compression_proof.json" ] \
  && [ -f "$TMP/all/compression_vk.json" ]; then
    pass "prove-all --save-intermediates"
else
    fail "prove-all --save-intermediates"
fi

echo ""
if [ "$FAILED" -ne 0 ]; then
    echo "=== Some tests FAILED ($LABEL) ==="
    exit 1
else
    echo "=== All tests passed ($LABEL) ==="
fi

echo ""
echo "=== Benchmark Summary ($LABEL) ==="
for f in "$BENCH_DIR"/*.time; do
    [ -f "$f" ] || continue
    name=$(basename "$f" .time)
    echo ""
    echo "[$name]"
    grep -E "Elapsed \(wall clock\)|Maximum resident set size|User time|System time" "$f" || true
done
