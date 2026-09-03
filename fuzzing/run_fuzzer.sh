#!/usr/bin/env bash
set -euo pipefail

TARGET_BIN="${TARGET_BIN:-}"
SEED_DIR="${SEED_DIR:-}"
OUTPUT_DIR="${OUTPUT_DIR:-/fuzzer_out}"
TIMEOUT="${TIMEOUT:-30}"
MAX_MEMORY_MB="${MAX_MEMORY_MB:-0}"

if [[ -z "$TARGET_BIN" || -z "$SEED_DIR" ]]; then
    echo "ERROR: TARGET_BIN and SEED_DIR must be set" >&2
    exit 1
fi

if [[ ! -f "$TARGET_BIN" ]]; then
    echo "ERROR: TARGET_BIN not found: $TARGET_BIN" >&2
    exit 1
fi

if [[ ! -d "$SEED_DIR" || -z "$(ls -A "$SEED_DIR" 2>/dev/null)" ]]; then
    echo "WARN: SEED_DIR empty, creating seed"
    mkdir -p "$SEED_DIR"
    printf "AAAA" > "$SEED_DIR/seed_auto"
fi

# Always start AFL with a clean output directory
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# Memory limit configuration for AFL++ (-m none is required for AddressSanitizer shadow memory)
MEM_ARG="-m none"

echo "[kavach-fuzzer] Starting AFL++ on $TARGET_BIN"
echo "[kavach-fuzzer] Timeout: ${TIMEOUT}s | Memory: $MEM_ARG"

timeout "${TIMEOUT}" afl-fuzz \
    -i "$SEED_DIR" \
    -o "$OUTPUT_DIR" \
    $MEM_ARG \
    -t 5000 \
    -- "$TARGET_BIN" @@ 2>&1 || true

CRASH_COUNT=0

if [[ -d "$OUTPUT_DIR/default/crashes" ]]; then
    CRASH_COUNT=$(find "$OUTPUT_DIR/default/crashes" \
        -type f \
        -not -name 'README.txt' | wc -l)
fi

echo "[kavach-fuzzer] Fuzzing complete. Crashes found: $CRASH_COUNT"
echo "CRASH_COUNT=$CRASH_COUNT" > "$OUTPUT_DIR/summary.txt"

if [[ "$CRASH_COUNT" -gt 0 ]]; then
    exit 0
else
    exit 2
fi