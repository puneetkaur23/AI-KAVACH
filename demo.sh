#!/usr/bin/env bash
# AI Kavach — Single-Command Demo Script (Bash / WSL / Linux)
# Usage: ./demo.sh [target_directory] [fuzz_timeout_seconds]

set -euo pipefail

TARGET="${1:-targets/vuln_bof}"
TIMEOUT="${2:-30}"

echo "=============================================================================="
echo "  🛡️  AI KAVACH — CYBER-REASONING SYSTEM (CRS) DEMO RUNNER"
echo "  Autonomous Vulnerability Discovery, Root Cause Reasoning & Proven Patching"
echo "=============================================================================="
echo ""

echo "[1/3] Ensuring Docker Sandbox Containers are Running..."
docker compose up -d validator fuzzer

echo ""
echo "[2/3] Executing Cyber-Reasoning Pipeline on $TARGET (Timeout: ${TIMEOUT}s)..."
echo ""

python3 kavach.py --target "$TARGET" --timeout "$TIMEOUT"

echo ""
echo "[3/3] Locating Proof-of-Fix Artifacts..."
LATEST_REPORT=$(ls -t output/reports/*.html 2>/dev/null | head -n 1 || true)

if [ -n "$LATEST_REPORT" ]; then
    echo "Latest Proof-of-Fix Report Generated: $LATEST_REPORT"
    if command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$LATEST_REPORT" || true
    elif command -v open >/dev/null 2>&1; then
        open "$LATEST_REPORT" || true
    fi
fi

echo ""
echo "✨ Demonstration Run Complete!"
