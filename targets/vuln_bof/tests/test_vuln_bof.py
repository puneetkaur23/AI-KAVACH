#!/usr/bin/env python3
"""Unit tests for vuln_bof target — used in regression validation."""
import subprocess, os, tempfile, sys

BIN = os.path.join(os.path.dirname(__file__), '..', 'vuln_bof_asan')

def run(data: bytes) -> subprocess.CompletedProcess:
    with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
        f.write(data)
        fname = f.name
    try:
        result = subprocess.run(
            [BIN, fname],
            capture_output=True, timeout=5,
            env={**os.environ, "ASAN_OPTIONS": "halt_on_error=1:detect_leaks=0"}
        )
    finally:
        os.unlink(fname)
    return result

def test_normal_short_input():
    r = run(b"Alice")
    assert r.returncode == 0, f"Expected 0, got {r.returncode}\n{r.stderr.decode()}"
    assert b"Hello, Alice" in r.stdout
    print("PASS test_normal_short_input")

def test_normal_long_but_safe_input():
    # 63 chars — fits in buf[64]
    r = run(b"A" * 63)
    assert r.returncode == 0, f"Expected 0, got {r.returncode}"
    print("PASS test_normal_long_but_safe_input")

def test_empty_input():
    r = run(b"\x00")
    assert r.returncode == 0
    print("PASS test_empty_input")

if __name__ == '__main__':
    tests = [test_normal_short_input, test_normal_long_but_safe_input, test_empty_input]
    failed = 0
    for t in tests:
        try:
            t()
        except Exception as e:
            print(f"FAIL {t.__name__}: {e}")
            failed += 1
    sys.exit(failed)
