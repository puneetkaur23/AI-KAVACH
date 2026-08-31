#!/usr/bin/env python3
"""Unit tests for vuln_intoverflow target."""
import subprocess, os, tempfile, struct, sys

BIN = os.path.join(os.path.dirname(__file__), '..', 'vuln_intoverflow_asan')

def run(count: int, size: int):
    data = struct.pack('<II', count, size)
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
        try:
            os.unlink(fname)
        except OSError:
            pass
    return result

def test_safe_small_allocation():
    r = run(4, 8)
    assert r.returncode == 0, f"Expected 0, got {r.returncode}\n{r.stderr.decode()}"
    print("PASS test_safe_small_allocation")

def test_zero_count():
    r = run(0, 8)
    assert r.returncode == 1, "Zero count should fail gracefully"
    print("PASS test_zero_count")

if __name__ == '__main__':
    tests = [test_safe_small_allocation, test_zero_count]
    failed = 0
    for t in tests:
        try:
            t()
        except Exception as e:
            print(f"FAIL {t.__name__}: {e}")
            failed += 1
    sys.exit(failed)
