#!/usr/bin/env python3
"""Unit tests for clean_target."""
import subprocess, os, tempfile, sys

BIN = os.path.join(os.path.dirname(__file__), '..', 'clean_target_asan')

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
        try:
            os.unlink(fname)
        except OSError:
            pass
    return result

def test_clean():
    r = run(b"SafeUser")
    assert r.returncode == 0
    assert b"Hello, SafeUser" in r.stdout
    print("PASS test_clean")

if __name__ == '__main__':
    try:
        test_clean()
        sys.exit(0)
    except Exception as e:
        print(f"FAIL: {e}")
        sys.exit(1)
