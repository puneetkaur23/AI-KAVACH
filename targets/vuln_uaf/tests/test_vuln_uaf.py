#!/usr/bin/env python3
"""Unit tests for vuln_uaf target."""
import subprocess, os, tempfile, sys

BIN = os.path.join(os.path.dirname(__file__), '..', 'vuln_uaf_asan')

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

def test_normal_input():
    r = run(b"Widget")
    assert r.returncode == 0, f"Expected 0 on patched code, got {r.returncode}\n{r.stderr.decode()}"
    assert b"Item name: Widget" in r.stdout or b"Widget" in r.stdout
    print("PASS test_normal_input")

if __name__ == '__main__':
    try:
        test_normal_input()
        sys.exit(0)
    except Exception as e:
        print(f"FAIL: {e}")
        sys.exit(1)
