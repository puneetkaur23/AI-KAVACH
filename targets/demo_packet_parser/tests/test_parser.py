#!/usr/bin/env python3
"""Unit tests for demo_packet_parser target — used in regression validation."""
import subprocess, os, tempfile, sys

BIN = os.path.join(os.path.dirname(__file__), '..', 'demo_packet_parser_asan')

def run(data: bytes) -> subprocess.CompletedProcess:
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        fname = f.name
    try:
        result = subprocess.run(
            [BIN, fname],
            capture_output=True, timeout=5
        )
    finally:
        os.unlink(fname)
    return result

def test_valid_short_packet():
    # 5-byte header + 10 bytes payload (less than 64)
    # magic: 0x4B56 ('V', 'K' in little endian) -> b'VK'
    # length: 10 -> b'\x0a\x00'
    # type: 1 -> b'\x01'
    data = b'VK\x0a\x00\x01' + b'A' * 10
    r = run(data)
    assert r.returncode == 0, f"Expected 0, got {r.returncode}\n{r.stderr.decode()}"
    assert b"processed successfully" in r.stdout
    print("PASS test_valid_short_packet")

def test_safe_raw_fallback():
    data = b"Hello, AI Kavach test packet!"
    r = run(data)
    assert r.returncode == 0
    print("PASS test_safe_raw_fallback")

if __name__ == '__main__':
    tests = [test_valid_short_packet, test_safe_raw_fallback]
    failed = 0
    for t in tests:
        try:
            t()
        except Exception as e:
            print(f"FAIL {t.__name__}: {e}")
            failed += 1
    sys.exit(failed)
