"""
tests/test_api.py — API endpoint tests for AI Kavach.

Run with:
    py -3 -m pytest tests/test_api.py -v
    -- or --
    py -3 tests/test_api.py
"""
from __future__ import annotations

import json
import os
import sys
import time

# Ensure project root on path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Conditionally import test client
try:
    from fastapi.testclient import TestClient
    from api.main import app
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False


def run_api_tests():
    """Run all API tests and report results."""
    if not HAS_FASTAPI:
        print("SKIP: FastAPI not installed, skipping API tests")
        return 0, 0, 0

    # Initialize the scan service for tests (TestClient doesn't trigger lifespan)
    from api.services.scan_service import ScanService
    from api.routes.scans import set_scan_service
    set_scan_service(ScanService())

    client = TestClient(app)
    passed = 0
    failed = 0
    tests = []

    def test(name, fn):
        nonlocal passed, failed
        try:
            fn(client)
            print(f"  ✓ {name}")
            passed += 1
            tests.append((name, True))
        except Exception as e:
            print(f"  ✗ {name}: {e}")
            failed += 1
            tests.append((name, False))

    print("\n━━━ API Tests ━━━")

    # ── Health ─────────────────────────────────────────────────
    def test_health(c):
        r = c.get("/health")
        assert r.status_code == 200, f"Expected 200, got {r.status_code}"
        data = r.json()
        assert "status" in data
        assert "version" in data
        assert data["version"] == "1.0.0"
        assert "docker_validator" in data
        assert "docker_fuzzer" in data

    test("A1: Health endpoint returns 200", test_health)

    # ── Root ───────────────────────────────────────────────────
    def test_root(c):
        # Explicit JSON client
        r_json = c.get("/", headers={"Accept": "application/json"})
        assert r_json.status_code == 200
        data = r_json.json()
        assert data["name"] == "AI Kavach CRS API"
        assert "endpoints" in data

        # Web browser client
        r_html = c.get("/", headers={"Accept": "text/html,application/xhtml+xml"})
        assert r_html.status_code == 200
        assert "AI KAVACH" in r_html.text

    test("A2: Root endpoint returns API info for JSON clients and HTML for browsers", test_root)

    # ── Targets ────────────────────────────────────────────────
    def test_targets_list(c):
        r = c.get("/api/v1/targets")
        assert r.status_code == 200
        data = r.json()
        assert "targets" in data
        assert data["count"] >= 1
        # Check at least vuln_bof exists
        names = [t["name"] for t in data["targets"]]
        assert "vuln_bof" in names, f"vuln_bof not in {names}"

    test("A3: Targets endpoint lists available targets", test_targets_list)

    def test_targets_metadata(c):
        r = c.get("/api/v1/targets")
        data = r.json()
        bof = next(t for t in data["targets"] if t["name"] == "vuln_bof")
        assert bof["has_makefile"] is True
        assert bof["has_tests"] is True
        assert bof["has_seeds"] is True
        assert "vuln.c" in bof["source_files"]

    test("A4: Target metadata includes source files, seeds, tests", test_targets_metadata)

    # ── Scan creation ──────────────────────────────────────────
    def test_create_scan_valid(c):
        r = c.post("/api/v1/scans", json={
            "target": "targets/vuln_bof",
            "timeout": 30,
            "skip_fuzzing": True,
        })
        assert r.status_code == 201, f"Expected 201, got {r.status_code}: {r.text}"
        data = r.json()
        assert "scan_id" in data
        assert data["status"] in ("QUEUED", "RUNNING", "COMPLETED")
        assert data["target"] == "targets/vuln_bof"

    test("A5: Create scan with valid target returns 201", test_create_scan_valid)

    def test_create_scan_path_traversal(c):
        r = c.post("/api/v1/scans", json={"target": "../../../etc/passwd"})
        assert r.status_code == 422, f"Expected 422 for path traversal, got {r.status_code}"

    test("A6: Path traversal in target rejected with 422", test_create_scan_path_traversal)

    def test_create_scan_nonexistent(c):
        r = c.post("/api/v1/scans", json={"target": "targets/does_not_exist"})
        assert r.status_code == 404, f"Expected 404, got {r.status_code}"

    test("A7: Non-existent target rejected with 404", test_create_scan_nonexistent)

    def test_create_scan_outside_targets(c):
        r = c.post("/api/v1/scans", json={"target": "api/routes"})
        assert r.status_code == 422, f"Expected 422 for outside targets, got {r.status_code}"

    test("A8: Target outside targets/ rejected", test_create_scan_outside_targets)

    def test_timeout_validation(c):
        r = c.post("/api/v1/scans", json={"target": "targets/vuln_bof", "timeout": 5})
        assert r.status_code == 422, f"Expected 422 for timeout too low, got {r.status_code}"
        r2 = c.post("/api/v1/scans", json={"target": "targets/vuln_bof", "timeout": 700})
        assert r2.status_code == 422, f"Expected 422 for timeout too high, got {r2.status_code}"

    test("A9: Timeout validation (10-600 range)", test_timeout_validation)

    # ── Scan status & list ─────────────────────────────────────
    def test_scan_list(c):
        r = c.get("/api/v1/scans")
        assert r.status_code == 200
        data = r.json()
        assert "scans" in data
        assert "count" in data
        assert data["count"] >= 1  # At least the one we created above

    test("A10: Scan list returns created scans", test_scan_list)

    def test_scan_not_found(c):
        r = c.get("/api/v1/scans/00000000-0000-0000-0000-000000000000")
        assert r.status_code == 404

    test("A11: Non-existent scan returns 404", test_scan_not_found)

    # ── Finding not found ──────────────────────────────────────
    def test_finding_not_found(c):
        r = c.get("/api/v1/findings/00000000-0000-0000-0000-000000000000")
        assert r.status_code == 404

    test("A12: Non-existent finding returns 404", test_finding_not_found)

    # ── OpenAPI spec ───────────────────────────────────────────
    def test_openapi(c):
        r = c.get("/openapi.json")
        assert r.status_code == 200
        spec = r.json()
        assert "paths" in spec
        paths = list(spec["paths"].keys())
        assert "/health" in paths
        assert "/api/v1/targets" in paths
        assert "/api/v1/scans" in paths
        assert "/api/v1/scans/{scan_id}" in paths
        assert "/api/v1/scans/{scan_id}/report/html" in paths

    test("A13: OpenAPI spec contains all endpoints", test_openapi)

    # ── Target Upload ──────────────────────────────────────────
    def test_target_upload(c):
        dummy_c_code = b"""#include <stdio.h>\nint main() { printf("test"); return 0; }\n"""
        r = c.post(
            "/api/v1/targets/upload",
            files={"file": ("test_prog.c", dummy_c_code, "text/x-c")},
            data={"target_name": "api_test_upload"}
        )
        assert r.status_code == 201, f"Expected 201, got {r.status_code}: {r.text}"
        data = r.json()
        assert "name" in data
        assert "has_makefile" in data
        assert data["has_makefile"] is True

    test("A14: Upload custom target creates target directory", test_target_upload)

    # ── Report Downloads ───────────────────────────────────────
    def test_report_downloads_not_found(c):
        r1 = c.get("/api/v1/scans/00000000-0000-0000-0000-000000000000/report/html")
        assert r1.status_code == 404
        r2 = c.get("/api/v1/scans/00000000-0000-0000-0000-000000000000/report/markdown")
        assert r2.status_code == 404
        r3 = c.get("/api/v1/scans/00000000-0000-0000-0000-000000000000/report/json")
        assert r3.status_code == 404

    test("A15: Report download endpoints handle nonexistent scan", test_report_downloads_not_found)

    # ── Static UI Mounting ─────────────────────────────────────
    def test_ui_served(c):
        r = c.get("/ui")
        assert r.status_code in (200, 307), f"Expected 200/307, got {r.status_code}"

    test("A16: Frontend static UI is mounted and served", test_ui_served)

    # ── Summary ────────────────────────────────────────────────
    total = passed + failed
    print(f"\n  Result: {passed}/{total} passed")
    return passed, failed, total


if __name__ == "__main__":
    passed, failed, total = run_api_tests()
    sys.exit(1 if failed > 0 else 0)
