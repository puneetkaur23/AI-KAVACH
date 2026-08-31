"""
sandbox/validator.py
AI Kavach CRS — Sandboxed Patch Validator.

Three-step validation pipeline (all inside Docker):
  Step 1. Pre-patch crash reproduction  — must crash (confirms bug is real)
  Step 2. Apply patch via `patch` command
  Step 3. Post-patch crash replay       — must NOT crash (confirms fix works)
  Step 4. Regression test suite         — must ALL pass (confirms no breakage)

Returns a ValidationResult with per-step evidence.
"""
from __future__ import annotations

import logging
import os
import subprocess
import tempfile
import time
from pathlib import Path

from models import (
    CrashRecord, PatchAttempt, ValidationResult, ValidationStepResult
)

log = logging.getLogger(__name__)


class PatchValidator:
    """
    Validates an LLM-generated patch inside the Docker sandbox.

    The validator communicates with the `kavach_validator` Docker container
    to apply patches and run tests in isolation from the host system.
    """

    def __init__(
        self,
        container_name: str = "kavach_validator",
        workspace_path: str = "/workspace",
    ):
        self.container_name = container_name
        self.workspace_path = workspace_path

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate(self, crash: CrashRecord, patch: PatchAttempt) -> ValidationResult:
        """
        Run the full 3-step validation pipeline.

        Args:
            crash: The crash record being fixed.
            patch: The LLM-generated patch attempt.

        Returns:
            ValidationResult with overall_pass and per-step evidence.
        """
        result = ValidationResult(patch=patch)
        target_dir = f"{self.workspace_path}/targets/{crash.target_name}"

        log.info("[validator] Starting validation for %s (attempt %d)",
                 crash.target_name, patch.attempt_number)

        # ── Step 1: Build ASan binary on UNPATCHED code ───────────────
        log.info("[validator] Step 1: Pre-patch crash reproduction")
        build_ok = self._build_asan(target_dir)
        if not build_ok:
            result.pre_patch_crash = ValidationStepResult(
                "pre_patch_crash", False,
                notes="ASan build failed on unpatched code"
            )
            result.overall_pass = False
            result.failure_reason = "Pre-patch ASan build failed"
            return result

        # Replay crash on unpatched binary — must crash
        pre_step = self._replay_crash(crash, target_dir, expect_crash=True)
        result.pre_patch_crash = pre_step

        if not pre_step.passed:
            # The crash doesn't reproduce — might be a fluke or environment issue
            log.warning("[validator] Crash did not reproduce on unpatched build!")
            result.overall_pass = False
            result.failure_reason = "Crash did not reproduce on unpatched build"
            return result

        log.info("[validator] ✓ Crash reproduced on unpatched build (good — it's a real bug)")

        # ── Step 2: Apply the patch ───────────────────────────────────
        log.info("[validator] Step 2: Applying patch")
        apply_ok, apply_stderr = self._apply_patch(patch, target_dir)
        if not apply_ok:
            result.post_patch_crash = ValidationStepResult(
                "post_patch_crash", False,
                stderr=apply_stderr,
                notes="Patch application failed (malformed diff?)"
            )
            result.overall_pass = False
            result.failure_reason = f"Patch application failed: {apply_stderr[:300]}"
            # Roll back and return
            self._rollback_patch(target_dir)
            return result

        log.info("[validator] ✓ Patch applied successfully")

        # ── Step 3: Rebuild with patch applied ───────────────────────
        log.info("[validator] Step 3: Rebuilding with patch")
        build_ok_patched = self._build_asan(target_dir)
        if not build_ok_patched:
            result.post_patch_crash = ValidationStepResult(
                "post_patch_crash", False,
                notes="ASan build failed AFTER applying patch (compilation error in patch?)"
            )
            result.overall_pass = False
            result.failure_reason = "Patched code does not compile"
            self._rollback_patch(target_dir)
            return result

        # ── Step 4: Replay crash on PATCHED binary — must NOT crash ───
        log.info("[validator] Step 4: Post-patch crash replay")
        post_step = self._replay_crash(crash, target_dir, expect_crash=False)
        result.post_patch_crash = post_step

        if not post_step.passed:
            log.warning("[validator] ✗ Crash still reproduces after patch!")
            result.overall_pass = False
            result.failure_reason = "Crash still reproduces after applying patch"
            self._rollback_patch(target_dir)
            return result

        log.info("[validator] ✓ Crash no longer reproduces after patch")

        # ── Step 5: Regression test suite ────────────────────────────
        log.info("[validator] Step 5: Running regression test suite")
        regression_step = self._run_regression(crash, target_dir)
        result.regression = regression_step

        if not regression_step.passed:
            log.warning("[validator] ✗ Regression tests failed after patch!")
            result.overall_pass = False
            result.failure_reason = f"Regression suite failed: {regression_step.notes}"
            self._rollback_patch(target_dir)
            return result

        log.info("[validator] ✓ All regression tests pass")

        # All steps passed
        result.overall_pass = True
        log.info("[validator] ✓✓✓ VALIDATION PASSED")

        # Always rollback so target stays in original vulnerable state
        self._rollback_patch(target_dir)
        return result

    # ------------------------------------------------------------------
    # Private: Docker operations
    # ------------------------------------------------------------------

    def _docker_exec(
        self, cmd: str, check: bool = False, timeout: int = 120
    ) -> subprocess.CompletedProcess:
        """Execute a command inside the validator container."""
        full_cmd = [
            "docker", "exec", self.container_name,
            "bash", "-c", cmd
        ]
        log.debug("[validator] docker exec: %s", cmd[:200])
        res = subprocess.run(
            full_cmd,
            capture_output=True,
            timeout=timeout
        )
        stdout = res.stdout.decode('utf-8', errors='replace') if res.stdout else ""
        stderr = res.stderr.decode('utf-8', errors='replace') if res.stderr else ""
        result = subprocess.CompletedProcess(res.args, res.returncode, stdout, stderr)
        if check and result.returncode != 0:
            raise RuntimeError(
                f"Command failed (rc={result.returncode}): {cmd}\n"
                f"STDERR: {result.stderr[:500]}"
            )
        return result

    def _build_asan(self, target_dir: str) -> bool:
        """Build the ASan-instrumented binary inside the container."""
        r = self._docker_exec(
            f"cd '{target_dir}' && make clean asan 2>&1",
            check=False
        )
        if r.returncode != 0:
            log.error("[validator] ASan build failed:\n%s", r.stdout[-1000:])
            return False
        log.debug("[validator] ASan build OK")
        return True

    def _replay_crash(
        self, crash: CrashRecord, target_dir: str, expect_crash: bool
    ) -> ValidationStepResult:
        """
        Replay the crash input against the ASan binary.

        Args:
            expect_crash: If True, we WANT it to crash. If False, we want no crash.
        """
        # Write crash input to a temp file inside container
        crash_tmp = f"/tmp/kavach_crash_{crash.stack_fingerprint[:8]}"

        # Re-create crash file from hex dump
        hex_data = crash.crash_input_hex
        write_cmd = f"echo '{hex_data}' | xxd -r -p > '{crash_tmp}' 2>/dev/null || cp '{crash.crash_input_path}' '{crash_tmp}' 2>/dev/null || true"
        self._docker_exec(write_cmd)

        # Determine binary name
        asan_bin = f"{target_dir}/{crash.target_name}_asan"

        # Run with ASan
        run_cmd = (
            f"ASAN_OPTIONS=halt_on_error=1:detect_leaks=0 "
            f"'{asan_bin}' '{crash_tmp}' 2>&1; echo \"EXIT_CODE:$?\""
        )
        r = self._docker_exec(run_cmd, check=False, timeout=30)
        combined = r.stdout + r.stderr

        # Parse exit code
        import re
        exit_match = re.search(r'EXIT_CODE:(\d+)', combined)
        exit_code = int(exit_match.group(1)) if exit_match else r.returncode

        # Crash = non-zero exit code OR "AddressSanitizer" in output
        crashed = exit_code != 0 or "AddressSanitizer" in combined or "ERROR:" in combined

        step_name = "pre_patch_crash" if expect_crash else "post_patch_crash"

        if expect_crash:
            passed = crashed
            notes = "Crash reproduced (expected)" if crashed else "Crash did NOT reproduce (unexpected)"
        else:
            passed = not crashed
            notes = "No crash after patch (expected)" if not crashed else "Crash still reproduces after patch"

        return ValidationStepResult(
            step_name=step_name,
            passed=passed,
            stdout=combined[:3000],
            stderr="",
            exit_code=exit_code,
            notes=notes,
        )

    def _apply_patch(self, patch: PatchAttempt, target_dir: str) -> tuple[bool, str]:
        """Apply the unified diff patch using `patch` command with -p1 / -p0 fallback.

        Uses base64 encoding to transfer the diff safely, preventing
        injection attacks via crafted diff content.
        Backs up the target directory first to guarantee clean rollback.
        """
        import base64

        diff_text = patch.diff.strip()
        if not diff_text:
            return False, "Empty diff"

        # Ensure trailing newline
        if not diff_text.endswith('\n'):
            diff_text += '\n'

        # Backup target directory inside container before patching
        backup_dir = f"/tmp/kavach_target_backup_{patch.finding_id[:8]}"
        self._docker_exec(f"rm -rf '{backup_dir}' && cp -a '{target_dir}' '{backup_dir}'", check=False)

        # Encode diff as base64 to prevent heredoc injection
        b64_diff = base64.b64encode(diff_text.encode('utf-8')).decode('ascii')
        patch_file = f"/tmp/kavach_patch_{patch.finding_id[:8]}.diff"
        write_cmd = f"echo '{b64_diff}' | base64 -d > '{patch_file}'"
        self._docker_exec(write_cmd)

        # Try -p1 first, fallback to -p0
        apply_cmd = f"cd '{target_dir}' && patch -p1 < '{patch_file}' 2>&1"
        r = self._docker_exec(apply_cmd, check=False)

        if r.returncode != 0:
            log.debug("[validator] patch -p1 failed, trying patch -p0...")
            apply_cmd_p0 = f"cd '{target_dir}' && patch -p0 < '{patch_file}' 2>&1"
            r_p0 = self._docker_exec(apply_cmd_p0, check=False)
            if r_p0.returncode == 0:
                return True, ""
            log.error("[validator] patch command failed:\n%s", r.stdout + "\n" + r_p0.stdout)
            return False, r.stdout + "\n" + r_p0.stdout

        return True, ""

    def _rollback_patch(self, target_dir: str) -> None:
        """Rollback any applied patches by restoring backup snapshot and cleaning up."""
        log.info("[validator] Rolling back patch to pristine state")
        # Try restoring from backup first if exists
        finding_id_prefix = self.finding_id[:8] if hasattr(self, 'finding_id') and self.finding_id else "*"
        restore_cmd = (
            f"for b in /tmp/kavach_target_backup_{finding_id_prefix}; do "
            f"  if [ -d \"$b\" ]; then "
            f"    cp -a \"$b/.\" '{target_dir}/' && rm -rf \"$b\"; "
            f"  fi; "
            f"done; "
            f"cd '{target_dir}' && (git checkout -- . 2>/dev/null; git clean -fd 2>/dev/null || true)"
        )
        self._docker_exec(restore_cmd, check=False)

    def _run_regression(self, crash: CrashRecord, target_dir: str) -> ValidationStepResult:
        """Run the target's test suite."""
        # Try standard test targets
        test_commands = [
            f"cd '{target_dir}' && make test 2>&1",
            f"cd '{target_dir}' && python3 tests/test_{crash.target_name}.py 2>&1",
        ]

        for cmd in test_commands:
            r = self._docker_exec(cmd, check=False, timeout=60)
            combined = r.stdout + r.stderr

            if r.returncode == 0:
                return ValidationStepResult(
                    "regression",
                    passed=True,
                    stdout=combined[:3000],
                    exit_code=0,
                    notes="All tests passed"
                )

            # Check for "no such file" on make test — try next command
            if "No rule to make target" in combined or "No such file" in combined:
                continue

            # Actual test failure
            return ValidationStepResult(
                "regression",
                passed=False,
                stdout=combined[:3000],
                exit_code=r.returncode,
                notes=f"Tests failed (exit code {r.returncode})"
            )

        # No test suite found — smoke test: just build successfully
        build_r = self._docker_exec(
            f"cd '{target_dir}' && make 2>&1",
            check=False
        )
        passed = build_r.returncode == 0
        return ValidationStepResult(
            "regression",
            passed=passed,
            stdout=build_r.stdout[:2000],
            exit_code=build_r.returncode,
            notes="No test suite found; smoke test (build) " + ("PASSED" if passed else "FAILED")
        )
