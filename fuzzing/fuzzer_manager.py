"""
fuzzing/fuzzer_manager.py
Python wrapper around the Docker-based AFL++ fuzzer.

Interacts with the `kavach_fuzzer` Docker container to:
  1. Build the AFL-instrumented target
  2. Run AFL++ for a bounded time
  3. Collect crash inputs + sanitizer output
  4. Return list of CrashRecord objects
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import subprocess
import time
from dataclasses import dataclass
from typing import Optional

# Import from project root (add parent to path if needed)
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from models import CrashRecord

log = logging.getLogger(__name__)


@dataclass
class FuzzerConfig:
    target_name: str         # e.g. "vuln_bof"
    target_dir: str          # absolute path to target dir on host
    timeout_secs: int = 60
    max_memory_mb: int = 200
    container_name: str = "kavach_fuzzer"


class FuzzerManager:
    """Manages a Docker-based AFL++ fuzzing run."""

    def __init__(self, config: FuzzerConfig, fuzzer_out_volume: str = "kavach_fuzzer_out"):
        self.cfg = config
        self.fuzzer_out_volume = fuzzer_out_volume
        # Container-internal path where volume is mounted
        self.container_out_dir = f"/fuzzer_out/{config.target_name}"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self) -> list[CrashRecord]:
        """Run AFL++, return deduplicated crash records."""
        start = time.time()
        log.info("[fuzzer] Starting fuzz run on %s (timeout=%ds)",
                 self.cfg.target_name, self.cfg.timeout_secs)

        # Step 1: build AFL-instrumented binary inside container
        self._build_afl_target()

        # Step 2: run fuzzer
        rc = self._run_afl()
        elapsed = time.time() - start
        log.info("[fuzzer] Fuzz run finished in %.1fs (exit=%d)", elapsed, rc)

        # Step 3: collect crashes
        crashes = self._collect_crashes()
        log.info("[fuzzer] Collected %d unique crash input(s)", len(crashes))
        return crashes

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _docker_exec(self, cmd: str, check: bool = True, timeout: int = 300) -> subprocess.CompletedProcess:
        """Run a shell command inside the fuzzer container."""
        full_cmd = [
            "docker", "exec", self.cfg.container_name,
            "bash", "-c", cmd
        ]
        log.debug("[docker-exec] %s", cmd[:200])
        res = subprocess.run(full_cmd, capture_output=True, timeout=timeout)
        stdout = res.stdout.decode('utf-8', errors='replace') if res.stdout else ""
        stderr = res.stderr.decode('utf-8', errors='replace') if res.stderr else ""
        result = subprocess.CompletedProcess(res.args, res.returncode, stdout, stderr)
        if check and result.returncode not in (0, 2):
            raise RuntimeError(
                f"Docker exec failed (rc={result.returncode}):\n"
                f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}"
            )
        return result

    def _build_afl_target(self) -> None:
        """Build AFL++ instrumented binary inside container."""
        target_path = f"/workspace/targets/{self.cfg.target_name}"
        log.info("[fuzzer] Building AFL target at %s", target_path)
        self._docker_exec(f"cd {target_path} && make clean afl 2>&1", check=True)

    def _run_afl(self) -> int:
        """Run AFL++ inside container, return exit code."""
        target_path = f"/workspace/targets/{self.cfg.target_name}"
        afl_bin = f"{target_path}/{self.cfg.target_name}_afl"
        seed_dir = f"{target_path}/seeds"
        output_dir = self.container_out_dir

        cmd = (
            f"TARGET_BIN='{afl_bin}' "
            f"SEED_DIR='{seed_dir}' "
            f"OUTPUT_DIR='{output_dir}' "
            f"TIMEOUT='{self.cfg.timeout_secs}' "
            f"MAX_MEMORY_MB='{self.cfg.max_memory_mb}' "
            f"bash /workspace/fuzzing/run_fuzzer.sh"
        )
        result = self._docker_exec(cmd, check=False, timeout=self.cfg.timeout_secs + 30)
        log.debug("[fuzzer stdout] %s", result.stdout[-2000:])
        return result.returncode

    def _collect_crashes(self) -> list[CrashRecord]:
        """Read crash inputs from AFL output dir and run through ASan to get stack traces."""
        crashes_dir = f"{self.container_out_dir}/default/crashes"
        target_path = f"/workspace/targets/{self.cfg.target_name}"
        asan_bin = f"{target_path}/{self.cfg.target_name}_asan"

        # First build ASan binary (needed for stack traces)
        self._docker_exec(f"cd {target_path} && make asan 2>&1", check=False)

        # List crash files
        result = self._docker_exec(
            f"ls '{crashes_dir}' 2>/dev/null || echo ''",
            check=False
        )
        crash_files = [
            f for f in result.stdout.strip().split("\n")
            if f and f != "README.txt" and f.strip()
        ]

        records: list[CrashRecord] = []
        seen_fingerprints: set[str] = set()

        for cf in crash_files:
            crash_path = f"{crashes_dir}/{cf}"

            # Read crash input bytes as hex
            read_result = self._docker_exec(
                f"xxd -p '{crash_path}' 2>/dev/null | tr -d '\\n' || true",
                check=False
            )
            crash_hex = read_result.stdout.strip()

            # Run through ASan binary to get stack trace
            asan_result = self._docker_exec(
                f"ASAN_OPTIONS=halt_on_error=1:detect_leaks=0 "
                f"'{asan_bin}' '{crash_path}' 2>&1 || true",
                check=False
            )
            asan_output = asan_result.stdout

            # Compute fingerprint from top-3 stack frames
            fingerprint = _fingerprint_stack(asan_output)
            if fingerprint in seen_fingerprints:
                log.debug("[triage] Duplicate fingerprint skipped: %s", fingerprint)
                continue
            seen_fingerprints.add(fingerprint)

            record = CrashRecord(
                target_name=self.cfg.target_name,
                crash_input_path=crash_path,
                crash_input_hex=crash_hex,
                asan_output=asan_output,
                stack_fingerprint=fingerprint,
            )
            records.append(record)

        return records


def _fingerprint_stack(asan_output: str) -> str:
    """Extract top-3 stack frame symbols as a fingerprint (ASLR-independent)."""
    frames = re.findall(r'#\d+ 0x[0-9a-f]+ in (\S+)', asan_output)
    top3 = frames[:3]
    if not top3:
        # Fallback: hash the whole output
        return hashlib.md5(asan_output[:500].encode()).hexdigest()
    return hashlib.md5("|".join(top3).encode()).hexdigest()
