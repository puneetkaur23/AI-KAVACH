"""
triage/triage_engine.py
Crash Triage Engine for AI Kavach CRS.

Responsibilities:
  1. Deduplication: group crashes by stack fingerprint
  2. Multi-tier CWE Classification: map ASan / glibc / signal / static analysis to CWE tag
  3. Severity Ranking: score by exploitability heuristic
  4. Code Slice Extraction: pull relevant code around crash site or source context
"""
from __future__ import annotations

import logging
import os
import re
from typing import Optional

from models import CrashRecord, Severity, CWE_NAMES

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# ASan / Glibc / Signal error type → CWE mapping
# ---------------------------------------------------------------------------

ASAN_TO_CWE: dict[str, str] = {
    # Direct buffer overflow patterns (ASan & Glibc)
    "stack-buffer-overflow": "CWE-121",
    "buffer overflow detected": "CWE-121",
    "stack smashing detected": "CWE-121",
    "buffer-overflow": "CWE-121",
    "buffer overflow": "CWE-121",
    "stack overflow": "CWE-121",
    "heap-buffer-overflow": "CWE-122",
    "global-buffer-overflow": "CWE-787",
    "out-of-bounds write": "CWE-787",
    "out-of-bounds read": "CWE-125",
    "out-of-bounds": "CWE-787",

    # Use-after-free & heap memory errors
    "heap-use-after-free": "CWE-416",
    "use-after-poison": "CWE-416",
    "heap-use-after-return": "CWE-416",
    "heap-use-after-scope": "CWE-416",
    "use-after-free": "CWE-416",
    "double-free": "CWE-416",
    "free(): invalid pointer": "CWE-416",

    # Integer overflows & UBSan
    "integer-overflow": "CWE-190",
    "signed-integer-overflow": "CWE-190",
    "unsigned-integer-overflow": "CWE-190",
    "integer overflow": "CWE-190",
    "runtime error: signed integer overflow": "CWE-190",
    "runtime error: unsigned integer overflow": "CWE-190",

    # Null & memory dereference / signal errors
    "null-deref": "CWE-476",
    "null pointer": "CWE-476",
    "null-pointer-dereference": "CWE-476",
    "memory-leak": "CWE-401",
    "segv on unknown address": "CWE-787",
    "segmentation fault": "CWE-787",
    "sigsegv": "CWE-787",
    "sigabrt": "CWE-119",
    "aborted": "CWE-119",
}

# Severity heuristic: write primitives / code exec > read primitives > crash-only
EXPLOITABILITY_RANK: dict[str, int] = {
    "CWE-787": 90,   # OOB Write — high exploitability
    "CWE-121": 90,   # Stack BOF — critical exploitability
    "CWE-122": 90,   # Heap BOF — high exploitability
    "CWE-120": 85,   # Classic Buffer Copy without bounds
    "CWE-119": 85,   # Memory Bounds Violation
    "CWE-416": 85,   # Use-After-Free — high exploitability
    "CWE-78": 95,    # Command Injection
    "CWE-134": 90,   # Format String
    "CWE-190": 70,   # Integer overflow
    "CWE-125": 50,   # OOB Read
    "CWE-476": 40,   # NULL deref
    "CWE-401": 20,   # Memory leak
    "UNKNOWN": 60,   # Crashing under ASan is at least HIGH severity
}


class TriageEngine:
    """Triage and enrich crash records."""

    def __init__(self, target_src_root: str, static_findings: list = None):
        """
        Args:
            target_src_root: Absolute path to the target's source directory.
            static_findings: Optional list of Semgrep / static analysis findings.
        """
        self.target_src_root = target_src_root
        self.static_findings = static_findings or []

    def triage(self, crashes: list[CrashRecord]) -> list[CrashRecord]:
        """
        Process a list of crash records:
          - Deduplicate by stack fingerprint
          - Classify CWE using multi-tier evidence
          - Rank severity
          - Extract code slice

        Returns sorted list (highest severity first), deduplicated.
        """
        seen: set[str] = set()
        unique: list[CrashRecord] = []

        for crash in crashes:
            if crash.stack_fingerprint in seen:
                log.debug("[triage] Duplicate fingerprint skipped: %s", crash.stack_fingerprint)
                continue
            seen.add(crash.stack_fingerprint)

            # Enrich the crash record in-place
            self._classify_cwe(crash)
            self._rank_severity(crash)
            self._extract_code_slice(crash)
            unique.append(crash)
            log.info("[triage] Finding: %s | %s (%s) | %s",
                     crash.target_name, crash.cwe, crash.cwe_name, crash.severity.value)

        # Sort: highest exploitability score first
        unique.sort(
            key=lambda c: EXPLOITABILITY_RANK.get(c.cwe, 50),
            reverse=True
        )
        return unique

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _classify_cwe(self, crash: CrashRecord) -> None:
        """
        Multi-tier evidence-based CWE classification:
          Tier 1: ASan / Glibc / Signal output pattern matching
          Tier 2: Static analysis findings (Semgrep)
          Tier 3: Source code heuristic pattern analysis
          Tier 4: Generic memory bounds fallback
        """
        asan_lower = (crash.asan_output or "").lower()

        # Tier 1: Check runtime crash output against known sanitizer/glibc patterns
        for pattern, cwe in ASAN_TO_CWE.items():
            if pattern.lower() in asan_lower:
                crash.cwe = cwe
                crash.cwe_name = CWE_NAMES.get(cwe, "Unknown Vulnerability")
                log.debug("[triage] Tier 1 classified: %s (%s) from pattern '%s'", cwe, crash.cwe_name, pattern)
                return

        # Tier 2: Check Static Analysis findings if available
        for sf in self.static_findings:
            sf_cwe = getattr(sf, "cwe", "")
            if sf_cwe and sf_cwe != "UNKNOWN" and sf_cwe in CWE_NAMES:
                crash.cwe = sf_cwe
                crash.cwe_name = CWE_NAMES.get(sf_cwe, "Unknown Vulnerability")
                log.debug("[triage] Tier 2 classified: %s (%s) from static analysis", sf_cwe, crash.cwe_name)
                return

        # Tier 3: Source code heuristic pattern matching
        src_cwe = self._classify_from_source()
        if src_cwe and src_cwe in CWE_NAMES:
            crash.cwe = src_cwe
            crash.cwe_name = CWE_NAMES.get(src_cwe, "Unknown Vulnerability")
            log.debug("[triage] Tier 3 classified: %s (%s) from source inspection", src_cwe, crash.cwe_name)
            return

        # Tier 4: Fallback for confirmed crashing memory-safety bug
        if "runtime error" in asan_lower:
            crash.cwe = "CWE-190"
            crash.cwe_name = CWE_NAMES["CWE-190"]
        elif crash.asan_output and ("error" in asan_lower or "abort" in asan_lower or "exit" in asan_lower):
            crash.cwe = "CWE-119"
            crash.cwe_name = CWE_NAMES["CWE-119"]
        else:
            crash.cwe = "CWE-119"
            crash.cwe_name = CWE_NAMES["CWE-119"]

    def _classify_from_source(self) -> Optional[str]:
        """Inspect source files in target directory for classic vulnerable patterns."""
        try:
            for fname in os.listdir(self.target_src_root):
                if fname.endswith(('.c', '.cpp')):
                    path = os.path.join(self.target_src_root, fname)
                    with open(path, 'r', encoding='utf-8', errors='replace') as fp:
                        content = fp.read()

                    # Check for classic stack buffer overflow patterns
                    if "strcpy(" in content or "gets(" in content or "sprintf(" in content:
                        return "CWE-121"
                    # Check for use-after-free patterns
                    if "free(" in content and ("->" in content or "print" in content):
                        return "CWE-416"
                    # Check for integer overflow allocation patterns
                    if "*" in content and ("malloc(" in content or "calloc(" in content):
                        return "CWE-190"
        except Exception as e:
            log.debug("[triage] Source inspection error: %s", e)
        return None

    def _rank_severity(self, crash: CrashRecord) -> None:
        """Assign severity based on CWE exploitability score."""
        score = EXPLOITABILITY_RANK.get(crash.cwe, 70)
        if score >= 85:
            crash.severity = Severity.CRITICAL
        elif score >= 65:
            crash.severity = Severity.HIGH
        elif score >= 40:
            crash.severity = Severity.MEDIUM
        else:
            crash.severity = Severity.LOW

        # Human-readable exploitability note
        if crash.cwe in ("CWE-121", "CWE-122", "CWE-787", "CWE-120"):
            crash.exploitability_note = "Memory Write-Primitive / Buffer Overflow — high potential for arbitrary code execution."
        elif crash.cwe == "CWE-416":
            crash.exploitability_note = "Use-After-Free — heap memory reuse allows hijacking control flow or leaking pointers."
        elif crash.cwe == "CWE-190":
            crash.exploitability_note = "Integer Overflow — arithmetic wraparound triggers undersized buffer allocation and subsequent OOB write."
        elif crash.cwe == "CWE-125":
            crash.exploitability_note = "Out-of-Bounds Read — exposes sensitive memory or cryptographic keys."
        elif crash.cwe == "CWE-476":
            crash.exploitability_note = "NULL Pointer Dereference — causes application crash and denial of service."
        elif crash.cwe == "CWE-119":
            crash.exploitability_note = "Memory Buffer Bounds Violation — memory corruption detected during execution."

    def _extract_code_slice(self, crash: CrashRecord) -> None:
        """
        Extract the relevant code snippet around the crash site.
        Falls back to full file or function slice when ASan format does not contain line numbers.
        """
        # Parse the crashing function from ASan output if available
        func_match = re.search(
            r'#0 0x[0-9a-f]+ in (\S+)[^\n]*?(\w+\.c(?:pp)?)?:(\d+)',
            crash.asan_output or ""
        )
        if not func_match:
            func_match = re.search(
                r'in (\w+)\s+(\S+\.c(?:pp)?)_:(\d+)',
                crash.asan_output or ""
            )

        if func_match:
            src_file = func_match.group(2) or ""
            crash_line = int(func_match.group(3) or 0)
            src_path = self._find_source_file(src_file)
            if src_path and os.path.exists(src_path):
                crash.code_slice = self._read_slice(src_path, crash_line, context=10)
                return

        # Fallback: Extract the primary source file directly
        src_path = self._find_primary_source_file()
        if src_path and os.path.exists(src_path):
            try:
                with open(src_path, 'r', encoding='utf-8', errors='replace') as f:
                    lines = f.readlines()
                if len(lines) <= 120:
                    numbered = [f"{i + 1:4d}: {lines[i]}" for i in range(len(lines))]
                    crash.code_slice = f"// {src_path} (full file)\n" + "".join(numbered)
                else:
                    numbered = [f"{i + 1:4d}: {lines[i]}" for i in range(min(60, len(lines)))]
                    crash.code_slice = f"// {src_path} (lines 1–60)\n" + "".join(numbered)
            except Exception as e:
                crash.code_slice = f"[Could not read {src_path}: {e}]"
        else:
            crash.code_slice = f"[Source file not found in {self.target_src_root}]"

    def _find_primary_source_file(self) -> Optional[str]:
        """Find the main .c/.cpp file for the target."""
        # Prefer vuln.c or clean.c or multi.c
        for candidate in ("vuln.c", "clean.c", "multi.c", "main.c"):
            p = os.path.join(self.target_src_root, candidate)
            if os.path.exists(p):
                return p

        for f in sorted(os.listdir(self.target_src_root)):
            if f.endswith(('.c', '.cpp')):
                return os.path.join(self.target_src_root, f)
        return None

    def _find_source_file(self, filename: str) -> Optional[str]:
        """Search for source file in target source root."""
        if not filename:
            return self._find_primary_source_file()

        direct = os.path.join(self.target_src_root, filename)
        if os.path.exists(direct):
            return direct

        for root, _, files in os.walk(self.target_src_root):
            for f in files:
                if f == filename or f == os.path.basename(filename):
                    return os.path.join(root, f)
        return None

    def _read_slice(self, path: str, line: int, context: int = 10) -> str:
        """Read ±context lines around the given line number from a file."""
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()
        except OSError as e:
            return f"[Could not read {path}: {e}]"

        start = max(0, line - context - 1)
        end = min(len(lines), line + context)
        numbered = [
            f"{i + 1:4d}: {lines[i]}"
            for i in range(start, end)
        ]
        return f"// {path} (lines {start+1}–{end})\n" + "".join(numbered)
