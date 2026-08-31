"""
static_analysis/run_semgrep.py
Semgrep static analysis wrapper for AI Kavach CRS.

Runs Semgrep against a target directory and returns ranked risky functions.
Results are cached to disk to avoid redundant re-runs.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")
CACHE_DIR = os.path.join(os.path.dirname(__file__), ".cache")


@dataclass
class SemgrepFinding:
    rule_id: str
    cwe: str
    file: str
    line: int
    message: str
    severity: str
    function_name: str = ""


class SemgrepAnalyzer:
    """Run Semgrep on a target and return ranked findings."""

    def __init__(self, target_dir: str, use_cache: bool = True):
        self.target_dir = os.path.abspath(target_dir)
        self.use_cache = use_cache
        os.makedirs(CACHE_DIR, exist_ok=True)

    def run(self) -> list[SemgrepFinding]:
        """Run Semgrep analysis, using cache if available."""
        cache_key = self._cache_key()
        cache_file = os.path.join(CACHE_DIR, f"{cache_key}.json")

        if self.use_cache and os.path.exists(cache_file):
            log.info("[semgrep] Using cached results: %s", cache_file)
            return self._load_cache(cache_file)

        findings = self._run_semgrep()

        if self.use_cache:
            self._save_cache(cache_file, findings)

        return findings

    def risky_functions(self) -> list[str]:
        """Return list of function names flagged by Semgrep (for fuzzing prioritization)."""
        findings = self.run()
        funcs = list(dict.fromkeys(
            f.function_name for f in findings if f.function_name
        ))
        return funcs

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _cache_key(self) -> str:
        h = hashlib.md5()
        for root, _, files in os.walk(self.target_dir):
            for fname in sorted(files):
                if fname.endswith(('.c', '.cpp', '.h')):
                    fpath = os.path.join(root, fname)
                    h.update(fpath.encode())
                    try:
                        h.update(open(fpath, 'rb').read())
                    except OSError:
                        pass
        return h.hexdigest()

    def _run_semgrep(self) -> list[SemgrepFinding]:
        cmd = [
            "semgrep",
            "--config", RULES_DIR,
            "--json",
            "--no-git-ignore",
            self.target_dir
        ]
        log.info("[semgrep] Running: %s", " ".join(cmd))

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        except FileNotFoundError:
            log.warning("[semgrep] Semgrep not found. Skipping static analysis.")
            return []
        except subprocess.TimeoutExpired:
            log.warning("[semgrep] Semgrep timed out.")
            return []

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            log.warning("[semgrep] Could not parse Semgrep JSON output")
            return []

        findings = []
        for r in data.get("results", []):
            meta = r.get("extra", {}).get("metadata", {})
            cwe_list = meta.get("cwe", [meta.get("cwe-id", "UNKNOWN")])
            cwe = cwe_list[0] if isinstance(cwe_list, list) and cwe_list else str(cwe_list)

            findings.append(SemgrepFinding(
                rule_id=r.get("check_id", ""),
                cwe=cwe,
                file=r.get("path", ""),
                line=r.get("start", {}).get("line", 0),
                message=r.get("extra", {}).get("message", ""),
                severity=r.get("extra", {}).get("severity", "WARNING"),
                function_name=self._extract_function(r),
            ))

        log.info("[semgrep] Found %d findings", len(findings))
        return findings

    def _extract_function(self, result: dict) -> str:
        metavars = result.get("extra", {}).get("metavars", {})
        for key in ("$FUNC", "$FUNCTION", "$NAME"):
            if key in metavars:
                return metavars[key].get("abstract_content", "")
        return ""

    def _save_cache(self, path: str, findings: list[SemgrepFinding]) -> None:
        data = [{"rule_id": f.rule_id, "cwe": f.cwe, "file": f.file,
                 "line": f.line, "message": f.message, "severity": f.severity,
                 "function_name": f.function_name} for f in findings]
        with open(path, 'w') as fp:
            json.dump(data, fp, indent=2)

    def _load_cache(self, path: str) -> list[SemgrepFinding]:
        with open(path) as fp:
            data = json.load(fp)
        return [SemgrepFinding(**d) for d in data]
