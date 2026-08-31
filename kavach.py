#!/usr/bin/env python3
"""
kavach.py — AI Kavach CRS Command-Line Interface
Single entry point for the full Cyber-Reasoning System pipeline.

Usage:
    python kavach.py --target targets/vuln_bof [OPTIONS]

Options:
    --target       Path to target directory (required)
    --timeout      Fuzzing timeout in seconds (default: 60)
    --llm          LLM provider: google|openai|ollama (default: google)
    --max-retries  Max patch retry attempts (default: 3)
    --output       Output directory for reports (default: output/reports)
    --skip-fuzzing Use pre-existing crashes dir instead of re-fuzzing
    --no-docker    Run without Docker (for local testing with native tools)
    --verbose      Enable verbose logging
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Add project root to Python path
sys.path.insert(0, os.path.dirname(__file__))

from models import CrashRecord, FindingReport, PipelineStatus
from llm.llm_client import LLMClient, LLMConfig
from llm.orchestrator import PipelineOrchestrator
from triage.triage_engine import TriageEngine
from static_analysis.run_semgrep import SemgrepAnalyzer
from sandbox.validator import PatchValidator
from reporting.report_generator import ReportGenerator


class FuzzingError(Exception):
    """Raised when the fuzzer infrastructure itself fails (not 'no crashes found')."""
    pass


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s [%(levelname)s] %(name)s — %(message)s"
    logging.basicConfig(level=level, format=fmt, handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("output/kavach.log", mode="a"),
    ])


# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AI Kavach — Cyber-Reasoning System (CRS)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full pipeline on buffer overflow target
  python kavach.py --target targets/vuln_bof --timeout 60

  # Use a different LLM provider
  python kavach.py --target targets/vuln_uaf --llm openai

  # Skip fuzzing, use existing crashes
  python kavach.py --target targets/vuln_bof --skip-fuzzing

  # Run all targets
  python kavach.py --all-targets --timeout 120
"""
    )
    parser.add_argument("--target", help="Path to target directory")
    parser.add_argument("--all-targets", action="store_true",
                        help="Run pipeline on all targets/ subdirectories")
    parser.add_argument("--timeout", type=int, default=60,
                        help="Fuzzing timeout in seconds (default: 60)")
    parser.add_argument("--llm", choices=["google", "openai", "ollama"],
                        default=os.getenv("KAVACH_LLM_PROVIDER", "google"),
                        help="LLM provider (default: google)")
    parser.add_argument("--max-retries", type=int, default=3,
                        help="Max patch retry attempts (default: 3)")
    parser.add_argument("--output", default="output/reports",
                        help="Output directory for reports (default: output/reports)")
    parser.add_argument("--skip-fuzzing", action="store_true",
                        help="Skip fuzzing, use pre-existing crashes directory")
    parser.add_argument("--no-docker", action="store_true",
                        help="Run without Docker (for local/CI environments)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable verbose logging")
    parser.add_argument("--dry-run", action="store_true",
                        help="Run everything except LLM calls (for testing pipeline)")
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Main pipeline runner
# ---------------------------------------------------------------------------

class KavachRunner:
    """Orchestrates the full AI Kavach pipeline for one or more targets."""

    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.log = logging.getLogger("kavach.runner")

        # Initialize components
        self.llm_client = self._init_llm()
        self.validator = PatchValidator(
            container_name="kavach_validator",
            workspace_path="/workspace",
        ) if not args.no_docker else _MockValidator()

        self.reporter = ReportGenerator(output_dir=args.output)
        os.makedirs("output", exist_ok=True)
        os.makedirs(args.output, exist_ok=True)

    def run_target(self, target_path: str) -> list[FindingReport]:
        """Run the full pipeline on a single target directory."""
        target_path = os.path.abspath(target_path)
        target_name = os.path.basename(target_path)

        self.log.info("")
        self.log.info("━" * 70)
        self.log.info("  AI KAVACH — Processing target: %s", target_name)
        self.log.info("━" * 70)

        pipeline_start = time.time()
        reports: list[FindingReport] = []

        # ── Phase 1: Static Analysis (prioritization) ─────────────────
        self.log.info("[kavach] Phase 1/4: Static Analysis")
        semgrep = SemgrepAnalyzer(target_path)
        static_findings = semgrep.run()
        risky_funcs = [f.function_name for f in static_findings if f.function_name]
        self.log.info("[kavach] Static analysis: %d findings, risky functions: %s",
                      len(static_findings), risky_funcs[:5])

        # ── Phase 2: Fuzzing ──────────────────────────────────────────
        crashes: list[CrashRecord] = []

        if self.args.skip_fuzzing or self.args.no_docker:
            self.log.info("[kavach] Phase 2/4: Fuzzing (SKIPPED — using existing crashes)")
            crashes = self._load_existing_crashes(target_path, target_name)
        else:
            self.log.info("[kavach] Phase 2/4: Fuzzing (timeout=%ds)", self.args.timeout)
            try:
                crashes = self._run_fuzzing(target_path, target_name)
            except FuzzingError as e:
                self.log.error("[kavach] ✗ FUZZER FAILED for %s: %s", target_name, e)
                self.log.error("[kavach] This is NOT 'no findings' — the fuzzer itself crashed.")
                raise  # Let caller handle or propagate

        if not crashes:
            self.log.info("[kavach] No crashes found for %s — target appears clean.", target_name)
            return []

        self.log.info("[kavach] %d unique crash(es) found after dedup", len(crashes))

        # ── Phase 3: Triage ───────────────────────────────────────────
        self.log.info("[kavach] Phase 3/4: Triage and CWE Classification")
        triage_engine = TriageEngine(target_src_root=target_path, static_findings=static_findings)
        triaged = triage_engine.triage(crashes)

        # Annotate with Semgrep risky functions
        for crash in triaged:
            crash.risky_functions = risky_funcs

        # ── Phase 4: LLM Reasoning + Patch + Validate ─────────────────
        self.log.info("[kavach] Phase 4/4: LLM Reasoning + Patch + Validation")

        for i, crash in enumerate(triaged):
            self.log.info("[kavach] Finding %d/%d: %s | %s | %s",
                          i + 1, len(triaged),
                          crash.target_name, crash.cwe, crash.severity.value)

            if self.args.dry_run:
                self.log.info("[kavach] DRY RUN — skipping LLM calls")
                continue

            orchestrator = PipelineOrchestrator(
                llm_client=self.llm_client,
                validator=self.validator,
                source_dir=target_path,
                max_retries=self.args.max_retries,
            )

            report = orchestrator.run(crash)
            reports.append(report)

            # Generate report files
            paths = self.reporter.generate(report)
            self.log.info("[kavach] Report: %s", paths["html_path"])

            # Print summary
            self._print_finding_summary(report)

        elapsed = time.time() - pipeline_start
        self.log.info("")
        self.log.info("[kavach] Target '%s' complete in %.1fs", target_name, elapsed)
        self.log.info("[kavach] %d/%d findings resulted in proven fixes",
                      sum(1 for r in reports if r.is_proven_fix()), len(reports))

        return reports

    def run_all_targets(self) -> dict[str, list[FindingReport]]:
        """Run pipeline on all subdirectories of targets/."""
        targets_dir = os.path.join(os.path.dirname(__file__), "targets")
        all_results: dict[str, list[FindingReport]] = {}

        target_dirs = sorted([
            d for d in os.listdir(targets_dir)
            if os.path.isdir(os.path.join(targets_dir, d))
        ])

        self.log.info("[kavach] Running on %d targets: %s", len(target_dirs), target_dirs)

        for tdir in target_dirs:
            tpath = os.path.join(targets_dir, tdir)
            try:
                reports = self.run_target(tpath)
                all_results[tdir] = reports
            except Exception as e:
                self.log.error("[kavach] Target %s failed with error: %s", tdir, e)
                all_results[tdir] = []

        self._print_summary_table(all_results)
        return all_results

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _init_llm(self) -> LLMClient:
        """Initialize LLM client from environment + args."""
        cfg = LLMConfig(
            provider=self.args.llm,
            google_api_key=os.getenv("GOOGLE_API_KEY", ""),
            openai_api_key=os.getenv("OPENAI_API_KEY", ""),
            ollama_base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
            max_calls_per_finding=8,
        )
        client = LLMClient(cfg)
        self.log.info("[kavach] LLM provider: %s", cfg.provider)
        return client

    def _run_fuzzing(self, target_path: str, target_name: str) -> list[CrashRecord]:
        """Run AFL++ fuzzing via Docker.

        Returns a list of CrashRecord on success (may be empty if no crashes found).
        Raises FuzzingError if the fuzzer infrastructure itself fails.
        """
        try:
            from fuzzing.fuzzer_manager import FuzzerManager, FuzzerConfig
            config = FuzzerConfig(
                target_name=target_name,
                target_dir=target_path,
                timeout_secs=self.args.timeout,
            )
            manager = FuzzerManager(config)
            return manager.run()
        except Exception as e:
            self.log.error("[kavach] Fuzzing FAILED (infrastructure error): %s", e)
            raise FuzzingError(f"Fuzzer infrastructure error for {target_name}: {e}") from e

    def _load_existing_crashes(self, target_path: str, target_name: str) -> list[CrashRecord]:
        """
        Load crash records from an existing crashes directory
        (for use when --skip-fuzzing is set or for testing).
        """
        # Look for pre-staged crash inputs
        crash_dirs = [
            os.path.join(target_path, "crashes"),
            os.path.join("output", "crashes", target_name),
        ]

        records = []
        from triage.triage_engine import TriageEngine
        import hashlib, re

        for crash_dir in crash_dirs:
            if not os.path.isdir(crash_dir):
                continue
            for fname in os.listdir(crash_dir):
                fpath = os.path.join(crash_dir, fname)
                if not os.path.isfile(fpath):
                    continue
                try:
                    with open(fpath, "rb") as f:
                        data = f.read()
                    crash_hex = data.hex()
                    fingerprint = hashlib.md5(fname.encode()).hexdigest()

                    # Try to run through ASan binary if it exists
                    asan_bin = os.path.join(target_path, f"{target_name}_asan")
                    asan_output = ""
                    if os.path.exists(asan_bin):
                        import subprocess
                        r = subprocess.run(
                            [asan_bin, fpath],
                            capture_output=True, text=True, timeout=5,
                            env={**os.environ, "ASAN_OPTIONS": "halt_on_error=1:detect_leaks=0"}
                        )
                        asan_output = r.stdout + r.stderr
                        # Use actual fingerprint from stack
                        frames = re.findall(r'#\d+ 0x[0-9a-f]+ in (\S+)', asan_output)
                        if frames:
                            fingerprint = hashlib.md5("|".join(frames[:3]).encode()).hexdigest()

                    records.append(CrashRecord(
                        target_name=target_name,
                        crash_input_path=fpath,
                        crash_input_hex=crash_hex,
                        asan_output=asan_output,
                        stack_fingerprint=fingerprint,
                    ))
                except Exception as e:
                    self.log.warning("[kavach] Could not load crash file %s: %s", fpath, e)

        return records

    def _print_finding_summary(self, report: FindingReport) -> None:
        """Print a one-line summary of a finding to stdout."""
        status = "✅ PROVEN FIX" if report.is_proven_fix() else "❌ COULD NOT PATCH"
        print(f"\n{'─'*60}")
        print(f"  {status}")
        print(f"  Target : {report.crash.target_name}")
        print(f"  CWE    : {report.crash.cwe} — {report.crash.cwe_name}")
        print(f"  Time   : {report.wall_clock_seconds:.1f}s")
        print(f"  LLM calls: {report.total_llm_calls} | Retries: {report.retry_count}")
        if report.patch:
            print(f"  Patch confidence: {report.patch.confidence}/10")
        print(f"{'─'*60}")

    def _print_summary_table(self, all_results: dict[str, list[FindingReport]]) -> None:
        """Print a summary table across all targets."""
        print("\n" + "═" * 70)
        print("  AI KAVACH — FINAL SUMMARY")
        print("═" * 70)
        print(f"  {'Target':<20} {'Findings':>8} {'Proven Fixes':>12} {'Could Not Patch':>16}")
        print("  " + "─" * 60)

        total_findings = 0
        total_proven = 0
        total_failed = 0

        for target, reports in all_results.items():
            proven = sum(1 for r in reports if r.is_proven_fix())
            failed = len(reports) - proven
            total_findings += len(reports)
            total_proven += proven
            total_failed += failed
            print(f"  {target:<20} {len(reports):>8} {proven:>12} {failed:>16}")

        print("  " + "─" * 60)
        print(f"  {'TOTAL':<20} {total_findings:>8} {total_proven:>12} {total_failed:>16}")
        print("═" * 70)

        if total_findings > 0:
            success_rate = (total_proven / total_findings) * 100
            print(f"\n  Patch success rate: {success_rate:.0f}%")
        print()


# ---------------------------------------------------------------------------
# Mock validator (for --no-docker mode)
# ---------------------------------------------------------------------------

class _MockValidator:
    """Mock validator for local testing without Docker."""
    def validate(self, crash, patch):
        from models import ValidationResult, ValidationStepResult
        log = logging.getLogger("kavach.mock_validator")
        log.warning("[mock-validator] No Docker — returning simulated PASS result")
        result = ValidationResult(patch=patch)
        result.pre_patch_crash = ValidationStepResult("pre_patch_crash", True, notes="[MOCK] Simulated crash")
        result.post_patch_crash = ValidationStepResult("post_patch_crash", True, notes="[MOCK] Simulated no crash")
        result.regression = ValidationStepResult("regression", True, notes="[MOCK] Tests assumed pass")
        result.overall_pass = True
        return result


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    args = parse_args()

    # Ensure output dir exists for log file
    os.makedirs("output", exist_ok=True)

    setup_logging(args.verbose)
    log = logging.getLogger("kavach.main")

    # Print banner
    print("""
  ╔══════════════════════════════════════════════════════════╗
  ║         🛡️  AI KAVACH — Cyber-Reasoning System           ║
  ║      Autonomous Vulnerability Detection & Patching       ║
  ╚══════════════════════════════════════════════════════════╝
""")

    runner = KavachRunner(args)

    if args.all_targets:
        runner.run_all_targets()
    elif args.target:
        target_path = args.target
        if not os.path.isdir(target_path):
            log.error("Target directory not found: %s", target_path)
            return 1
        reports = runner.run_target(target_path)
        if not reports and not args.dry_run:
            log.info("No findings for target '%s'", target_path)
    else:
        print("Error: Must specify --target <dir> or --all-targets")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
