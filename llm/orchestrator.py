"""
llm/orchestrator.py
AI Kavach CRS — Core Orchestration State Machine.

State flow:
  IDLE → TRIAGE → ROOT_CAUSE → PATCH_GEN → VALIDATE
                                              │
                              ┌──── PASS ─────┴──── FAIL ────┐
                              ▼                               ▼
                           REPORT                    RETRY (bounded)
                                                     └── if retries exhausted → COULD_NOT_PATCH

This module is the "brain" that coordinates all pipeline stages.
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from typing import Optional

from models import (
    CrashRecord, RootCauseAnalysis, PatchAttempt, ValidationResult,
    FindingReport, PipelineStatus, Severity, CWE_NAMES
)
from llm.llm_client import LLMClient

log = logging.getLogger(__name__)

# Confidence threshold below which we flag the patch for manual review
CONFIDENCE_THRESHOLD = 6
# Maximum retry attempts for patch generation
MAX_RETRIES = 3


class PipelineOrchestrator:
    """
    Coordinates the full vulnerability analysis pipeline for a single crash record.

    Usage:
        orchestrator = PipelineOrchestrator(llm_client, validator, source_dir)
        report = orchestrator.run(crash_record)
    """

    def __init__(
        self,
        llm_client: LLMClient,
        validator,          # sandbox.validator.PatchValidator
        source_dir: str,    # absolute path to target source directory
        max_retries: int = MAX_RETRIES,
        confidence_threshold: int = CONFIDENCE_THRESHOLD,
    ):
        self.llm = llm_client
        self.validator = validator
        self.source_dir = source_dir
        self.max_retries = max_retries
        self.confidence_threshold = confidence_threshold

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def run(self, crash: CrashRecord) -> FindingReport:
        """
        Run the full pipeline for one crash record.
        Returns a FindingReport (PASS or COULD_NOT_PATCH).
        """
        self.llm.reset_usage()
        pipeline_start = time.time()
        stage_timings: dict[str, float] = {}

        log.info("=" * 60)
        log.info("[orchestrator] Processing finding: %s | %s", crash.target_name, crash.cwe)
        log.info("=" * 60)

        # ── Stage 1: Root Cause Analysis ──────────────────────────────
        t0 = time.time()
        rca = self._do_root_cause_analysis(crash)
        stage_timings["root_cause_secs"] = time.time() - t0

        if rca is None:
            return self._failure_report(
                crash, None, None, None,
                pipeline_start, stage_timings,
                error_message="Root cause analysis failed — LLM did not return valid JSON"
            )

        # Refine crash record CWE from verified RCA if confirmed
        if rca.cwe_confirmed and rca.cwe_confirmed != "UNKNOWN":
            crash.cwe = rca.cwe_confirmed
            crash.cwe_name = rca.cwe_name or CWE_NAMES.get(rca.cwe_confirmed, crash.cwe_name)
            if crash.severity == Severity.LOW or crash.severity == Severity.UNKNOWN:
                crash.severity = Severity.HIGH

        log.info("[orchestrator] Confirmed vulnerability: %s (%s) | %s",
                 crash.cwe, crash.cwe_name, crash.severity.value)

        # ── Stage 2: Patch Generation + Validation Loop ───────────────
        retry_count = 0
        last_validation: Optional[ValidationResult] = None
        last_patch: Optional[PatchAttempt] = None
        retry_context = ""

        while retry_count <= self.max_retries:
            attempt_num = retry_count + 1
            log.info("[orchestrator] Patch attempt %d / %d", attempt_num, self.max_retries + 1)

            # Generate patch
            t0 = time.time()
            patch = self._do_patch_generation(crash, rca, attempt_num, retry_context)
            stage_timings[f"patch_gen_{attempt_num}_secs"] = time.time() - t0

            if patch is None:
                retry_count += 1
                retry_context = "Previous patch generation returned invalid JSON. Try again."
                continue

            last_patch = patch

            # Low confidence warning
            if patch.confidence < self.confidence_threshold:
                log.warning(
                    "[orchestrator] Patch confidence %d < threshold %d — flagging",
                    patch.confidence, self.confidence_threshold
                )

            # Validate patch
            t0 = time.time()
            validation = self.validator.validate(crash, patch)
            stage_timings[f"validate_{attempt_num}_secs"] = time.time() - t0
            last_validation = validation

            if validation.overall_pass:
                log.info("[orchestrator] ✓ Patch VALIDATED on attempt %d", attempt_num)
                peak_mb = self._get_memory_mb()
                return FindingReport(
                    crash=crash,
                    root_cause=rca,
                    patch=patch,
                    validation=validation,
                    status=PipelineStatus.PASS,
                    wall_clock_seconds=time.time() - pipeline_start,
                    total_llm_calls=self.llm.usage.call_count,
                    retry_count=retry_count,
                    peak_memory_mb=peak_mb,
                    stage_timings=stage_timings,
                )
            else:
                log.warning("[orchestrator] ✗ Patch FAILED validation: %s", validation.failure_reason)
                retry_context = self._build_retry_context(patch, validation)
                retry_count += 1

        # Exhausted retries
        log.error("[orchestrator] Could not patch %s after %d attempts", crash.target_name, self.max_retries + 1)
        peak_mb = self._get_memory_mb()
        return FindingReport(
            crash=crash,
            root_cause=rca,
            patch=last_patch,
            validation=last_validation,
            status=PipelineStatus.COULD_NOT_PATCH,
            wall_clock_seconds=time.time() - pipeline_start,
            total_llm_calls=self.llm.usage.call_count,
            retry_count=retry_count,
            peak_memory_mb=peak_mb,
            stage_timings=stage_timings,
            error_message=f"Exceeded max retries ({self.max_retries}). Last failure: {last_validation.failure_reason if last_validation else 'unknown'}"
        )

    # ------------------------------------------------------------------
    # Stage: Root Cause Analysis
    # ------------------------------------------------------------------

    def _do_root_cause_analysis(self, crash: CrashRecord) -> Optional[RootCauseAnalysis]:
        """Call LLM to analyze root cause. Returns None on failure."""
        prompt_template = self._load_prompt("root_cause.txt")
        prompt = _fill_template(prompt_template, {
            "code_slice": crash.code_slice or "[Code slice not available]",
            "asan_output": crash.asan_output[:3000],  # cap to avoid token overflow
            "cwe": crash.cwe,
        })

        log.info("[orchestrator] Calling LLM for root cause analysis...")
        try:
            response = self.llm.call(prompt, mode="reasoning")
        except RuntimeError as e:
            log.error("[orchestrator] LLM call failed: %s", e)
            return None

        rca_data = _parse_json_response(response)
        if not rca_data:
            log.error("[orchestrator] RCA response is not valid JSON:\n%s", response[:500])
            return None

        cwe = rca_data.get("cwe", crash.cwe)
        return RootCauseAnalysis(
            finding_id=crash.stack_fingerprint,
            explanation=rca_data.get("explanation", ""),
            cwe_confirmed=cwe,
            cwe_name=rca_data.get("cwe_name", CWE_NAMES.get(cwe, "Unknown")),
            confidence=int(rca_data.get("confidence", 5)),
            llm_call_index=self.llm.usage.call_count,
        )

    # ------------------------------------------------------------------
    # Stage: Patch Generation
    # ------------------------------------------------------------------

    def _do_patch_generation(
        self,
        crash: CrashRecord,
        rca: RootCauseAnalysis,
        attempt: int,
        retry_context: str,
    ) -> Optional[PatchAttempt]:
        """Call LLM to generate a patch. Returns None on failure."""
        # Load source code of the target file
        source_code, source_file = self._load_source_code(crash)

        prompt_template = self._load_prompt("patch_gen.txt")
        prompt = _fill_template(prompt_template, {
            "root_cause_explanation": rca.explanation,
            "cwe": rca.cwe_confirmed,
            "cwe_name": rca.cwe_name,
            "source_file": source_file,
            "source_code": source_code,
            "retry_context": (
                f"=== PREVIOUS ATTEMPT FEEDBACK ===\n{retry_context}\n"
                if retry_context else ""
            ),
        })

        log.info("[orchestrator] Calling LLM for patch generation (attempt %d)...", attempt)
        try:
            response = self.llm.call(prompt, mode="reasoning")
        except RuntimeError as e:
            log.error("[orchestrator] LLM call failed: %s", e)
            return None

        patch_data = _parse_json_response(response)
        if not patch_data or "diff" not in patch_data:
            log.error("[orchestrator] Patch response is not valid JSON:\n%s", response[:500])
            return None

        return PatchAttempt(
            finding_id=crash.stack_fingerprint,
            attempt_number=attempt,
            diff=patch_data.get("diff", ""),
            explanation=patch_data.get("explanation", ""),
            confidence=int(patch_data.get("confidence", 5)),
            target_file=patch_data.get("target_file", source_file),
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _load_prompt(self, filename: str) -> str:
        """Load a prompt template from llm/prompts/."""
        prompt_dir = os.path.join(os.path.dirname(__file__), "prompts")
        path = os.path.join(prompt_dir, filename)
        with open(path, "r", encoding="utf-8") as f:
            return f.read()

    def _load_source_code(self, crash: CrashRecord) -> tuple[str, str]:
        """Load the primary source file for the target."""
        # Find .c or .cpp files in the source directory
        for f in sorted(os.listdir(self.source_dir)):
            if f.endswith((".c", ".cpp")) and not f.startswith("fuzz"):
                path = os.path.join(self.source_dir, f)
                try:
                    with open(path, "r", encoding="utf-8") as fh:
                        return fh.read(), f
                except OSError:
                    pass
        return "[Source not found]", "unknown.c"

    def _build_retry_context(self, patch: PatchAttempt, validation: ValidationResult) -> str:
        """Build structured diagnostic context string to feed back to LLM on retry."""
        diagnostics = []
        if validation.pre_patch_crash and not validation.pre_patch_crash.passed:
            diagnostics.append(f"- Pre-patch check issue: {validation.pre_patch_crash.notes}")
        if validation.post_patch_crash and not validation.post_patch_crash.passed:
            diag_err = (validation.post_patch_crash.stderr or validation.post_patch_crash.stdout)[-800:]
            diagnostics.append(f"- Crash STILL occurs with your patch applied:\n```\n{diag_err}\n```")
        if validation.regression and not validation.regression.passed:
            reg_err = (validation.regression.stderr or validation.regression.stdout)[-800:]
            diagnostics.append(f"- Regression tests FAILED after your patch:\n```\n{reg_err}\n```")

        diag_text = "\n".join(diagnostics) if diagnostics else validation.failure_summary()

        return (
            f"=== PREVIOUS ATTEMPT (Attempt {patch.attempt_number}) FAILED VALIDATION ===\n"
            f"Previous proposed diff:\n```diff\n{patch.diff}\n```\n\n"
            f"Detailed Failure Reason:\n{diag_text}\n\n"
            "Instructions for next attempt:\n"
            "1. Carefully inspect the compiler error / sanitizer trace above.\n"
            "2. Ensure your unified diff format is exact: starts with `--- a/<file>` and `+++ b/<file>`.\n"
            "3. Make sure the fix actually eliminates the vulnerability without changing return codes or breaking valid input handling.\n"
            "4. Return ONLY valid JSON with the new diff."
        )

    def _get_memory_mb(self) -> float:
        """Estimate current resident memory in MB."""
        try:
            import psutil
            process = psutil.Process()
            return process.memory_info().rss / (1024 * 1024)
        except Exception:
            return 0.0

    def _failure_report(
        self, crash, rca, patch, validation,
        start, timings, error_message=""
    ) -> FindingReport:
        return FindingReport(
            crash=crash,
            root_cause=rca,
            patch=patch,
            validation=validation,
            status=PipelineStatus.ERROR,
            wall_clock_seconds=time.time() - start,
            total_llm_calls=self.llm.usage.call_count,
            retry_count=0,
            stage_timings=timings,
            error_message=error_message,
        )


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _parse_json_response(text: str) -> Optional[dict]:
    """
    Extract and parse JSON from LLM response.
    LLMs sometimes wrap JSON in markdown code fences — handle that.
    """
    # Strip markdown code fences if present
    text = text.strip()
    if text.startswith("```"):
        # Remove opening fence (```json or ```)
        text = re.sub(r'^```(?:json)?\s*\n?', '', text)
        # Remove closing fence
        text = re.sub(r'\n?```\s*$', '', text)

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Try to find JSON object within the text
        match = re.search(r'\{.*\}', text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass
    return None


def _fill_template(template: str, substitutions: dict[str, str]) -> str:
    """
    Safely replace {key} placeholders in template without interpreting literal JSON braces.
    """
    result = template
    for key, val in substitutions.items():
        result = result.replace(f"{{{key}}}", str(val))
    return result
