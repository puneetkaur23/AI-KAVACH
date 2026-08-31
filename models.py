"""
models.py — Shared data models for AI Kavach CRS.
All pipeline stages share these dataclasses as their communication contract.
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Any


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class PipelineStatus(str, Enum):
    IDLE = "IDLE"
    TRIAGE = "TRIAGE"
    ROOT_CAUSE = "ROOT_CAUSE"
    PATCH_GEN = "PATCH_GEN"
    VALIDATE = "VALIDATE"
    PASS = "PASS"
    FAIL = "FAIL"
    COULD_NOT_PATCH = "COULD_NOT_PATCH"
    ERROR = "ERROR"


class ScanStatus(str, Enum):
    """Lifecycle status of a scan job."""
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


# CWE tag → human name mapping
CWE_NAMES = {
    "CWE-787": "Out-of-bounds Write",
    "CWE-121": "Stack-based Buffer Overflow",
    "CWE-122": "Heap-based Buffer Overflow",
    "CWE-120": "Buffer Copy without Checking Size of Input",
    "CWE-119": "Improper Restriction of Operations within Bounds of Memory Buffer",
    "CWE-416": "Use After Free",
    "CWE-415": "Double Free",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-125": "Out-of-bounds Read",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-134": "Use of Externally-Controlled Format String",
    "CWE-78": "OS Command Injection",
    "CWE-401": "Memory Leak",
    "UNKNOWN": "Unknown Vulnerability",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _serialize(obj: Any) -> Any:
    """Custom serializer for dataclass fields that aren't directly JSON-safe."""
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, bytes):
        return obj.hex()
    if hasattr(obj, 'to_dict'):
        return obj.to_dict()
    return obj


def _deep_serialize(d: dict) -> dict:
    """Recursively serialize a dict produced by asdict()."""
    result = {}
    for k, v in d.items():
        if isinstance(v, dict):
            result[k] = _deep_serialize(v)
        elif isinstance(v, list):
            result[k] = [_deep_serialize(i) if isinstance(i, dict) else _serialize(i) for i in v]
        else:
            result[k] = _serialize(v)
    return result


# ---------------------------------------------------------------------------
# Stage 1: Crash Record (output of FuzzerManager + initial triage)
# ---------------------------------------------------------------------------

@dataclass
class CrashRecord:
    """A single deduplicated crash, as produced by the fuzzing + dedup stage."""
    target_name: str
    crash_input_path: str          # Path to the crash file
    crash_input_hex: str           # Hex dump of crash input
    asan_output: str               # Full ASan/UBSan stderr output
    stack_fingerprint: str         # MD5 of top-3 stack frames
    cwe: str = "UNKNOWN"
    cwe_name: str = "Unknown Vulnerability"
    severity: Severity = Severity.UNKNOWN
    exploitability_note: str = ""
    code_slice: str = ""           # Relevant code snippet (populated by triage)
    risky_functions: list[str] = field(default_factory=list)  # From Semgrep
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return _deep_serialize(asdict(self))

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


# ---------------------------------------------------------------------------
# Stage 2: LLM Analysis (output of root-cause analysis)
# ---------------------------------------------------------------------------

@dataclass
class RootCauseAnalysis:
    """Root cause explanation produced by LLM reasoning layer."""
    finding_id: str                # Same as crash record stack_fingerprint
    explanation: str               # 2-3 sentence plain-English root cause
    cwe_confirmed: str             # LLM-confirmed CWE tag
    cwe_name: str = ""
    confidence: int = 0            # 0–10
    llm_call_index: int = 0        # Which call number this was

    def to_dict(self) -> dict:
        return _deep_serialize(asdict(self))

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


# ---------------------------------------------------------------------------
# Stage 3: Patch Attempt
# ---------------------------------------------------------------------------

@dataclass
class PatchAttempt:
    """A single LLM-generated patch attempt."""
    finding_id: str
    attempt_number: int            # 1-indexed
    diff: str                      # Unified diff
    explanation: str               # LLM's explanation of what the patch does
    confidence: int = 0            # 0–10
    target_file: str = ""          # File being patched (relative to target dir)

    def to_dict(self) -> dict:
        return _deep_serialize(asdict(self))

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


# ---------------------------------------------------------------------------
# Stage 4: Validation Result
# ---------------------------------------------------------------------------

@dataclass
class ValidationStepResult:
    """Result of a single validation step."""
    step_name: str                 # e.g. "pre_patch_crash", "post_patch_crash", "regression"
    passed: bool
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    notes: str = ""

    def to_dict(self) -> dict:
        return _deep_serialize(asdict(self))


@dataclass
class ValidationResult:
    """Full validation result for a patch attempt."""
    patch: PatchAttempt
    pre_patch_crash: ValidationStepResult = field(
        default_factory=lambda: ValidationStepResult("pre_patch_crash", False))
    post_patch_crash: ValidationStepResult = field(
        default_factory=lambda: ValidationStepResult("post_patch_crash", False))
    regression: ValidationStepResult = field(
        default_factory=lambda: ValidationStepResult("regression", False))
    overall_pass: bool = False
    failure_reason: str = ""

    def failure_summary(self) -> str:
        """Return a human-readable failure summary for LLM feedback."""
        lines = []
        if not self.pre_patch_crash.passed:
            lines.append(f"Pre-patch crash check failed: {self.pre_patch_crash.notes}")
        if not self.post_patch_crash.passed:
            lines.append(f"Patch did NOT fix the crash: {self.post_patch_crash.stderr[-500:]}")
        if not self.regression.passed:
            lines.append(f"Regression suite failed after patch: {self.regression.stderr[-500:]}")
        return "\n".join(lines) if lines else "Unknown failure"

    def to_dict(self) -> dict:
        return _deep_serialize(asdict(self))

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


# ---------------------------------------------------------------------------
# Stage 5: Final Report Record
# ---------------------------------------------------------------------------

@dataclass
class FindingReport:
    """Complete proof-of-fix (or failure) report for one vulnerability."""
    crash: CrashRecord
    root_cause: Optional[RootCauseAnalysis]
    patch: Optional[PatchAttempt]
    validation: Optional[ValidationResult]
    status: PipelineStatus        # PASS or COULD_NOT_PATCH
    wall_clock_seconds: float = 0.0
    total_llm_calls: int = 0
    retry_count: int = 0
    peak_memory_mb: float = 0.0
    stage_timings: dict[str, float] = field(default_factory=dict)
    error_message: str = ""
    report_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def is_proven_fix(self) -> bool:
        return self.status == PipelineStatus.PASS

    def to_dict(self) -> dict:
        return _deep_serialize(asdict(self))

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


# ---------------------------------------------------------------------------
# Scan Result (wraps full pipeline output for API consumption)
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    """Complete result of a scan pipeline run on a target."""
    scan_id: str
    target: str
    target_name: str
    status: ScanStatus
    started_at: str = ""
    completed_at: str = ""
    duration_seconds: float = 0.0
    findings: list[FindingReport] = field(default_factory=list)
    static_analysis_count: int = 0
    crashes_found: int = 0
    error_message: str = ""
    error_code: str = ""
    current_stage: str = ""
    recent_logs: list[str] = field(default_factory=list)

    @property
    def findings_count(self) -> int:
        return len(self.findings)

    @property
    def proven_fixes(self) -> int:
        return sum(1 for f in self.findings if f.is_proven_fix())

    def to_dict(self) -> dict:
        return _deep_serialize(asdict(self))

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)
