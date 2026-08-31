"""
api/schemas/finding.py — Pydantic models for vulnerability finding responses.
"""
from __future__ import annotations

from pydantic import BaseModel, Field
from typing import Optional


class CWEInfo(BaseModel):
    """CWE classification details."""
    id: str = Field(..., description="CWE identifier (e.g. 'CWE-121')")
    name: str = Field("", description="CWE human-readable name")


class EvidenceItem(BaseModel):
    """A single piece of evidence supporting the finding."""
    type: str = Field(..., description="Evidence type: asan_output|code_slice|crash_input|static_analysis")
    content: str = Field(..., description="Evidence content")


class RootCauseInfo(BaseModel):
    """Root cause analysis details."""
    explanation: str = Field("", description="Plain-English root cause explanation")
    cwe_confirmed: str = Field("", description="LLM-confirmed CWE tag")
    cwe_name: str = Field("", description="LLM-confirmed CWE name")
    confidence: int = Field(0, description="Confidence score 0–10")


class PatchInfo(BaseModel):
    """Patch generation details."""
    attempt_number: int = Field(0, description="Which attempt produced this patch")
    diff: str = Field("", description="Unified diff")
    explanation: str = Field("", description="What the patch does")
    confidence: int = Field(0, description="Patch confidence 0–10")
    target_file: str = Field("", description="File being patched")


class ValidationStepInfo(BaseModel):
    """Single validation step result."""
    step_name: str
    passed: bool
    notes: str = ""


class ValidationInfo(BaseModel):
    """Patch validation results."""
    overall_pass: bool = False
    failure_reason: str = ""
    steps: list[ValidationStepInfo] = Field(default_factory=list)


class FindingResponse(BaseModel):
    """Complete vulnerability finding for API consumers."""
    id: str = Field(..., description="Unique finding identifier (report_id)")
    scan_id: str = Field("", description="Parent scan ID")
    target: str = Field(..., description="Target name")
    severity: str = Field("UNKNOWN", description="Severity: CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN")
    cwe: CWEInfo
    confidence: float = Field(0.0, description="Overall confidence 0.0–1.0")
    description: str = Field("", description="Root cause description")
    root_cause: Optional[RootCauseInfo] = None
    evidence: list[EvidenceItem] = Field(default_factory=list)
    patch: Optional[PatchInfo] = None
    validation: Optional[ValidationInfo] = None
    patch_status: str = Field("none", description="none|generated|validated|failed")
    exploitability_note: str = Field("", description="Exploitability assessment")
    wall_clock_seconds: float = 0.0
    total_llm_calls: int = 0
    created_at: str = ""


class FindingListResponse(BaseModel):
    """Response listing findings for a scan."""
    scan_id: str
    findings: list[FindingResponse]
    count: int
