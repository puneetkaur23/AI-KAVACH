"""
api/schemas/scan.py — Pydantic models for scan requests and responses.
"""
from __future__ import annotations

from pydantic import BaseModel, Field, field_validator
from typing import Optional
import os


class ScanRequest(BaseModel):
    """Request body for creating a new scan."""
    target: str = Field(..., description="Path to target directory (e.g. 'targets/vuln_bof')")
    timeout: int = Field(60, ge=10, le=600, description="Fuzzing timeout in seconds (10–600)")
    llm_provider: str = Field("google", description="LLM provider: google|openai|ollama")
    max_retries: int = Field(3, ge=0, le=10, description="Max patch retry attempts")
    skip_fuzzing: bool = Field(False, description="Skip fuzzing, use existing crashes")

    @field_validator("target")
    @classmethod
    def validate_target_path(cls, v: str) -> str:
        """Prevent path traversal and ensure target is within allowed directories."""
        # Normalize separators
        v = v.replace("\\", "/").strip("/")
        # Block path traversal
        if ".." in v:
            raise ValueError("Path traversal not allowed")
        # Must start with targets/
        if not v.startswith("targets/"):
            raise ValueError("Target must be within the 'targets/' directory")
        return v

    @field_validator("llm_provider")
    @classmethod
    def validate_llm_provider(cls, v: str) -> str:
        allowed = {"google", "openai", "ollama"}
        if v not in allowed:
            raise ValueError(f"LLM provider must be one of: {allowed}")
        return v


class ScanSummaryResponse(BaseModel):
    """Minimal scan info returned on creation."""
    scan_id: str
    status: str
    target: str
    message: str = ""


class ScanStatusResponse(BaseModel):
    """Detailed scan status."""
    scan_id: str
    target: str
    target_name: str
    status: str
    started_at: str = ""
    completed_at: str = ""
    duration_seconds: float = 0.0
    findings_count: int = 0
    proven_fixes: int = 0
    crashes_found: int = 0
    static_analysis_count: int = 0
    error_message: str = ""
    error_code: str = ""


class ScanListResponse(BaseModel):
    """Response listing all scans."""
    scans: list[ScanStatusResponse]
    count: int
