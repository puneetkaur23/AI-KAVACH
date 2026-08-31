"""
api/schemas/common.py — Shared Pydantic schemas for AI Kavach API.
"""
from __future__ import annotations

from pydantic import BaseModel, Field
from typing import Optional, Any


class ErrorDetail(BaseModel):
    """Structured error response."""
    code: str = Field(..., description="Machine-readable error code")
    message: str = Field(..., description="Human-readable error message")
    details: dict[str, Any] = Field(default_factory=dict, description="Additional error context")


class ErrorResponse(BaseModel):
    """Standard error envelope."""
    error: ErrorDetail


class HealthResponse(BaseModel):
    """System health check response."""
    status: str = Field(..., description="Overall system status: healthy | degraded | unhealthy")
    version: str = Field("1.0.0", description="API version")
    docker_validator: str = Field(..., description="Status of kavach_validator container")
    docker_fuzzer: str = Field(..., description="Status of kavach_fuzzer container")
    llm_provider: str = Field("", description="Configured LLM provider")
    api_key_configured: bool = Field(False, description="Whether the LLM API key is set")


class TargetInfo(BaseModel):
    """Information about an available scan target."""
    name: str = Field(..., description="Target directory name")
    path: str = Field(..., description="Relative path to target")
    source_files: list[str] = Field(default_factory=list, description="C/C++ source files")
    has_seeds: bool = Field(False, description="Whether seed files exist")
    has_tests: bool = Field(False, description="Whether unit tests exist")
    has_makefile: bool = Field(False, description="Whether a Makefile exists")


class TargetListResponse(BaseModel):
    """Response for target listing."""
    targets: list[TargetInfo]
    count: int
