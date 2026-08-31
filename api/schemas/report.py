"""
api/schemas/report.py — Pydantic models for structured report responses.
"""
from __future__ import annotations

from pydantic import BaseModel, Field
from typing import Optional, Any


class ReportResponse(BaseModel):
    """Structured report for API consumers — wraps the full FindingReport as JSON."""
    scan_id: str
    report_id: str
    target: str
    status: str = Field(..., description="Pipeline status: PASS|COULD_NOT_PATCH|ERROR")
    report_data: dict[str, Any] = Field(
        default_factory=dict,
        description="Full structured report (FindingReport.to_dict())"
    )
    html_path: str = Field("", description="Path to generated HTML report file")
    markdown_path: str = Field("", description="Path to generated Markdown report file")
