"""
api/routes/findings.py — Individual finding lookup endpoint.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException

from api.services.scan_service import ScanService
from api.routes.scans import _get_service, _report_to_finding
from api.schemas.finding import FindingResponse

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["Findings"])


@router.get("/findings/{finding_id}", response_model=FindingResponse)
async def get_finding(finding_id: str):
    """
    Get a specific vulnerability finding by its report ID.

    Searches across all scans for the matching finding.
    """
    service = _get_service()

    # Search through all scans for this finding ID
    for scan in service.list_scans():
        for report in scan.findings:
            if report.report_id == finding_id:
                return _report_to_finding(report, scan.scan_id)

    raise HTTPException(status_code=404, detail=f"Finding not found: {finding_id}")
