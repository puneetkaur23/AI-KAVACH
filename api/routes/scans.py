"""
api/routes/scans.py — Scan CRUD endpoints.
"""
from __future__ import annotations

import logging
import os

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse

from api.schemas.scan import (
    ScanRequest, ScanSummaryResponse, ScanStatusResponse, ScanListResponse,
)
from api.schemas.finding import FindingResponse, FindingListResponse, CWEInfo, RootCauseInfo, PatchInfo, ValidationInfo, ValidationStepInfo, EvidenceItem
from api.schemas.report import ReportResponse
from api.services.scan_service import ScanService

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["Scans"])

# Singleton scan service — instantiated in main.py and injected via app.state
_scan_service: ScanService | None = None


def set_scan_service(service: ScanService) -> None:
    """Inject the scan service singleton (called from main.py)."""
    global _scan_service
    _scan_service = service


def _get_service() -> ScanService:
    if _scan_service is None:
        raise HTTPException(status_code=503, detail="Scan service not initialized")
    return _scan_service


# Resolve project root for target validation
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))


def _validate_target_exists(target: str) -> None:
    """Ensure the target directory actually exists on disk."""
    target_abs = os.path.abspath(os.path.join(_PROJECT_ROOT, target))
    targets_root = os.path.abspath(os.path.join(_PROJECT_ROOT, "targets"))

    # Must resolve inside targets/ (prevents symlink escapes)
    if not target_abs.startswith(targets_root):
        raise HTTPException(
            status_code=400,
            detail=f"Target must be within the 'targets/' directory"
        )

    if not os.path.isdir(target_abs):
        raise HTTPException(
            status_code=404,
            detail=f"Target directory not found: {target}"
        )

    # Must contain at least one source file
    source_files = [f for f in os.listdir(target_abs) if f.endswith(('.c', '.cpp'))]
    if not source_files:
        raise HTTPException(
            status_code=400,
            detail=f"Target directory has no C/C++ source files: {target}"
        )


# ------------------------------------------------------------------
# Endpoints
# ------------------------------------------------------------------

@router.post("/scans", response_model=ScanSummaryResponse, status_code=201)
async def create_scan(req: ScanRequest):
    """
    Start a new asynchronous security scan.

    The scan runs in the background. Poll `GET /api/v1/scans/{scan_id}`
    for status updates.
    """
    service = _get_service()

    # Validate target exists
    _validate_target_exists(req.target)

    scan = await service.create_scan(
        target=req.target,
        timeout=req.timeout,
        llm_provider=req.llm_provider,
        max_retries=req.max_retries,
        skip_fuzzing=req.skip_fuzzing,
    )

    return ScanSummaryResponse(
        scan_id=scan.scan_id,
        status=scan.status.value,
        target=scan.target,
        message="Scan queued. Poll GET /api/v1/scans/{scan_id} for status.",
    )


@router.get("/scans", response_model=ScanListResponse)
async def list_scans():
    """List all scans with current status."""
    service = _get_service()
    scans = service.list_scans()
    return ScanListResponse(
        scans=[_scan_to_status(s) for s in scans],
        count=len(scans),
    )


@router.get("/scans/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str):
    """Get detailed status of a specific scan."""
    service = _get_service()
    scan = service.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")
    return _scan_to_status(scan)


@router.post("/scans/{scan_id}/cancel")
async def cancel_scan(scan_id: str):
    """Cancel a running scan."""
    service = _get_service()
    scan = service.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")

    cancelled = await service.cancel_scan(scan_id)
    if not cancelled:
        raise HTTPException(status_code=409, detail="Scan is not running or already finished")

    return {"message": "Scan cancelled", "scan_id": scan_id}


@router.get("/scans/{scan_id}/findings", response_model=FindingListResponse)
async def get_scan_findings(scan_id: str):
    """Get vulnerability findings for a completed scan."""
    service = _get_service()
    scan = service.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")

    if scan.status.value in ("QUEUED", "RUNNING"):
        raise HTTPException(status_code=409, detail="Scan is still running. Poll status first.")

    findings = [_report_to_finding(r, scan_id) for r in scan.findings]
    return FindingListResponse(
        scan_id=scan_id,
        findings=findings,
        count=len(findings),
    )


@router.get("/scans/{scan_id}/report", response_model=ReportResponse)
async def get_scan_report(scan_id: str):
    """Get the structured JSON report for a completed scan."""
    service = _get_service()
    scan = service.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")

    if scan.status.value in ("QUEUED", "RUNNING"):
        raise HTTPException(status_code=409, detail="Scan is still running.")

    if not scan.findings:
        return ReportResponse(
            scan_id=scan_id,
            report_id="",
            target=scan.target,
            status=scan.status.value,
            report_data={},
        )

    # Use the first finding's report (primary vulnerability)
    report = scan.findings[0]
    paths = service.get_report_paths(scan_id)

    return ReportResponse(
        scan_id=scan_id,
        report_id=report.report_id,
        target=scan.target,
        status=report.status.value if hasattr(report.status, 'value') else str(report.status),
        report_data=report.to_dict(),
        html_path=paths.get("html_path", ""),
        markdown_path=paths.get("md_path", ""),
    )


@router.get("/scans/{scan_id}/report/html", response_class=HTMLResponse)
async def get_scan_report_html(scan_id: str):
    """View the HTML report in browser or download."""
    service = _get_service()
    scan = service.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")

    paths = service.get_report_paths(scan_id)
    html_path = paths.get("html_path", "")
    if html_path and os.path.isfile(html_path):
        with open(html_path, "r", encoding="utf-8", errors="replace") as f:
            return HTMLResponse(content=f.read())

    # Fallback to search output/reports for matching scan or target
    reports_dir = os.path.join(_PROJECT_ROOT, "output", "reports")
    if os.path.isdir(reports_dir):
        for fname in sorted(os.listdir(reports_dir), reverse=True):
            if fname.endswith(".html") and scan.target_name in fname:
                full_p = os.path.join(reports_dir, fname)
                with open(full_p, "r", encoding="utf-8", errors="replace") as f:
                    return HTMLResponse(content=f.read())

    raise HTTPException(status_code=404, detail="HTML report not yet generated or found")


@router.get("/scans/{scan_id}/report/markdown")
async def download_scan_report_markdown(scan_id: str):
    """Download the Markdown report."""
    service = _get_service()
    scan = service.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")

    paths = service.get_report_paths(scan_id)
    md_path = paths.get("md_path", "")
    if md_path and os.path.isfile(md_path):
        return FileResponse(md_path, media_type="text/markdown", filename=os.path.basename(md_path))

    reports_dir = os.path.join(_PROJECT_ROOT, "output", "reports")
    if os.path.isdir(reports_dir):
        for fname in sorted(os.listdir(reports_dir), reverse=True):
            if fname.endswith(".md") and scan.target_name in fname:
                full_p = os.path.join(reports_dir, fname)
                return FileResponse(full_p, media_type="text/markdown", filename=fname)

    raise HTTPException(status_code=404, detail="Markdown report not found")


@router.get("/scans/{scan_id}/report/json")
async def download_scan_report_json(scan_id: str):
    """Download the structured JSON report."""
    service = _get_service()
    scan = service.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")

    return JSONResponse(
        content=scan.to_dict(),
        headers={"Content-Disposition": f'attachment; filename="kavach_report_{scan_id[:8]}.json"'}
    )


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _scan_to_status(scan) -> ScanStatusResponse:
    """Convert a ScanResult to a ScanStatusResponse."""
    return ScanStatusResponse(
        scan_id=scan.scan_id,
        target=scan.target,
        target_name=scan.target_name,
        status=scan.status.value if hasattr(scan.status, 'value') else str(scan.status),
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        duration_seconds=scan.duration_seconds,
        findings_count=scan.findings_count,
        proven_fixes=scan.proven_fixes,
        crashes_found=scan.crashes_found,
        static_analysis_count=scan.static_analysis_count,
        error_message=scan.error_message,
        error_code=scan.error_code,
        current_stage=getattr(scan, "current_stage", ""),
        recent_logs=getattr(scan, "recent_logs", []),
    )


def _report_to_finding(report, scan_id: str) -> FindingResponse:
    """Convert a FindingReport to a FindingResponse."""
    # Build evidence items
    evidence = []
    if report.crash.asan_output:
        evidence.append(EvidenceItem(type="asan_output", content=report.crash.asan_output[:2000]))
    if report.crash.code_slice:
        evidence.append(EvidenceItem(type="code_slice", content=report.crash.code_slice))
    if report.crash.crash_input_hex:
        evidence.append(EvidenceItem(type="crash_input", content=report.crash.crash_input_hex[:500]))

    # Root cause info
    root_cause = None
    if report.root_cause:
        root_cause = RootCauseInfo(
            explanation=report.root_cause.explanation,
            cwe_confirmed=report.root_cause.cwe_confirmed,
            cwe_name=report.root_cause.cwe_name,
            confidence=report.root_cause.confidence,
        )

    # Patch info
    patch_info = None
    patch_status = "none"
    if report.patch:
        patch_info = PatchInfo(
            attempt_number=report.patch.attempt_number,
            diff=report.patch.diff,
            explanation=report.patch.explanation,
            confidence=report.patch.confidence,
            target_file=report.patch.target_file,
        )
        patch_status = "generated"

    # Validation info
    validation = None
    if report.validation:
        steps = []
        for step_attr in ['pre_patch_crash', 'post_patch_crash', 'regression']:
            step = getattr(report.validation, step_attr, None)
            if step:
                steps.append(ValidationStepInfo(
                    step_name=step.step_name,
                    passed=step.passed,
                    notes=step.notes,
                ))

        validation = ValidationInfo(
            overall_pass=report.validation.overall_pass,
            failure_reason=report.validation.failure_reason,
            steps=steps,
        )
        if report.validation.overall_pass:
            patch_status = "validated"
        else:
            patch_status = "failed"

    severity_val = report.crash.severity
    if hasattr(severity_val, 'value'):
        severity_val = severity_val.value

    return FindingResponse(
        id=report.report_id,
        scan_id=scan_id,
        target=report.crash.target_name,
        severity=severity_val,
        cwe=CWEInfo(id=report.crash.cwe, name=report.crash.cwe_name),
        confidence=report.root_cause.confidence / 10.0 if report.root_cause else 0.0,
        description=report.root_cause.explanation if report.root_cause else "",
        root_cause=root_cause,
        evidence=evidence,
        patch=patch_info,
        validation=validation,
        patch_status=patch_status,
        exploitability_note=report.crash.exploitability_note,
        wall_clock_seconds=report.wall_clock_seconds,
        total_llm_calls=report.total_llm_calls,
        created_at=report.created_at,
    )
