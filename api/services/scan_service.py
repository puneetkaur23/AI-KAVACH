"""
api/services/scan_service.py — Scan lifecycle management for AI Kavach API.

Wraps the existing KavachRunner to provide async scan execution
without duplicating any security pipeline logic.
"""
from __future__ import annotations

import asyncio
import logging
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from threading import Lock
from typing import Optional

# Ensure project root is on path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from models import ScanResult, ScanStatus, FindingReport

log = logging.getLogger(__name__)


class ScanService:
    """
    Manages scan lifecycle: create → queue → run → complete/fail.

    Uses asyncio.to_thread() for background execution of the blocking
    KavachRunner pipeline. Stores results in-memory (dict).
    """

    def __init__(self):
        self._scans: dict[str, ScanResult] = {}
        self._scan_tasks: dict[str, asyncio.Task] = {}
        self._report_paths: dict[str, dict] = {}  # scan_id -> {html_path, md_path}
        self._lock = Lock()

    def list_scans(self) -> list[ScanResult]:
        """Return all scans, most recent first."""
        with self._lock:
            return sorted(
                self._scans.values(),
                key=lambda s: s.started_at or "",
                reverse=True
            )

    def get_scan(self, scan_id: str) -> Optional[ScanResult]:
        """Get a scan by ID."""
        with self._lock:
            return self._scans.get(scan_id)

    def get_report_paths(self, scan_id: str) -> dict:
        """Get generated report file paths for a scan."""
        with self._lock:
            return self._report_paths.get(scan_id, {})

    async def create_scan(
        self,
        target: str,
        timeout: int = 60,
        llm_provider: str = "google",
        max_retries: int = 3,
        skip_fuzzing: bool = False,
    ) -> ScanResult:
        """
        Create a new scan and start it asynchronously.

        Returns immediately with a QUEUED scan record.
        The actual pipeline runs in a background thread.
        """
        scan_id = str(uuid.uuid4())
        target_name = os.path.basename(target.rstrip("/\\"))

        scan = ScanResult(
            scan_id=scan_id,
            target=target,
            target_name=target_name,
            status=ScanStatus.QUEUED,
            started_at=datetime.now(timezone.utc).isoformat(),
        )

        with self._lock:
            self._scans[scan_id] = scan

        # Start background execution
        task = asyncio.create_task(
            self._run_scan_async(scan_id, target, timeout, llm_provider, max_retries, skip_fuzzing)
        )
        self._scan_tasks[scan_id] = task

        return scan

    async def cancel_scan(self, scan_id: str) -> bool:
        """Cancel a running scan."""
        task = self._scan_tasks.get(scan_id)
        if task and not task.done():
            task.cancel()
            with self._lock:
                scan = self._scans.get(scan_id)
                if scan:
                    scan.status = ScanStatus.CANCELLED
                    scan.completed_at = datetime.now(timezone.utc).isoformat()
            return True
        return False

    # ------------------------------------------------------------------
    # Private: background execution
    # ------------------------------------------------------------------

    async def _run_scan_async(
        self,
        scan_id: str,
        target: str,
        timeout: int,
        llm_provider: str,
        max_retries: int,
        skip_fuzzing: bool,
    ) -> None:
        """Run the scan pipeline in a background thread."""
        # Update status to RUNNING
        with self._lock:
            scan = self._scans[scan_id]
            scan.status = ScanStatus.RUNNING

        try:
            # Run the blocking pipeline in a thread
            result = await asyncio.to_thread(
                self._execute_pipeline,
                scan_id, target, timeout, llm_provider, max_retries, skip_fuzzing
            )

            with self._lock:
                self._scans[scan_id] = result

        except asyncio.CancelledError:
            log.info("[scan_service] Scan %s cancelled", scan_id)
            with self._lock:
                scan = self._scans[scan_id]
                scan.status = ScanStatus.CANCELLED
                scan.completed_at = datetime.now(timezone.utc).isoformat()

        except Exception as e:
            log.exception("[scan_service] Scan %s failed with error", scan_id)
            with self._lock:
                scan = self._scans[scan_id]
                scan.status = ScanStatus.FAILED
                scan.error_message = str(e)
                scan.error_code = "PIPELINE_ERROR"
                scan.completed_at = datetime.now(timezone.utc).isoformat()

    def _execute_pipeline(
        self,
        scan_id: str,
        target: str,
        timeout: int,
        llm_provider: str,
        max_retries: int,
        skip_fuzzing: bool,
    ) -> ScanResult:
        """
        Execute the KavachRunner pipeline synchronously.

        This runs in a separate thread via asyncio.to_thread().
        """
        import argparse

        # Build args namespace that KavachRunner expects
        args = argparse.Namespace(
            target=target,
            timeout=timeout,
            llm=llm_provider,
            max_retries=max_retries,
            output="output/reports",
            skip_fuzzing=skip_fuzzing,
            no_docker=False,
            verbose=False,
            dry_run=False,
            all_targets=False,
        )

        start_time = time.time()
        target_name = os.path.basename(target.rstrip("/\\"))

        # Validate target exists
        target_path = os.path.abspath(target)
        if not os.path.isdir(target_path):
            return ScanResult(
                scan_id=scan_id,
                target=target,
                target_name=target_name,
                status=ScanStatus.FAILED,
                started_at=datetime.now(timezone.utc).isoformat(),
                completed_at=datetime.now(timezone.utc).isoformat(),
                error_message=f"Target directory not found: {target}",
                error_code="TARGET_NOT_FOUND",
            )

        try:
            from kavach import KavachRunner
            runner = KavachRunner(args)
            reports = runner.run_target(target_path)

            elapsed = time.time() - start_time

            scan_result = ScanResult(
                scan_id=scan_id,
                target=target,
                target_name=target_name,
                status=ScanStatus.COMPLETED,
                started_at=self._scans[scan_id].started_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                duration_seconds=round(elapsed, 2),
                findings=reports if reports else [],
                crashes_found=len(reports) if reports else 0,
            )

            # Store report paths if generated
            if reports:
                for report in reports:
                    report_paths = {}
                    # Find the most recent report files matching this report
                    reports_dir = os.path.join("output", "reports")
                    if os.path.isdir(reports_dir):
                        for fname in sorted(os.listdir(reports_dir), reverse=True):
                            if target_name in fname:
                                if fname.endswith(".html") and "html_path" not in report_paths:
                                    report_paths["html_path"] = os.path.join(reports_dir, fname)
                                elif fname.endswith(".md") and "md_path" not in report_paths:
                                    report_paths["md_path"] = os.path.join(reports_dir, fname)
                    with self._lock:
                        self._report_paths[scan_id] = report_paths

            return scan_result

        except Exception as e:
            elapsed = time.time() - start_time
            log.exception("[scan_service] Pipeline execution failed for %s", target)
            return ScanResult(
                scan_id=scan_id,
                target=target,
                target_name=target_name,
                status=ScanStatus.FAILED,
                started_at=self._scans[scan_id].started_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                duration_seconds=round(elapsed, 2),
                error_message=str(e),
                error_code="PIPELINE_ERROR",
            )
