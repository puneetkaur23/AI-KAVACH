"""
api/routes/targets.py — Target listing endpoint.
"""
from __future__ import annotations

import logging
import os

from fastapi import APIRouter

from api.schemas.common import TargetInfo, TargetListResponse

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["Targets"])

# Resolve the targets/ directory relative to project root
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
_TARGETS_DIR = os.path.join(_PROJECT_ROOT, "targets")


@router.get("/targets", response_model=TargetListResponse)
async def list_targets():
    """
    List all available scan targets.

    Scans the `targets/` directory and returns metadata about each target
    including source files, seed availability, and test coverage.
    """
    targets = []

    if not os.path.isdir(_TARGETS_DIR):
        return TargetListResponse(targets=[], count=0)

    for entry in sorted(os.listdir(_TARGETS_DIR)):
        target_path = os.path.join(_TARGETS_DIR, entry)
        if not os.path.isdir(target_path):
            continue

        # Gather metadata
        source_files = [
            f for f in os.listdir(target_path)
            if f.endswith(('.c', '.cpp', '.h'))
        ]

        seeds_dir = os.path.join(target_path, "seeds")
        has_seeds = os.path.isdir(seeds_dir) and bool(os.listdir(seeds_dir))

        tests_dir = os.path.join(target_path, "tests")
        has_tests = os.path.isdir(tests_dir) and bool(os.listdir(tests_dir))

        has_makefile = os.path.isfile(os.path.join(target_path, "Makefile"))

        targets.append(TargetInfo(
            name=entry,
            path=f"targets/{entry}",
            source_files=source_files,
            has_seeds=has_seeds,
            has_tests=has_tests,
            has_makefile=has_makefile,
        ))

    return TargetListResponse(targets=targets, count=len(targets))
