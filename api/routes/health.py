"""
api/routes/health.py — Health check endpoint.
"""
from __future__ import annotations

import logging
import os
import subprocess

from fastapi import APIRouter

from api.schemas.common import HealthResponse

log = logging.getLogger(__name__)
router = APIRouter()


def _check_container(name: str) -> str:
    """Check if a Docker container is running."""
    try:
        r = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Status}}", name],
            capture_output=True, text=True, timeout=5
        )
        if r.returncode == 0:
            return r.stdout.strip()  # "running", "exited", etc.
        return "not_found"
    except FileNotFoundError:
        return "docker_not_installed"
    except Exception:
        return "unknown"


@router.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check():
    """
    System health check.

    Returns the status of Docker containers, LLM configuration,
    and overall system readiness.
    """
    validator_status = _check_container("kavach_validator")
    fuzzer_status = _check_container("kavach_fuzzer")

    llm_provider = os.getenv("KAVACH_LLM_PROVIDER", "google")
    api_key_configured = bool(os.getenv("GOOGLE_API_KEY") or os.getenv("OPENAI_API_KEY"))

    # Determine overall status
    if validator_status == "running" and fuzzer_status == "running":
        overall = "healthy"
    elif validator_status == "running" or fuzzer_status == "running":
        overall = "degraded"
    else:
        overall = "unhealthy"

    return HealthResponse(
        status=overall,
        version="1.0.0",
        docker_validator=validator_status,
        docker_fuzzer=fuzzer_status,
        llm_provider=llm_provider,
        api_key_configured=api_key_configured,
    )
