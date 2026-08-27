"""
CyberForge Investigation API — General-Purpose Investigation Endpoint

Accepts a user query and target, runs the agent analysis pipeline,
and returns a structured security finding.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional

from agent.agent import run_investigation, _validate_ip


router = APIRouter(prefix="/api", tags=["investigate"])

MAX_QUERY_LENGTH = 500


class InvestigationRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=MAX_QUERY_LENGTH)
    target_ip: Optional[str] = None


@router.post("/investigate")
def investigate(body: InvestigationRequest):
    """
    Run a security investigation.

    Accepts a user query (e.g. 'Analyze this suspicious IP')
    and optional target_ip. Returns a structured finding with
    severity, evidence, tool results, and recommendation.
    """
    query = body.query.strip()
    if not query:
        raise HTTPException(
            status_code=422,
            detail="Investigation query cannot be empty.",
        )

    # Validate target_ip if provided
    target_ip = body.target_ip
    if target_ip is not None:
        target_ip = target_ip.strip()
        if not target_ip:
            target_ip = None
        elif not _validate_ip(target_ip):
            raise HTTPException(
                status_code=422,
                detail="Invalid target_ip format. Expected IPv4 address.",
            )

    try:
        result = run_investigation(query, target_ip)
    except Exception:
        # Do not leak exception types or internal details
        raise HTTPException(
            status_code=500,
            detail="Investigation failed due to an internal error.",
        )

    # Partial results are returned to the frontend — they carry
    # evidence_complete=false and a cautious recommendation.
    # Only hard-fail (success=False with status "error") returns 502.
    if not result.get("success") and result.get("status") == "error":
        raise HTTPException(
            status_code=502,
            detail="Investigation produced no results.",
        )

    return result
