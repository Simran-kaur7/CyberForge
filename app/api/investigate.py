"""
CyberForge Investigation API — General-Purpose Investigation Endpoint

Accepts a user query and target, runs the agent analysis pipeline,
and returns a structured security finding.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional

from agent.agent import run_investigation, _validate_ip
from app.sdk_client import (
    create_session,
    find_session_by_incident,
    update_session,
)


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

    # --- Create or reuse a local session for this investigation ---
    # This gives the frontend a session_id needed for the approval lifecycle.
    incident_id = result.get("query", "INC-UNKNOWN")[:50]
    existing = find_session_by_incident(incident_id)
    if existing:
        local_session = existing
    else:
        local_session = create_session(
            incident_id,
            evidence_snapshot=result.get("tool_results", {}),
        )

    # Persist investigation evidence into the session
    update_result = update_session(
        local_session["id"],
        evidence_snapshot=result.get("tool_results", {}),
        risk_score=result.get("risk_score"),
    )
    if not update_result.get("success"):
        # Log but do not fail the investigation — the result is still valid
        import logging
        logging.getLogger(__name__).warning(
            "Failed to update session %s: %s",
            local_session["id"],
            update_result.get("error", "unknown"),
        )

    result["session_id"] = local_session["id"]
    result["incident_id"] = incident_id

    return result
