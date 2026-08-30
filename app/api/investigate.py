"""
CyberForge Investigation API — General-Purpose Investigation Endpoint

Accepts a user query and target, runs the agent analysis pipeline,
and returns a structured security finding.
"""

import logging
import re
import uuid
from typing import Optional

try:
    from fastapi import APIRouter
except ImportError:  # pragma: no cover - keeps local tests working without FastAPI
    class APIRouter:
        def __init__(self, *args, **kwargs):
            self.routes = []

        def _decorator(self, *args, **kwargs):
            def wrapper(func):
                self.routes.append((args, kwargs, func))
                return func
            return wrapper

        post = get = _decorator

# Sourced from approvals so the whole app raises one HTTPException class,
# including its no-FastAPI fallback.
from app.api.approvals import HTTPException

try:
    from pydantic import BaseModel, Field
except ImportError:  # pragma: no cover - lightweight fallback for tests
    from app.api.approvals import BaseModel

    def Field(default=None, **kwargs):
        return default

from agent.agent import run_investigation, _validate_ip
from app.sdk_client import (
    claim_orphan_session,
    create_session,
    find_session_by_incident,
    update_session,
)


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["investigate"])

MAX_QUERY_LENGTH = 500
MAX_INCIDENT_ID_LENGTH = 64

# Incident identifiers are persisted, echoed back to clients, and matched
# against upstream approval metadata, so restrict them to a predictable set.
_INCIDENT_ID_PATTERN = re.compile(r"[A-Za-z0-9._:-]+")

_PERSISTENCE_FAILURE_DETAIL = "Investigation session could not be persisted."

# Known incident-to-target mappings for the demo dataset.
# When an incident_id is provided without an explicit target_ip,
# the investigation resolves the target automatically so that
# target-specific evidence collection runs against the correct IP.
_INCIDENT_TARGET_MAP: dict[str, str] = {
    "INC-1024": "10.0.0.25",
    "INC-DAY5-E2E": "10.0.0.25",
}


class InvestigationRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=MAX_QUERY_LENGTH)
    target_ip: Optional[str] = None
    # A stable, caller-supplied incident identifier. Sessions are only ever
    # reused when the caller names the incident explicitly — the free-form
    # query text is never used as a session key, because unrelated
    # investigations routinely share the same query or query prefix.
    incident_id: Optional[str] = Field(
        default=None, max_length=MAX_INCIDENT_ID_LENGTH
    )


def _normalize_incident_id(raw) -> Optional[str]:
    """Return a validated incident id, None if absent, or raise 422."""
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise HTTPException(
            status_code=422, detail="incident_id must be a string."
        )
    candidate = raw.strip()
    if not candidate:
        return None
    if (
        len(candidate) > MAX_INCIDENT_ID_LENGTH
        or not _INCIDENT_ID_PATTERN.fullmatch(candidate)
    ):
        raise HTTPException(
            status_code=422,
            detail=(
                "Invalid incident_id. Expected up to "
                f"{MAX_INCIDENT_ID_LENGTH} characters from "
                "A-Z, a-z, 0-9, '.', '_', ':' or '-'."
            ),
        )
    return candidate


@router.post("/investigate")
def investigate(body: InvestigationRequest):
    """
    Run a security investigation.

    Accepts a user query (e.g. 'Analyze this suspicious IP'), an optional
    target_ip, and an optional stable incident_id. Returns a structured
    finding with severity, evidence, tool results, and recommendation.
    """
    query = getattr(body, "query", None)
    query = query.strip() if isinstance(query, str) else ""
    if not query:
        raise HTTPException(
            status_code=422,
            detail="Investigation query cannot be empty.",
        )
    if len(query) > MAX_QUERY_LENGTH:
        raise HTTPException(
            status_code=422,
            detail=(
                "Investigation query exceeds "
                f"{MAX_QUERY_LENGTH} characters."
            ),
        )

    # Validate target_ip if provided
    target_ip = getattr(body, "target_ip", None)
    if target_ip is not None:
        if not isinstance(target_ip, str):
            raise HTTPException(
                status_code=422,
                detail="Invalid target_ip format. Expected IPv4 address.",
            )
        target_ip = target_ip.strip()
        if not target_ip:
            target_ip = None
        elif not _validate_ip(target_ip):
            raise HTTPException(
                status_code=422,
                detail="Invalid target_ip format. Expected IPv4 address.",
            )

    incident_id = _normalize_incident_id(getattr(body, "incident_id", None))

    # Resolve target from incident mapping when no explicit target is given.
    # The demo dataset contains target-specific evidence only for known IPs,
    # so an incident without a target would otherwise produce incomplete
    # investigations.  This does NOT fabricate evidence -- it merely tells
    # the investigation pipeline which IP to analyse.
    # Canonicalize to uppercase so that mixed-case spellings of the same
    # incident (e.g. "inc-day5-e2e") share the same session identity.
    if incident_id:
        canonical = incident_id.upper()
        if canonical in _INCIDENT_TARGET_MAP:
            incident_id = canonical
            if not target_ip:
                target_ip = _INCIDENT_TARGET_MAP[canonical]

    try:
        result = run_investigation(query, target_ip)
    except HTTPException:
        raise
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
    # The returned session_id gates the containment/approval lifecycle, so it
    # must identify exactly one investigation. A session is reused only when
    # the caller supplied a stable incident_id AND that session concerns the
    # same target; otherwise a fresh, uniquely-keyed session is created.
    resolved_target = result.get("target_ip") or "unknown"
    evidence_snapshot = result.get("tool_results", {})
    risk_score = result.get("risk_score")
    tools_used = result.get("tools_used", [])

    if incident_id:
        session_incident_id = incident_id
        # Try exact target_ip match first
        existing = find_session_by_incident(
            session_incident_id, target_ip=resolved_target
        )
    else:
        session_incident_id = f"INV-{uuid.uuid4().hex[:12]}"
        existing = None

    try:
        if existing:
            local_session_id = existing["id"]
            update_result = update_session(
                local_session_id,
                evidence_snapshot=evidence_snapshot,
                risk_score=risk_score,
                target_ip=resolved_target,
                query=query,
                investigation_status=result.get("status", "partial"),
                tools_used=tools_used,
                supersede_stale_approval=True,
            )
            if not update_result.get("success"):
                if update_result.get("approval_in_progress"):
                    raise HTTPException(
                        status_code=409,
                        detail="An approval operation is in progress; retry after it completes.",
                    )
                logger.warning(
                    "Failed to persist investigation into session %s: %s",
                    local_session_id,
                    update_result.get("error", "unknown"),
                )
                raise HTTPException(
                    status_code=503,
                    detail=_PERSISTENCE_FAILURE_DETAIL,
                )
        elif incident_id and resolved_target and resolved_target != "unknown":
            # No exact match — atomically claim an orphan session (no target_ip)
            # to prevent concurrent investigations from overwriting each other.
            orphan = claim_orphan_session(
                session_incident_id, resolved_target,
                evidence_snapshot=evidence_snapshot,
                risk_score=risk_score,
                query=query,
                investigation_status=result.get("status", "partial"),
                tools_used=tools_used,
            )
            if orphan:
                local_session_id = orphan["id"]
                # Supersede any stale approval on the claimed orphan
                update_result = update_session(
                    local_session_id,
                    evidence_snapshot=evidence_snapshot,
                    risk_score=risk_score,
                    query=query,
                    investigation_status=result.get("status", "partial"),
                    tools_used=tools_used,
                    supersede_stale_approval=True,
                )
                if not update_result.get("success"):
                    if update_result.get("approval_in_progress"):
                        raise HTTPException(
                            status_code=409,
                            detail="An approval operation is in progress; retry after it completes.",
                        )
                    logger.warning(
                        "Failed to persist investigation into session %s: %s",
                        local_session_id,
                        update_result.get("error", "unknown"),
                    )
                    raise HTTPException(
                        status_code=503,
                        detail=_PERSISTENCE_FAILURE_DETAIL,
                    )
            else:
                # Orphan was claimed by a concurrent request — create new
                local_session = create_session(
                    session_incident_id,
                    evidence_snapshot=evidence_snapshot,
                    risk_score=risk_score,
                    target_ip=resolved_target,
                    query=query,
                    investigation_status=result.get("status", "partial"),
                    tools_used=tools_used,
                )
                local_session_id = local_session["id"]
        else:
            local_session = create_session(
                session_incident_id,
                evidence_snapshot=evidence_snapshot,
                risk_score=risk_score,
                target_ip=resolved_target,
                query=query,
                investigation_status=result.get("status", "partial"),
                tools_used=tools_used,
            )
            local_session_id = local_session["id"]
    except HTTPException:
        raise
    except Exception:
        logger.exception(
            "Session persistence failed for incident %s", session_incident_id
        )
        raise HTTPException(
            status_code=503,
            detail=_PERSISTENCE_FAILURE_DETAIL,
        )

    result["session_id"] = local_session_id
    result["incident_id"] = session_incident_id

    return result
