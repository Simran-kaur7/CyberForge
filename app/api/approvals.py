"""
CyberForge Approval API — TrueForge native approval gate.

Forwards approve/reject to TrueForge's HTTP API.
Requires CYBERFORGE_API_KEY for containment decisions.
"""

import os
import json
import urllib.request
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from typing import Optional


router = APIRouter(prefix="/api/approvals", tags=["approvals"])

TRUEFORGE_URL = os.environ.get("TRUEFORGE_URL", "http://localhost:8790")
EXPECTED_API_KEY = os.environ.get("CYBERFORGE_API_KEY", "")


class ApprovalRequest(BaseModel):
    session_id: str
    action_type: str
    action_detail: dict


class DecisionRequest(BaseModel):
    session_id: str
    action_id: str
    # Bug #1: removed decided_by from body — derived from auth context


def _require_api_key(authorization: Optional[str] = Header(None)) -> str:
    """Validate API key. Returns the analyst identity."""
    if not EXPECTED_API_KEY:
        # Lab mode: no key configured, use default identity
        return "analyst"
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    token = authorization.replace("Bearer ", "").strip()
    if token != EXPECTED_API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return "analyst"


def _tf_post(path: str, body: dict) -> dict:
    """POST to TrueForge HTTP API."""
    url = f"{TRUEFORGE_URL}{path}"
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"TrueForge returned HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Cannot reach TrueForge") from exc


def _tf_get(path: str) -> dict:
    """GET from TrueForge HTTP API."""
    url = f"{TRUEFORGE_URL}{path}"
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"TrueForge returned HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Cannot reach TrueForge") from exc


@router.post("/request")
def request_containment_approval(
    body: ApprovalRequest,
    authorization: Optional[str] = Header(None),
):
    """Request approval. Requires authenticated analyst."""
    analyst = _require_api_key(authorization)
    return {
        "success": True,
        "status": "pending",
        "action_type": body.action_type,
        "session_id": body.session_id,
        "analyst": analyst,
    }


@router.post("/approve")
def approve_containment(
    body: DecisionRequest,
    authorization: Optional[str] = Header(None),
):
    """Approve via TrueForge. Requires authenticated analyst."""
    analyst = _require_api_key(authorization)
    try:
        result = _tf_post(
            f"/api/v1/sessions/{body.session_id}/turns",
            {
                "input": [{
                    "type": "tool_approval",
                    "tool_call_id": body.action_id,
                    "status": "allow",
                }]
            },
        )
        return {
            "success": True, "action_id": body.action_id,
            "status": "approved", "analyst": analyst,
        }
    except RuntimeError:
        raise HTTPException(status_code=502, detail="TrueForge unavailable")


@router.post("/reject")
def reject_containment(
    body: DecisionRequest,
    authorization: Optional[str] = Header(None),
):
    """Reject via TrueForge. Requires authenticated analyst."""
    analyst = _require_api_key(authorization)
    try:
        result = _tf_post(
            f"/api/v1/sessions/{body.session_id}/turns",
            {
                "input": [{
                    "type": "tool_approval",
                    "tool_call_id": body.action_id,
                    "status": "deny",
                    "reason": f"Rejected by {analyst}",
                }]
            },
        )
        return {
            "success": True, "action_id": body.action_id,
            "status": "rejected", "analyst": analyst,
        }
    except RuntimeError:
        raise HTTPException(status_code=502, detail="TrueForge unavailable")


@router.get("/pending")
def get_pending_approvals():
    """List pending approvals from TrueForge sessions."""
    try:
        sessions = _tf_get("/api/v1/sessions")
        session_list = sessions.get("data", sessions) if isinstance(sessions, dict) else sessions
        pending = []
        if isinstance(session_list, list):
            for s in session_list:
                state = s.get("state") or {}
                actions = state.get("required_actions") or []
                if actions:
                    pending.append({
                        "session_id": s.get("id"),
                        "title": s.get("title"),
                        "required_actions": actions,
                    })
        return {"count": len(pending), "approvals": pending}
    except RuntimeError:
        # Bug #2: don't crash — return empty with warning
        return {"count": 0, "approvals": [], "warning": "TrueForge unavailable"}
