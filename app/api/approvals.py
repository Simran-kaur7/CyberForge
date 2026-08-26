"""
CyberForge Approval API — TrueForge native approval gate.

Approvals are native TrueForge turn events. This API:
1. Starts an agent turn that triggers the block_ip approval gate
2. Forwards allow/deny decisions to resume the paused tool call
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
AGENT_NAME = os.environ.get("CYBERFORGE_AGENT_NAME", "cyberforge-investigator")


class ApprovalRequest(BaseModel):
    session_id: str
    message: str = "Investigate and contain the incident"
    thread_id: Optional[str] = None


class DecisionRequest(BaseModel):
    session_id: str
    action_id: str
    thread_id: Optional[str] = None
    reason: Optional[str] = None


def _require_api_key(authorization: Optional[str] = Header(None)) -> str:
    if not EXPECTED_API_KEY:
        return "analyst"
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    token = authorization.replace("Bearer ", "").strip()
    if token != EXPECTED_API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return "analyst"


def _tf_post(path: str, body: dict) -> dict:
    url = f"{TRUEFORGE_URL}{path}"
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode()
            if not raw.strip():
                return {"status": "ok"}
            return json.loads(raw)
    except json.JSONDecodeError:
        raise RuntimeError("TrueForge returned invalid JSON")
    except urllib.error.HTTPError:
        raise RuntimeError("TrueForge returned an error")
    except urllib.error.URLError:
        raise RuntimeError("Cannot reach TrueForge")


def _tf_get(path: str) -> dict:
    url = f"{TRUEFORGE_URL}{path}"
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode()
            if not raw.strip():
                return {}
            return json.loads(raw)
    except json.JSONDecodeError:
        raise RuntimeError("TrueForge returned invalid JSON")
    except urllib.error.HTTPError:
        raise RuntimeError("TrueForge returned an error")
    except urllib.error.URLError:
        raise RuntimeError("Cannot reach TrueForge")


@router.post("/request")
def request_containment_approval(
    body: ApprovalRequest,
    authorization: Optional[str] = Header(None),
):
    """
    Start an agent turn that will trigger the block_ip approval gate.
    TrueForge pauses on block_ip (require_approval_for_tools) and
    emits a tool.approval_required event with the tool_call_id.
    """
    analyst = _require_api_key(authorization)
    try:
        result = _tf_post(
            f"/api/v1/sessions/{body.session_id}/turns",
            {
                "input": [{
                    "type": "user.message",
                    "content": body.message,
                }]
            },
        )
        return {
            "success": True,
            "session_id": body.session_id,
            "analyst": analyst,
            "trueforge_response": result,
        }
    except RuntimeError:
        raise HTTPException(status_code=502, detail="TrueForge unavailable")


@router.post("/approve")
def approve_containment(
    body: DecisionRequest,
    authorization: Optional[str] = Header(None),
):
    """
    Approve a pending tool call via TrueForge.
    Uses type: user.tool_approval with thread_id and nested approval object.
    """
    analyst = _require_api_key(authorization)
    approval_input = {
        "type": "user.tool_approval",
        "tool_call_id": body.action_id,
        "approval": {"status": "allow"},
    }
    if body.thread_id:
        approval_input["thread_id"] = body.thread_id
    try:
        _tf_post(
            f"/api/v1/sessions/{body.session_id}/turns",
            {"input": [approval_input]},
        )
        return {"success": True, "action_id": body.action_id, "status": "approved", "analyst": analyst}
    except RuntimeError:
        raise HTTPException(status_code=502, detail="TrueForge unavailable")


@router.post("/reject")
def reject_containment(
    body: DecisionRequest,
    authorization: Optional[str] = Header(None),
):
    """
    Reject a pending tool call via TrueForge.
    Uses type: user.tool_approval with deny status and reason.
    """
    analyst = _require_api_key(authorization)
    reason = body.reason or f"Rejected by {analyst}"
    approval_input = {
        "type": "user.tool_approval",
        "tool_call_id": body.action_id,
        "approval": {"status": "deny", "reason": reason},
    }
    if body.thread_id:
        approval_input["thread_id"] = body.thread_id
    try:
        _tf_post(
            f"/api/v1/sessions/{body.session_id}/turns",
            {"input": [approval_input]},
        )
        return {"success": True, "action_id": body.action_id, "status": "rejected", "analyst": analyst}
    except RuntimeError:
        raise HTTPException(status_code=502, detail="TrueForge unavailable")


@router.get("/pending")
def get_pending_approvals():
    """List sessions with pending approval state from TrueForge."""
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
        return {"count": 0, "approvals": [], "warning": "TrueForge unavailable"}
