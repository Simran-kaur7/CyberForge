"""
CyberForge Approval API — connects to TrueForge's native approval gate.

When the agent tries to call block_ip (which requires approval),
TrueForge pauses the turn and surfaces a pending-approval state.
This API forwards approve/reject decisions to TrueForge via HTTP,
which then resumes the agent turn with the decision.
"""

import os
import json
import urllib.request
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel


router = APIRouter(prefix="/api/approvals", tags=["approvals"])

TRUEFORGE_URL = os.environ.get("TRUEFORGE_URL", "http://localhost:8790")


class ApprovalRequest(BaseModel):
    session_id: str
    action_type: str
    action_detail: dict


class DecisionRequest(BaseModel):
    session_id: str
    action_id: str
    decided_by: str = "analyst"


class TrueForgeTurnRequest(BaseModel):
    input: list


def _tf_post(path: str, body: dict) -> dict:
    """Make a POST request to the TrueForge HTTP API."""
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
        error_body = exc.read().decode() if exc.fp else ""
        raise RuntimeError(
            f"TrueForge API error {exc.code}: {error_body}"
        ) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(
            f"Cannot reach TrueForge at {TRUEFORGE_URL}: {exc.reason}"
        ) from exc


def _tf_get(path: str) -> dict:
    """Make a GET request to the TrueForge HTTP API."""
    url = f"{TRUEFORGE_URL}{path}"
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode() if exc.fp else ""
        raise RuntimeError(
            f"TrueForge API error {exc.code}: {error_body}"
        ) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(
            f"Cannot reach TrueForge at {TRUEFORGE_URL}: {exc.reason}"
        ) from exc


@router.post("/request")
def request_containment_approval(body: ApprovalRequest):
    """
    Request human approval for a containment action.

    In the TrueForge flow, this is handled natively:
    the agent calls block_ip, TrueForge pauses, and the turn
    ends with required_actions containing the pending approval.
    This endpoint just returns the pending state for the UI.
    """
    return {
        "success": True,
        "status": "pending",
        "message": f"Approval requested for {body.action_type} on session {body.session_id}",
        "trueforge_url": TRUEFORGE_URL,
    }


@router.post("/approve")
def approve_containment(body: DecisionRequest):
    """
    Approve a pending containment action via TrueForge.

    Sends a new turn to TrueForge with the approval decision,
    which resumes the agent and allows it to call block_ip.
    """
    try:
        result = _tf_post(
            f"/api/v1/sessions/{body.session_id}/turns",
            {
                "input": [
                    {
                        "type": "tool_approval",
                        "tool_call_id": body.action_id,
                        "status": "allow",
                    }
                ]
            },
        )
        return {
            "success": True,
            "action_id": body.action_id,
            "status": "approved",
            "trueforge_response": result,
        }
    except RuntimeError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Failed to forward approval to TrueForge: {exc}",
        )


@router.post("/reject")
def reject_containment(body: DecisionRequest):
    """
    Reject a pending containment action via TrueForge.

    Sends a denial to TrueForge — the agent receives the rejection
    and must not proceed with the action.
    """
    try:
        result = _tf_post(
            f"/api/v1/sessions/{body.session_id}/turns",
            {
                "input": [
                    {
                        "type": "tool_approval",
                        "tool_call_id": body.action_id,
                        "status": "deny",
                        "reason": f"Rejected by {body.decided_by}",
                    }
                ]
            },
        )
        return {
            "success": True,
            "action_id": body.action_id,
            "status": "rejected",
            "trueforge_response": result,
        }
    except RuntimeError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Failed to forward rejection to TrueForge: {exc}",
        )


@router.get("/pending")
def get_pending_approvals():
    """
    List sessions with pending approval state from TrueForge.
    """
    try:
        sessions = _tf_get("/api/v1/sessions")
        session_list = sessions.get("data", sessions) if isinstance(sessions, dict) else sessions
        pending = []
        if isinstance(session_list, list):
            for s in session_list:
                state = s.get("state", {})
                actions = state.get("required_actions", [])
                if actions:
                    pending.append({
                        "session_id": s.get("id"),
                        "title": s.get("title"),
                        "required_actions": actions,
                    })
        return {"count": len(pending), "approvals": pending}
    except RuntimeError as exc:
        return {
            "count": 0,
            "approvals": [],
            "warning": f"Could not reach TrueForge: {exc}",
        }
