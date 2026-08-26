"""
CyberForge Approval API — endpoints for approve/reject containment actions.

The approval gate is the hard boundary between agent recommendation
and human decision. The agent never crosses this without explicit consent.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.sdk_client import (
    approve_action,
    get_session,
    list_sessions,
    reject_action,
    request_approval,
)


router = APIRouter(prefix="/api/approvals", tags=["approvals"])


class ApprovalRequest(BaseModel):
    session_id: str
    action_type: str
    action_detail: dict


class DecisionRequest(BaseModel):
    session_id: str
    action_id: str
    decided_by: str = "analyst"


@router.post("/request")
def request_containment_approval(body: ApprovalRequest):
    """
    Request human approval for a containment action (e.g. BLOCK_IP).
    Transitions the session to 'pending_approval' state.
    """
    result = request_approval(body.session_id, body.action_type, body.action_detail)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error", "Request failed"))
    return result


@router.post("/approve")
def approve_containment(body: DecisionRequest):
    """
    Approve a pending containment action.
    The agent may now execute the action (e.g. call block_ip).
    """
    result = approve_action(body.session_id, body.action_id, body.decided_by)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error", "Approval failed"))
    return result


@router.post("/reject")
def reject_containment(body: DecisionRequest):
    """
    Reject a pending containment action.
    No action is taken — the agent must not proceed.
    """
    result = reject_action(body.session_id, body.action_id, body.decided_by)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error", "Rejection failed"))
    return result


@router.get("/pending")
def get_pending_approvals():
    """
    List all sessions with pending approval state.
    Used by the UI to show actions awaiting human decision.
    """
    sessions = list_sessions()
    pending = [
        s for s in sessions
        if s.get("approval_state", {}).get("status") == "pending"
    ]
    return {"count": len(pending), "approvals": pending}
