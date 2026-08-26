"""
CyberForge SDK Client — Session & Approval Management

Provides session persistence and approval gate functionality.
Sessions are stored locally in JSON for the lab environment.
In production, this would connect to TrueForge's native session store.
"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "mcp_server" / "data"
SESSIONS_FILE = DATA_DIR / "sessions.json"


def _load_sessions() -> list[dict]:
    """Load all sessions from disk."""
    if SESSIONS_FILE.exists():
        return json.loads(SESSIONS_FILE.read_text(encoding="utf-8"))
    return []


def _save_sessions(sessions: list[dict]) -> None:
    """Persist sessions to disk."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SESSIONS_FILE.write_text(
        json.dumps(sessions, indent=2, default=str),
        encoding="utf-8",
    )


def create_session(incident_id: str, evidence_snapshot: dict | None = None) -> dict:
    """
    Create a new investigation session.

    Returns the session object with a generated ID.
    """
    sessions = _load_sessions()
    session_id = str(uuid.uuid4())[:8]
    now = datetime.now(timezone.utc).isoformat()

    session = {
        "id": session_id,
        "incident_id": incident_id,
        "status": "active",
        "created_at": now,
        "updated_at": now,
        "evidence_snapshot": evidence_snapshot or {},
        "risk_score": None,
        "approval_state": None,
        "actions": [],
        "findings": [],
    }

    sessions.append(session)
    _save_sessions(sessions)
    return session


def get_session(session_id: str) -> dict | None:
    """Fetch a session by ID."""
    sessions = _load_sessions()
    for s in sessions:
        if s["id"] == session_id:
            return s
    return None


def list_sessions() -> list[dict]:
    """List all sessions (summary view)."""
    sessions = _load_sessions()
    return [
        {
            "id": s["id"],
            "incident_id": s["incident_id"],
            "status": s["status"],
            "created_at": s["created_at"],
            "risk_score": s.get("risk_score"),
            "approval_state": s.get("approval_state"),
        }
        for s in sessions
    ]


def find_session_by_incident(incident_id: str) -> dict | None:
    """Find the most recent session for a given incident ID."""
    sessions = _load_sessions()
    matches = [s for s in sessions if s["incident_id"] == incident_id]
    if not matches:
        return None
    # Return most recent
    return sorted(matches, key=lambda s: s["created_at"], reverse=True)[0]


def request_approval(session_id: str, action_type: str, action_detail: dict) -> dict:
    """
    Request human approval for a containment action.
    Transitions the session to 'pending_approval' state.
    """
    sessions = _load_sessions()
    for s in sessions:
        if s["id"] == session_id:
            action_id = str(uuid.uuid4())[:8]
            approval = {
                "action_id": action_id,
                "action_type": action_type,
                "action_detail": action_detail,
                "status": "pending",
                "requested_at": datetime.now(timezone.utc).isoformat(),
                "decided_at": None,
                "decided_by": None,
            }
            s["approval_state"] = approval
            s["actions"].append(approval)
            s["updated_at"] = datetime.now(timezone.utc).isoformat()
            _save_sessions(sessions)
            return {"success": True, "action_id": action_id, "status": "pending"}
    return {"success": False, "error": f"Session {session_id} not found"}


def approve_action(session_id: str, action_id: str, decided_by: str = "analyst") -> dict:
    """Approve a pending containment action."""
    sessions = _load_sessions()
    for s in sessions:
        if s["id"] == session_id:
            if s.get("approval_state", {}).get("action_id") == action_id:
                s["approval_state"]["status"] = "approved"
                s["approval_state"]["decided_at"] = datetime.now(timezone.utc).isoformat()
                s["approval_state"]["decided_by"] = decided_by
                s["updated_at"] = datetime.now(timezone.utc).isoformat()
                # Update in actions list too
                for a in s["actions"]:
                    if a["action_id"] == action_id:
                        a["status"] = "approved"
                        a["decided_at"] = s["approval_state"]["decided_at"]
                        a["decided_by"] = decided_by
                _save_sessions(sessions)
                return {"success": True, "action_id": action_id, "status": "approved"}
            return {"success": False, "error": "No pending approval matches this action_id"}
    return {"success": False, "error": f"Session {session_id} not found"}


def reject_action(session_id: str, action_id: str, decided_by: str = "analyst") -> dict:
    """Reject a pending containment action."""
    sessions = _load_sessions()
    for s in sessions:
        if s["id"] == session_id:
            if s.get("approval_state", {}).get("action_id") == action_id:
                s["approval_state"]["status"] = "rejected"
                s["approval_state"]["decided_at"] = datetime.now(timezone.utc).isoformat()
                s["approval_state"]["decided_by"] = decided_by
                s["updated_at"] = datetime.now(timezone.utc).isoformat()
                for a in s["actions"]:
                    if a["action_id"] == action_id:
                        a["status"] = "rejected"
                        a["decided_at"] = s["approval_state"]["decided_at"]
                        a["decided_by"] = decided_by
                _save_sessions(sessions)
                return {"success": True, "action_id": action_id, "status": "rejected"}
            return {"success": False, "error": "No pending approval matches this action_id"}
    return {"success": False, "error": f"Session {session_id} not found"}


def update_session(session_id: str, **kwargs) -> dict:
    """Update arbitrary fields on a session."""
    sessions = _load_sessions()
    for s in sessions:
        if s["id"] == session_id:
            for key, value in kwargs.items():
                s[key] = value
            s["updated_at"] = datetime.now(timezone.utc).isoformat()
            _save_sessions(sessions)
            return {"success": True, "session": s}
    return {"success": False, "error": f"Session {session_id} not found"}


if __name__ == "__main__":
    # Demo: create a session and request approval
    import sys
    cmd = sys.argv[1] if len(sys.argv) > 1 else "list"

    if cmd == "list":
        sessions = list_sessions()
        print(json.dumps(sessions, indent=2))
    elif cmd == "demo":
        session = create_session("INC-1024", {"source_ip": "10.0.0.25"})
        print(f"Created session: {session['id']}")
        result = request_approval(
            session["id"], "BLOCK_IP", {"ip_address": "10.0.0.25"}
        )
        print(f"Approval requested: {json.dumps(result, indent=2)}")
        approve_result = approve_action(session["id"], result["action_id"])
        print(f"Action approved: {json.dumps(approve_result, indent=2)}")
    else:
        print(f"Unknown command: {cmd}")
