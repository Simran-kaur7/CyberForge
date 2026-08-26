"""
CyberForge SDK Client — Tool Runner, Session & Approval Management

1. Tool execution with timeout and error handling
2. Session management: create, get, list, find by incident ID
3. Approval flow: request -> pending -> approve/reject (enforced)
4. Local JSON persistence with file locking
"""

import os
import platform

if platform.system() == "Windows":
    import msvcrt
    def _lock_file(fd):
        msvcrt.locking(fd.fileno(), msvcrt.LK_LOCK, 1)
    def _unlock_file(fd):
        msvcrt.locking(fd.fileno(), msvcrt.LK_UNLCK, 1)
else:
    import fcntl
    def _lock_file(fd):
        fcntl.flock(fd, fcntl.LOCK_EX)
    def _unlock_file(fd):
        fcntl.flock(fd, fcntl.LOCK_UN)
import json
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = PROJECT_ROOT / "mcp_server" / "tools"
DATA_DIR = PROJECT_ROOT / "mcp_server" / "data"
SESSIONS_FILE = DATA_DIR / "sessions.json"

TOOL_TIMEOUT_SECONDS = 15
MAX_ERROR_OUTPUT = 500


class ToolTimeoutError(RuntimeError):
    """Raised when an investigation tool exceeds its execution timeout."""


# ---------------------------------------------------------------------------
# Tool Execution
# ---------------------------------------------------------------------------

def run_tool(script_name: str, *args: str) -> dict:
    """Run an MCP Python tool and return parsed JSON output."""
    script_path = TOOLS_DIR / script_name
    try:
        result = subprocess.run(
            ["python", str(script_path), *args],
            cwd=TOOLS_DIR,
            capture_output=True,
            text=True,
            check=False,
            timeout=TOOL_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = (exc.stdout or "").strip()
        stderr = (exc.stderr or "").strip()
        details = []
        if args:
            details.append(f"args={args}")
        if stdout:
            details.append(f"stdout={stdout[-MAX_ERROR_OUTPUT:]}")
        if stderr:
            details.append(f"stderr={stderr[-MAX_ERROR_OUTPUT:]}")
        context = "; ".join(details)
        raise ToolTimeoutError(
            f"{script_name} timed out after "
            f"{TOOL_TIMEOUT_SECONDS} seconds"
            + (f" ({context})" if context else "")
        ) from exc
    if result.returncode != 0:
        raise RuntimeError(
            f"{script_name} failed: "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{script_name} returned invalid JSON") from exc


def analyze_evidence() -> dict:
    return run_tool("analyze_evidence.py")


def search_security_logs(query: str = "") -> dict:
    return run_tool("search_security_logs.py", query)


def check_system_activity() -> dict:
    return run_tool("check_system_activity.py")


def block_ip(ip_address: str) -> dict:
    return run_tool("block_ip.py", ip_address)


# ---------------------------------------------------------------------------
# Session Persistence (with file locking)
# ---------------------------------------------------------------------------

def _load_sessions() -> list:
    if SESSIONS_FILE.exists():
        return json.loads(SESSIONS_FILE.read_text(encoding="utf-8"))
    return []


def _save_sessions(sessions: list) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SESSIONS_FILE.write_text(
        json.dumps(sessions, indent=2, default=str), encoding="utf-8"
    )


def _mutate_sessions(fn):
    """Load, apply fn, save — under an exclusive file lock."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    lock_path = DATA_DIR / ".sessions.lock"
    lock_path.touch(exist_ok=True)
    fd = open(lock_path, "r+")
    try:
        _lock_file(fd)
        sessions = _load_sessions()
        result = fn(sessions)
        _save_sessions(sessions)
        return result
    finally:
        _unlock_file(fd)
        fd.close()


# ---------------------------------------------------------------------------
# Session Management
# ---------------------------------------------------------------------------

def create_session(incident_id: str, evidence_snapshot=None) -> dict:
    def _create(sessions):
        sid = str(uuid.uuid4())[:8]
        now = datetime.now(timezone.utc).isoformat()
        s = {
            "id": sid, "incident_id": incident_id, "status": "active",
            "created_at": now, "updated_at": now,
            "evidence_snapshot": evidence_snapshot or {},
            "risk_score": None, "approval_state": None,
            "trueforge_session_id": None,
            "actions": [], "findings": [],
        }
        sessions.append(s)
        return s
    return _mutate_sessions(_create)


def get_session(sid: str):
    for s in _load_sessions():
        if s["id"] == sid:
            return s
    return None


def list_sessions() -> list:
    return [
        {
            "id": s["id"], "incident_id": s["incident_id"],
            "status": s["status"], "created_at": s["created_at"],
            "risk_score": s.get("risk_score"),
            "approval_state": s.get("approval_state"),
            "trueforge_session_id": s.get("trueforge_session_id"),
        }
        for s in _load_sessions()
    ]


def find_session_by_incident(iid: str):
    ms = [s for s in _load_sessions() if s["incident_id"] == iid]
    return sorted(ms, key=lambda s: s["created_at"], reverse=True)[0] if ms else None


# ---------------------------------------------------------------------------
# Approval Flow (enforced state machine)
# ---------------------------------------------------------------------------

def request_approval(sid: str, atype: str, adetail: dict) -> dict:
    """Request approval. Fails if one is already pending."""
    def _req(sessions):
        for s in sessions:
            if s["id"] != sid:
                continue
            # Bug #4: block if already pending
            existing = s.get("approval_state")
            if existing and existing.get("status") == "pending":
                return {"success": False, "error": "An approval is already pending for this session"}
            aid = str(uuid.uuid4())[:8]
            ap = {
                "action_id": aid, "action_type": atype,
                "action_detail": adetail, "status": "pending",
                "requested_at": datetime.now(timezone.utc).isoformat(),
                "decided_at": None, "decided_by": None,
            }
            s["approval_state"] = ap
            s["actions"].append(ap)
            s["updated_at"] = datetime.now(timezone.utc).isoformat()
            return {"success": True, "action_id": aid, "status": "pending"}
        return {"success": False, "error": "Session not found"}
    return _mutate_sessions(_req)


def approve_action(sid: str, aid: str, decided_by: str = "analyst") -> dict:
    """Approve only if status is pending."""
    def _approve(sessions):
        for s in sessions:
            if s["id"] != sid:
                continue
            current = s.get("approval_state")
            if not current or current.get("action_id") != aid:
                return {"success": False, "error": "No matching pending approval"}
            # Bug #3: enforce terminal state
            if current["status"] != "pending":
                return {"success": False, "error": f"Action already {current['status']}"}
            now = datetime.now(timezone.utc).isoformat()
            current["status"] = "approved"
            current["decided_at"] = now
            current["decided_by"] = decided_by
            s["updated_at"] = now
            for a in s["actions"]:
                if a["action_id"] == aid:
                    a["status"] = "approved"
                    a["decided_at"] = now
                    a["decided_by"] = decided_by
            return {"success": True, "action_id": aid, "status": "approved"}
        return {"success": False, "error": "Session not found"}
    return _mutate_sessions(_approve)


def reject_action(sid: str, aid: str, decided_by: str = "analyst") -> dict:
    """Reject only if status is pending."""
    def _reject(sessions):
        for s in sessions:
            if s["id"] != sid:
                continue
            current = s.get("approval_state")
            if not current or current.get("action_id") != aid:
                return {"success": False, "error": "No matching pending approval"}
            # Bug #3: enforce terminal state
            if current["status"] != "pending":
                return {"success": False, "error": f"Action already {current['status']}"}
            now = datetime.now(timezone.utc).isoformat()
            current["status"] = "rejected"
            current["decided_at"] = now
            current["decided_by"] = decided_by
            s["updated_at"] = now
            for a in s["actions"]:
                if a["action_id"] == aid:
                    a["status"] = "rejected"
                    a["decided_at"] = now
                    a["decided_by"] = decided_by
            return {"success": True, "action_id": aid, "status": "rejected"}
        return {"success": False, "error": "Session not found"}
    return _mutate_sessions(_reject)


def update_session(sid: str, **kw) -> dict:
    def _update(sessions):
        for s in sessions:
            if s["id"] == sid:
                s.update(kw)
                s["updated_at"] = datetime.now(timezone.utc).isoformat()
                return {"success": True, "session": s}
        return {"success": False, "error": "Session not found"}
    return _mutate_sessions(_update)


def set_approval_tool_call_id(sid: str, action_id: str, tool_call_id: str) -> dict:
    """Atomically set tool_call_id on the current approval_state.

    Only writes if the current approval still belongs to the given
    action_id — prevents a stale TrueForge response from overwriting
    a newer approval's tool_call_id.

    If the approval is already terminal (approved/rejected) when this
    write arrives, returns ``pending_decision`` so the caller can
    forward the late-arriving decision to TrueForge.
    """
    def _set(sessions):
        for s in sessions:
            if s["id"] != sid:
                continue
            ap = s.get("approval_state")
            if not ap:
                return {"success": False, "error": "No approval state"}
            if ap.get("action_id") != action_id:
                return {"success": False, "error": "Approval already replaced by a newer request"}
            ap["tool_call_id"] = tool_call_id
            s["updated_at"] = datetime.now(timezone.utc).isoformat()
            # If already decided, the caller must forward to TrueForge
            current_status = ap.get("status")
            if current_status in ("approved", "rejected"):
                return {
                    "success": True, "action_id": action_id,
                    "pending_decision": current_status,
                    "decided_by": ap.get("decided_by"),
                }
            return {"success": True, "action_id": action_id}
        return {"success": False, "error": "Session not found"}
    return _mutate_sessions(_set)


def persist_trueforge_session_id(sid: str, tf_session_id: str) -> dict:
    """Atomically persist a TrueForge session ID on the local session.

    Uses compare-and-set: only writes if the current value is still None.
    Returns the winning ID so callers can reuse it if another request won.
    """
    def _persist(sessions):
        for s in sessions:
            if s["id"] != sid:
                continue
            existing = s.get("trueforge_session_id")
            if existing:
                # Another request already set it — return the winner
                return {"success": True, "trueforge_session_id": existing, "reused": True}
            s["trueforge_session_id"] = tf_session_id
            s["updated_at"] = datetime.now(timezone.utc).isoformat()
            return {"success": True, "trueforge_session_id": tf_session_id, "reused": False}
        return {"success": False, "error": "Session not found"}
    return _mutate_sessions(_persist)


if __name__ == "__main__":
    import sys
    cmd = sys.argv[1] if len(sys.argv) > 1 else "list"
    if cmd == "list":
        print(json.dumps(list_sessions(), indent=2))
    elif cmd == "tools":
        print(json.dumps(analyze_evidence(), indent=2))
