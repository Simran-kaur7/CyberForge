import json
import subprocess
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = PROJECT_ROOT / "mcp_server" / "tools"

TOOL_TIMEOUT_SECONDS = 15
MAX_ERROR_OUTPUT = 500


class ToolTimeoutError(RuntimeError):
    """Raised when an investigation tool exceeds its execution timeout."""


def run_tool(script_name: str, *args: str) -> dict:
    script_path = TOOLS_DIR / script_name

    try:
        result = subprocess.run(
            ["python3", str(script_path), *args],
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
        raise RuntimeError(
            f"{script_name} returned invalid JSON"
        ) from exc


def analyze_evidence() -> dict:
    return run_tool("analyze_evidence.py")


def search_security_logs(query: str = "") -> dict:
    return run_tool("search_security_logs.py", query)


def check_system_activity() -> dict:
    return run_tool("check_system_activity.py")


def block_ip(ip_address: str) -> dict:
    return run_tool("block_ip.py", ip_address)

# ---------------------------------------------------------------------------
# Session Management
# ---------------------------------------------------------------------------

import uuid
from datetime import datetime, timezone

DATA_DIR = Path(__file__).resolve().parent.parent / "mcp_server" / "data"
SESSIONS_FILE = DATA_DIR / "sessions.json"


def _load_sessions():
    if SESSIONS_FILE.exists():
        return json.loads(SESSIONS_FILE.read_text(encoding="utf-8"))
    return []


def _save_sessions(sessions):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SESSIONS_FILE.write_text(json.dumps(sessions, indent=2, default=str), encoding="utf-8")


def create_session(incident_id, evidence_snapshot=None):
    sessions = _load_sessions()
    sid = str(uuid.uuid4())[:8]
    now = datetime.now(timezone.utc).isoformat()
    s = {"id": sid, "incident_id": incident_id, "status": "active",
         "created_at": now, "updated_at": now,
         "evidence_snapshot": evidence_snapshot or {},
         "risk_score": None, "approval_state": None, "actions": [], "findings": []}
    sessions.append(s)
    _save_sessions(sessions)
    return s


def get_session(sid):
    for s in _load_sessions():
        if s["id"] == sid:
            return s
    return None


def list_sessions():
    return [{"id": s["id"], "incident_id": s["incident_id"], "status": s["status"],
             "created_at": s["created_at"], "risk_score": s.get("risk_score"),
             "approval_state": s.get("approval_state")} for s in _load_sessions()]


def find_session_by_incident(iid):
    ms = [s for s in _load_sessions() if s["incident_id"] == iid]
    return sorted(ms, key=lambda s: s["created_at"], reverse=True)[0] if ms else None


# ---------------------------------------------------------------------------
# Approval Flow
# ---------------------------------------------------------------------------

def request_approval(sid, atype, adetail):
    sessions = _load_sessions()
    for s in sessions:
        if s["id"] == sid:
            aid = str(uuid.uuid4())[:8]
            ap = {"action_id": aid, "action_type": atype, "action_detail": adetail,
                  "status": "pending", "requested_at": datetime.now(timezone.utc).isoformat(),
                  "decided_at": None, "decided_by": None}
            s["approval_state"] = ap
            s["actions"].append(ap)
            s["updated_at"] = datetime.now(timezone.utc).isoformat()
            _save_sessions(sessions)
            return {"success": True, "action_id": aid, "status": "pending"}
    return {"success": False, "error": "Session not found"}


def approve_action(sid, aid, decided_by="analyst"):
    sessions = _load_sessions()
    for s in sessions:
        if s["id"] == sid and s.get("approval_state", {}).get("action_id") == aid:
            s["approval_state"]["status"] = "approved"
            s["approval_state"]["decided_at"] = datetime.now(timezone.utc).isoformat()
            s["approval_state"]["decided_by"] = decided_by
            s["updated_at"] = s["approval_state"]["decided_at"]
            for a in s["actions"]:
                if a["action_id"] == aid:
                    a["status"] = "approved"
                    a["decided_at"] = s["approval_state"]["decided_at"]
                    a["decided_by"] = decided_by
            _save_sessions(sessions)
            return {"success": True, "action_id": aid, "status": "approved"}
    return {"success": False, "error": "Not found"}


def reject_action(sid, aid, decided_by="analyst"):
    sessions = _load_sessions()
    for s in sessions:
        if s["id"] == sid and s.get("approval_state", {}).get("action_id") == aid:
            s["approval_state"]["status"] = "rejected"
            s["approval_state"]["decided_at"] = datetime.now(timezone.utc).isoformat()
            s["approval_state"]["decided_by"] = decided_by
            s["updated_at"] = s["approval_state"]["decided_at"]
            for a in s["actions"]:
                if a["action_id"] == aid:
                    a["status"] = "rejected"
                    a["decided_at"] = s["approval_state"]["decided_at"]
                    a["decided_by"] = decided_by
            _save_sessions(sessions)
            return {"success": True, "action_id": aid, "status": "rejected"}
    return {"success": False, "error": "Not found"}


def update_session(sid, **kw):
    sessions = _load_sessions()
    for s in sessions:
        if s["id"] == sid:
            s.update(kw)
            s["updated_at"] = datetime.now(timezone.utc).isoformat()
            _save_sessions(sessions)
            return {"success": True, "session": s}
    return {"success": False, "error": "Not found"}


if __name__ == "__main__":
    import sys
    cmd = sys.argv[1] if len(sys.argv) > 1 else "list"
    if cmd == "list":
        print(json.dumps(list_sessions(), indent=2))
    elif cmd == "tools":
        print(json.dumps(analyze_evidence(), indent=2))
