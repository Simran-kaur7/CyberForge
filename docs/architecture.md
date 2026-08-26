# CyberForge Architecture

## System Overview

```
┌─────────────────────────────────────────────────┐
│                  Frontend UI                      │
│  Dashboard │ Incident Detail │ Approval Gate      │
└────────────────────┬────────────────────────────┘
                     │ fetch / localStorage
┌────────────────────┴────────────────────────────┐
│              App / SDK Client Layer               │
│  Sessions │ Approval Flow │ Risk Score Engine     │
└────────────────────┬────────────────────────────┘
                     │ child_process spawn
┌────────────────────┴────────────────────────────┐
│               MCP Server (Node.js)                │
│  Tool Registration │ stdio transport │ Zod schema  │
└────────────────────┬────────────────────────────┘
                     │ Python scripts
┌────────────────────┴────────────────────────────┐
│              Evidence Layer (Python)               │
│  search_security_logs │ analyze_evidence          │
│  check_system_activity │ block_ip (simulated)     │
└────────────────────┬────────────────────────────┘
                     │ read/write JSON & log files
┌────────────────────┴────────────────────────────┐
│              Local Evidence Data                   │
│  auth.log │ processes.json │ network.log           │
│  simulated_firewall.json │ sessions.json           │
└─────────────────────────────────────────────────┘
```

## Components

### MCP Server (`mcp_server/server.js`)
- Registers four tools with the MCP protocol
- Spawns Python scripts as child processes
- Communicates via stdio (standard MCP transport)
- Validates input with Zod schemas

### Evidence Tools (`mcp_server/tools/`)
- **search_security_logs.py**: Regex search over `auth.log`, counts failed/successful logins
- **analyze_evidence.py**: Correlates auth + host + network signals into a findings list
- **check_system_activity.py**: Reads `processes.json` and `network.log`, identifies suspicious activity
- **block_ip.py**: Simulated firewall — writes to `simulated_firewall.json` (no real network impact)

### Risk Scoring Engine (`agent/risk_score.py`)
- Pure function: takes `risk_indicators` dict, returns score + level + breakdown
- Designed to run in Code Mode (sandbox) as a subagent task
- Weights: failed_attempts(+20), suspicious_login(+25), suspicious_process(+25), unusual_connection(+20), known_bad_ip(+10)

### SDK Client (`app/sdk_client.py`)
- Session management: create, get, list, find by incident ID
- Approval flow: request_approval → pending → approve/reject
- Local JSON persistence via `mcp_server/data/sessions.json`
- In production, this layer connects to TrueForge's native session store

### Frontend (`frontend/`)
- Static HTML/CSS/JS — no build step required
- **Dashboard** (`index.html`): Lists previously investigated incidents with risk badges
- **Incident Detail** (`incident.html`): Evidence panels, risk gauge, approval buttons, timeline
- Data flows from `mcp_server/data/` files and localStorage

## Persistent Sessions Design

### Storage
Sessions are stored in `mcp_server/data/sessions.json` as a JSON array. Each session contains:

```json
{
  "id": "a1b2c3d4",
  "incident_id": "INC-1024",
  "status": "active",
  "created_at": "2026-08-26T10:00:00Z",
  "updated_at": "2026-08-26T10:05:00Z",
  "evidence_snapshot": { "source_ip": "10.0.0.25" },
  "risk_score": { "score": 100, "level": "CRITICAL" },
  "approval_state": { "status": "approved", "decided_by": "analyst" },
  "actions": [...],
  "findings": [...]
}
```

### Reopen Flow
When an analyst reopens a prior incident:

1. **Lookup**: `find_session_by_incident(incident_id)` retrieves the most recent session
2. **Recall**: Prior findings, risk score, and approval state are displayed as context
3. **Resume vs. New**: The SDK supports creating a new session that references the prior one's findings as `evidence_snapshot`. This is preferred over resuming, because:
   - Evidence in the lab is static (same `auth.log`, same `processes.json`)
   - A new session preserves the audit trail cleanly
   - Prior findings serve as "recalled context" rather than live state
4. **Decision**: The analyst can either act on prior findings or trigger a fresh investigation

### Why JSON over SQLite
For the lab environment, JSON files are:
- Human-readable and git-trackable
- Compatible with the frontend (direct `fetch()`)
- Simple enough for a single-user investigation workspace

In production, this would be replaced by TrueForge's session persistence (SQLite locally, or a database service).

## Approval Gate Flow

```
Agent suggests block_ip
       │
       ▼
request_approval(session_id, "BLOCK_IP", {ip: "10.0.0.25"})
       │
       ▼
Session status → "pending_approval"
       │
       ▼
┌──────────────────┐
│   Human Review    │
│  Evidence + Risk  │
│  Score displayed  │
└──────┬───────────┘
       │
  ┌────┴────┐
  ▼         ▼
Approve    Reject
  │         │
  ▼         ▼
block_ip   No action
executed   Session status
           → "rejected"
```

The approval gate is the hard boundary between agent recommendation and human decision. The agent **never** crosses this boundary without explicit consent.

## Subagent Architecture

For parallel investigation, the agent spawns two subagents:

```
              Agent (Orchestrator)
             /                    \
    Subagent A                Subagent B
  (Auth Logs)              (System Activity)
       \                       /
        \                     /
         Merge risk_indicators
                │
                ▼
         risk_score.py
         (Code Mode)
                │
                ▼
         Risk Assessment
         → Human Review
```

This parallel approach reduces investigation time and demonstrates composable tool design — each subagent runs independently, and the orchestrator merges results.
