# 🛡️ CyberForge — Setup Guide

**CyberForge** is a local development/demo environment for an **AI-assisted SOC (Security Operations Center) investigation and response workflow**.

The system is built so that any potentially disruptive containment action **requires explicit human approval** — the agent investigates and recommends, the analyst decides.

> **Core design principle:** AI-assisted investigation and recommendation, with human-controlled containment.

---

## Table of Contents

- [Architecture at a Glance](#architecture-at-a-glance)
- [Prerequisites](#prerequisites)
- [1. Clone the Repository](#1-clone-the-repository)
- [2. Create the Python Environment](#2-create-the-python-environment)
- [3. Configure Environment Variables](#3-configure-environment-variables)
- [4. Start CyberForge](#4-start-cyberforge)
- [5. Start the TrueForge Bridge (Optional)](#5-start-the-trueforge-bridge-optional)
- [6. Verify the Demo Environment](#6-verify-the-demo-environment)
- [7. Human Approval Gate](#7-human-approval-gate)
- [8. Simulated Firewall](#8-simulated-firewall)
- [Command Cheat Sheet](#command-cheat-sheet)
- [Troubleshooting](#troubleshooting)
- [Clean Restart](#clean-restart)
- [Pre-Demo Final Checklist](#pre-demo-final-checklist)
- [Security Notes](#security-notes)

---

## Architecture at a Glance

```
Incident
   ↓
Investigation
   ↓
Evidence Correlation
   ↓
Target Identification
   ↓
Containment Recommendation
   ↓
┌───────────────────────┐
│  HUMAN APPROVAL GATE  │
└───────────────────────┘
   ↓ (approved)
Execute Containment
   ↓
Simulated Firewall Action
   ↓
Completed Timeline
```

The workflow must **never** jump directly from incident detection to firewall execution — the approval gate in the middle is intentional and non-negotiable.

---

## Prerequisites

Make sure the following are installed and verified before you begin:

| Requirement | Notes |
|---|---|
| Python 3.x | Used for the FastAPI backend |
| Git | For cloning/pulling the repository |
| A configured Linux environment | Commands in this guide assume Linux/Lubuntu unless a Windows-specific block is shown |
| VS Code (optional) | CyberForge may be edited from **Windows VS Code** while the repo/commands actually run inside the configured **Linux** environment (e.g. a VM) |

---

## 1. Clone the Repository

```bash
git clone <[CyberForge-Repo](https://github.com/Simran-kaur7/CyberForge)>
cd CyberForge
```

If the repository already exists locally, just update it:

```bash
cd CyberForge
git pull
```

> ⚠️ **Never commit** secrets, API keys, `.env` files containing credentials, or local machine configuration.

---

## 2. Create the Python Environment

<details>
<summary><strong>🪟 Windows</strong></summary>

```powershell
python -m venv .venv
.venv\Scripts\activate
```

</details>

<details>
<summary><strong>🐧 Linux / Lubuntu</strong></summary>

```bash
python3 -m venv .venv
source .venv/bin/activate
```

</details>

Then, on either platform, upgrade pip and install dependencies:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

> If the repository uses a different dependency manager (e.g. `pyproject.toml`), follow that project's configuration instead.

---

## 3. Configure Environment Variables

Copy the example environment file:

**Linux/macOS**
```bash
cp .env.example .env
```

**Windows PowerShell**
```powershell
Copy-Item .env.example .env
```

Then open `.env` and configure the required values. Typical values include:

```env
OPENAI_API_KEY=your_key_here
```

Use the exact variable names required by the current codebase.

> ⚠️ **Never commit `.env` or real API keys.**

---

## 4. Start CyberForge

Activate the virtual environment first, then launch the server.

**Windows PowerShell**
```powershell
.venv\Scripts\activate
uvicorn main:app --reload
```

**Linux/Lubuntu**
```bash
source .venv/bin/activate
uvicorn main:app --reload
```

> If the application uses a different FastAPI module/path, use the entry point defined by the repository.

Open the app in your browser:

```
http://127.0.0.1:8000
```
or
```
http://localhost:8000
```

---

## 5. Start the TrueForge Bridge (Optional)

The **TrueForge bridge** lives in a **separate project/folder** from the CyberForge repository — do not assume it exists inside `CyberForge/`.

1. Navigate to the separate TrueForge bridge project directory.
2. Start it using **that project's** documented command, e.g.:

```bash
uvicorn app.main:app --reload
```

3. Use the actual entry point and environment configuration provided by the bridge project.

> Start CyberForge and the TrueForge bridge **separately** when both are required for the demo.

---

## 6. Verify the Demo Environment

Before starting a demo, confirm the full investigation pipeline resolves end-to-end:

```
Incident → Investigation → Evidence Correlation → Target Identification
   → Containment Recommendation → Human Approval → Firewall Action
   → Completed Timeline
```

The workflow should **not** skip straight from incident detection to firewall execution.

---

## 7. Human Approval Gate

```
Critical Incident
       ↓
Investigate
       ↓
Correlate Evidence
       ↓
Recommend Containment
       ↓
┌──────────────────────┐
│  HUMAN APPROVAL GATE  │
└──────────────────────┘
       ↓ Approved
Execute Containment
       ↓
Simulated Firewall
       ↓
Action Result
```

CyberForge is presented as an **AI-assisted SOC system**: the agent investigates and recommends an action, while the human analyst remains responsible for **approving** any disruptive response. The approval gate is intentional and must remain enabled.

---

## 8. Simulated Firewall

The firewall used in the demo is a **controlled simulation**, not production infrastructure. Expected flow:

1. CyberForge identifies the target IP.
2. CyberForge recommends blocking it.
3. The analyst **approves** the recommendation.
4. CyberForge sends the containment action.
5. The simulated firewall records/applies the block.
6. CyberForge receives the result.
7. The investigation timeline advances to **completion**.

> Keep demo firewall data separate from production infrastructure.

---

## Command Cheat Sheet

| Action | Windows PowerShell | Linux / Lubuntu |
|---|---|---|
| Activate venv | `.venv\Scripts\activate` | `source .venv/bin/activate` |
| Start server | `uvicorn main:app --reload` | `uvicorn main:app --reload` |
| Start on a specific port | `uvicorn main:app --reload --port 8000` | `uvicorn main:app --reload --port 8000` |
| Check Git state | `git status` | `git status` |
| Create a branch | `git checkout -b feature/<name>` | `git checkout -b feature/<name>` |
| Pull latest changes | `git pull` | `git pull` |
| Commit changes | `git add .`<br>`git commit -m "Describe the change"` | `git add .`<br>`git commit -m "Describe the change"` |
| Push branch | `git push -u origin <branch-name>` | `git push -u origin <branch-name>` |

---

## Troubleshooting

<details>
<summary><code>uvicorn</code> is not recognized</summary>

Run it as a module instead, to ensure it executes from the active Python environment:

```bash
python -m uvicorn main:app --reload
```

</details>

<details>
<summary><code>ModuleNotFoundError</code></summary>

Confirm the virtual environment is active:

```bash
python --version
```

Then reinstall dependencies:

```bash
pip install -r requirements.txt
```

</details>

<details>
<summary>Port 8000 is already in use</summary>

Use a different port:

```bash
uvicorn main:app --reload --port 8001
```

Then open `http://127.0.0.1:8001`.

</details>

<details>
<summary>Timeline stops after approval</summary>

Check the complete post-approval path:

```
approval → containment execution → firewall response
        → action result → timeline update → completed state
```

Approval should **not** be treated as the terminal state of the investigation.

</details>

<details>
<summary>Target IP is incorrect or missing</summary>

Check the incident-to-target resolution logic and the seeded/demo incident data.

> ⚠️ Do not hard-code a target merely to make the UI pass the demo. The investigation should resolve the target from the incident/evidence data or the project's defined demo mapping.

</details>

<details>
<summary>Firewall action fails</summary>

Verify:
- The simulated firewall service/module is running
- The containment request payload matches the expected schema
- Approval was actually granted before the action was dispatched

</details>

---

## Clean Restart

If the application gets into a bad demo state:

1. Stop the running server: `Ctrl+C`
2. Restart CyberForge: `uvicorn main:app --reload`
3. Reload the browser.
4. Return to the seeded incident.
5. Start a fresh investigation.

> If the project maintains session/demo state in local JSON or another persistence layer, reset it **only** according to the repository's documented development procedure.

---

## Pre-Demo Final Checklist

- [ ] CyberForge starts
- [ ] Dashboard loads
- [ ] Critical incident visible
- [ ] Investigation starts
- [ ] Evidence appears
- [ ] Target IP is resolved
- [ ] Recommendation appears
- [ ] Approval gate appears
- [ ] Approve button works
- [ ] Timeline continues after approval
- [ ] Simulated firewall action succeeds
- [ ] Final action/result appears
- [ ] TrueForge bridge works (if demonstrated)
- [ ] No secrets are visible

---

## Security Notes

CyberForge is a **security demonstration environment**. For demos and development:

- ✅ Use simulated infrastructure.
- ✅ Use test data.
- ✅ Keep credentials in environment variables.
- 🚫 Do not expose API keys in screenshots, Git commits, or recordings.
- 🚫 Do not point the simulated containment workflow at production infrastructure.
- ✅ Keep human approval enabled for all disruptive actions.

> **AI-assisted investigation and recommendation, with human-controlled containment.**