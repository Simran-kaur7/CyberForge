<div align="center">
  <img src="assets/banner.svg" alt="CyberForge - security investigation" width="100%" />

  <h3>Signal from noise. Confidence before containment.</h3>
  <p>A local MCP-powered security investigation workspace for evidence correlation, explainable analysis, and human-approved response.</p>

  <code>OBSERVE</code> &rarr; <code>INVESTIGATE</code> &rarr; <code>CORRELATE</code> &rarr; <code>ASSESS</code> &rarr; <code>RECOMMEND</code> &rarr; <code>HUMAN APPROVAL</code> &rarr; <code>ACTION</code> &rarr; <code>VERIFY RESULT</code>
</div>

## What CyberForge is

CyberForge is an AI SOC (Security Operations Center) incident-investigation agent. Given a scattered trail of authentication, host, and network signals, it produces a single, evidence-backed incident narrative that a human analyst can review and act on.

## The problem it solves

Real incidents rarely announce themselves with one clean alert. A brute-force login, a suspicious process, and a strange outbound connection can each look like noise in isolation — and an analyst who has to manually stitch together three different logs to see the pattern loses the time that matters most in a live incident. CyberForge automates that stitching step: it correlates the separate signals into one narrative and explains *why* they belong together, without taking the containment decision away from a human.

## What the agent actually does

CyberForge does not "auto-respond" to incidents. It:

1. Reads evidence from local, committed data sources (authentication logs, simulated host/process activity, simulated network activity).
2. Correlates that evidence into a single incident narrative.
3. Explains, in plain language, why the correlated signals indicate a security incident.
4. Recommends a containment action.
5. Waits for explicit human approval before any containment action is recorded.
6. Records the outcome of that action so the result can be verified.

## Investigation lifecycle

<div align="center">
  <img src="assets/pipeline.png" alt="CyberForge investigation pipeline" width="85%" />
</div>

```text
OBSERVE
   ↓
INVESTIGATE
   ↓
CORRELATE
   ↓
ASSESS
   ↓
RECOMMEND
   ↓
HUMAN APPROVAL
   ↓
ACTION
   ↓
VERIFY RESULT
```

| Stage | What happens |
| --- | --- |
| **Observe** | The agent pulls in raw evidence — authentication events, host/process activity, network activity — for the incident under investigation. |
| **Investigate** | Individual tools (`search_security_logs`, `check_system_activity`) surface the specific events relevant to the suspected actor/IP. |
| **Correlate** | `analyze_evidence` joins authentication, host, and network signals into a single timeline/narrative. |
| **Assess** | The agent evaluates whether the correlated sequence constitutes a credible incident, rather than isolated noise. |
| **Recommend** | The agent proposes a containment action (e.g., blocking an IP) with the evidence behind the recommendation. |
| **Human Approval** | A human analyst reviews the evidence and the recommendation, and explicitly approves or rejects the action. High-impact containment never proceeds without this step. |
| **Action** | Only after approval, `block_ip` records the containment action. |
| **Verify Result** | The recorded action and the underlying evidence remain inspectable, so the outcome can be checked against what was approved. |

## Human-in-the-loop design

CyberForge is deliberately not autonomous at the point that matters most:

- The agent **investigates and recommends** — it can search logs, correlate evidence, and propose a containment action.
- **High-impact containment requires human approval.** The agent does not call `block_ip` on its own initiative.
- **After approval**, the approved action is recorded via `block_ip`, which writes to local, simulated firewall data only.
- The evidence trail that led to the recommendation remains visible before and after the decision, so the human's approval is an informed one, not a rubber stamp.

```text
OBSERVATION --> ANALYSIS --> RECOMMENDATION --> HUMAN DECISION --> ACTION
```

## MCP architecture and security tools

<div align="center">
  <img src="assets/cyberforge_ai_agent_architecture.svg" alt="CyberForge agent and MCP architecture" width="100%" />
</div>

```text
AI / Agent --> MCP --> CyberForge tools --> Evidence layer
```

The agent talks to CyberForge exclusively through MCP tools — it never touches the evidence files directly. This keeps every action the agent takes auditable and swappable.

| Tool | Purpose |
| --- | --- |
| `search_security_logs` | Search synthetic authentication events for users, IP addresses, or indicators. |
| `analyze_evidence` | Correlate authentication, process, and network evidence into an incident narrative. |
| `check_system_activity` | Inspect simulated processes and active network connections. |
| `block_ip` | Record a simulated firewall containment action after explicit human approval. |

> [!WARNING]
> `block_ip` is a simulation. It only modifies this repository's local firewall data. It does not block traffic on the host machine or an external network. A production deployment must add authentication, authorization, approval, and audit controls before any real containment action.

## Demo incident: `INC-1024`

<div align="center">
  <img src="assets/incident_signal_chain.svg" alt="INC-1024 incident signal chain" width="90%" />
</div>

`INC-1024` models an SSH brute-force sequence associated with `10.0.0.25` that progresses through the following signals:

| Stage | Observed signal |
| --- | --- |
| 1. SSH brute force | Repeated authentication failures. |
| 2. Successful login | A successful login from `10.0.0.25`. |
| 3. Host activity | `suspicious.py` executes on the host. |
| 4. Network signal | A TCP connection is established on port `4444`. |
| 5. Human review | Evidence is reviewed before any containment decision. |

The evidence is committed locally, making the scenario repeatable: **inspect → replay → analyze → compare**.

## Evidence correlation

<div align="center">
  <img src="assets/incident_evidence_correlation.svg" alt="Evidence correlation across authentication, process, and network signals" width="90%" />
</div>

| Evidence source | Signal |
| --- | --- |
| Authentication log | 45 failed attempts, then 3 successful logins from `10.0.0.25`. |
| Host | `python3 suspicious.py` running as `admin` immediately after login. |
| Network | A TCP connection on port `4444`, correlated with the host activity. |

The strength of the investigation comes from correlation, not a single event. A failed login can be noise; a connected sequence of login, process, and network activity is a stronger incident signal.

## Simulated firewall / containment behavior

`block_ip` represents the containment action a human analyst has approved. It:

- Writes a record to this repository's local firewall state only.
- Does **not** modify the real host firewall, any OS-level firewall rule, or any external network device.
- Does **not** send any traffic or configuration to a real firewall, router, or cloud security group.

This keeps the demo safe to run repeatedly on any machine without side effects outside the repository. `INC-1024`'s underlying evidence is committed/local data, as described above; the firewall state that `block_ip` writes to is separate local state produced by running the tool.

## TrueForge Integration

The TrueForge bridge is a separate project/folder from this CyberForge repository, not part of the code here.

CyberForge is designed to run as an agent through the TrueForge harness. This repository provides the MCP server and the security investigation tools (`search_security_logs`, `analyze_evidence`, `check_system_activity`, `block_ip`) over a standard MCP transport; the TrueForge bridge/integration that connects those tools to a running agent is maintained separately from this repository.

## Quick start

### Requirements

| Dependency | Version / purpose |
| --- | --- |
| Node.js | 20 or newer; runs the MCP server. |
| Python | 3.x; runs the local evidence-analysis tools. |
| MCP-compatible client | Connects to the server over standard input/output (e.g., TrueForge). |

### Install and start

```bash
# Install MCP server dependencies
npm install

# Start the MCP server over standard input/output
npm run mcp
```

The Python tools currently use only the standard library, so no Python package installation is required.

### Run the investigation manually

```bash
# Correlate the demo incident
python mcp_server/tools/analyze_evidence.py

# Search authentication events for the suspicious address
python mcp_server/tools/search_security_logs.py 10.0.0.25

# Inspect simulated host and network activity
python mcp_server/tools/check_system_activity.py

# Simulate containment (writes only local fixture data)
python mcp_server/tools/block_ip.py
```

## Running the demo (~3 minutes)

1. **Introduce CyberForge** — one line: an AI SOC agent that correlates evidence and recommends containment, with a human approving the final action.
2. **Show the incident** — open `INC-1024`: an SSH brute-force sequence from `10.0.0.25`.
3. **Run the agent** — trigger `analyze_evidence` (via TrueForge or directly) against `INC-1024`.
4. **Show investigation/evidence correlation** — walk through the authentication, host, and network signals side by side (`incident_evidence_correlation.svg`).
5. **Show the timeline** — the correlated signal chain (`incident_signal_chain.svg`) showing how the events connect into one narrative.
6. **Show human approval** — the point where the agent's recommendation is presented and a human explicitly approves the containment action.
7. **Show progression after approval** — `block_ip` is called and recorded.
8. **Show the resulting action** — the recorded, simulated containment entry produced by `block_ip`.
9. **Show the final result** — confirm the incident evidence, the recommendation, and the approved action all line up, closing the loop.

## Project structure

```text
CyberForge/
|- assets/                 Local README artwork and diagrams
|- mcp_server/
|  |- server.js            MCP tool registration
|  |- tools/               Python investigation and simulation tools
|  `- data/                Committed synthetic evidence
|- agent/                  Agent design and risk-scoring space
|- app/                    API application space
`- frontend/               Investigation interface space
```

## Qodo Code Review Evidence

CyberForge used Qodo Code Review during development.

### Representative reviewed PR

- [fix: address qodo review findings](https://github.com/Simran-kaur7/CyberForge/pull/3) — merged PR addressing findings raised by Qodo Code Review.

## Reproducibility

CyberForge's demo is designed to be repeatable, not one-off:

- **Synthetic/local evidence** — `INC-1024`'s authentication, host, and network signals are committed data files, not live external logs.
- **Repeatable demo incident** — because the evidence is fixed and local, the same investigation produces the same correlated narrative every run.
- **Inspect → replay → analyze → compare** — a reviewer can open the raw evidence files directly, re-run the tools independently, and compare the tool output against the raw data to confirm the correlation is genuine rather than scripted for the demo.

## Security & limitations

- All evidence in this demo is **synthetic/local data**, not real production logs.
- Containment via `block_ip` is a **simulation**: it only writes to local fixture data and never touches a real firewall, host, or network device.
- Every containment action requires **explicit human approval** before it is recorded.
- This project is a hackathon demonstration. A production deployment would additionally require real authentication, authorization, and auditing controls around every tool call, plus appropriate safety review before any tool is given the ability to act on real infrastructure.

## Design principles

1. **Evidence first** — every conclusion needs evidence behind it.
2. **Correlation over isolation** — a sequence of related events is stronger than one event alone.
3. **Explain before act** — the system should explain why an incident is suspicious before recommending containment.
4. **Human before containment** — high-impact actions require human approval.
5. **Reproducible by design** — committed evidence should reproduce the same investigation scenario.
6. **Inspectable infrastructure** — logs, tools, evidence, and simulated actions remain visible.

## License

Released under the [MIT License](LICENSE).