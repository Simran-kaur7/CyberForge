/**
 * CyberForge Dashboard — loads and displays investigation sessions.
 */

const API_BASE = '../mcp_server/data';

async function loadIncidents() {
  const container = document.getElementById('incidents-list');
  try {
    const res = await fetch(`${API_BASE}/sessions.json`);
    if (!res.ok) {
      container.innerHTML = renderEmptyState();
      return;
    }
    const sessions = await res.json();
    if (!sessions || sessions.length === 0) {
      container.innerHTML = renderEmptyState();
      return;
    }
    // Sort by most recent
    sessions.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    container.innerHTML = sessions.map(renderIncidentCard).join('');
  } catch (err) {
    container.innerHTML = renderEmptyState();
  }
}

function renderEmptyState() {
  return `
    <div class="empty-state">
      <p>No investigations yet. Start one from Quick Actions below.</p>
    </div>
  `;
}

function renderIncidentCard(session) {
  const riskLevel = session.risk_score?.level || 'UNKNOWN';
  const riskClass = `risk-${riskLevel.toLowerCase()}`;
  const date = new Date(session.created_at).toLocaleString();
  const status = session.status || 'active';
  const approvalState = session.approval_state?.status || '';

  return `
    <div class="incident-card" onclick="openIncident('${session.id}')">
      <div class="incident-card-header">
        <span class="incident-id">${session.incident_id}</span>
        <span class="risk-badge ${riskClass}">${riskLevel}</span>
      </div>
      <div class="incident-card-meta">
        <span class="session-id">Session: ${session.id}</span>
        <span class="incident-date">${date}</span>
      </div>
      <div class="incident-card-footer">
        <span class="status-badge status-${status}">${status}</span>
        ${approvalState ? `<span class="approval-badge approval-${approvalState}">${approvalState}</span>` : ''}
      </div>
    </div>
  `;
}

function openIncident(sessionId) {
  window.location.href = `incident.html?session=${sessionId}`;
}

async function startNewInvestigation(incidentId) {
  // Create a new session and navigate to it
  try {
    const res = await fetch(`${API_BASE}/sessions.json`);
    let sessions = [];
    if (res.ok) {
      sessions = await res.json();
    }

    const newSession = {
      id: Math.random().toString(36).substring(2, 10),
      incident_id: incidentId,
      status: 'active',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      evidence_snapshot: { source_ip: '10.0.0.25' },
      risk_score: null,
      approval_state: null,
      actions: [],
      findings: [],
    };

    sessions.push(newSession);

    // Note: In production this would be a POST to the API.
    // For the lab, we store in localStorage as a fallback.
    localStorage.setItem('cyberforge_pending_session', JSON.stringify(newSession));
    window.location.href = `incident.html?session=${newSession.id}&new=1`;
  } catch (err) {
    console.error('Failed to create session:', err);
  }
}

function runRiskScore() {
  window.location.href = 'incident.html?session=demo&showRiskOnly=1';
}

function checkSystemActivity() {
  window.location.href = 'incident.html?session=demo&showActivityOnly=1';
}

// Initialize
document.addEventListener('DOMContentLoaded', loadIncidents);
