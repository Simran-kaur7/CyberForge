/**
 * CyberForge Incident Detail — loads evidence and populates the incident page.
 */

const DATA_BASE = '../mcp_server/data';

// Demo evidence data for INC-1024 (used when no backend is available)
const DEMO_EVIDENCE = {
  auth: {
    success: true,
    query: '10.0.0.25',
    match_count: 48,
    failed_logins: 45,
    successful_logins: 3,
    matches: [
      'Aug 24 10:01:01 cyberforge sshd[1001]: Failed password for admin from 10.0.0.25 port 51001 ssh2',
      '... (45 failed attempts over 5 minutes)',
      'Aug 24 10:06:16 cyberforge sshd[1046]: Accepted password for admin from 10.0.0.25 port 51046 ssh2',
      'Aug 24 10:06:22 cyberforge sshd[1047]: Accepted password for admin from 10.0.0.25 port 51047 ssh2',
      'Aug 24 10:06:28 cyberforge sshd[1048]: Accepted password for admin from 10.0.0.25 port 51048 ssh2',
    ],
  },
  host: {
    success: true,
    process_count: 3,
    suspicious_process_count: 1,
    unusual_connection_count: 2,
    suspicious_processes: [
      { pid: 4242, user: 'admin', command: 'python3 suspicious.py', started: '2026-08-24T10:06:35', status: 'running' },
    ],
    unusual_connections: [
      '2026-08-24T10:06:40 connection src=10.0.0.10 dst=10.0.0.25 port=4444 protocol=tcp status=established',
      '2026-08-24T10:06:45 connection src=10.0.0.10 dst=10.0.0.25 port=4444 protocol=tcp status=established',
    ],
  },
  analysis: {
    success: true,
    incident_id: 'INC-1024',
    source_ip: '10.0.0.25',
    findings: [
      'High volume of failed SSH authentication attempts.',
      'Successful SSH login occurred after repeated failures.',
      'Suspicious process detected after successful login.',
      'Unusual network connection to port 4444 detected.',
    ],
    risk_indicators: {
      failed_attempts: 45,
      successful_suspicious_login: true,
      suspicious_process: true,
      unusual_connection: true,
    },
  },
  risk: {
    score: 100,
    level: 'CRITICAL',
    max_score: 100,
    breakdown: {
      failed_attempts: { points: 20, reason: '45 failed attempts (≥20)' },
      successful_suspicious_login: { points: 25, reason: 'Successful login detected after repeated failures' },
      suspicious_process: { points: 25, reason: 'Suspicious process detected on host' },
      unusual_connection: { points: 20, reason: 'Unusual network connection detected' },
      known_bad_source: { points: 10, reason: 'Source IP 10.0.0.25 is on known-bad list' },
    },
  },
};

let currentSession = null;
let currentEvidence = DEMO_EVIDENCE;

async function loadIncidentData() {
  const params = new URLSearchParams(window.location.search);
  const sessionId = params.get('session') || 'demo';

  // Try to load session from localStorage or demo data
  const pendingSession = localStorage.getItem('cyberforge_pending_session');
  if (pendingSession) {
    currentSession = JSON.parse(pendingSession);
  }

  if (currentSession && currentSession.risk_score) {
    currentEvidence.risk = currentSession.risk_score;
  }

  // Try loading real data files; fall back to demo
  try {
    const [authRes, hostRes, analysisRes] = await Promise.all([
      fetch(`${DATA_BASE}/auth.log`).catch(() => null),
      fetch(`${DATA_BASE}/processes.json`).catch(() => null),
    ]);

    if (authRes?.ok) {
      // Parse auth log summary
      const authText = await authRes.text();
      const lines = authText.split('\n').filter(Boolean);
      currentEvidence.auth.match_count = lines.length;
      currentEvidence.auth.failed_logins = lines.filter(l => l.includes('Failed password')).length;
      currentEvidence.auth.successful_logins = lines.filter(l => l.includes('Accepted password')).length;
    }
    if (hostRes?.ok) {
      currentEvidence.host.processes_raw = await hostRes.json();
    }
  } catch (err) {
    // Use demo data
  }

  renderAll();
}

function renderAll() {
  renderAuthEvidence();
  renderHostEvidence();
  renderNetworkEvidence();
  renderFindings();
  renderRiskScore();
  initTimeline();
}

function renderAuthEvidence() {
  const el = document.getElementById('auth-evidence');
  const d = currentEvidence.auth;
  el.innerHTML = `
    <div class="evidence-stats">
      <div class="stat">
        <span class="stat-value stat-danger">${d.failed_logins}</span>
        <span class="stat-label">Failed Logins</span>
      </div>
      <div class="stat">
        <span class="stat-value stat-warning">${d.successful_logins}</span>
        <span class="stat-label">Successful Logins</span>
      </div>
      <div class="stat">
        <span class="stat-value">${d.match_count}</span>
        <span class="stat-label">Total Events</span>
      </div>
    </div>
    <div class="evidence-detail">
      <p>Source IP: <code>${d.query}</code></p>
      <p>Pattern: SSH brute-force (45 failures) followed by 3 successful logins within 12 seconds</p>
    </div>
  `;
}

function renderHostEvidence() {
  const el = document.getElementById('host-evidence');
  const d = currentEvidence.host;
  el.innerHTML = `
    <div class="evidence-stats">
      <div class="stat">
        <span class="stat-value">${d.process_count}</span>
        <span class="stat-label">Total Processes</span>
      </div>
      <div class="stat">
        <span class="stat-value stat-danger">${d.suspicious_process_count}</span>
        <span class="stat-label">Suspicious</span>
      </div>
    </div>
    <div class="evidence-detail">
      ${d.suspicious_processes.map(p => `
        <div class="evidence-item evidence-danger">
          <code>${p.command}</code>
          <span>PID ${p.pid} &mdash; user: ${p.user} &mdash; started: ${p.started}</span>
        </div>
      `).join('')}
    </div>
  `;
}

function renderNetworkEvidence() {
  const el = document.getElementById('network-evidence');
  const d = currentEvidence.host;
  el.innerHTML = `
    <div class="evidence-stats">
      <div class="stat">
        <span class="stat-value stat-danger">${d.unusual_connection_count}</span>
        <span class="stat-label">Unusual Connections</span>
      </div>
    </div>
    <div class="evidence-detail">
      ${d.unusual_connections.map(c => `
        <div class="evidence-item evidence-warning">
          <code>${c}</code>
        </div>
      `).join('')}
      <p class="evidence-note">C2 traffic on port 4444 correlates with suspicious.py execution timeline</p>
    </div>
  `;
}

function renderFindings() {
  const el = document.getElementById('findings-list');
  const findings = currentEvidence.analysis.findings;
  el.innerHTML = findings.map(f => `<li class="finding-item">${f}</li>`).join('');
}

function renderRiskScore() {
  const risk = currentEvidence.risk;

  // Update badge
  const badge = document.getElementById('risk-badge');
  badge.textContent = risk.level;
  badge.className = `risk-badge risk-${risk.level.toLowerCase()}`;

  // Update gauge
  const fill = document.getElementById('risk-gauge-fill');
  const label = document.getElementById('risk-gauge-label');
  const scoreNum = document.getElementById('risk-score-number');

  fill.style.width = `${risk.score}%`;
  fill.className = `risk-gauge-fill risk-fill-${risk.level.toLowerCase()}`;
  label.textContent = risk.level;
  scoreNum.textContent = `${risk.score}/${risk.max_score}`;

  // Update breakdown
  const breakdownEl = document.getElementById('risk-breakdown');
  breakdownEl.innerHTML = Object.entries(risk.breakdown)
    .map(([key, val]) => `
      <div class="breakdown-item ${val.points > 0 ? 'breakdown-active' : 'breakdown-inactive'}">
        <span class="breakdown-indicator">${val.points > 0 ? '&#9889;' : '&#9898;'}</span>
        <span class="breakdown-key">${key.replace(/_/g, ' ')}</span>
        <span class="breakdown-points">+${val.points}</span>
        <span class="breakdown-reason">${val.reason}</span>
      </div>
    `).join('');
}

function initTimeline() {
  const stream = new window.ActivityStream('activity-timeline');
  window._activityStream = stream;

  // Pre-populate with investigation events
  const events = [
    { type: 'investigation', message: 'Authentication log search initiated for 10.0.0.25', timestamp: '2026-08-24T10:07:00Z' 
