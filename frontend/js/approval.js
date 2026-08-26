/**
 * CyberForge Approval Gate — handles approve/reject for containment actions.
 *
 * In the lab, this writes to the local simulated firewall data.
 * In production, this would call the TrueForge SDK approval API.
 */

let pendingActionId = null;
let sessionId = null;

function handleApprove() {
  if (!pendingActionId) {
    // Demo mode — simulate the approval
    pendingActionId = 'demo-' + Math.random().toString(36).substring(2, 8);
  }

  const statusEl = document.getElementById('approval-status');
  const actionsEl = document.getElementById('approval-actions');
  const targetIp = document.getElementById('target-ip')?.textContent || '10.0.0.25';

  statusEl.innerHTML = `
    <div class="approval-status-pending">
      <span class="spinner"></span> Executing containment action...
    </div>
  `;

  // Simulate the block_ip action
  setTimeout(() => {
    statusEl.innerHTML = `
      <div class="approval-status-approved">
        <strong>&#9989; Approved &amp; Executed</strong>
        <p>IP <code>${targetIp}</code> has been blocked in the simulated firewall.</p>
        <p class="approval-timestamp">Decided at: ${new Date().toLocaleString()}</p>
      </div>
    `;
    actionsEl.style.display = 'none';

    // Add to timeline
    if (window._activityStream) {
      window._activityStream.addEvent(
        'containment',
        `BLOCK_IP ${targetIp} approved and executed — simulated firewall updated`
      );
    }

    // Store approval in session
    updateSessionApproval('approved', targetIp);
  }, 800);
}

function handleReject() {
  const statusEl = document.getElementById('approval-status');
  const actionsEl = document.getElementById('approval-actions');
  const targetIp = document.getElementById('target-ip')?.textContent || '10.0.0.25';

  statusEl.innerHTML = `
    <div class="approval-status-rejected">
      <strong>&#10060; Rejected</strong>
      <p>Containment action for <code>${targetIp}</code> has been rejected. No changes made.</p>
      <p class="approval-timestamp">Decided at: ${new Date().toLocaleString()}</p>
    </div>
  `;
  actionsEl.style.display = 'none';

  if (window._activityStream) {
    window._activityStream.addEvent(
      'approval',
      `BLOCK_IP ${targetIp} rejected by analyst — no containment applied`
    );
  }

  updateSessionApproval('rejected', targetIp);
}

function updateSessionApproval(status, ip) {
  try {
    const pending = localStorage.getItem('cyberforge_pending_session');
    if (pending) {
      const session = JSON.parse(pending);
      session.approval_state = {
        action_id: pendingActionId || 'demo',
        action_type: 'BLOCK_IP',
        action_detail: { ip_address: ip },
        status: status,
        decided_at: new Date().toISOString(),
        decided_by: 'analyst',
      };
      session.status = status === 'approved' ? 'contained' : 'rejected';
      localStorage.setItem('cyberforge_pending_session', JSON.stringify(session));
    }
  } catch (err) {
    console.error('Failed to update session:', err);
  }
}

// Check for existing approval state on page load
document.addEventListener('DOMContentLoaded', () => {
  try {
    const pending = localStorage.getItem('cyberforge_pending_session');
    if (pending) {
      const session = JSON.parse(pending);
      sessionId = session.id;
      if (session.approval_state?.status) {
        const statusEl = document.getElementById('approval-status');
        const actionsEl = document.getElementById('approval-actions');
        if (session.approval_state.status === 'approved') {
          statusEl.innerHTML = `
            <div class="approval-status-approved">
              <strong>&#9989; Previously Approved</strong>
              <p>IP <code>10.0.0.25</code> was blocked at ${new Date(session.approval_state.decided_at).toLocaleString()}</p>
            </div>
          `;
          actionsEl.style.display = 'none';
        } else if (session.approval_state.status === 'rejected') {
          statusEl.innerHTML = `
            <div class="approval-status-rejected">
              <strong>&#10060; Previously Rejected</strong>
              <p>Containment was rejected at ${new Date(session.approval_state.decided_at).toLocaleString()}</p>
            </div>
          `;
          actionsEl.style.display = 'none';
        }
      }
    }
  } catch (err) {
    // Ignore
  }
});
