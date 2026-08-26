/**
 * CyberForge Activity Stream — renders the investigation timeline.
 */

class ActivityStream {
  constructor(containerId) {
    this.container = document.getElementById(containerId);
    this.events = [];
  }

  addEvent(type, message, timestamp = null) {
    this.events.push({
      type,
      message,
      timestamp: timestamp || new Date().toISOString(),
    });
    this.render();
  }

  setEvents(events) {
    this.events = events.sort(
      (a, b) => new Date(a.timestamp) - new Date(b.timestamp)
    );
    this.render();
  }

  render() {
    if (!this.container) return;
    if (this.events.length === 0) {
      this.container.innerHTML = '<p class="empty-state">No activity yet.</p>';
      return;
    }

    const icons = {
      investigation: '&#128269;',
      correlation: '&#128279;',
      risk: '&#128200;',
      approval: '&#9989;',
      containment: '&#128683;',
      info: '&#8505;&#65039;',
      error: '&#9888;&#65039;',
    };

    this.container.innerHTML = this.events
      .map((event) => {
        const icon = icons[event.type] || icons.info;
        const time = new Date(event.timestamp).toLocaleTimeString();
        return `
        <div class="timeline-item timeline-${event.type}">
          <div class="timeline-icon">${icon}</div>
          <div class="timeline-content">
            <div class="timeline-message">${event.message}</div>
            <div class="timeline-time">${time}</div>
          </div>
        </div>
      `;
      })
      .join('');
  }
}

// Export for use in other modules
window.ActivityStream = ActivityStream;
