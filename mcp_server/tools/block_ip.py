import json
from datetime import datetime, timezone
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
FIREWALL_FILE = DATA_DIR / "simulated_firewall.json"


def block_ip(ip_address: str) -> dict:
    """Simulate blocking an IP in the CyberForge lab firewall."""

    if not ip_address:
        return {
            "success": False,
            "error": "IP address is required"
        }

    if FIREWALL_FILE.exists():
        firewall = json.loads(
            FIREWALL_FILE.read_text(encoding="utf-8")
        )
    else:
        firewall = {
            "blocked_ips": [],
            "events": []
        }

    blocked_ips = firewall.setdefault("blocked_ips", [])
    events = firewall.setdefault("events", [])

    if ip_address not in blocked_ips:
        blocked_ips.append(ip_address)

    events.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": "BLOCK_IP",
        "ip": ip_address,
        "mode": "SIMULATED"
    })

    FIREWALL_FILE.write_text(
        json.dumps(firewall, indent=2),
        encoding="utf-8"
    )

    return {
        "success": True,
        "mode": "SIMULATED",
        "action": "BLOCK_IP",
        "ip": ip_address,
        "message": f"Simulated firewall block applied to {ip_address}"
    }


if __name__ == "__main__":
    print(json.dumps(block_ip("10.0.0.25"), indent=2))