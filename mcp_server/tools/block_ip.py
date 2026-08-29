import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
FIREWALL_FILE = DATA_DIR / "simulated_firewall.json"

# Strict IPv4 pattern: four groups of 1-3 digits, full string match
_IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")


def _validate_ipv4(ip: str) -> bool:
    """Return True only for valid IPv4 addresses (0-255 per octet)."""
    if not isinstance(ip, str):
        return False
    m = _IPV4_RE.match(ip.strip())
    if not m:
        return False
    for octet_str in m.groups():
        try:
            if int(octet_str) > 255:
                return False
        except (ValueError, TypeError):
            return False
    return True


def block_ip(ip_address: str) -> dict:
    """Simulate blocking an IP in the CyberForge lab firewall."""

    if not ip_address:
        return {
            "success": False,
            "error": "IP address is required"
        }

    # Strict IPv4 validation — reject malformed or out-of-range addresses
    if not _validate_ipv4(ip_address):
        return {
            "success": False,
            "error": "Invalid IP address format"
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

    # Atomic write: write to a temp file, then rename to prevent
    # a concurrent reader from seeing a partially written file.
    import tempfile
    firewall_dir = FIREWALL_FILE.parent
    firewall_dir.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_path = tempfile.mkstemp(
        dir=str(firewall_dir), suffix=".tmp", prefix="firewall_"
    )
    try:
        with os.fdopen(tmp_fd, 'w', encoding='utf-8') as f:
            f.write(json.dumps(firewall, indent=2))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, str(FIREWALL_FILE))
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    return {
        "success": True,
        "mode": "SIMULATED",
        "action": "BLOCK_IP",
        "ip": ip_address,
        "message": f"Simulated firewall block applied to {ip_address}"
    }


if __name__ == "__main__":
    print(json.dumps(block_ip("10.0.0.25"), indent=2))