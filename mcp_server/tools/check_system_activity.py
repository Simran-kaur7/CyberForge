import json
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
PROCESSES_FILE = DATA_DIR / "processes.json"
NETWORK_FILE = DATA_DIR / "network.log"


def check_system_activity() -> dict:
    """Inspect synthetic process and network activity."""
    if not PROCESSES_FILE.exists():
        return {
            "success": False,
            "error": "processes.json not found"
        }

    processes = json.loads(
        PROCESSES_FILE.read_text(encoding="utf-8")
    )

    network_lines = []
    if NETWORK_FILE.exists():
        network_lines = NETWORK_FILE.read_text(
            encoding="utf-8"
        ).splitlines()

    suspicious_processes = [
        process
        for process in processes
        if "suspicious" in process.get("command", "").lower()
    ]

    unusual_connections = [
        line
        for line in network_lines
        if "port=4444" in line
    ]

    return {
        "success": True,
        "process_count": len(processes),
        "suspicious_processes": suspicious_processes,
        "unusual_connections": unusual_connections,
        "suspicious_process_count": len(suspicious_processes),
        "unusual_connection_count": len(unusual_connections)
    }


if __name__ == "__main__":
    print(json.dumps(check_system_activity(), indent=2))