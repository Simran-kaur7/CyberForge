import json
import re
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
AUTH_LOG = DATA_DIR / "auth.log"


def search_security_logs(query: str = "") -> dict:
    """Search the synthetic authentication log."""
    if not AUTH_LOG.exists():
        return {
            "success": False,
            "error": "auth.log not found"
        }

    lines = AUTH_LOG.read_text(encoding="utf-8").splitlines()

    if not query:
        matches = lines
    else:
        pattern = re.compile(re.escape(query), re.IGNORECASE)
        matches = [line for line in lines if pattern.search(line)]

    failed = sum("Failed password" in line for line in matches)
    successful = sum("Accepted password" in line for line in matches)

    return {
        "success": True,
        "query": query,
        "match_count": len(matches),
        "failed_logins": failed,
        "successful_logins": successful,
        "matches": matches
    }


if __name__ == "__main__":
    import sys

    query = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.25"

    print(json.dumps(search_security_logs(query), indent=2))