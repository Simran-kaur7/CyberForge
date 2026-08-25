import json
import subprocess
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = PROJECT_ROOT / "mcp_server" / "tools"

TOOL_TIMEOUT_SECONDS = 15
MAX_ERROR_OUTPUT = 500


def run_tool(script_name: str, *args: str) -> dict:
    script_path = TOOLS_DIR / script_name

    try:
        result = subprocess.run(
            ["python3", str(script_path), *args],
            cwd=TOOLS_DIR,
            capture_output=True,
            text=True,
            check=False,
            timeout=TOOL_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = (exc.stdout or "").strip()
        stderr = (exc.stderr or "").strip()

        details = []

        if args:
            details.append(f"args={args}")

        if stdout:
            details.append(f"stdout={stdout[-MAX_ERROR_OUTPUT:]}")

        if stderr:
            details.append(f"stderr={stderr[-MAX_ERROR_OUTPUT:]}")

        context = "; ".join(details)

        raise RuntimeError(
            f"{script_name} timed out after "
            f"{TOOL_TIMEOUT_SECONDS} seconds"
            + (f" ({context})" if context else "")
        ) from exc

    if result.returncode != 0:
        raise RuntimeError(
            f"{script_name} failed: "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"{script_name} returned invalid JSON"
        ) from exc


def analyze_evidence() -> dict:
    return run_tool("analyze_evidence.py")


def search_security_logs(query: str = "") -> dict:
    return run_tool("search_security_logs.py", query)


def check_system_activity() -> dict:
    return run_tool("check_system_activity.py")


def block_ip(ip_address: str) -> dict:
    return run_tool("block_ip.py", ip_address)