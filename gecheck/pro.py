"""GoldenEye Check Pro: account, check packages and Pro rules from the goldeneye.kz server.

The server receives only the email, the login code and the project id (a hash of the git remote
or the folder name). The code is checked on this computer. Pro rules are downloaded for one check
and deleted after it.
"""

import json
import os
import re
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

from . import __version__
from .paths import home

BUY_URL = "https://goldeneye.kz/en/check/#plans"
UA = f"GoldenEye-Check/{__version__}"
RULE_FILE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,60}\.yaml$")


class ApiError(Exception):
    def __init__(self, status, code):
        super().__init__(code)
        self.status, self.code = status, code


def server() -> str:
    return os.environ.get("GECHECK_PRO_SERVER", "https://goldeneye.kz/api/pro").rstrip("/")


def _state_file() -> Path:
    return home() / "account.json"


def load_state() -> dict:
    try:
        return json.loads(_state_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_state(state: dict):
    p = _state_file()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(state, indent=2), encoding="utf-8")
    if os.name != "nt":
        p.chmod(0o600)


def token():
    """Token from gecheck login, or from GECHECK_TOKEN (for CI)."""
    return os.environ.get("GECHECK_TOKEN") or load_state().get("token")


def call(endpoint: str, payload=None, token=None, timeout=30) -> dict:
    data = json.dumps(payload or {}).encode("utf-8")
    req = urllib.request.Request(f"{server()}/{endpoint}", data=data, method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": UA})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode("utf-8"))
        except Exception:
            body = {}
        raise ApiError(e.code, body.get("error", "http_error")) from None
    except (urllib.error.URLError, OSError, ValueError):
        raise ApiError(0, "network") from None


def explain(err: ApiError) -> str:
    return {
        "unauthorized": "Your login has expired. Log in again: gecheck login",
        "no_credits": f"No Pro checks left in your package. Packages: {BUY_URL}",
        "rate_limited": "Too many attempts. Wait a few minutes and try again.",
        "bad_code": "The code is wrong or expired. Request a new one: gecheck login",
        "mail_failed": "Could not send the email with the code. Try again in a few minutes.",
        "rules_missing": "Pro rules are temporarily unavailable. No check was used.",
        "not_configured": "The Pro server is not available yet.",
        "network": "Cannot reach goldeneye.kz. Check your internet connection.",
    }.get(err.code, f"Server error: {err.code}")


def quote(tok: str, project_id: str) -> dict:
    """Whether a Pro check of this project is free and how many checks are left. Nothing is charged."""
    return call("rules.php", {"project_id": project_id, "confirm": False}, token=tok)


def fetch_rules(tok: str, project_id: str):
    """Charges 1 check (unless the re-check is free) and saves the rules to a temp folder.

    Returns (folder, server response). The caller deletes the folder after the scan.
    """
    res = call("rules.php", {"project_id": project_id, "confirm": True}, token=tok)
    folder = Path(tempfile.mkdtemp(prefix="gecheck-pro-"))
    for item in res.get("rules", []):
        name = str(item.get("name", ""))
        if RULE_FILE.match(name):
            (folder / name).write_text(str(item.get("content", "")), encoding="utf-8")
    return folder, res
