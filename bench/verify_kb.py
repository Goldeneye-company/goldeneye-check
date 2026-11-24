"""Confirms the KB of image defaults (gecheck/kb/defaults.json) on real images. Needs Docker.

    python bench/verify_kb.py           check every entry, exit 1 on a mismatch
    python bench/verify_kb.py --update  also write today's date to "checked" of entries that passed
"""

import json
import re
import subprocess
import sys
from datetime import date
from pathlib import Path

KB_FILE = Path(__file__).resolve().parent.parent / "gecheck" / "kb" / "defaults.json"


def run(check: dict) -> str:
    cmd = ["docker", "run", "--rm"]
    for key, value in check.get("env", {}).items():
        cmd += ["-e", f"{key}={value}"]
    cmd += ["--entrypoint", check["run"][0], check["image"], *check["run"][1:]]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    return proc.stdout.strip()


def main() -> int:
    update = "--update" in sys.argv
    data = json.loads(KB_FILE.read_text(encoding="utf-8"))
    failed = 0
    for entry in data["images"]:
        if not entry.get("verify"):
            print(f"{entry['id']:12} not verifiable automatically")
            continue
        ok = True
        for check in entry["verify"]:
            out = run(check)
            good = re.search(check["expect"], out) is not None
            ok = ok and good
            print(f"{entry['id']:12} {check['image']:22} {'ok' if good else 'MISMATCH'}  {out[:80]!r}")
        if ok and update:
            entry["checked"] = date.today().isoformat()
        failed += 0 if ok else 1
    if update:
        KB_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
