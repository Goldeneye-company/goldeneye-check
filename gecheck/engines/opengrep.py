"""Code analysis with opengrep using the rules from gecheck/rules."""

import json
import re
from pathlib import Path

from ..model import SKIP_DIRS, Finding, mask_quoted, mask_secret
from ..paths import RULES_DIR
from .base import rel_path, run_engine


# Passwords in seed scripts and tests are lowered to low
SEED_OR_TEST = re.compile(r"(^|/)(tests?|__tests__|spec|fixtures?|mocks?|seeds?|examples?)(/|$)"
                          r"|(^|/)seed[^/]*$|[._](test|spec)\.", re.I)


def _mask_snippet(snippet: str, metavars: dict) -> str:
    """Masks the $VALUE value, or all quoted strings if there is none."""
    value = ((metavars or {}).get("$VALUE") or {}).get("abstract_content")
    if value and len(value) >= 3:
        return snippet.replace(value, mask_secret(value))
    return mask_quoted(snippet)


def scan(root: Path, warnings: list, rules_dir: Path = RULES_DIR, engine: str = "opengrep"):
    args = ["scan", "--config", str(rules_dir), "--json", "--quiet", "--no-git-ignore",
            "--timeout", "20", "--max-target-bytes", "2000000"]
    for d in SKIP_DIRS:
        args += ["--exclude", d]
    proc = run_engine("opengrep", args + [str(root)])
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        warnings.append(f"opengrep: could not read the output ({proc.stderr.strip()[:200]})")
        return []
    for err in data.get("errors", []):
        if err.get("level") == "error" or err.get("type") == "SemgrepError":
            warnings.append(f"opengrep: {str(err.get('message'))[:200]}")

    findings = []
    for r in data.get("results", []):
        meta = (r.get("extra", {}).get("metadata") or {}).get("ge") or {}
        check_id = r["check_id"]
        rule = check_id[check_id.find("ge."):] if "ge." in check_id else check_id
        snippet = (r["extra"].get("lines") or "").strip()
        file = rel_path(root, r["path"])
        severity = meta.get("severity", "medium")
        if meta.get("category") == "secrets":
            snippet = _mask_snippet(snippet, r["extra"].get("metavars"))
            if SEED_OR_TEST.search(file):
                severity = "low"
        findings.append(Finding(
            rule=rule, engine=engine,
            severity=severity, category=meta.get("category", "code"),
            file=file, line=r["start"]["line"],
            title=meta.get("title", {}), fix=meta.get("fix", {}), cwe=meta.get("cwe"),
            snippet=snippet[:400],
        ))
    return findings


def version() -> str:
    from ..install import OPENGREP
    return OPENGREP
