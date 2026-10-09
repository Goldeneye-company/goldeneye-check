"""Runs the engines, merges findings and calculates the score."""

import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from . import __version__
from .engines import builtin, gitleaks, opengrep, osv
from .engines.base import EngineMissing
from .model import SEV_RANK, SEVERITIES, Finding


@dataclass
class Options:
    history: bool = True
    deps: bool = True
    offline: bool = False


@dataclass
class ScanResult:
    root: Path
    findings: list
    warnings: list
    engines: dict
    started_at: str
    duration: float
    git: dict = field(default_factory=dict)
    options: Options = field(default_factory=Options)
    kind: str = "code"  # "code" or "site"
    notice: Optional[dict] = None  # message above the list of findings, per language

    @property
    def counts(self):
        return {s: sum(1 for f in self.findings if f.severity == s) for s in SEVERITIES}

    def _counts(self, deps: bool):
        own = [f for f in self.findings if (f.category == "dependencies") == deps]
        return {s: sum(1 for f in own if f.severity == s) for s in SEVERITIES}

    @property
    def score(self) -> int:
        """100 minus a penalty: 25/10/4/1 for critical/high/medium/low.

        For dependencies 10/4/1, but no more than 30 in total.
        """
        c, d = self._counts(False), self._counts(True)
        code = 25 * c["critical"] + 10 * c["high"] + 4 * c["medium"] + c["low"]
        deps = min(30, 10 * d["critical"] + 4 * d["high"] + d["medium"])
        return max(0, 100 - code - deps)

    @property
    def grade(self) -> str:
        c, d, s = self._counts(False), self._counts(True), self.score
        if s < 25:
            return "F"
        if c["critical"] or s < 50:
            return "D"
        if c["high"] or d["critical"] or s < 75:
            return "C"
        if s < 90:
            return "B"
        return "A"

    @property
    def project_id(self) -> str:
        """First 16 characters of the sha256 of the origin URL or the folder name."""
        base = self.git.get("remote") or self.root.name
        return hashlib.sha256(base.encode("utf-8")).hexdigest()[:16]


# Which finding to keep when several engines report the same line with a secret
SECRET_PRIORITY = {"builtin": 0, "gitleaks": 1, "opengrep": 2}


def _dedupe(findings):
    best = {}
    rest = []
    for f in findings:
        if f.category == "secrets" and f.line is not None:
            key = (f.file, f.line)
            cur = best.get(key)
            if cur is None or SECRET_PRIORITY.get(f.engine, 9) < SECRET_PRIORITY.get(cur.engine, 9):
                best[key] = f
        else:
            rest.append(f)
    unique, seen = [], set()
    for f in rest + list(best.values()):
        fp = f.fingerprint()
        if fp not in seen:
            seen.add(fp)
            unique.append(f)
    return unique


def _git_info(root: Path) -> dict:
    if not (root / ".git").exists():
        return {}
    info = {}
    for key, args in (("commit", ["rev-parse", "--short", "HEAD"]),
                      ("branch", ["rev-parse", "--abbrev-ref", "HEAD"]),
                      ("remote", ["config", "--get", "remote.origin.url"])):
        proc = builtin._git(root, *args)
        if proc is not None and proc.returncode == 0 and proc.stdout.strip():
            info[key] = proc.stdout.strip()
    return info


def run(root: Path, options: Options = None, log=print) -> ScanResult:
    options = options or Options()
    root = Path(root).resolve()
    started = datetime.now(timezone.utc)
    t0 = time.monotonic()
    findings, warnings, engines = [], [], {}

    steps = [
        ("gitleaks", gitleaks.version(), lambda: gitleaks.scan(root, warnings, history=options.history)),
        ("opengrep", opengrep.version(), lambda: opengrep.scan(root, warnings)),
        ("builtin", __version__, lambda: builtin.scan(root, warnings)),
    ]
    if options.deps:
        steps.insert(1, ("osv-scanner", osv.version(), lambda: osv.scan(root, warnings, offline=options.offline)))

    for name, ver, fn in steps:
        log(f"  {name}…")
        try:
            found = fn()
            findings += found
            engines[name] = {"version": ver, "status": "ok", "findings": len(found)}
        except EngineMissing:
            engines[name] = {"version": ver, "status": "missing", "findings": 0}
            warnings.append(f"{name}: engine is not installed, run gecheck install")
        except Exception as exc:  # a failure in one engine does not stop the scan
            engines[name] = {"version": ver, "status": "error", "findings": 0}
            warnings.append(f"{name} failed: {str(exc)[:200]}")

    findings = _dedupe(findings)
    findings.sort(key=lambda f: (SEV_RANK.get(f.severity, 9), f.file, f.line or 0))
    return ScanResult(root=root, findings=findings, warnings=warnings, engines=engines,
                      started_at=started.isoformat(timespec="seconds"),
                      duration=round(time.monotonic() - t0, 1), git=_git_info(root), options=options)
