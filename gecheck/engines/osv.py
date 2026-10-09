"""Зависимости: osv-scanner по lock-файлам (npm, pip, composer, go и др.).

В онлайн-режиме в базу OSV уходят только названия и версии пакетов, код — никогда.
С --offline база скачивается целиком и проверка идёт локально.
"""

import json
import re
from pathlib import Path

from ..i18n import TEXTS, tri
from ..model import SEV_RANK, Finding
from .base import rel_path, run_engine


def _vkey(v: str):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4])


def _severity_from_score(score: str) -> str:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return ""
    return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low"


GHSA_SEV = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}


def _fixed_version(vulns, name, current):
    """Минимальная версия, в которой закрыты все найденные уязвимости пакета."""
    need = []
    for v in vulns:
        candidates = []
        for aff in v.get("affected", []):
            if aff.get("package", {}).get("name") != name:
                continue
            for rng in aff.get("ranges", []):
                for ev in rng.get("events", []):
                    fixed = ev.get("fixed")
                    if fixed and _vkey(fixed) > _vkey(current):
                        candidates.append(fixed)
        if candidates:
            need.append(min(candidates, key=_vkey))
    return max(need, key=_vkey) if need else None


def scan(root: Path, warnings: list, offline: bool = False):
    args = ["scan", "source", "-r", "--format", "json"]
    if offline:
        args += ["--offline-vulnerabilities", "--download-offline-databases"]
    proc = run_engine("osv-scanner", args + [str(root)])
    if not proc.stdout.strip():
        if "No package sources found" not in proc.stderr:
            warnings.append(f"osv-scanner: {proc.stderr.strip()[:200]}")
        return []
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        warnings.append("osv-scanner: не удалось прочитать результат")
        return []

    findings = []
    for result in data.get("results") or []:
        file = rel_path(root, result.get("source", {}).get("path", ""))
        for pkg in result.get("packages") or []:
            info = pkg.get("package", {})
            name, current = info.get("name", "?"), info.get("version", "?")
            vulns = pkg.get("vulnerabilities") or []
            if not vulns:
                continue
            sev = "low"
            for g in pkg.get("groups") or []:
                s = _severity_from_score(g.get("max_severity"))
                if s and SEV_RANK[s] < SEV_RANK[sev]:
                    sev = s
            for v in vulns:
                s = GHSA_SEV.get(str((v.get("database_specific") or {}).get("severity", "")).upper())
                if s and SEV_RANK[s] < SEV_RANK[sev]:
                    sev = s
            ids = []
            for v in vulns:
                cve = next((a for a in v.get("aliases", []) if a.startswith("CVE-")), None)
                ids.append(cve or v.get("id"))
            fixed = _fixed_version(vulns, name, current)
            fix = (tri(TEXTS["dependency"]["fix"], name=name, fixed=fixed) if fixed
                   else tri(TEXTS["dependency"]["fix_nofix"], name=name))
            findings.append(Finding(
                rule=f"osv.{info.get('ecosystem', 'pkg').lower()}", engine="osv-scanner",
                severity=sev, category="dependencies", file=file, line=None,
                title=tri(TEXTS["dependency"]["title"], name=name, version=current), fix=fix,
                cwe="CWE-1395", detail=tri(TEXTS["dependency"]["detail"], ids=", ".join(sorted(set(ids)))),
                anchor=f"{name}@{current}",
            ))
    return findings


def version() -> str:
    from ..install import OSV
    return OSV
