import hashlib
import re
from dataclasses import dataclass, field
from typing import Optional

SEVERITIES = ("critical", "high", "medium", "low")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# Folders that are not scanned
SKIP_DIRS = ("node_modules", ".git", ".next", ".nuxt", ".svelte-kit", "dist", "build", "out",
             "vendor", ".venv", "venv", "__pycache__", ".cache", "coverage", ".turbo",
             ".vercel", ".goldeneye-check")


@dataclass
class Finding:
    rule: str
    engine: str
    severity: str
    category: str
    file: str
    line: Optional[int]
    title: dict
    fix: dict
    cwe: Optional[str] = None
    detail: dict = field(default_factory=dict)
    snippet: Optional[str] = None
    in_history: bool = False
    commit: Optional[str] = None
    # part of the fingerprint that does not depend on the line number
    anchor: Optional[str] = None
    # the report shows only the severity and category
    locked: bool = False

    def fingerprint(self) -> str:
        base = self.anchor if self.anchor is not None else re.sub(r"\s+", " ", (self.snippet or "")).strip()
        raw = f"{self.rule}|{self.file}|{base or self.line}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]

    def text(self, attr: str, lang: str) -> str:
        value = getattr(self, attr) or {}
        return value.get(lang) or value.get("en") or ""


def mask_secret(value: str) -> str:
    """Keeps the first 6 and the last 2 characters."""
    value = value.strip().strip("\"'")
    if len(value) <= 10:
        return "•" * 6
    return f"{value[:6]}…{value[-2:]}"


_QUOTED = re.compile(r"""(["'`])([^"'`\s]{6,})\1""")


def mask_quoted(line: str) -> str:
    return _QUOTED.sub(lambda m: m.group(1) + mask_secret(m.group(2)) + m.group(1), line)
