"""Stage 1 from the documentation: purpose, declared measures and admitted limitations.

The README and the other documents in the project root and docs/ are read without AI, with a
dictionary of phrases in Russian, Kazakh and English. Declared measures go to stage 6 (declaration
against implementation), admitted limitations mark findings as known (stage 8), and the purpose
tells what the system protects.
"""

import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from ..i18n_phrases import CLAIMS, LIMIT_TOPICS, PURPOSE
from ..i18n_phrases import LIMITS_HEADING as _LIMITS
from .context import Context, _read

DOC_NAMES = re.compile(r"^(readme|security|deploy|install|architecture)[\w.-]*\.(md|rst|txt|adoc)$", re.I)
HEADING = re.compile(r"^\s{0,3}(#{1,6})\s+(.*)$|^(.+)\n[=-]{3,}\s*$")
LIMITS_HEADING = re.compile(_LIMITS, re.I)


@dataclass
class Claim:
    key: str
    category: str
    file: str
    line: int
    text: str


@dataclass
class Docs:
    files: list = field(default_factory=list)
    purpose: list = field(default_factory=list)      # asset classes from the description
    claims: list = field(default_factory=list)
    limitations: list = field(default_factory=list)  # (file, line, text)
    known_rules: set = field(default_factory=set)    # rule keys explained by an admitted limitation
    plans_proxy: bool = False

    def to_json(self) -> dict:
        return {"files": self.files, "purpose": self.purpose,
                "claims": [{"key": c.key, "category_code": c.category, "file": c.file, "line": c.line, "text": c.text}
                           for c in self.claims],
                "limitations": [{"file": f, "line": n, "text": t} for f, n, t in self.limitations],
                "plans_reverse_proxy": self.plans_proxy}


def _doc_files(ctx: Context) -> list:
    out = []
    for rel in sorted(ctx.files):
        p = PurePosixPath(rel)
        top = len(p.parts) == 1 or (len(p.parts) == 2 and p.parts[0].lower() in ("docs", "doc"))
        if top and DOC_NAMES.match(p.name):
            out.append(rel)
    return out


def build(ctx: Context) -> Docs:
    docs = Docs(files=_doc_files(ctx))
    seen = set()
    intro = []
    for rel in docs.files:
        lines = _read(ctx.root / rel).splitlines()
        in_limits, in_code = False, False
        for i, line in enumerate(lines, 1):
            if line.strip().startswith("```"):
                in_code = not in_code
                continue
            if in_code:
                continue
            m = HEADING.match(line)
            if m:
                in_limits = bool(LIMITS_HEADING.search(m.group(2) or ""))
                continue
            text = line.strip().lstrip("-*0123456789. ").strip()
            if not text:
                continue
            if len(intro) < 8:
                intro.append(text)
            if in_limits:
                docs.limitations.append((rel, i, text))
                continue
            for key, (category, pattern) in CLAIMS.items():
                if key not in seen and re.search(pattern, text, re.I):
                    seen.add(key)
                    docs.claims.append(Claim(key, category, rel, i, text[:200]))
    head = " ".join(intro)
    docs.purpose = [k for k, rx in PURPOSE.items() if re.search(rx, head, re.I)]
    limits_text = " ".join(t for _f, _n, t in docs.limitations)
    for topic, (rx, rules) in LIMIT_TOPICS.items():
        if re.search(rx, limits_text, re.I):
            docs.known_rules.update(rules)
            if topic == "proxy":
                docs.plans_proxy = True
    return docs
