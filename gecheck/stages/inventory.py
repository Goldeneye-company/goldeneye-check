"""Stage 2, file inventory: roles of the files, what is missing, and what git would publish by mistake.

The list of missing files (production runtime configuration, web server configuration, migrations,
tests, CI, git) goes to the report section "Coverage and limitations". Files that are not excluded
by .gitignore but should be (scanner reports, dumps, logs and reports with internal addresses)
become findings of category N.
"""

import os
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from .. import kb
from ..i18n_code import CODE_WORDS
from ..model import SKIP_DIRS
from .context import Context, _read
from .findings import make

PRIVATE_IP = re.compile(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|"
                        r"172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b(?!/\d)")
REPORT_NAME = re.compile(r"(report|scan|audit|findings|results?|pentest|nuclei|zap|burp)[\w.-]*"
                         r"\.(html?|md|json|sarif|xml|txt|csv|pdf)$", re.I)
REPORT_DIRS = ("reports", "report", ".zap", "zap", "scan-results", "security-reports", ".goldeneye-check")
DUMP_EXT = (".dump", ".bak", ".sqlite", ".sqlite3", ".db", ".rdb")
LOG_EXT = (".log", ".har")

ROLES = {
    "entry": re.compile(r"(^|/)(index\.php|app\.py|main\.py|wsgi\.py|asgi\.py|manage\.py|server\.(js|ts)|"
                        r"app\.(js|ts)|main\.go|Application\.java)$"),
    "init": re.compile(r"(^|/)(bootstrap\.php|config\.php|settings\.py|config\.(js|ts)|application\.(properties|ya?ml))$"),
    "infra": re.compile(r"(^|/)(Dockerfile[\w.-]*|[\w.-]*\.Dockerfile|(docker-)?compose[\w.-]*\.ya?ml|Caddyfile|"
                        r"nginx\.conf|[\w.-]+\.conf|[\w.-]+\.ini|Procfile|[\w.-]+\.tf)$"),
    "secrets": re.compile(r"(^|/)(\.env[\w.-]*|secrets/.*|[\w.-]+\.(pem|key|p12|pfx|jks))$"),
}


@dataclass
class Inventory:
    roles: dict = field(default_factory=dict)       # role -> files
    absent: list = field(default_factory=list)      # what is missing: php_ini, web_server_config, ...
    exposed: list = field(default_factory=list)     # (file, kind) that git would publish

    def to_json(self) -> dict:
        return {"roles": self.roles, "absent": self.absent,
                "exposed": [{"file": f, "kind": k} for f, k in self.exposed]}


class GitIgnore:
    """The subset of .gitignore rules that matters here: globs, **, anchors, directories, negation."""

    def __init__(self, root: Path):
        self.rules = []  # (base dir, regex, negate, dir_only)
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d != ".git" and d not in ("node_modules", "vendor")]
            if ".gitignore" in filenames:
                base = Path(dirpath).relative_to(root).as_posix()
                base = "" if base == "." else base
                for raw in _read(Path(dirpath) / ".gitignore").splitlines():
                    self._add(base, raw)

    def _add(self, base: str, raw: str):
        line = raw.rstrip()
        if not line or line.startswith("#"):
            return
        negate = line.startswith("!")
        line = line[1:] if negate else line
        dir_only = line.endswith("/")
        line = line.strip("/") if dir_only else line
        anchored = line.startswith("/") or "/" in line
        line = line.lstrip("/")
        rx = ""
        i = 0
        while i < len(line):
            if line.startswith("**/", i):
                rx += "(?:.*/)?"
                i += 3
            elif line.startswith("**", i):
                rx += ".*"
                i += 2
            elif line[i] == "*":
                rx += "[^/]*"
                i += 1
            elif line[i] == "?":
                rx += "[^/]"
                i += 1
            else:
                rx += re.escape(line[i])
                i += 1
        prefix = "" if anchored else "(?:.*/)?"
        self.rules.append((base, re.compile(f"^{prefix}{rx}$"), negate, dir_only))

    def ignored(self, rel: str) -> bool:
        parts = rel.split("/")
        # a path is ignored when the path itself or one of its folders matches the last matching rule
        for depth in range(1, len(parts) + 1):
            sub = "/".join(parts[:depth])
            is_dir = depth < len(parts)
            state = None
            for base, rx, negate, dir_only in self.rules:
                if base and not (sub == base or sub.startswith(base + "/")):
                    continue
                local = sub[len(base) + 1:] if base else sub
                if not local or (dir_only and not is_dir):
                    continue
                if rx.match(local):
                    state = not negate
            if state:
                return True
        return False


def _walk(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d == ".goldeneye-check" or d not in SKIP_DIRS]
        for name in filenames:
            p = Path(dirpath) / name
            if not p.is_symlink():
                yield p.relative_to(root).as_posix()


def _absent(ctx: Context, files: list) -> list:
    names = {PurePosixPath(f).name for f in files}
    lower = [f.lower() for f in files]
    out = []
    images = " ".join(c.image for c in ctx.containers).lower()
    php_images = [c for c in ctx.containers if any(e["id"] == "php" for e in kb.entries_for(c.image))]
    # on shared hosting php.ini belongs to the host; in an image it is the project's job
    if php_images and not any(f.endswith(".ini") for f in lower) and \
            not any(c.stage and any("php.ini-production" in i.args for i in c.stage.instructions) for c in php_images):
        out.append("php_ini")
    if re.search(r"apache|httpd|nginx", images) and not any(
            re.search(r"(apache|httpd|nginx|sites-available|conf\.d)[^/]*/|\.conf$|nginx\.conf|\.htaccess$", f)
            for f in lower):
        out.append("web_server_config")
    uses_db = re.search(r"postgres|mysql|mariadb|mongo", images) or any(f.endswith(".sql") for f in lower)
    if uses_db and not any(re.search(r"(^|/)(migrations?|migrate|alembic|flyway|liquibase|db/init|schema)(/|\.)", f)
                           for f in lower):
        out.append("migrations")
    if not any(re.search(r"(^|/)(tests?|spec|__tests__)/|(^|/)test_[\w]+\.py$|_test\.(go|py)$|\.(test|spec)\.[jt]sx?$|"
                         r"Test\.java$", f) for f in files):
        out.append("tests")
    if not any(re.search(r"^\.github/workflows/|^\.gitlab-ci\.yml$|^Jenkinsfile$|^\.circleci/|^azure-pipelines\.yml$|"
                         r"^bitbucket-pipelines\.yml$", f) for f in files):
        out.append("ci")
    if not (ctx.root / ".git").exists():
        out.append("git")
    if "composer.json" in names and "composer.lock" not in names or \
            "package.json" in names and not names & {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb"}:
        out.append("lockfile")
    return out


def _artifact_kind(root: Path, rel: str):
    p = PurePosixPath(rel)
    parts = [x.lower() for x in p.parts[:-1]]
    name = p.name.lower()
    if name == ".gitignore":
        return None
    if ".goldeneye-check" in parts:
        return "scanner_report"
    size = (root / rel).stat().st_size
    if name.endswith(DUMP_EXT) and size > 0:
        return "dump"
    text = None
    if name.endswith(".sql") and size > 20_000:
        text = _read(root / rel)
        if len(re.findall(r"\bINSERT\s+INTO\b", text, re.I)) >= 20:
            return "dump"
    if name.endswith(".sarif"):
        return "security_report"
    if name.endswith(LOG_EXT) or REPORT_NAME.search(name) or any(d in REPORT_DIRS for d in parts):
        text = text if text is not None else _read(root / rel)
        if PRIVATE_IP.search(text):
            return "private_ip"
    return None


def build(ctx: Context) -> Inventory:
    inv = Inventory()
    files = list(_walk(ctx.root))
    for role, rx in ROLES.items():
        found = sorted(f for f in files if rx.search(f) and ".goldeneye-check/" not in f)
        if found:
            inv.roles[role] = found
    inv.absent = _absent(ctx, files)
    gi = GitIgnore(ctx.root)
    for rel in sorted(files):
        kind = _artifact_kind(ctx.root, rel)
        if kind and not gi.ignored(rel):
            inv.exposed.append((rel, kind))
    return inv


def check(inv: Inventory) -> list:
    out, folders = [], set()
    for rel, kind in inv.exposed:
        folder = rel.rsplit("/", 1)[0] if "/" in rel else ""
        # one finding per folder of scanner reports, one per file otherwise
        if kind == "scanner_report":
            if folder in folders:
                continue
            folders.add(folder)
        out.append(make("repo_artifact", "medium", rel, None, anchor=f"artifact:{rel}",
                        kind=CODE_WORDS[kind]))
    return out
