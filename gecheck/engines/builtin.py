"""Встроенные проверки конфигураций — то, что не видят gitleaks, osv-scanner и opengrep."""

import base64
import json
import re
import subprocess
from pathlib import Path

from ..i18n import TEXTS, tri
from ..model import SKIP_DIRS, Finding, mask_secret

GIT_SAFE = ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=", "-c", "core.longpaths=true"]


def _git(root: Path, *args):
    try:
        return subprocess.run(GIT_SAFE + ["-C", str(root), *args], capture_output=True,
                              text=True, encoding="utf-8", errors="replace", timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None


def _walk(root: Path, pattern: str):
    for p in root.rglob(pattern):
        rel = p.relative_to(root)
        if any(part in SKIP_DIRS for part in rel.parts[:-1]) or p.is_symlink() or not p.is_file():
            continue
        yield p, rel.as_posix()


def _read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="ignore") if p.stat().st_size < 2_000_000 else ""
    except OSError:
        return ""


def _finding(key, severity, category, path, line=None, cwe=None, anchor=None, snippet=None, **kw):
    return Finding(rule=f"ge.config.{key.replace('_', '-')}", engine="builtin", severity=severity,
                   category=category, file=path, line=line, title=tri(TEXTS[key]["title"], **kw),
                   fix=tri(TEXTS[key]["fix"], **kw), cwe=cwe, anchor=anchor, snippet=snippet)


ENV_EXAMPLE = re.compile(r"\.(example|sample|template|dist|defaults)$", re.I)


SECRET_VAR = re.compile(r"(SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|PRIVATE|CREDENTIAL|ACCESS_KEY|DSN|DATABASE_URL)", re.I)
PLACEHOLDER = re.compile(r"^(|changethis|change[-_]?me|your[-_ ].*|<.*>|x{3,}|\*+|example.*|dummy.*|todo|null|none|test|secret|password)$", re.I)
ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")


def env_secret_level(text: str) -> str:
    """real — есть похожие на настоящие секреты; placeholder — только заглушки; none — секретов нет."""
    real = placeholder = 0
    for line in text.splitlines():
        m = ENV_LINE.match(line)
        if not m or not SECRET_VAR.search(m.group(1)):
            continue
        value = re.split(r"\s+#", m.group(2), maxsplit=1)[0].strip().strip("\"'")
        if PLACEHOLDER.match(value) or "${" in value:
            placeholder += 1
        else:
            real += 1
    return "real" if real else "placeholder" if placeholder else "none"


ENV_LEVEL_SEVERITY = {"real": "critical", "placeholder": "medium", "none": "low"}


def check_env_files(root: Path, tracked):
    out = []
    if tracked is not None:
        for f in sorted(tracked):
            name = Path(f).name
            if name.startswith(".env") and not ENV_EXAMPLE.search(name):
                level = env_secret_level(_read(root / f))
                finding = _finding("env_in_git", ENV_LEVEL_SEVERITY[level], "secrets", f,
                                   cwe="CWE-538", anchor=f, file=f)
                finding.detail = tri(TEXTS["env_in_git"]["detail_" + level])
                out.append(finding)
        for p, rel in _walk(root, ".env*"):
            if ENV_EXAMPLE.search(p.name) or rel in tracked:
                continue
            proc = _git(root, "check-ignore", "-q", rel)
            if proc is not None and proc.returncode == 1:
                out.append(_finding("env_not_ignored", "medium", "secrets", rel, cwe="CWE-538", anchor=rel, file=rel))
    return out


PUBLIC_PREFIX = r"(?:NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|NUXT_PUBLIC_|PUBLIC_)"
PUBLIC_SECRET = re.compile(PUBLIC_PREFIX + r"[A-Z0-9_]*?(SECRET|PRIVATE|SERVICE_ROLE|SERVICE_KEY|PASSWORD|PASSWD|ADMIN_KEY)[A-Z0-9_]*")
PUBLIC_ASSIGN = re.compile(r"^\s*(?:export\s+)?(" + PUBLIC_PREFIX + r"[A-Z0-9_]+)\s*=\s*(\S+)", re.M)
CODE_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro"}


def _jwt_role(token: str):
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload)).get("role")
    except Exception:
        return None


def check_public_env(root: Path):
    out, seen = [], set()
    for p, rel in _walk(root, ".env*"):
        if ENV_EXAMPLE.search(p.name):
            continue
        text = _read(p)
        for m in PUBLIC_ASSIGN.finditer(text):
            name, value = m.group(1), m.group(2).strip("\"'")
            line = text.count("\n", 0, m.start()) + 1
            secret_name = PUBLIC_SECRET.fullmatch(name)
            service_jwt = _jwt_role(value) == "service_role"
            if secret_name or service_jwt:
                seen.add(name)
                sev = "critical" if service_jwt or "SERVICE" in name else "high"
                out.append(_finding("public_env_secret", sev, "secrets", rel, line, "CWE-200", anchor=name,
                                    snippet=f"{name}={mask_secret(value)}", name=name))
    for ext in CODE_EXT:
        for p, rel in _walk(root, f"*{ext}"):
            text = _read(p)
            for m in PUBLIC_SECRET.finditer(text):
                if m.group(0) in seen:
                    continue
                seen.add(m.group(0))
                line = text.count("\n", 0, m.start()) + 1
                out.append(_finding("public_env_secret", "high", "secrets", rel, line, "CWE-200",
                                    anchor=m.group(0), name=m.group(0)))
    return out


CREATE_TABLE = re.compile(r"create\s+table\s+(?:if\s+not\s+exists\s+)?((?:\"?\w+\"?\.)?\"?\w+\"?)", re.I)
ENABLE_RLS = re.compile(r"alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?((?:\"?\w+\"?\.)?\"?\w+\"?)\s+enable\s+row\s+level\s+security", re.I)


def _table_name(raw: str) -> str:
    name = raw.replace('"', "").lower()
    return name if "." in name else f"public.{name}"


def uses_supabase(root: Path) -> bool:
    """RLS важен только там, где таблицы открыты наружу через Supabase (PostgREST)."""
    if (root / "supabase").is_dir():
        return True
    manifests = ["package.json", "requirements.txt", "pyproject.toml"]
    candidates = [root / m for m in manifests] + [p for m in manifests for p in root.glob(f"*/{m}")]
    return any("supabase" in _read(p).lower() for p in candidates if p.is_file())


def check_supabase_rls(root: Path):
    if not uses_supabase(root):
        return []
    created, enabled = {}, set()
    for p, rel in sorted(_walk(root, "*.sql")):
        if "supabase" not in rel and "migrations" not in rel:
            continue
        text = _read(p)
        for m in CREATE_TABLE.finditer(text):
            table = _table_name(m.group(1))
            created.setdefault(table, (rel, text.count("\n", 0, m.start()) + 1))
        for m in ENABLE_RLS.finditer(text):
            enabled.add(_table_name(m.group(1)))
    out = []
    for table, (rel, line) in created.items():
        if table.startswith("public.") and table not in enabled:
            out.append(_finding("supabase_no_rls", "high", "data-access", rel, line, "CWE-284",
                                anchor=table, table=table))
    return out


OPEN_RULE = re.compile(r"allow\s+([\w,\s]+?)\s*:\s*if\s+true\s*;", re.I)
OPEN_JSON = re.compile(r'"\.(read|write)"\s*:\s*true')


def check_firebase(root: Path):
    out = []
    for name in ("firestore.rules", "storage.rules", "database.rules.json"):
        for p, rel in _walk(root, name):
            text = _read(p)
            matches = list(OPEN_RULE.finditer(text)) + list(OPEN_JSON.finditer(text))
            for m in matches:
                ops = m.group(1).lower()
                sev = "critical" if "write" in ops or ops.strip() in ("", "all") else "high"
                out.append(_finding("firebase_open", sev, "data-access", rel,
                                    text.count("\n", 0, m.start()) + 1, "CWE-284",
                                    anchor=m.group(0), file=rel))
    return out


DB_PASS = re.compile(r"(POSTGRES_PASSWORD|MYSQL_ROOT_PASSWORD|MYSQL_PASSWORD|MARIADB_ROOT_PASSWORD|"
                     r"MONGO_INITDB_ROOT_PASSWORD|REDIS_PASSWORD)\s*[:=]\s*[\"']?"
                     r"(postgres|root|password|admin|secret|example|123456|12345678|qwerty|changeme)[\"']?\s*(#.*)?$",
                     re.I | re.M)
DB_PORT = re.compile(r"^\s*-\s*[\"']?(?:0\.0\.0\.0:)?(5432|3306|27017|6379|9200|1433):\d+[\"']?\s*(#.*)?$", re.M)


def check_compose(root: Path):
    out = []
    for pattern in ("docker-compose*.yml", "docker-compose*.yaml", "compose*.yml", "compose*.yaml"):
        for p, rel in _walk(root, pattern):
            text = _read(p)
            # override-файлы — для локальной разработки, их риск ниже
            dev = "override" in p.name.lower()
            for m in DB_PASS.finditer(text):
                out.append(_finding("compose_default_password", "low" if dev else "high", "config", rel,
                                    text.count("\n", 0, m.start()) + 1, "CWE-1393",
                                    anchor=m.group(1), var=m.group(1)))
            for m in DB_PORT.finditer(text):
                out.append(_finding("compose_db_port", "low" if dev else "medium", "config", rel,
                                    text.count("\n", 0, m.start()) + 1, "CWE-668",
                                    anchor=m.group(1), port=m.group(1)))
    return out


SENSITIVE = re.compile(r"(^|/)(id_rsa|id_ed25519|.*\.pem|.*\.p12|.*\.pfx|.*\.keystore|.*\.jks|"
                       r".*(dump|backup).*\.(sql|gz|zip)|.*\.sqlite3?|.*\.db)$", re.I)


def check_sensitive_files(tracked):
    out = []
    for f in sorted(tracked or ()):
        if SENSITIVE.search(f) and not f.endswith(".pub"):
            out.append(_finding("sensitive_file", "high", "secrets", f, cwe="CWE-538", anchor=f, file=f))
    return out


def check_htaccess(root: Path):
    out = []
    for p, rel in _walk(root, ".htaccess"):
        text = _read(p)
        m = re.search(r"^\s*Options\s+[^#\n]*\+?Indexes", text, re.I | re.M)
        if m and "-Indexes" not in m.group(0):
            out.append(_finding("directory_listing", "medium", "config", rel,
                                text.count("\n", 0, m.start()) + 1, "CWE-548", anchor="indexes", file=rel))
    return out


def scan(root: Path, warnings: list):
    tracked = None
    if (root / ".git").exists():
        proc = _git(root, "ls-files")
        if proc is not None and proc.returncode == 0:
            tracked = set(proc.stdout.splitlines())
        else:
            warnings.append("git: не удалось получить список файлов репозитория")
    findings = []
    findings += check_env_files(root, tracked)
    findings += check_public_env(root)
    findings += check_supabase_rls(root)
    findings += check_firebase(root)
    findings += check_compose(root)
    findings += check_sensitive_files(tracked)
    findings += check_htaccess(root)
    return findings
