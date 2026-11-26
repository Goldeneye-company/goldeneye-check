"""Stage 4, the second pass of each category: a measure that is expected here and is missing.

Categories B (sign-in), F (files), G (strength of generated secrets), H (limits and races),
I (error handling), K (data lifecycle) and O (availability). The checks work on the code
structure from code.py and on the measures from measures.py; verify.py then removes or lowers
candidates (stage 7).
"""

import math
import re
from pathlib import PurePosixPath

from .. import kb
from ..i18n import LANGS
from ..i18n_code import CODE_WORDS
from .context import Context
from .findings import make
from .measures import Sources, by_key

PASSWORD_CHECK = re.compile(
    r"password_verify\s*\(|bcrypt(js)?\.compare(Sync)?\s*\(|argon2\.verify\s*\(|check_password_hash\s*\(|"
    r"bcrypt\.checkpw\s*\(|passwordEncoder\.matches\s*\(|\.check_password\s*\(", re.I)
# guards that mean the caller is already signed in (a password change, a confirmation)
SIGNED_IN = re.compile(r"\brequire_?(employee|user|login|auth|admin)\w*\s*\(|\brequireAuth\b|\bensureAuth|"
                       r"@login_required|@PreAuthorize|authenticate_user!|Depends\(\s*get_current_user", re.I)
LIMIT = re.compile(r"attempt|throttl|rate.?limit|limiter|lockout|locked|too many|brute|captcha|"
                   r"failed_?logins?|fail_?count", re.I)
LIMIT_PACKAGES = re.compile(r"express-rate-limit|rate-limiter-flexible|flask[-_]limiter|django-axes|"
                            r"django-ratelimit|rack-attack|slowapi|bucket4j|resilience4j-ratelimiter", re.I)
TIMING = re.compile(r"\$\w+(\[[^\]]+\])?\s*&&\s*password_verify|\w+\s*&&\s*(await\s+)?bcrypt\w*\.compare|"
                    r"\w+\s+and\s+(check_password_hash|bcrypt\.checkpw)")
HASH_CALL = re.compile(r"password_hash\s*\(|hash_password\s*\(|bcrypt\w*\.hash|generate_password_hash|dummy", re.I)

UPLOAD_STORE = re.compile(r"move_uploaded_file\s*\(|->storeAs?\s*\(|\.transferTo\s*\(|\.mv\s*\(|"
                          r"multer\s*\(\s*\{|diskStorage\s*\(", re.I)
PY_UPLOAD = re.compile(r"request\.(files|FILES)\b")
SERVED = re.compile(r"\breadfile\s*\(|fpassthru\s*\(|res\.(download|sendFile)\s*\(|send_file\s*\(|"
                    r"FileResponse|X-Sendfile|X-Accel-Redirect|StreamedResponse|->download\s*\(", re.I)

LOCK = re.compile(r"beginTransaction\s*\(|\bBEGIN\b|FOR\s+UPDATE|advisory|LOCK\s+TABLE|->lock\s*\(|\bflock\s*\(|"
                  r"SERIALIZABLE|GET_LOCK|\.transaction\s*\(|@Transactional|redis.*\b(incr|setnx)\b", re.I)
COUNT_SQL = re.compile(r"SELECT\s+COUNT\s*\(", re.I)
ATTEMPT_WORD = re.compile(r"fail|wrong|attempt|tries|login|password", re.I)
COMPARE = re.compile(r"(>=|>)\s*(\d+|\$\w+|\w+\[)")

FRAMEWORKS = re.compile(r"laravel/framework|symfony/|slim/slim|yiisoft/|cakephp/|codeigniter|laminas/", re.I)
DB_RUNTIMES = ("postgres", "mysql", "mariadb", "mongo")

GENERATED = [
    # PHP: substr(bin2hex(random_bytes(n)), 0, k)
    (re.compile(r"\$(?P<name>\w+)\s*=.*?substr\(\s*bin2hex\(\s*random_bytes\(\s*(?P<n>\d+)\s*\)\s*\)\s*,\s*0\s*,\s*(?P<k>\d+)"),
     lambda m: min(8 * int(m["n"]), 4 * int(m["k"]))),
    (re.compile(r"\$(?P<name>\w+)\s*=\s*bin2hex\(\s*random_bytes\(\s*(?P<n>\d+)\s*\)\s*\)"), lambda m: 8 * int(m["n"])),
    # PHP: random_int(a, b) and mt_rand(a, b)
    (re.compile(r"\$(?P<name>\w+)\s*=\s*\(?\s*(?:string\)\s*)?(?:random_int|mt_rand|rand)\(\s*(?P<a>\d+)\s*,\s*(?P<b>\d+)\s*\)"),
     lambda m: math.log2(max(2, int(m["b"]) - int(m["a"]) + 1))),
    # JavaScript: crypto.randomBytes(n).toString('hex')[.slice(0, k)]
    (re.compile(r"(?:const|let|var)\s+(?P<name>\w+)\s*=\s*(?:crypto\.)?randomBytes\(\s*(?P<n>\d+)\s*\)\.toString\(\s*['\"]hex['\"]\s*\)"
                r"(?:\.slice\(\s*0\s*,\s*(?P<k>\d+)\s*\))?"),
     lambda m: min(8 * int(m["n"]), 4 * int(m["k"] or 10 ** 6))),
    # Python: secrets.token_hex(n)[:k], secrets.token_urlsafe(n)
    (re.compile(r"(?P<name>\w+)\s*=\s*secrets\.token_hex\(\s*(?P<n>\d+)\s*\)(?:\[\s*:\s*(?P<k>\d+)\s*\])?"),
     lambda m: min(8 * int(m["n"]), 4 * int(m["k"] or 10 ** 6))),
    (re.compile(r"(?P<name>\w+)\s*=\s*secrets\.token_urlsafe\(\s*(?P<n>\d+)\s*\)"), lambda m: 8 * int(m["n"])),
]
SECRET_NAME = re.compile(r"pass|secret|token|apikey|api_key", re.I)



def _python_unit(text: str, line: int, before_only: bool) -> str:
    lines = text.split("\n")
    start = 0
    for i in range(line - 1, -1, -1):
        if re.match(r"\s*(async\s+)?def\s", lines[i]):
            start = i
            break
    indent = len(lines[start]) - len(lines[start].lstrip())
    end = len(lines)
    if not before_only:
        for j in range(line, len(lines)):
            s = lines[j]
            if s.strip() and len(s) - len(s.lstrip()) <= indent and not s.lstrip().startswith(("#", ")")):
                end = j
                break
    return "\n".join(lines[start:line if before_only else end])


def unit_text(sources: Sources, rel: str, line: int, before_only: bool = False) -> str:
    if rel.endswith(".py"):
        return _python_unit(sources.clean(rel), line, before_only)
    s = sources.structure(rel)
    start, end = s.unit_range(line)
    text = sources.clean(rel).split("\n")
    return "\n".join(text[start - 1:line if before_only else end])


# Category B: sign-in without an attempt limit; response time tells existing accounts

def check_login(sources: Sources) -> list:
    out, seen = [], set()
    project_limiter = sources.has(LIMIT_PACKAGES, sources.code + sources.other)
    for rel, line in sources.find(PASSWORD_CHECK):
        before = unit_text(sources, rel, line, before_only=True)
        if SIGNED_IN.search(before):
            continue
        unit = unit_text(sources, rel, line)
        key = (rel, unit[:200])
        if key in seen:
            continue
        seen.add(key)
        code_line = sources.clean(rel).split("\n")[line - 1]
        if TIMING.search(code_line) and len(HASH_CALL.findall(unit)) == 0:
            out.append(make("login_timing", "low", rel, line, anchor=f"timing:{line}"))
        if not LIMIT.search(unit) and not project_limiter:
            out.append(make("login_no_limit", "critical", rel, line, anchor=f"login:{line}"))
    return out


# Category F, K and O: what happens to an uploaded file

def _upload_sites(sources: Sources) -> list:
    sites = sources.find(UPLOAD_STORE)
    for rel in sources.code:
        if not rel.endswith(".py"):
            continue
        lines = sources.clean(rel).split("\n")
        for i, line in enumerate(lines, 1):
            if re.search(r"\.save\s*\(", line) and PY_UPLOAD.search("\n".join(lines[max(0, i - 8):i])):
                sites.append((rel, i))
    return sites


def check_uploads(sources: Sources, measures: dict) -> list:
    sites = _upload_sites(sources)
    if not sites:
        return []
    rel, line = sites[0]
    served = sources.has(SERVED)
    out = []
    missing = [m for m in ("antivirus", "integrity_hash", "encryption_at_rest") if m not in measures]
    if missing:
        if "antivirus" in missing and served:
            severity = "high"
        else:
            severity = "medium" if len(missing) >= 2 else "low"
        cwe = "CWE-311" if "encryption_at_rest" in missing else ("CWE-354" if "integrity_hash" in missing else "CWE-434")
        names = {lang: ", ".join(CODE_WORDS[m][lang] for m in missing) for lang in LANGS}
        out.append(make("upload_unprotected", severity, rel, line, anchor="upload", cwe=cwe, missing=names))
    if "deletion" not in measures:
        lines = sources.clean(rel).split("\n")
        insert = next((i for i in range(line, min(len(lines), line + 6) + 1)
                       if re.search(r"INSERT\s+INTO|\.create\s*\(|\.save\s*\(", lines[i - 1], re.I)), line)
        out.append(make("no_deletion", "high" if served else "medium", rel, insert, anchor="deletion"))
    if "quota" not in measures:
        out.append(make("no_quota", "low", rel, line, anchor="quota"))
    return out


# Category G: secrets generated with too little entropy

def check_generated_secrets(sources: Sources) -> list:
    out = []
    for rel, i, line in sources.lines(sources.code):
        for rx, bits_of in GENERATED:
            m = rx.search(line)
            if not m or not SECRET_NAME.search(m["name"]):
                continue
            bits = bits_of(m)
            need = 128 if re.search(r"token|secret|key", m["name"], re.I) else 64
            if bits < need:
                out.append(make("weak_generated_secret", "medium", rel, i, anchor=f"entropy:{m['name']}",
                                name=m["name"], bits=int(bits), need=need))
            break
    return out


# Category H: read the counter, decide, write, without a lock

def _locked_before(sources: Sources, rel: str, line: int) -> bool:
    return bool(LOCK.search(unit_text(sources, rel, line, before_only=True)))


def _callers_locked(sources: Sources, rel: str, line: int) -> bool:
    """The check is in a function, and every call of it is made under a lock."""
    if not rel.endswith((".php", ".js", ".ts", ".java", ".go")):
        return False
    unit = sources.structure(rel).unit(line)
    if unit is None or not unit.is_function or not unit.name:
        return False
    call = re.compile(rf"\b{re.escape(unit.name)}\s*\(")
    calls = [(r, i) for r, i in sources.find(call) if not (r == rel and unit.start - 1 <= i <= unit.end)]
    calls = [(r, i) for r, i in calls if not re.search(r"\bfunction\s+" + re.escape(unit.name),
                                                       sources.clean(r).split("\n")[i - 1])]
    return bool(calls) and all(_locked_before(sources, r, i) for r, i in calls)


def check_limit_races(sources: Sources) -> list:
    out = []
    for rel in sources.code:
        lines = sources.clean(rel).split("\n")
        last = -10
        for i, line in enumerate(lines, 1):
            if not COUNT_SQL.search(line) or i - last <= 3:  # several COUNTs of one statement: one finding
                continue
            context_text = " ".join(lines[i - 1:i + 2])
            if not ATTEMPT_WORD.search(context_text):
                continue
            if not COMPARE.search(" ".join(lines[i:i + 6])):
                continue
            if _locked_before(sources, rel, i) or _callers_locked(sources, rel, i):
                continue
            last = i
            by_ip = bool(re.search(r"REMOTE_ADDR|\$ip\b|ip_address|req\.ip\b|remote_addr|client_ip",
                                   " ".join(lines[max(0, i - 3):i + 4]), re.I))
            # a limit on failed guesses protects a secret; a limit on sends or requests protects a resource
            guessing = bool(re.search(r"fail|wrong|attempt|tries", context_text, re.I))
            out.append(make("limit_race", "high" if guessing else "medium", rel, i, anchor=f"race:{i}",
                            key=CODE_WORDS["per_ip"] if by_ip else ""))
    return out


# Category I: no global exception handler in plain PHP

def check_error_handler(sources: Sources, measures: dict) -> list:
    php = [r for r in sources.code if r.endswith(".php")]
    if not php or "exception_handler" in measures:
        return []
    composer = [r for r in sources.other if r.rsplit("/", 1)[-1] == "composer.json"]
    if composer and sources.has(FRAMEWORKS, composer):
        return []
    for rel in php:
        s = sources.structure(rel)
        for i, line in enumerate(sources.clean(rel).split("\n"), 1):
            if re.search(r"\bthrow\b", line) and not s.in_function(i):
                return [make("no_error_handler", "low", rel, i, anchor="exception_handler")]
    entry = next((r for r in php if PurePosixPath(r).name == "index.php"), php[0])
    return [make("no_error_handler", "low", entry, 1, anchor="exception_handler")]


# Category K: a database without backups

def check_backup(ctx: Context, measures: dict) -> list:
    if "backup" in measures:
        return []
    for c in ctx.containers:
        if c.compose_file and "backup" in (c.name + " " + c.image).lower():
            return []
    for c in ctx.containers:
        if c.service is None:
            continue
        runtimes = {e["runtime"] for e in kb.entries_for(c.image)}
        if runtimes & set(DB_RUNTIMES) or any(db in c.image.lower() for db in DB_RUNTIMES):
            return [make("no_backup", "medium", c.compose_file, c.image_line, anchor="backup", service=c.name)]
    return []


# Category O: expensive work at the top level of a file that runs on every request

INCLUDE = re.compile(r"""\b(?:require|include)(?:_once)?\b[^;]*?['"]([^'"]*?([\w.-]+\.php))['"]""")


def check_per_request(sources: Sources) -> list:
    """Top-level code of a file that other files include (bootstrap, config): every request runs it."""
    php = [r for r in sources.code if r.endswith(".php")]
    included = {m.group(2) for rel in php for m in INCLUDE.finditer(sources.clean(rel))}
    out = []
    for rel in php:
        if PurePosixPath(rel).name not in included:
            continue
        s = sources.structure(rel)
        lines = sources.clean(rel).split("\n")
        for i, line in enumerate(lines, 1):
            if not s.always_runs(i):
                continue
            if re.search(r"password_hash\s*\(", line):
                out.append(make("per_request_heavy", "medium", rel, i, anchor=f"hash:{i}", what="password_hash"))
            elif re.search(r"->(exec|query)\s*\(", line) and re.search(r"CREATE\s+(TABLE|INDEX)",
                                                                        " ".join(lines[i - 1:i + 3]), re.I):
                out.append(make("per_request_heavy", "medium", rel, i, anchor=f"ddl:{i}", what="CREATE TABLE"))
    return out


PASSWORD_CHANGE = re.compile(r"change_?password|changePassword|password_?reset|reset_?password|resetPassword|"
                             r"UPDATE\s+\w+\s+SET\s+[^;]*password|set_password\s*\(|PasswordResetView|"
                             r"update\(\s*\{[^}]*password", re.I)
ACCOUNT_DISABLE = re.compile(r"is_active|isActive|\bdisabled\b|deactivat|locked_at|is_blocked|\bbanned\b|suspend", re.I)
# the project keeps passwords of people, not only hashes of one-time codes
USER_PASSWORDS = re.compile(r"(password_hash|hash_password|bcrypt\w*\.hash\w*|generate_password_hash|make_password)\s*\("
                            r"\s*[^,)]*pass|^\s*[\"`]?password(_hash)?[\"`]?\s+(TEXT|VARCHAR|CHAR)", re.I | re.M)


def check_account_management(sources: Sources) -> list:
    """Category B: accounts with passwords but no way to change a password or disable an account."""
    checks = sources.find(PASSWORD_CHECK)
    if not checks or not sources.has(USER_PASSWORDS, sources.code + sources.other):
        return []
    missing = [w for w, rx in (("change", PASSWORD_CHANGE), ("disable", ACCOUNT_DISABLE)) if not sources.has(rx)]
    if not missing:
        return []
    rel, line = checks[0]
    return [make("no_account_management", "low", rel, line, anchor="accounts",
                 missing={lang: ", ".join(CODE_WORDS["account_" + w][lang] for w in missing) for lang in LANGS})]


def scan(ctx: Context, sources: Sources, measures: list) -> list:
    m = by_key(measures)
    return (check_login(sources) + check_account_management(sources) + check_uploads(sources, m)
            + check_generated_secrets(sources)
            + check_limit_races(sources) + check_error_handler(sources, m) + check_backup(ctx, m)
            + check_per_request(sources))
