"""Stage 7, confirmed measures: security measures the code implements, with references to lines.

The list goes to the report (stage 9 maps it to ISO/IEC 27002 controls), and the absence checks
use it as evidence: a measure found in the project is not reported as missing, and a measure
nearby lowers or removes a candidate finding (suppress_if, see verify.py).
"""

import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from .code import LANG_BY_EXT, Structure, mask
from .context import Context, _read

CODE_EXT = (".php", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".rb", ".java", ".go", ".cs", ".kt",
            ".vue", ".svelte")
DOC_EXT = (".md", ".txt", ".rst", ".adoc", ".html", ".htm", ".pdf", ".csv", ".log")
DOC_DIRS = ("docs", "doc", "documentation")
# Code that a web request cannot reach: command-line tools, tests, migrations
OFFLINE_DIRS = ("bin", "cli", "scripts", "script", "console", "commands", "migrations", "seeds", "seeders",
                "tests", "test", "spec", "__tests__", "fixtures", "examples", "bench")


@dataclass
class Measure:
    key: str
    category: str
    cwe: list
    file: str
    lines: list = field(default_factory=list)


class Sources:
    """Texts of the project files, read once and shared by the stage 7 and stage 4 checks."""

    def __init__(self, ctx: Context):
        self.ctx = ctx
        self._text, self._clean, self._structure = {}, {}, {}
        self.code = [r for r in sorted(ctx.files) if r.lower().endswith(CODE_EXT)]
        self.other = [r for r in sorted(ctx.files)
                      if r not in self.code and not r.lower().endswith(DOC_EXT)
                      and not any(p.lower() in DOC_DIRS for p in PurePosixPath(r).parts[:-1])]

    def text(self, rel: str) -> str:
        if rel not in self._text:
            self._text[rel] = _read(self.ctx.root / rel)
        return self._text[rel]

    def clean(self, rel: str) -> str:
        """The text without comments: a "TODO: add antivirus" comment is not a measure."""
        if rel not in self._clean:
            suffix = PurePosixPath(rel).suffix.lower()
            text = self.text(rel)
            if suffix in LANG_BY_EXT:
                text = mask(text, LANG_BY_EXT[suffix], keep_strings=True)
            elif suffix == ".py":
                text = mask(text, "python")
            elif suffix == ".sql":
                text = "\n".join("" if line.lstrip().startswith("--") else line for line in text.split("\n"))
            elif suffix not in (".json",):
                text = mask(text, "config")
            self._clean[rel] = text
        return self._clean[rel]

    def structure(self, rel: str) -> Structure:
        if rel not in self._structure:
            lang = LANG_BY_EXT.get(PurePosixPath(rel).suffix.lower(), "js")
            self._structure[rel] = Structure(self.text(rel), lang)
        return self._structure[rel]

    def lines(self, files):
        for rel in files:
            for i, line in enumerate(self.clean(rel).split("\n"), 1):
                yield rel, i, line

    def find(self, pattern, files=None):
        """(file, line) of every match outside comments in code files (or the given files)."""
        rx = re.compile(pattern, re.I) if isinstance(pattern, str) else pattern
        return [(rel, i) for rel, i, line in self.lines(self.code if files is None else files) if rx.search(line)]

    def has(self, pattern, files=None) -> bool:
        rx = re.compile(pattern, re.I) if isinstance(pattern, str) else pattern
        return any(rx.search(self.clean(rel)) for rel in (self.code if files is None else files))


def reachable(sources: Sources, rel: str) -> bool:
    """False for command-line tools, tests and migrations: a web request does not run them."""
    parts = [p.lower() for p in PurePosixPath(rel).parts[:-1]]
    if any(p in OFFLINE_DIRS for p in parts):
        return False
    return not re.search(r"PHP_SAPI\s*===?\s*'cli'\s*\)\s*\{?\s*(exit|die|return)|\$argv\[1\]", sources.text(rel))


# key: (category, cwe, regex on a line); the regex is case-insensitive
PROBES = {
    "prepared_statements": ("E", ["CWE-89"],
                            r"->prepare\s*\(|->execute\s*\(\s*\[|\.prepare(Statement)?\s*\(|"
                            r"\bexecute\s*\(\s*['\"][^'\"]*(%s|\?|:\w+)[^'\"]*['\"]\s*,"),
    "session_regenerate": ("C", ["CWE-384"],
                           r"session_regenerate_id\s*\(|session\.regenerate\s*\(|cycle_key\s*\(|changeSessionId"),
    "mime_by_content": ("F", ["CWE-434"], r"\bfinfo\b|mime_content_type\s*\(|getimagesize\s*\(|magic\.from_|fileTypeFromBuffer"),
    "random_storage_name": ("F", ["CWE-22", "CWE-73", "CWE-434"],
                            r"\$\w*(stored|file|disk)\w*\s*=\s*(bin2hex\s*\(\s*random_bytes|Str::random|uniqid|"
                            r"Uuid|uuid)|(stored|disk)_?name\s*=\s*(secrets\.|uuid|crypto\.random)"),
    "strong_random": ("G", ["CWE-330", "CWE-331", "CWE-338"],
                      r"random_bytes\s*\(\s*(1[6-9]|[2-9]\d|\d{3,})\s*\)|secrets\.token_\w+\s*\(|"
                      r"randomBytes\s*\(\s*(1[6-9]|[2-9]\d|\d{3,})\s*\)|\bSecureRandom\b|\"crypto/rand\""),
    "password_hashing": ("G", ["CWE-916", "CWE-328", "CWE-759"],
                         r"password_hash\s*\(|bcrypt\.(hash|hashpw|genSalt)|\bargon2|PBKDF2|make_password\s*\(|"
                         r"generate_password_hash\s*\(|BCryptPasswordEncoder|hash_password\s*\("),
    "atomic_update": ("H", ["CWE-362", "CWE-367"],
                      r"beginTransaction\s*\(|\bFOR\s+UPDATE\b|pg_advisory|LOCK\s+TABLES?\b|\.transaction\s*\(|"
                      r"@Transactional|UPDATE\s+\w+\s+SET\s+(\w+)\s*=\s*\1\s*\+\s*1\b.*\bWHERE\b.*<"),
    "security_headers": ("L", ["CWE-1021", "CWE-79", "CWE-200", "CWE-693"],
                         r"X-Content-Type-Options|X-Frame-Options|Referrer-Policy|Content-Security-Policy|"
                         r"Strict-Transport-Security|frame-ancestors|\bhelmet\s*\(|Content-Disposition:\s*attachment"),
    "attempt_limit": ("B", ["CWE-307"],
                      r"COUNT\s*\(.*\b\w*(fail|wrong|attempt)\w*|(attempts|failures|failed)\w*[^;\n]{0,40}\s(>=|>)\s|"
                      r"\bRateLimiter\b|rateLimit\s*\(|express-rate-limit|\bthrottle\b|flask_limiter|@limiter\.|"
                      r"login_is_locked|lockout"),
    "mfa": ("B", ["CWE-308"],
            r"\b(totp|hotp|mfa|2fa)\b|two.?factor|webauthn|google2fa|speakeasy|pyotp|otplib|totp_verify"),
    "exception_handler": ("I", ["CWE-209", "CWE-755"],
                          r"set_exception_handler\s*\(|@app\.errorhandler|@ControllerAdvice|@ExceptionHandler|"
                          r"handler500|app\.use\(\s*(async\s*)?\(\s*err\b|process\.on\(\s*['\"]uncaughtException"),
    "antivirus": ("F", ["CWE-509"], r"clamav|clamd|\bclamscan\b|antivir|INSTREAM|virustotal|\bmalware\b"),
    "integrity_hash": ("F", ["CWE-354"],
                       r"hash_file\s*\(|hash_init\s*\(\s*['\"]sha|['\"]sha256['\"]|createHash\s*\(|hashlib\.sha\d+|"
                       r"MessageDigest|sha256sum"),
    "encryption_at_rest": ("G", ["CWE-311", "CWE-312"],
                           r"sodium_crypto_(secretstream|secretbox|aead)|openssl_encrypt\s*\(|\bFernet\b|"
                           r"createCipheriv\s*\(|AES/GCM|crypto_aead|encrypt_file\s*\("),
    "deletion": ("K", ["CWE-459"],
                 r"\bunlink\s*\(|\bDELETE\s+FROM\b|fs\.(unlink|rm)(Sync)?\s*\(|os\.(remove|unlink)\s*\(|"
                 r"Files\.delete|\.destroy\s*\(|shutil\.rmtree"),
    "retention": ("K", ["CWE-212"],
                  r"retention|\bcron\b|crontab|--loop|celery|APScheduler|@Scheduled|schedule:run|maintenance\.php"),
    "quota": ("O", ["CWE-770"], r"disk_free_space\s*\(|\bquota\b|SUM\s*\(\s*\w*size|storage_limit|max_storage"),
    "audit_log": ("J", ["CWE-778"], r"\baudit\w*\s*\(|\badd_?log\s*\(|log_?event\s*\(|INSERT\s+INTO\s+\w*(audit|log)\w*"),
}
# found in configuration, scripts and compose files as well as in code
EVERYWHERE = ("antivirus", "retention", "backup")
BACKUP = r"pg_dump|pg_basebackup|mysqldump|mariadb-dump|mongodump|\brestic\b|\bborg\b|wal-g|pgbackrest|barman|xtrabackup"


def _escape_helpers(sources: Sources) -> set:
    """Project functions that return htmlspecialchars/htmlentities of their argument."""
    names = set()
    for rel in sources.code:
        if not rel.endswith(".php"):
            continue
        s = sources.structure(rel)
        for name, b in s.functions().items():
            if re.search(r"htmlspecialchars|htmlentities", s.text(b.start - 1, b.end)):
                names.add(name)
    return names


def collect(ctx: Context, sources: Sources = None) -> list:
    sources = sources or Sources(ctx)
    out = []

    def add(key, category, cwe, hits):
        by_file = {}
        for rel, line in hits:
            by_file.setdefault(rel, []).append(line)
        for rel, lines in sorted(by_file.items()):
            out.append(Measure(key, category, list(cwe), rel, sorted(set(lines))))

    for key, (category, cwe, pattern) in PROBES.items():
        files = sources.code + sources.other if key in EVERYWHERE else sources.code
        add(key, category, cwe, sources.find(pattern, files))

    add("backup", "K", ["CWE-1059"], sources.find(BACKUP, sources.code + sources.other))

    helpers = _escape_helpers(sources)
    rx = r"htmlspecialchars\s*\(|htmlentities\s*\(" + "".join(rf"|\b{re.escape(n)}\s*\(" for n in sorted(helpers))
    php = [r for r in sources.code if r.endswith(".php")]
    add("output_escaping", "E", ["CWE-79"],
        sources.find(rx, php) + sources.find(r"escapeHtml\s*\(|markupsafe|DOMPurify\.sanitize", sources.code))

    if sources.has(r"hash_equals\s*\([^)]*csrf|csrf[^\n]*hash_equals|csrf_protect|CsrfViewMiddleware|csurf|"
                   r"VerifyCsrfToken|CSRFProtect|csrf\(\)"):
        add("csrf_check", "E", ["CWE-352"], sources.find(r"csrf"))

    gitignore = [r for r in ctx.files if r.rsplit("/", 1)[-1] == ".gitignore"]
    add("env_ignored", "N", ["CWE-538"], sources.find(r"^\s*/?\.env\b", gitignore))
    composes = [rel for rel, _node, _text in ctx.composes]
    add("db_port_local", "M", ["CWE-668"],
        sources.find(r"""["']?(127\.0\.0\.1|localhost|\[::1\]):\d+:(5432|3306|27017|6379)\b""", composes))
    return out


def by_key(measures: list) -> dict:
    out = {}
    for m in measures:
        out.setdefault(m.key, []).append(m)
    return out
