"""Stage 4, categories A and C in code: default secrets, credentials shown on pages, insecure cookies."""

import re

from .context import Context, _read
from .defaults import DEFAULT_REF, PLACEHOLDER, SECRET_VAR
from .findings import make

CODE_EXT = (".php", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".rb", ".vue", ".svelte")
PAGE_EXT = CODE_EXT + (".html", ".htm", ".twig", ".blade.php", ".erb", ".hbs", ".ejs", ".jinja", ".j2")

# getenv('X') ?: 'v' | $_ENV['X'] ?? 'v' | process.env.X || 'v' | os.getenv('X', 'v') | os.environ.get('X', 'v')
FALLBACKS = [
    re.compile(r"""getenv\(\s*['"](?P<var>\w+)['"]\s*\)\s*(?:\?:|\?\?|\|\|)\s*(?P<q>['"])(?P<val>[^'"]*)(?P=q)"""),
    re.compile(r"""\$_(?:ENV|SERVER)\[\s*['"](?P<var>\w+)['"]\s*\]\s*\?\?\s*(?P<q>['"])(?P<val>[^'"]*)(?P=q)"""),
    re.compile(r"""process\.env(?:\.(?P<var>\w+)|\[\s*['"](?P<var2>\w+)['"]\s*\])\s*(?:\|\||\?\?)\s*(?P<q>['"`])(?P<val>[^'"`]*)(?P=q)"""),
    re.compile(r"""os\.(?:getenv|environ\.get)\(\s*['"](?P<var>\w+)['"]\s*,\s*(?P<q>['"])(?P<val>[^'"]*)(?P=q)"""),
]
OUTPUT = re.compile(r"""\b(echo|print|printf|render|innerHTML|res\.send|return)\b|<[a-zA-Z/!]""")
ENV_READ = re.compile(r"getenv|process\.env|os\.environ|\$_ENV|\$\{\w+:?-")

COOKIE_INSECURE = [
    re.compile(r"""['"]secure['"]\s*=>\s*(false|0)\b""", re.I),                       # PHP arrays
    re.compile(r"""ini_set\(\s*['"]session\.cookie_secure['"]\s*,\s*['"]?(0|off|false)""", re.I),
    re.compile(r"""\b(SESSION|CSRF)_COOKIE_SECURE\s*=\s*False\b"""),                    # Django
    re.compile(r"""\bsecure\s*=\s*False\b"""),                                        # Flask set_cookie
    re.compile(r"""\bsecure\s*:\s*false\b"""),                                        # Express / cookie options
]
COOKIE_CONTEXT = re.compile(r"cookie|session", re.I)


def _code_files(ctx: Context, exts):
    for rel in sorted(ctx.files):
        if rel.lower().endswith(exts):
            yield rel, _read(ctx.root / rel)


def _var(m):
    return m.groupdict().get("var") or m.groupdict().get("var2") or ""


def check_fallbacks(ctx: Context):
    """Secrets that fall back to a literal when the environment variable is not set."""
    out, literals = [], {}
    for rel, code in _code_files(ctx, CODE_EXT):
        for i, line in enumerate(code.splitlines(), 1):
            for rx in FALLBACKS:
                for m in rx.finditer(line):
                    var, value = _var(m), m.group("val")
                    if not value or not SECRET_VAR.search(var):
                        continue
                    severity = "medium" if PLACEHOLDER.match(value) else "high"
                    out.append(make("code_default_secret", severity, rel, i, anchor=var, var=var))
                    literals.setdefault(value, (rel, i, var))
    return out, literals


def _compose_literals(ctx: Context) -> dict:
    found = {}
    for rel, _node, text in ctx.composes:
        for i, line in enumerate(text.splitlines(), 1):
            for m in DEFAULT_REF.finditer(line):
                value = m.group(2).strip().strip("\"'")
                if value and SECRET_VAR.search(m.group(1)):
                    found.setdefault(value, (rel, i, m.group(1)))
    return found


def check_credentials_in_pages(ctx: Context, literals: dict):
    """A default secret printed on a page: anyone who opens it can sign in."""
    out = []
    usable = {v: src for v, src in literals.items() if len(v) >= 6 and not PLACEHOLDER.match(v)}
    if not usable:
        return out
    for rel, code in _code_files(ctx, PAGE_EXT):
        for i, line in enumerate(code.splitlines(), 1):
            if ENV_READ.search(line) or not OUTPUT.search(line):
                continue
            for value, (_src, _line, var) in usable.items():
                if value in line:
                    out.append(make("credentials_in_page", "critical", rel, i, anchor=var, var=var))
                    break
    return out


def check_cookies(ctx: Context):
    out = []
    for rel, code in _code_files(ctx, CODE_EXT):
        lines = code.splitlines()
        for i, line in enumerate(lines, 1):
            for n, rx in enumerate(COOKIE_INSECURE):
                if not rx.search(line):
                    continue
                if n >= 3:  # generic forms: only next to cookie or session code
                    window = " ".join(lines[max(0, i - 4):i + 3])
                    if not COOKIE_CONTEXT.search(window):
                        continue
                out.append(make("cookie_not_secure", "high", rel, i, anchor=f"secure:{i}"))
                break
    return out


def scan(ctx: Context) -> list:
    fallbacks, literals = check_fallbacks(ctx)
    for value, src in _compose_literals(ctx).items():
        literals.setdefault(value, src)
    return fallbacks + check_credentials_in_pages(ctx, literals) + check_cookies(ctx)
