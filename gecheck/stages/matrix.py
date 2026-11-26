"""Stage 4 on routes: the "route x measure" matrix of the methodology and the checks of categories C, D, E, G, I, J, L.

For every route the matrix records whether it requires a signed-in user, whether it changes data,
and whether the measures expected there are present: CSRF check, object owner check, audit log
entry, Cache-Control: no-store. An empty cell where the measure is expected is a finding.
One finding per measure lists all routes with the empty cell, so one missing habit does not
count as ten problems.
"""

import re
from dataclasses import dataclass, field

from .. import kb
from ..i18n import LANGS
from ..i18n_code import CODE_WORDS
from .absence import PASSWORD_CHECK
from .context import Context
from .findings import make
from .measures import Sources
from .routes import Functions, Route, body_text

AUTH_GUARD = re.compile(
    r"\brequire_?(employee|user|login|auth|admin|role|permission)\w*\s*\(|\brequire(Employee|User|Login|Auth|Admin|Role)\w*\s*\(|"
    r"@login_required|\blogin_required\b|Depends\(\s*\w*(current_user|auth|get_user)\w*|@PreAuthorize|@Secured|@RolesAllowed|"
    r"\b(ensure|require|check|verify)_?(Auth|LoggedIn|Authenticated|Token|Jwt|Session)\w*\s*\(|passport\.authenticate|"
    r"\bauth(Middleware|enticate[dD]?|Required|Guard)\b|\bisAuthenticated\b|\brequire_token\s*\(|->middleware\(\s*['\"]auth", re.I)
# middleware passed by name: app.post('/x', requireAuth, handler), r.Group("/", AuthRequired())
MIDDLEWARE_AUTH = re.compile(r"\b(require_?auth|ensure_?auth\w*|is_?authenticated|authenticate\w*|auth_?required|"
                             r"verify_?(token|jwt)|require_?login|logged_?in|jwt\w*|auth)\b", re.I)
ADMIN_GUARD =re.compile(r"\brequire_?admin\w*\s*\(|requireAdmin|role\W+admin|is_admin|hasRole\(\s*['\"](ROLE_)?ADMIN", re.I)
MUTATES = re.compile(r"\b(INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b|move_uploaded_file\s*\(|\bunlink\s*\(|"
                     r"session_destroy\s*\(|\$_SESSION\s*=\s*\[\s*\]|\.(save|create|update|destroy|delete|insert\w*)\s*\(|"
                     r"req\.session\.destroy|\blogout\s*\(|session\.(add|merge)\s*\(|\.commit\s*\(\s*\)|"
                     r"\.(persist|remove)\s*\(", re.I)
CSRF = re.compile(r"csrf|xsrf|hash_equals\s*\(\s*\$_SESSION", re.I)
OWNER = re.compile(r"\b\w*(user|owner|uploaded_by|created_by|author|employee|account|tenant|org)(_id|Id|ID)?\b\s*(=|==|===)|"
                   r"uploaded_by|created_by|owner_?id|user_?id|is_admin|\brole\b|can\(|authorize\(|@PreAuthorize|"
                   r"hasPermission|policy", re.I)
AUDIT = re.compile(r"\baudit\w*\s*\(|\badd_?log\s*\(|log_?event\s*\(|\blogger\.\w+\s*\(|\blog\.(info|warn|warning|error|notice)\s*\(|"
                   r"\blogging\.\w+\s*\(|\berror_log\s*\(|INSERT\s+INTO\s+\w*(audit|log|event|history)\w*|Log::\w+\s*\(|"
                   r"\bslog\.\w+\s*\(|\bzap\.\w+|log\.Printf\s*\(", re.I)
NO_STORE = re.compile(r"Cache-Control[^\n]*no-store|no_store\s*=\s*True|cache_control\(\s*no_store|CacheControl\.noStore|"
                      r"noStore\(\)|nocache\(\)", re.I)
SERVES_FILE = re.compile(r"\breadfile\s*\(|fpassthru\s*\(|res\.(download|sendFile)\s*\(|send_file\s*\(|FileResponse\s*\(|"
                         r"X-Sendfile|StreamedResponse|http\.ServeFile|c\.File\s*\(|ResponseEntity<Resource>|"
                         r"Content-Disposition", re.I)
SECRET_OUTPUT = re.compile(r"(\becho\b|\bprint\b|render|res\.(send|json)|return\b).*\[\s*['\"](password|token|secret|"
                           r"temporary_password)['\"]\s*\]|(\becho\b|\bprint\b).*\$\w*(password|secret)\w*\b", re.I)
ID_INPUT = re.compile(r"\$(?P<php>\w+)\s*=\s*(?:\(int\)\s*)?(?:filter_input\(\s*INPUT_(?:POST|GET)\s*,\s*['\"](?:\w*_id|id)['\"]|"
                      r"\(?\s*(?:int\)\s*)?\(?\$_(?:POST|GET|REQUEST)\s*\[\s*['\"](?:\w*_id|id)['\"]\s*\])|"
                      r"(?:const|let|var)\s+(?P<js>\w+)\s*=\s*(?:Number\(|parseInt\()?\s*req\.(?:params|body|query)\.(?:\w*[iI]d)\b|"
                      r"(?P<py>\w+)\s*=\s*(?:int\()?\s*request\.(?:args|form|json|values)(?:\.get\(\s*|\[\s*)['\"](?:\w*_id|id)['\"]")
DATA_ACCESS = re.compile(r"->execute\s*\(|->query\s*\(|\.query\s*\(|\.execute\s*\(|\.find\w*\s*\(|\.get\s*\(|\.where\s*\(|"
                         r"\.filter(_by)?\s*\(|\.(update|delete|destroy)\w*\s*\(", re.I)
TOKEN_QUERY = re.compile(r"\$_GET\s*\[\s*['\"](\w*(token|key|secret|password|code|hash)\w*)['\"]\s*\]|"
                         r"req\.query\.(\w*(token|key|secret|password)\w*)|"
                         r"request\.args(?:\.get\(\s*|\[\s*)['\"](\w*(token|key|secret|password)\w*)['\"]|"
                         r"r\.URL\.Query\(\)\.Get\(\s*\"(\w*(token|key|secret|password)\w*)\"|"
                         r"c\.Query\(\s*\"(\w*(token|key|secret|password)\w*)\"", re.I)
HOST_HEADER = re.compile(r"\$_SERVER\s*\[\s*['\"]HTTP_(X_FORWARDED_)?HOST['\"]\s*\]|req\.(headers\.host|get\(\s*['\"]host['\"]\s*\)|"
                         r"hostname)\b|request\.(host_url|url_root|host)\b|getServerName\s*\(", re.I)
SESSION_SECRET = re.compile(r"\$_SESSION\s*\[[^\]]+\]\s*(\[[^\]]+\]\s*)?=\s*.*['\"](password|token|secret|private_key)['\"]\s*=>|"
                            r"\$_SESSION\s*\[\s*['\"]\w*(password|secret)\w*['\"]\s*\]\s*=|"
                            r"req\.session\.\w*(password|secret)\w*\s*=|session\[\s*['\"]\w*(password|secret)\w*['\"]\s*\]\s*=", re.I)
SESSION_USE = re.compile(r"session_start\s*\(|express-session|req\.session\b", re.I)
SESSION_TIMEOUT = re.compile(r"last_activity|lastActivity|\bidle\b|absolute|gc_maxlifetime|cookie_lifetime|['\"]lifetime['\"]\s*=>\s*[1-9]|"
                             r"SESSION_TIMEOUT|maxAge|PERMANENT_SESSION_LIFETIME|SESSION_COOKIE_AGE|session_expired|rolling\s*:", re.I)
CSP = re.compile(r"Content-Security-Policy", re.I)
INLINE = re.compile(r"\son(click|load|submit|error|change|input|mouseover|focus)\s*=\s*\\?['\"]|<script>(?!\s*</script>)", re.I)
HTML_OUTPUT = re.compile(r"\becho\s*['\"]<|<html|res\.send\(\s*[`'\"]<|render_template|res\.render\s*\(|\.html['\"]", re.I)
LOGOUT = re.compile(r"logout|sign-?out|log-?off", re.I)
JSON_API = re.compile(r"php://input|json_decode\s*\(\s*file_get_contents|application/json|express\.json\s*\(|@RestController|"
                      r"request\.get_json|request\.json", re.I)
TOKEN_AUTH = re.compile(r"HTTP_AUTHORIZATION|Authorization|Bearer\b|getallheaders", re.I)
POST_ONLY = re.compile(r"REQUEST_METHOD['\"]\s*\]\s*(\?\?\s*['\"]\w+['\"]\s*\)?)?\s*!==?\s*['\"]POST|require_?post\s*\(|"
                       r"requirePost\s*\(", re.I)


@dataclass
class Cell:
    """One row of the matrix."""
    route: Route
    signed_in: bool
    admin: bool
    mutates: bool
    sign_in_route: bool
    csrf: bool
    owner: bool
    audit: bool
    no_store: bool
    sensitive: list = field(default_factory=list)   # (file, line) of responses that need no-store
    text: str = ""

    def to_json(self) -> dict:
        r = self.route
        return {"route": r.name, "method": r.method, "file": r.file, "line": r.line, "adapter": r.adapter,
                "signed_in": self.signed_in, "admin": self.admin, "changes_data": self.mutates,
                "sign_in": self.sign_in_route, "csrf": self.csrf, "owner_check": self.owner,
                "audit_log": self.audit, "no_store": self.no_store}


def _lines_in(sources: Sources, route: Route, rx: re.Pattern) -> list:
    hits = []
    for rel, start, end in route.body:
        lines = sources.clean(rel).split("\n")
        for i in range(start, min(end, len(lines)) + 1):
            if rx.search(lines[i - 1]):
                hits.append((rel, i))
    return hits


def _global_no_store(sources: Sources, routes: list, ctx: Context) -> bool:
    """no-store set outside the route handlers (a header function, middleware, web server or proxy config)."""
    inside = {(rel, i) for r in routes for rel, s, e in r.body for i in range(s, e + 1)}
    # code and server or proxy configuration; data files (JSON) that mention the header do not set it
    config = [r for r in sources.other if not r.lower().endswith((".json", ".csv", ".lock"))]
    for rel, i in sources.find(NO_STORE, sources.code + config):
        if (rel, i) not in inside:
            return True
    return False


def build(sources: Sources, routes: list, ctx: Context) -> list:
    funcs = Functions(sources)
    global_store = _global_no_store(sources, routes, ctx)
    cells = []
    for r in routes:
        text = body_text(sources, r, funcs)
        guard_text = text + "\n" + r.middleware
        # the call that sends the file first; a Content-Disposition header only when there is no such call
        serves = _lines_in(sources, r, SERVES_FILE)
        calls = [h for h in serves if not re.search(r"Content-Disposition", sources.clean(h[0]).split("\n")[h[1] - 1], re.I)]
        sensitive = (calls or serves) + _lines_in(sources, r, SECRET_OUTPUT)
        if not sensitive and r.body:
            # a handler that calls a helper which streams the file
            if SERVES_FILE.search(text):
                sensitive = [(r.file, r.line)]
        cells.append(Cell(
            route=r,
            signed_in=r.guard_before or bool(AUTH_GUARD.search(guard_text))
            or bool(r.adapter in ("express", "go") and MIDDLEWARE_AUTH.search(r.middleware)),
            admin=bool(ADMIN_GUARD.search(guard_text)),
            mutates=bool(MUTATES.search(text)),
            sign_in_route=bool(PASSWORD_CHECK.search(text)) and not AUTH_GUARD.search(guard_text),
            csrf=bool(CSRF.search(guard_text)),
            owner=bool(OWNER.search(text)),
            audit=bool(AUDIT.search(text)),
            no_store=global_store or bool(NO_STORE.search(text)),
            sensitive=sorted(set(sensitive)),
            text=text,
        ))
    return cells


def _names(cells: list) -> str:
    names = [c.route.name for c in cells]
    return ", ".join(names[:6]) + (", …" if len(names) > 6 else "")


# Category J: actions of signed-in users and sign-in events without an audit entry

def check_audit(cells: list) -> list:
    missing = [c for c in cells if not c.audit and ((c.signed_in and c.mutates) or c.sign_in_route
                                                     or LOGOUT.search(c.route.name))]
    if not missing:
        return []
    staff = any(c.signed_in and c.mutates for c in missing)
    first = min(missing, key=lambda c: (c.route.file, c.route.line))
    return [make("route_no_audit", "high" if staff else "medium", first.route.file, first.route.line,
                 anchor="audit", routes=_names(missing))]


# Category L: responses with secrets or files that browsers and proxies may cache

def check_no_store(cells: list) -> list:
    missing = [c for c in cells if c.sensitive and not c.no_store]
    if not missing:
        return []
    first = min(missing, key=lambda c: (c.route.file, c.route.line))
    rel, line = min(first.sensitive, key=lambda h: (h[0] != first.route.file, h[1]))
    return [make("route_no_store", "high", rel, line, anchor="no-store", routes=_names(missing))]


# Category D: an object id from the request used without an owner check

def check_owner(cells: list, sources: Sources) -> list:
    hits = []
    for c in cells:
        if not c.signed_in or c.admin or c.owner:
            continue
        for rel, start, end in c.route.body:
            lines = sources.clean(rel).split("\n")
            for i in range(start, min(end, len(lines)) + 1):
                m = ID_INPUT.search(lines[i - 1])
                if not m:
                    continue
                var = m.group("php") or m.group("js") or m.group("py")
                use = re.compile(rf"[\$\b]?\b{re.escape(var)}\b")
                for j in range(i + 1, min(end, len(lines)) + 1):
                    if use.search(lines[j - 1]) and DATA_ACCESS.search(lines[j - 1]):
                        hits.append((c, rel, j))
                        break
                break
    if not hits:
        return []
    c, rel, line = min(hits, key=lambda h: (h[1], h[2]))
    routes = []
    for h in hits:
        if h[0].route.name not in routes:
            routes.append(h[0].route.name)
    return [make("object_no_owner", "medium", rel, line, anchor="owner", routes=", ".join(routes[:6]))]


# Category E: state changes without a CSRF check; logout by GET

def check_csrf(cells: list, sources: Sources) -> list:
    out = []
    uses_session = sources.has(SESSION_USE)
    framework_csrf = sources.has(r"VerifyCsrfToken|CsrfViewMiddleware|csurf|CSRFProtect|csrf\(\)\.|lusca\.csrf|"
                                 r"@csrf_protect|gorilla/csrf|nosurf", sources.code + sources.other)
    if not uses_session or framework_csrf:
        return out
    missing, logout = [], []
    for c in cells:
        if not c.mutates or c.csrf or c.route.method == "GET" and not LOGOUT.search(c.route.name):
            continue
        if JSON_API.search(c.text) or TOKEN_AUTH.search(c.text):
            continue
        (logout if LOGOUT.search(c.route.name) else missing).append(c)
    for c in logout:
        if not POST_ONLY.search(c.text):
            out.append(make("logout_get", "low", c.route.file, c.route.line, anchor=f"logout:{c.route.name}"))
    if missing:
        first = min(missing, key=lambda c: (c.route.file, c.route.line))
        out.append(make("csrf_missing", "medium", first.route.file, first.route.line, anchor="csrf",
                        routes=_names(missing)))
    return out


# Category J: secrets in the query string end up in access logs

def _query_logged(ctx: Context, sources: Sources) -> bool:
    """False when every web server and proxy in the project is configured not to log the query string."""
    servers = set()
    for c in ctx.containers:
        for e in kb.entries_for(c.stage.image if c.stage else c.image):
            if e["runtime"] in ("apache", "nginx"):
                servers.add(e["runtime"])
        if re.search(r"\bcaddy\b", c.image or ""):
            servers.add("caddy")
    if not servers:
        return True
    files = sources.code + sources.other
    for server in servers:
        if server == "apache":
            formats = [(rel, i) for rel, i in sources.find(r"^\s*LogFormat\s", files)]
            if not formats or any(re.search(r"%r|%q|%\{QUERY_STRING\}", sources.clean(rel).split("\n")[i - 1])
                                  for rel, i in formats):
                return True
        elif server == "nginx":
            if not sources.has(r"access_log\s+off|log_format[^;]*\$uri\b(?![^;]*\$(request|args|request_uri))", files):
                return True
        elif server == "caddy":
            caddyfiles = [r for r in files if r.rsplit("/", 1)[-1].lower().startswith("caddyfile")]
            if not caddyfiles or sources.has(r"^\s*log\b", caddyfiles):
                return True
    return False


def check_query_tokens(cells: list, sources: Sources, ctx: Context) -> list:
    hits = []
    for c in cells:
        hits += [(rel, i) for rel, i in _lines_in(sources, c.route, TOKEN_QUERY)]
    if not hits or not _query_logged(ctx, sources):
        return []
    rel, line = min(hits)
    return [make("token_in_query", "medium", rel, line, anchor="query-token")]


# Category E: links built from the Host header

def check_host_header(cells: list, sources: Sources) -> list:
    for c in sorted(cells, key=lambda c: (c.route.file, c.route.line)):
        for rel, i in _lines_in(sources, c.route, HOST_HEADER):
            line = sources.clean(rel).split("\n")[i - 1]
            if re.search(r"://|url|link|href|redirect|location", line, re.I):
                return [make("host_header_url", "low", rel, i, anchor="host-header")]
    return []


# Category G: secrets kept in the session in plain text

def check_session_secrets(sources: Sources) -> list:
    out = []
    for rel, i in sources.find(SESSION_SECRET):
        line = sources.clean(rel).split("\n")[i - 1]
        if re.search(r"csrf|totp|nonce", line, re.I):
            continue
        out.append(make("secret_in_session", "low", rel, i, anchor=f"session-secret:{i}"))
        break
    return out


# Category C: sessions without an idle or absolute timeout

def check_session_timeout(sources: Sources) -> list:
    starts = sources.find(r"\bsession_start\s*\(|\bsession\s*\(\s*\{|express-session")
    config = [r for r in sources.other if r.lower().endswith((".ini", ".conf", ".yml", ".yaml", ".env", ".properties"))]
    if not starts or sources.has(SESSION_TIMEOUT, sources.code + config):
        return []
    rel, line = starts[0]
    return [make("session_no_timeout", "medium", rel, line, anchor="session-timeout")]


# Category L: HTML pages without a Content-Security-Policy

def check_csp(sources: Sources) -> list:
    if not sources.has(HTML_OUTPUT) or sources.has(CSP, sources.code + sources.other):
        return []
    inline = sources.find(INLINE)
    if inline:
        rel, line = inline[0]
        return [make("csp_missing", "medium", rel, line, anchor="csp",
                     inline=CODE_WORDS["inline_handlers"])]
    headers = sources.find(r"X-Frame-Options|X-Content-Type-Options|Referrer-Policy|helmet\s*\(")
    rel, line = headers[0] if headers else sources.find(HTML_OUTPUT)[0]
    return [make("csp_missing", "medium", rel, line, anchor="csp", inline={lang: "" for lang in LANGS})]


# Category I: an id that passed the type check but points to nothing raises an unhandled exception

def check_error_paths(cells: list, sources: Sources, measures: dict) -> list:
    if "exception_handler" in measures:
        return []
    for c in sorted(cells, key=lambda c: (c.route.file, c.route.line)):
        if re.search(r"\btry\b", c.text):
            continue
        for rel, start, end in c.route.body:
            lines = sources.clean(rel).split("\n")
            for i in range(start, min(end, len(lines)) + 1):
                m = ID_INPUT.search(lines[i - 1])
                if not m:
                    continue
                var = m.group("php") or m.group("js") or m.group("py")
                use = re.compile(rf"\b{re.escape(var)}\b")
                checked = False
                for j in range(i + 1, min(end, len(lines)) + 1):
                    line = lines[j - 1]
                    if re.search(r"\bSELECT\b|\.find\w*\(|\.get\(", line, re.I) and use.search(" ".join(lines[j - 1:j + 2])):
                        checked = True
                    if re.search(r"INSERT\s+INTO", line, re.I) and not checked:
                        for k in range(j, min(end, len(lines)) + 1):
                            if use.search(lines[k - 1]) and re.search(r"execute|query", lines[k - 1]):
                                return [make("error_path_unhandled", "medium", rel, k, anchor=f"error-path:{c.route.name}",
                                             var=var)]
                break
    return []


def scan(ctx: Context, sources: Sources, cells: list, measures: dict) -> list:
    return (check_audit(cells) + check_no_store(cells) + check_owner(cells, sources) + check_csrf(cells, sources)
            + check_query_tokens(cells, sources, ctx) + check_host_header(cells, sources)
            + check_session_secrets(sources) + check_session_timeout(sources) + check_csp(sources)
            + check_error_paths(cells, sources, measures))
