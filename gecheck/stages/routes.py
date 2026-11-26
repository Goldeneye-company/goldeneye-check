"""Stage 3, entry points: the routes of the application with their method, path and handler code.

Adapters: PHP front controller (if ($page === 'x'), a table of route names to functions, one file per
endpoint), Express, Flask, FastAPI, Django, Spring and Go (net/http, gin, chi, echo). A handler is
the code range that runs for the route; the checks of stage 4 read it together with the project
functions it calls (one level deep), because guards and audit calls usually live in helpers.
"""

import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from .measures import Sources, reachable

ROUTE_VAR = re.compile(r"\$(\w+)\s*=\s*.*\$_(GET|REQUEST|POST)\s*\[\s*['\"](page|action|route|p|a|r|do|cmd|view|section)['\"]")
PHP_IF_ROUTE = re.compile(r"^\s*(?:else)?if\s*\(\s*\$(\w+)\s*===?\s*['\"]([\w./-]*)['\"]\s*\)\s*\{?")
PHP_ROUTE_TABLE = re.compile(r"\$(\w+)\s*=\s*\[")
PHP_TABLE_ITEM = re.compile(r"""['"]([\w./-]+)['"]\s*=>\s*['"](\w+)['"]""")
EXPRESS = re.compile(r"\b(\w+)\.(get|post|put|patch|delete|all)\s*\(\s*(['\"`])([^'\"`]+)\3\s*,(.*)$")
PY_ROUTE = re.compile(r"^\s*@(\w+)\.(route|get|post|put|patch|delete|api_route)\s*\(\s*['\"]([^'\"]*)['\"](.*)$")
DJANGO = re.compile(r"""\b(?:re_)?path\s*\(\s*r?['"]([^'"]*)['"]\s*,\s*(?:views\.)?(\w+)""")
SPRING = re.compile(r"@(Get|Post|Put|Patch|Delete|Request)Mapping\b(\((.*)\))?")
GO_ROUTE = re.compile(r"\b(\w+)\.(GET|POST|PUT|PATCH|DELETE|Any|Handle|HandleFunc|Get|Post|Put|Patch|Delete)\s*\(\s*\"([^\"]+)\"\s*,\s*(.*)$")
PUBLIC_DIRS = ("public", "public_html", "www", "htdocs", "html", "web", "webroot", "api")


@dataclass
class Route:
    adapter: str
    file: str
    line: int
    method: str                      # GET, POST, ... or ANY
    path: str
    body: list = field(default_factory=list)   # [(file, start, end)]
    guard_before: bool = False       # a sign-in guard runs before the route (front controller)
    middleware: str = ""             # text of the arguments before the handler (Express, Go)

    @property
    def name(self) -> str:
        return self.path or PurePosixPath(self.file).name


class Functions:
    """Project functions by name, for handlers given by name and for one level of calls."""

    def __init__(self, sources: Sources):
        self.sources = sources
        self.index = {}
        for rel in sources.code:
            if rel.endswith(".py"):
                lines = sources.clean(rel).split("\n")
                for i, line in enumerate(lines, 1):
                    m = re.match(r"\s*(?:async\s+)?def\s+(\w+)\s*\(", line)
                    if m:
                        self.index.setdefault(m.group(1), (rel, i, _py_end(lines, i)))
            else:
                for name, b in sources.structure(rel).functions().items():
                    self.index.setdefault(name, (rel, max(1, b.start - 1), b.end))

    def get(self, name):
        return self.index.get(name)


def _py_end(lines, start):
    indent = len(lines[start - 1]) - len(lines[start - 1].lstrip())
    for j in range(start, len(lines)):
        s = lines[j]
        if s.strip() and len(s) - len(s.lstrip()) <= indent and not s.lstrip().startswith((")", "#")):
            return j
    return len(lines)


def _block_from(sources: Sources, rel: str, line: int):
    """The block that opens on the line (or the next line): its range, or None."""
    s = sources.structure(rel)
    starts = [b for b in s.blocks if line <= b.start <= line + 1]
    return (rel, line, starts[0].end) if starts else None


# PHP

def _php_front_controller(sources: Sources, rel: str, funcs: Functions) -> list:
    text = sources.clean(rel)
    lines = text.split("\n")
    names = {m.group(1) for m in ROUTE_VAR.finditer(text)} | {"page", "action", "route"}
    s = sources.structure(rel)
    out = []
    guard_line = None
    for i, line in enumerate(lines, 1):
        if guard_line is None and s.always_runs(i) and re.search(r"\brequire_?(employee|user|login|auth|admin)\w*\s*\(|"
                                                                 r"\brequire(Employee|User|Login|Auth|Admin)\w*\s*\(", line):
            guard_line = i
        m = PHP_IF_ROUTE.match(line)
        # routes of a front controller are top-level blocks; an if inside a function is a sub-action
        if m and m.group(1) in names and m.group(2) and not s.in_function(i):
            rng = _block_from(sources, rel, i)
            if rng:
                out.append(Route("php-front", rel, i, "ANY", m.group(2), [rng],
                                 guard_before=guard_line is not None and guard_line < i))
    if out:
        last_end = max(r.body[0][2] for r in out)
        rest = [i for i in range(last_end + 1, len(lines) + 1) if re.search(r"\becho\b|\bprint\b|\?>", lines[i - 1])]
        if rest:
            start = last_end + 1
            out.append(Route("php-front", rel, start, "GET", "(default)", [(rel, start, len(lines))],
                             guard_before=guard_line is not None and guard_line < rest[0]))
        return out
    # a table of route names to handler functions, called as $routes[$page]()
    for m in PHP_ROUTE_TABLE.finditer(text):
        var = m.group(1)
        if not re.search(rf"\${var}\s*\[[^;\n]*\]\s*\(\s*\)", text):
            continue
        start = text[:m.start()].count("\n") + 1
        end_pos = text.find("];", m.end())
        chunk = text[m.end():end_pos if end_pos > 0 else len(text)]
        for item in PHP_TABLE_ITEM.finditer(chunk):
            handler = funcs.get(item.group(2))
            line = start + chunk[:item.start()].count("\n")
            if handler:
                out.append(Route("php-table", rel, line, "ANY", item.group(1), [handler]))
    return out


def _php_routes(sources: Sources, funcs: Functions) -> list:
    php = [r for r in sources.code if r.endswith(".php") and reachable(sources, r)]
    included = set()
    for rel in php:
        for m in re.finditer(r"""\b(?:require|include)(?:_once)?\b[^;]*?['"][^'"]*?([\w.-]+\.php)['"]""", sources.clean(rel)):
            included.add(m.group(1))
    out = []
    for rel in php:
        found = _php_front_controller(sources, rel, funcs)
        if found:
            out += found
            continue
        parts = [p.lower() for p in PurePosixPath(rel).parts[:-1]]
        name = PurePosixPath(rel).name
        # one file per endpoint: a file in the web root that no other file includes
        if name not in included and (any(p in PUBLIC_DIRS for p in parts) or len(parts) == 0) and \
                not name.startswith("_"):
            n = len(sources.clean(rel).split("\n"))
            out.append(Route("php-file", rel, 1, "ANY", "/" + rel, [(rel, 1, n)]))
    return out


# JavaScript, Python, Java, Go

def _handler_range(sources, funcs, rel, i, rest):
    """Inline callback on the line, or the last identifier argument resolved as a function."""
    rng = _block_from(sources, rel, i)
    if rng and re.search(r"=>|function\b|func\s*\(", rest):
        return rng, rest
    idents = re.findall(r"[\w.]+", rest)
    for ident in reversed(idents):
        target = funcs.get(ident.split(".")[-1])
        if target:
            return target, rest
    return None, rest


def _framework_routes(sources: Sources, funcs: Functions) -> list:
    out = []
    for rel in sources.code:
        if not reachable(sources, rel):
            continue
        lines = sources.clean(rel).split("\n")
        suffix = PurePosixPath(rel).suffix.lower()
        for i, line in enumerate(lines, 1):
            if suffix in (".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"):
                m = EXPRESS.search(line)
                if m and (m.group(4).startswith("/") or m.group(4) == "*"):
                    rng, middleware = _handler_range(sources, funcs, rel, i, m.group(5))
                    if rng:
                        out.append(Route("express", rel, i, m.group(2).upper().replace("ALL", "ANY"),
                                         m.group(4), [rng], middleware=middleware))
            elif suffix == ".py":
                m = PY_ROUTE.match(line)
                if m:
                    j = i
                    decorators = [line]
                    while j < len(lines) and not re.match(r"\s*(async\s+)?def\s", lines[j]):
                        decorators.append(lines[j])
                        j += 1
                    if j < len(lines):
                        methods = re.findall(r"['\"](GET|POST|PUT|PATCH|DELETE)['\"]", m.group(4))
                        method = m.group(2).upper() if m.group(2) not in ("route", "api_route") else \
                            ("ANY" if len(methods) != 1 else methods[0])
                        if m.group(2) == "route" and not methods:
                            method = "GET"
                        out.append(Route("python", rel, i, method, m.group(3), [(rel, j + 1, _py_end(lines, j + 1))],
                                         middleware="\n".join(decorators + [lines[j]])))
                if PurePosixPath(rel).name == "urls.py":
                    for dm in DJANGO.finditer(line):
                        target = funcs.get(dm.group(2))
                        if target:
                            out.append(Route("django", rel, i, "ANY", "/" + dm.group(1), [target]))
            elif suffix in (".java", ".kt"):
                m = SPRING.search(line)
                if m and not re.search(r"\bclass\b", " ".join(lines[i:i + 3])):
                    s = sources.structure(rel)
                    method_block = next((b for b in s.blocks if b.start > i and b.is_function), None)
                    if method_block:
                        verb = m.group(1).upper()
                        if verb == "REQUEST":
                            vm = re.search(r"RequestMethod\.(\w+)", m.group(3) or "")
                            verb = vm.group(1) if vm else "ANY"
                        path = re.search(r"['\"]([^'\"]*)['\"]", m.group(3) or "")
                        header = "\n".join(lines[i - 1:method_block.start])
                        out.append(Route("spring", rel, i, verb, path.group(1) if path else "",
                                         [(rel, i, method_block.end)], middleware=header))
            elif suffix == ".go":
                m = GO_ROUTE.search(line)
                if m:
                    rng, middleware = _handler_range(sources, funcs, rel, i, m.group(4))
                    if rng:
                        verb = m.group(2).upper()
                        verb = "ANY" if verb in ("HANDLE", "HANDLEFUNC", "ANY") else verb
                        out.append(Route("go", rel, i, verb, m.group(3), [rng], middleware=middleware))
    return out


def collect(sources: Sources) -> list:
    funcs = Functions(sources)
    routes = _php_routes(sources, funcs) + _framework_routes(sources, funcs)
    return routes


CALL = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
KEYWORDS = {"if", "for", "foreach", "while", "switch", "return", "echo", "print", "isset", "empty", "array",
            "function", "fn", "catch", "elseif", "list", "match", "new", "require", "include", "exit", "die"}


def body_text(sources: Sources, route: Route, funcs: Functions = None, depth: int = 1) -> str:
    """Code of the handler plus the project functions it calls (one level by default)."""
    parts = []
    for rel, start, end in route.body:
        parts.append("\n".join(sources.clean(rel).split("\n")[start - 1:end]))
    text = "\n".join(parts)
    if funcs is None or depth <= 0:
        return text
    seen = set()
    extra = []
    for m in CALL.finditer(text):
        name = m.group(1)
        if name in KEYWORDS or name in seen:
            continue
        seen.add(name)
        target = funcs.get(name)
        if target and all(target != b for b in route.body):
            rel, start, end = target
            extra.append("\n".join(sources.clean(rel).split("\n")[start - 1:end]))
    return text + "\n" + "\n".join(extra)
